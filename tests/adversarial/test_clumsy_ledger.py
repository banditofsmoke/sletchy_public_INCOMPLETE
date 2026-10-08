"""Two Sletchy processes write to the record at once. The chain must not fork (#95).

The window's Kernel and a terminal command, or a double-clicked command run twice, are
two processes writing one ledger. Each used to append from the snapshot it took when it
opened: both wrote `seq=0` with the genesis hash, and every later open failed with
`expected seq=1, found seq=0`. The ledger never repairs itself, so that was a permanent
halt caused by nobody doing anything wrong.

Now one writer at a time holds an operating-system lock, and catches up with what is on
disk before it writes. The lock dies with its holder, so a killed process leaves nothing
behind. Every process here is started by the test, under `tmp_path`, on an in-memory key.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

from sletchy.cli import main as cli_main
from sletchy.cli import paths
from sletchy.cli.bridge import Bridge
from sletchy.cli.main import EXIT_CORRUPT, EXIT_FAILED, main
from sletchy.kernel.contracts import Decision, Plane, Subject, SubjectKind, Verdict
from sletchy.kernel.contracts.ledger import LedgerEntry
from sletchy.kernel.flags import FlagStore
from sletchy.kernel.ledger import (
    InMemoryKeySource,
    Ledger,
    LedgerBusy,
    LedgerCorrupt,
    MalformedEntry,
    TornFinalEntry,
    chain,
)

pytestmark = pytest.mark.adversarial

KEY = b"k" * 32


def open_ledger(root: Path, lock_wait: float = 5.0) -> Ledger:
    return Ledger.open(root, InMemoryKeySource(KEY), lock_wait=lock_wait)


def add(ledger: Ledger, label: str) -> None:
    ledger.append(
        plane=Plane.KERNEL,
        actor_id=label,
        action="test.write",
        subject=Subject(kind=SubjectKind.LEDGER, identifier=label),
        verdict=Verdict(decision=Decision.ALLOW, reason=label, rule_id=None),
    )


def seqs(root: Path) -> list[int]:
    ledger = open_ledger(root)
    return [entry.seq for entry in ledger.entries()]


# ── two writers ──────────────────────────────────────────────────────────────


def test_two_writers_taking_turns_never_fork_the_chain(tmp_path: Path) -> None:
    """Two objects on one folder are exactly what two processes are."""
    root = tmp_path / "ledger"
    window, terminal = open_ledger(root), open_ledger(root)

    for turn in range(10):
        add(window, f"window-{turn}")
        add(terminal, f"terminal-{turn}")

    assert seqs(root) == list(range(20))
    assert open_ledger(root).verify() == 20


WRITER = """
import sys
from pathlib import Path
from sletchy.kernel.contracts import Decision, Plane, Subject, SubjectKind, Verdict
from sletchy.kernel.ledger import InMemoryKeySource, Ledger

root, name, count, go = Path(sys.argv[1]), sys.argv[2], int(sys.argv[3]), Path(sys.argv[4])
ledger = Ledger.open(root, InMemoryKeySource(b"k" * 32), lock_wait=60)
Path(f"{go}.{name}").write_text("opened", encoding="utf-8")
while not go.exists():
    pass
for i in range(count):
    ledger.append(
        plane=Plane.KERNEL,
        actor_id=name,
        action="test.write",
        subject=Subject(kind=SubjectKind.LEDGER, identifier=f"{name}-{i}"),
        verdict=Verdict(decision=Decision.ALLOW, reason=name, rule_id=None),
    )
"""


def kernel_env() -> dict[str, str]:
    return {**os.environ, "SLETCHY_ALLOW_INMEMORY_KEY": "1"}


def test_processes_writing_at_the_same_moment_never_fork_the_chain(tmp_path: Path) -> None:
    """The real thing: separate processes, released together, each appending 25."""
    root = tmp_path / "ledger"
    open_ledger(root).close()
    go = tmp_path / "go"
    writers = [
        subprocess.Popen(
            [sys.executable, "-c", WRITER, str(root), f"p{n}", "25", str(go)],
            env=kernel_env(),
        )
        for n in range(4)
    ]
    try:
        # Every writer says when it has opened its snapshot of the empty ledger. This was a
        # one-second sleep, which a busy machine outran (#149): a writer then opened while
        # the others appended, which is what exposed the open race.
        opened = [Path(f"{go}.p{n}") for n in range(4)]
        deadline = time.monotonic() + 120
        while not all(p.exists() for p in opened):
            assert time.monotonic() < deadline, "a writer never opened the ledger"
            assert all(w.poll() is None for w in writers), "a writer exited before opening"
            time.sleep(0.05)
        go.write_text("go", encoding="utf-8")
        codes = [w.wait(timeout=120) for w in writers]
    finally:
        for w in writers:
            if w.poll() is None:
                w.kill()
                w.wait(timeout=10)

    assert codes == [0, 0, 0, 0]
    assert open_ledger(root).verify() == 100, "the chain forked"
    actors = [e.actor_id for e in open_ledger(root).entries()]
    assert sorted(set(actors)) == ["p0", "p1", "p2", "p3"]
    assert all(actors.count(a) == 25 for a in set(actors))


# ── opening while someone else writes (#149) ─────────────────────────────────


def test_an_append_landing_while_the_ledger_opens_is_not_a_broken_chain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The race, made certain instead of likely: another writer appends at the exact
    moment the open has finished checking the chain. Opening used to read the end
    again, see one entry more than it had checked, and raise `SequenceBroken`."""
    root = tmp_path / "ledger"
    writer = open_ledger(root)
    add(writer, "first")
    original = Ledger._read_segment
    fired: list[bool] = []

    def read_then_someone_appends(self: Ledger, path: Path) -> Iterator[LedgerEntry]:
        yield from original(self, path)
        if self is not writer and not fired:
            fired.append(True)
            add(writer, "between")

    monkeypatch.setattr(Ledger, "_read_segment", read_then_someone_appends)
    reader = open_ledger(root)
    assert fired, "the append did not land mid-open; the test proves nothing"
    assert reader.length == 1, "it sees the chain as it was when it checked it"
    add(reader, "after")  # catches up under the lock, and chains from the new end
    monkeypatch.undo()
    assert open_ledger(root).verify() == 3
    assert [e.actor_id for e in open_ledger(root).entries()] == ["first", "between", "after"]


def _half_written(root: Path) -> tuple[Path, bytes]:
    """Cut the last line of the active segment in two: an append still in flight."""
    segment = sorted(root.glob(chain._SEGMENT_GLOB))[-1]
    data = segment.read_bytes()
    start = data.rfind(b"\n", 0, len(data) - 1) + 1
    cut = start + (len(data) - start) // 2
    segment.write_bytes(data[:cut])
    return segment, data[cut:]


def test_a_line_being_written_while_the_ledger_opens_is_not_called_torn(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Another process holds the lock and is halfway through a line. That is a write
    in flight, not a crash: the open waits for the lock, then reads the finished line."""
    root = tmp_path / "ledger"
    first = open_ledger(root)
    add(first, "one")
    add(first, "two")
    first.close()
    segment, rest = _half_written(root)
    holder = (root / chain._LOCK_NAME).open("a+b")
    assert chain._try_lock(holder), "positive control: the lock was free to take"
    original = Ledger._acquire

    def the_writer_finishes_first(self: Ledger) -> None:
        with segment.open("ab") as fh:
            fh.write(rest)
        chain._unlock(holder)
        holder.close()
        original(self)

    monkeypatch.setattr(Ledger, "_acquire", the_writer_finishes_first)
    reader = open_ledger(root)
    monkeypatch.undo()
    assert reader.length == 2
    assert [e.actor_id for e in reader.entries()] == ["one", "two"]


def test_a_line_cut_off_with_nobody_writing_is_still_torn(tmp_path: Path) -> None:
    """Control: the fix waits for a writer, never for a crash. With the lock free, a
    cut-off line is read again under the lock, is still cut off, and is reported."""
    root = tmp_path / "ledger"
    first = open_ledger(root)
    add(first, "one")
    add(first, "two")
    first.close()
    _half_written(root)
    with pytest.raises(TornFinalEntry):
        open_ledger(root)


# ── waiting, and refusing ────────────────────────────────────────────────────


def test_a_writer_waits_for_the_lock_then_refuses_and_writes_nothing(tmp_path: Path) -> None:
    root = tmp_path / "ledger"
    holder, other = open_ledger(root), open_ledger(root, lock_wait=0.2)

    with holder.batch():
        add(holder, "holding")
        started = time.monotonic()
        with pytest.raises(LedgerBusy, match="nothing was recorded"):
            add(other, "refused")
        waited = time.monotonic() - started

    assert 0.15 <= waited < 3, f"waited {waited:.2f} s for a 0.2 s limit"
    assert [e.actor_id for e in open_ledger(root).entries()] == ["holding"]
    add(other, "after")
    assert open_ledger(root).verify() == 2


def test_reads_are_not_blocked_by_a_writer(tmp_path: Path) -> None:
    root = tmp_path / "ledger"
    holder = open_ledger(root)
    add(holder, "first")
    with holder.batch():
        add(holder, "buffered")
        started = time.monotonic()
        reader = open_ledger(root, lock_wait=0.0)
        assert reader.verify() == 1
        assert time.monotonic() - started < 2


def test_a_switch_refused_by_a_busy_record_does_not_change(tmp_path: Path) -> None:
    """LAW 1: if the record cannot be written, the action does not happen."""
    root = tmp_path / "ledger"
    holder = open_ledger(root)
    store = FlagStore.open(open_ledger(root, lock_wait=0.1), tmp_path / "flags.json")

    with holder.batch():
        add(holder, "holding")
        with pytest.raises(LedgerBusy):
            store.set("senses_camera", True, reason="video call")

    assert not store.is_on("senses_camera")
    assert not (tmp_path / "flags.json").exists()
    assert not (tmp_path / "flags.tmp").exists()
    assert (
        FlagStore.open(open_ledger(root), tmp_path / "flags.json").is_on("senses_camera") is False
    )


# ── a writer that dies ───────────────────────────────────────────────────────

HOLDER = """
import sys, time
from pathlib import Path
from sletchy.kernel.ledger import InMemoryKeySource, Ledger

ledger = Ledger.open(Path(sys.argv[1]), InMemoryKeySource(b"k" * 32))
with ledger.batch():
    print("locked", flush=True)
    time.sleep(120)
"""


def test_a_killed_writer_leaves_no_lock_behind(tmp_path: Path) -> None:
    """The lock is the operating system's, so it goes when its holder does."""
    root = tmp_path / "ledger"
    open_ledger(root).close()
    holder = subprocess.Popen(
        [sys.executable, "-c", HOLDER, str(root)],
        env=kernel_env(),
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        assert holder.stdout is not None
        assert holder.stdout.readline().strip() == "locked"
        with pytest.raises(LedgerBusy):
            add(open_ledger(root, lock_wait=0.2), "while-alive")
        holder.kill()
        holder.wait(timeout=30)
    finally:
        if holder.poll() is None:
            holder.kill()
            holder.wait(timeout=10)

    add(open_ledger(root, lock_wait=5), "after-death")
    assert [e.actor_id for e in open_ledger(root).entries()] == ["after-death"]


# ── panic ────────────────────────────────────────────────────────────────────


def test_panic_waits_a_second_at_most_and_still_does_everything_else(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv(paths.ENV_HOME, str(tmp_path / "var"))
    monkeypatch.setenv("SLETCHY_ALLOW_INMEMORY_KEY", "1")
    monkeypatch.setattr(cli_main, "KeyringKeySource", lambda *a, **k: InMemoryKeySource(KEY))
    monkeypatch.setattr(
        "sletchy.cli.panic.remove_firewall_rules", lambda *, dry_run=False: (0, 0, None)
    )
    holder = open_ledger(paths.ledger_dir())
    (paths.runtime_dir()).mkdir(parents=True)
    (paths.runtime_dir() / "sletchy.lock").write_text("", encoding="utf-8")

    with holder.batch():
        add(holder, "holding")
        started = time.monotonic()
        code = main(["stop"])
        waited = time.monotonic() - started

    out = capsys.readouterr().out
    assert code == EXIT_FAILED
    assert waited < 4, f"panic waited {waited:.1f} s on a busy record"
    assert "could not reset flags: LedgerBusy" in out
    assert "runtime files cleared  1" in out, "panic stopped at the busy record"


# ── a write that never finished (#98) ────────────────────────────────────────


def segment_file(root: Path) -> Path:
    return root / "segment-00000.ndjson"


def three_entries(root: Path, reason: str = "plain") -> bytes:
    ledger = open_ledger(root)
    for label in ("one", "two", "three"):
        ledger.append(
            plane=Plane.KERNEL,
            actor_id=label,
            action="test.write",
            subject=Subject(kind=SubjectKind.LEDGER, identifier=label),
            verdict=Verdict(decision=Decision.ALLOW, reason=reason, rule_id=None),
        )
    ledger.close()
    return segment_file(root).read_bytes()


@pytest.mark.parametrize(
    ("cut", "reason"),
    [
        (20, "plain"),
        (1, "plain"),  # only the line ending lost: the entry is whole, the write is not
        (None, "caf\u00e9 \u2615"),  # cut inside a multi-byte character
    ],
    ids=["mid-line", "no line ending", "inside a character"],
)
def test_a_cut_off_last_line_is_reported_as_a_write_that_never_finished(
    tmp_path: Path, cut: int | None, reason: str
) -> None:
    root = tmp_path / "ledger"
    whole = three_entries(root, reason)
    if cut is None:
        cut = len(whole) - whole.rindex("\u2615".encode()) - 1  # through the coffee cup
    segment_file(root).write_bytes(whole[:-cut])
    torn = segment_file(root).read_bytes()

    with pytest.raises(
        TornFinalEntry, match=r"the last write to segment-00000.ndjson did not finish"
    ) as raised:
        open_ledger(root)

    assert isinstance(raised.value, LedgerCorrupt), "it is still corruption, and still halts"
    assert "after 2 complete entries" in str(raised.value)
    assert segment_file(root).read_bytes() == torn, "something repaired the record"


def test_a_bad_line_that_was_ended_is_still_plain_corruption(tmp_path: Path) -> None:
    """The control: only an unended last line is an unfinished write."""
    root = tmp_path / "ledger"
    whole = three_entries(root)
    last = whole.rstrip(b"\n").rindex(b"\n") + 1
    segment_file(root).write_bytes(whole[:last] + b"not an entry\n")

    with pytest.raises(MalformedEntry) as raised:
        open_ledger(root)
    assert not isinstance(raised.value, TornFinalEntry)


def test_the_operator_is_told_what_happened_and_nothing_is_changed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv(paths.ENV_HOME, str(tmp_path / "var"))
    monkeypatch.setenv("SLETCHY_ALLOW_INMEMORY_KEY", "1")
    monkeypatch.setattr(cli_main, "KeyringKeySource", lambda *a, **k: InMemoryKeySource(KEY))
    whole = three_entries(paths.ledger_dir())
    segment_file(paths.ledger_dir()).write_bytes(whole[:-20])
    torn = segment_file(paths.ledger_dir()).read_bytes()

    assert main(["ledger", "verify"]) == EXIT_CORRUPT
    assert "did not finish" in capsys.readouterr().err
    assert main(["status"]) == EXIT_CORRUPT
    assert "did not finish" in capsys.readouterr().out
    window = Bridge(InMemoryKeySource(KEY)).status(None)  # type: ignore[arg-type]
    assert window.ledger_state == "corrupt"
    assert "did not finish" in window.detail
    assert segment_file(paths.ledger_dir()).read_bytes() == torn
