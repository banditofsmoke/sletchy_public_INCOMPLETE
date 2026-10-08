"""Someone floods the ledger to fill the disk. It stops at a ceiling (#101).

Every flag flip is one entry, about 490 bytes, and an append costs one fsync, about 30 ms.
Anything that can call `flags.set` in a loop - a hostile page in the window, a script at
the terminal - grew the ledger by about 1.4 GB a day with nothing to stop it, on my
only computer and on friends' machines with 10 GB free.

My decision, 2026-10-03: **1 GB, and never below 2 GB free on the drive.** Past
the ceiling, nothing new may happen (LAW 1: no record, no action), except switching
things off and panic, which keep a small reserve so stopping can always be recorded. The
reserve never overrides the floor.

Ceilings here are a few kilobytes, set through the same arguments the real ones use.
"""

from __future__ import annotations

from collections import namedtuple
from pathlib import Path

import pytest

from sletchy.cli import main as cli_main
from sletchy.cli import paths
from sletchy.cli.bridge import Bridge
from sletchy.cli.main import EXIT_FAILED, main
from sletchy.cli.panic import panic
from sletchy.kernel.contracts import Decision, Plane, Subject, SubjectKind, Verdict
from sletchy.kernel.flags import FlagStore
from sletchy.kernel.ledger import InMemoryKeySource, Ledger, LedgerFull
from sletchy.kernel.ledger import chain as chain_mod

pytestmark = [pytest.mark.adversarial, pytest.mark.law_zero]

KEY = b"k" * 32
CEILING = 4_000

Usage = namedtuple("Usage", "total used free")


def open_ledger(root: Path, **kw: int) -> Ledger:
    return Ledger.open(root, InMemoryKeySource(KEY), max_bytes=kw.get("max_bytes", CEILING))


def add(ledger: Ledger, n: int = 0, *, safer: bool = False) -> None:
    ledger.append(
        plane=Plane.KERNEL,
        actor_id="flood",
        action="test.flood",
        subject=Subject(kind=SubjectKind.LEDGER, identifier=f"e{n}"),
        verdict=Verdict(decision=Decision.ALLOW, reason="x" * 100, rule_id=None),
        safer=safer,
    )


def flood(ledger: Ledger) -> int:
    """Append until refused. Returns how many got in."""
    written = 0
    with pytest.raises(LedgerFull, match="ceiling"):
        while written < 200:  # a few entries fit under CEILING; 200 is far past it
            add(ledger, written)
            written += 1
    return written


def size(root: Path) -> int:
    return sum(p.stat().st_size for p in root.glob("segment-*.ndjson"))


# ── the ceiling ──────────────────────────────────────────────────────────────


def test_a_flood_stops_at_the_ceiling_and_the_chain_still_verifies(tmp_path: Path) -> None:
    root = tmp_path / "ledger"
    written = flood(open_ledger(root))

    assert 0 < written < 200
    assert size(root) <= CEILING
    assert open_ledger(root).verify() == written
    assert open_ledger(root).full() is not None, "a full ledger does not say so"


def test_a_ledger_reopened_full_is_still_full(tmp_path: Path) -> None:
    """The size is read from disk at open, not counted from zero per process."""
    root = tmp_path / "ledger"
    flood(open_ledger(root))
    with pytest.raises(LedgerFull):
        add(open_ledger(root))


def test_a_switch_turned_on_against_a_full_ledger_stays_off(tmp_path: Path) -> None:
    """LAW 1: no record, no action - and nothing staged is left behind."""
    root = tmp_path / "ledger"
    ledger = open_ledger(root)
    flood(ledger)
    store = FlagStore.open(ledger, tmp_path / "flags.json")

    with pytest.raises(LedgerFull):
        store.set("senses_camera", True, reason="video call")

    assert not store.is_on("senses_camera")
    assert not (tmp_path / "flags.json").exists()
    assert not (tmp_path / "flags.tmp").exists()


# ── switching off still works ────────────────────────────────────────────────


def test_switching_off_and_panic_still_work_on_a_full_ledger(tmp_path: Path) -> None:
    root = tmp_path / "ledger"
    store = FlagStore.open(open_ledger(root, max_bytes=100_000), tmp_path / "flags.json")
    store.set("senses_camera", True, reason="video call")
    store.set("senses_microphone", True, reason="dictation")
    ledger = open_ledger(root, max_bytes=size(root) + 1)
    store = FlagStore.open(ledger, tmp_path / "flags.json")
    with pytest.raises(LedgerFull):
        add(ledger)

    store.set("senses_camera", False)
    report = panic(store)

    assert not store.is_on("senses_camera")
    assert not store.is_on("senses_microphone")
    assert report.flags_reset == 1
    assert report.ledger_sealed
    assert open_ledger(root).verify() == 4


def test_the_reserve_for_switching_off_runs_out_too(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A flood of "off" would otherwise be a flood after all."""
    monkeypatch.setattr(chain_mod, "SAFER_RESERVE_BYTES", 2_000)
    ledger = open_ledger(tmp_path / "ledger")
    flood(ledger)

    with pytest.raises(LedgerFull, match="reserve kept for switching things off is used up"):
        for n in range(200):
            add(ledger, n, safer=True)
    assert size(tmp_path / "ledger") <= CEILING + 2_000


# ── the disk ─────────────────────────────────────────────────────────────────


def nearly_full(monkeypatch: pytest.MonkeyPatch, free: int) -> None:
    monkeypatch.setattr(
        "sletchy.kernel.ledger.chain.shutil.disk_usage",
        lambda _: Usage(10**12, 10**12 - free, free),
    )


def test_nothing_is_written_that_would_leave_the_drive_under_two_gb(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ledger = open_ledger(tmp_path / "ledger", max_bytes=10**9)
    nearly_full(monkeypatch, chain_mod.MIN_FREE_BYTES + 100)

    with pytest.raises(LedgerFull, match="free on the drive"):
        add(ledger)
    with pytest.raises(LedgerFull, match="free on the drive"):
        add(ledger, safer=True)  # the reserve never overrides the floor
    assert size(tmp_path / "ledger") == 0


def test_a_drive_whose_free_space_cannot_be_read_refuses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Could not look is not "plenty of room" (L009)."""
    ledger = open_ledger(tmp_path / "ledger", max_bytes=10**9)

    def cannot(_: object) -> Usage:
        msg = "the drive did not answer"
        raise OSError(msg)

    monkeypatch.setattr("sletchy.kernel.ledger.chain.shutil.disk_usage", cannot)
    with pytest.raises(LedgerFull, match="could not read the free space"):
        add(ledger)


def test_a_ledger_well_inside_both_limits_writes_as_before(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control: plenty of room is not refused."""
    nearly_full(monkeypatch, chain_mod.MIN_FREE_BYTES * 10)
    ledger = open_ledger(tmp_path / "ledger", max_bytes=10**9)
    for n in range(20):
        add(ledger, n)
    assert open_ledger(tmp_path / "ledger").verify() == 20


# ── it is said plainly ───────────────────────────────────────────────────────


def test_status_and_the_window_say_the_ledger_is_full(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv(paths.ENV_HOME, str(tmp_path / "var"))
    monkeypatch.setenv("SLETCHY_ALLOW_INMEMORY_KEY", "1")
    monkeypatch.setattr(cli_main, "KeyringKeySource", lambda *a, **k: InMemoryKeySource(KEY))
    monkeypatch.setattr(chain_mod, "MAX_LEDGER_BYTES", CEILING)
    flood(Ledger.open(paths.ledger_dir(), InMemoryKeySource(KEY)))

    assert main(["status"]) == EXIT_FAILED
    assert "FULL - the ledger has reached its ceiling" in capsys.readouterr().out
    assert main(["flags", "set", "cli_verbose", "on"]) == EXIT_FAILED
    assert "ceiling" in capsys.readouterr().err
    window = Bridge(InMemoryKeySource(KEY)).status(None)  # type: ignore[arg-type]
    assert "full: the ledger has reached its ceiling" in window.detail
