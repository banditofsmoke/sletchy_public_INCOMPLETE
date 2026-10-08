"""Adversarial tests for the ledger.

Each test asserts the **specific** failure, not merely that something raised. A
tamper test that accepts any exception silently stops testing tampering the moment
an unrelated bug starts raising first.

Nothing here touches the host: every ledger lives in a pytest `tmp_path`.
"""

from __future__ import annotations

import itertools
import json
from pathlib import Path

import pytest

from sletchy.cli import main as cli_main
from sletchy.cli import paths
from sletchy.cli.main import EXIT_CORRUPT, EXIT_OK, main
from sletchy.kernel.contracts import (
    Decision,
    Plane,
    Subject,
    SubjectKind,
    Verdict,
)
from sletchy.kernel.ledger import (
    BadSignature,
    BrokenChain,
    InMemoryKeySource,
    Ledger,
    LedgerRolledBack,
    MalformedEntry,
    SequenceBroken,
    entry_hash,
)

pytestmark = pytest.mark.adversarial


def make_ledger(tmp_path: Path, key: bytes = b"k" * 32) -> Ledger:
    return Ledger.open(tmp_path / "ledger", InMemoryKeySource(key))


def add(ledger: Ledger, n: int = 3) -> None:
    for i in range(n):
        ledger.append(
            plane=Plane.WARDEN,
            actor_id="agent_a",
            action="warden.egress.request",
            subject=Subject(kind=SubjectKind.HOST, identifier=f"host{i}.example"),
            verdict=Verdict.default_deny(f"test entry {i}"),
        )


def lines(root: Path) -> list[str]:
    path = root / "segment-00000.ndjson"
    return path.read_text(encoding="utf-8").strip().splitlines()


def rewrite(root: Path, new_lines: list[str]) -> None:
    (root / "segment-00000.ndjson").write_text("\n".join(new_lines) + "\n", encoding="utf-8")


# ── the core claim: history cannot be edited ────────────────────────────────


def test_mutating_a_field_breaks_the_signature(tmp_path: Path) -> None:
    root = tmp_path / "ledger"
    add(make_ledger(tmp_path))

    rows = lines(root)
    entry = json.loads(rows[1])
    entry["actor_id"] = "someone_else"
    rows[1] = json.dumps(entry)
    rewrite(root, rows)

    with pytest.raises(BadSignature) as exc:
        make_ledger(tmp_path).verify()
    assert exc.value.seq == 1


def test_mutating_the_verdict_breaks_the_signature(tmp_path: Path) -> None:
    """The field an attacker would most want to change: deny -> allow."""
    root = tmp_path / "ledger"
    add(make_ledger(tmp_path))

    rows = lines(root)
    entry = json.loads(rows[1])
    entry["verdict"]["decision"] = Decision.ALLOW.value
    rows[1] = json.dumps(entry)
    rewrite(root, rows)

    with pytest.raises(BadSignature):
        make_ledger(tmp_path).verify()


def test_deleting_a_middle_entry_breaks_the_chain(tmp_path: Path) -> None:
    root = tmp_path / "ledger"
    add(make_ledger(tmp_path))

    rows = lines(root)
    rewrite(root, [rows[0], rows[2]])

    with pytest.raises(SequenceBroken) as exc:
        make_ledger(tmp_path).verify()
    assert exc.value.seq == 2


def test_truncating_the_tail_is_caught_by_the_keychain_mark(tmp_path: Path) -> None:
    """Was a documented gap: a chain cut short verifies on its own terms (#99).

    Nothing inside the file can prove entries once followed it, so the proof lives
    outside: the newest entry's `seq` and hash, in the keychain beside the signing key.
    """
    root = tmp_path / "ledger"
    keys = InMemoryKeySource(b"k" * 32)
    add(Ledger.open(root, keys), 5)

    rewrite(root, lines(root)[:3])

    with pytest.raises(
        LedgerRolledBack,
        match="shorter than it was: the keychain records entry 4, and the chain ends at entry 2",
    ):
        Ledger.open(root, keys)


def test_reordering_entries_is_detected(tmp_path: Path) -> None:
    root = tmp_path / "ledger"
    add(make_ledger(tmp_path))

    rows = lines(root)
    rewrite(root, [rows[0], rows[2], rows[1]])

    with pytest.raises(SequenceBroken):
        make_ledger(tmp_path).verify()


def test_swapping_a_signature_between_valid_entries_is_detected(tmp_path: Path) -> None:
    """Why `prev_hash` covers the signature too.

    Both signatures below are genuine. If the chain only committed to an entry's
    *content*, moving a real signature onto a different real entry would go
    unnoticed.
    """
    root = tmp_path / "ledger"
    add(make_ledger(tmp_path))

    rows = lines(root)
    a, b = json.loads(rows[1]), json.loads(rows[2])
    a["signature"], b["signature"] = b["signature"], a["signature"]
    rows[1], rows[2] = json.dumps(a), json.dumps(b)
    rewrite(root, rows)

    with pytest.raises(BadSignature):
        make_ledger(tmp_path).verify()


def test_appending_a_forged_entry_breaks_the_chain(tmp_path: Path) -> None:
    """An attacker who can write the file but not sign cannot extend the chain."""
    root = tmp_path / "ledger"
    add(make_ledger(tmp_path))

    rows = lines(root)
    forged = json.loads(rows[2])
    forged["seq"] = 3
    forged["actor_id"] = "attacker"
    rows.append(json.dumps(forged))
    rewrite(root, rows)

    with pytest.raises(BrokenChain) as exc:
        make_ledger(tmp_path).verify()
    assert exc.value.seq == 3


def test_a_chain_signed_with_the_wrong_key_fails(tmp_path: Path) -> None:
    add(make_ledger(tmp_path, key=b"a" * 32))

    with pytest.raises(BadSignature) as exc:
        Ledger.open(tmp_path / "ledger", InMemoryKeySource(b"b" * 32))
    assert exc.value.seq == 0


def test_a_malformed_line_is_rejected(tmp_path: Path) -> None:
    root = tmp_path / "ledger"
    add(make_ledger(tmp_path))

    rows = lines(root)
    rows[1] = '{"seq": 1, "garbage": true}'
    rewrite(root, rows)

    with pytest.raises(MalformedEntry):
        make_ledger(tmp_path).verify()


def test_a_second_genesis_cannot_be_spliced_in(tmp_path: Path) -> None:
    """Re-presenting a later entry as a fresh genesis is rejected by the contract."""
    root = tmp_path / "ledger"
    add(make_ledger(tmp_path))

    rows = lines(root)
    entry = json.loads(rows[2])
    entry["prev_hash"] = "0" * 64  # claim genesis while keeping seq=2
    rows[2] = json.dumps(entry)
    rewrite(root, rows)

    with pytest.raises(MalformedEntry):
        make_ledger(tmp_path).verify()


# ── open() refuses to hand back a corrupt ledger ────────────────────────────


def test_open_verifies_before_returning(tmp_path: Path) -> None:
    """A Ledger object that exists is one whose chain verified."""
    root = tmp_path / "ledger"
    add(make_ledger(tmp_path))

    rows = lines(root)
    entry = json.loads(rows[1])
    entry["action"] = "kernel.flag.flip"
    rows[1] = json.dumps(entry)
    rewrite(root, rows)

    with pytest.raises(BadSignature):
        make_ledger(tmp_path)


def test_there_is_no_repair_function(tmp_path: Path) -> None:
    """LAW 0 §7 made mechanical.

    If this fails, someone added the function that lets forged history be presented
    with the same confidence as real history.
    """
    forbidden = ("repair", "rebuild", "fix", "truncate", "reset", "recover", "prune")
    for name in dir(Ledger):
        assert not any(word in name.lower() for word in forbidden), (
            f"Ledger grew a {name!r} method; LAW 0 §7 forbids ledger repair"
        )


def test_verify_does_not_modify_the_file(tmp_path: Path) -> None:
    """Fail closed, never fail destructive: a failed verify leaves evidence intact."""
    root = tmp_path / "ledger"
    add(make_ledger(tmp_path))

    rows = lines(root)
    entry = json.loads(rows[1])
    entry["actor_id"] = "tampered"
    rows[1] = json.dumps(entry)
    rewrite(root, rows)
    before = (root / "segment-00000.ndjson").read_bytes()

    with pytest.raises(BadSignature):
        make_ledger(tmp_path)

    assert (root / "segment-00000.ndjson").read_bytes() == before


# ── the caller cannot influence the chain ───────────────────────────────────


def test_append_computes_prev_hash_itself(tmp_path: Path) -> None:
    """There is no parameter through which a caller could break or fake the chain."""
    import inspect

    params = set(inspect.signature(Ledger.append).parameters)
    assert "prev_hash" not in params
    assert "seq" not in params
    assert "signature" not in params


def test_chain_links_are_actual_hashes_of_predecessors(tmp_path: Path) -> None:
    ledger = make_ledger(tmp_path)
    add(ledger, 4)

    entries = list(ledger.entries())
    for prev, nxt in itertools.pairwise(entries):
        assert nxt.prev_hash == entry_hash(prev)


# ── the high-water mark (#99) ────────────────────────────────────────────────


def test_deleting_the_whole_ledger_is_caught_even_by_setup(tmp_path: Path) -> None:
    """`init` opens with `create=True`; an empty ledger the keychain remembers is not new."""
    root = tmp_path / "ledger"
    keys = InMemoryKeySource(b"k" * 32)
    add(Ledger.open(root, keys), 3)
    for segment in root.glob("segment-*.ndjson"):
        segment.unlink()

    with pytest.raises(LedgerRolledBack, match="the chain ends at nothing at all"):
        Ledger.open(root, keys)
    assert not list(root.glob("segment-*.ndjson"))


def test_history_replaced_from_the_mark_onwards_is_caught(tmp_path: Path) -> None:
    """Someone with the key cuts two entries and writes two of their own: same length."""
    root = tmp_path / "ledger"
    keys = InMemoryKeySource(b"k" * 32)
    add(Ledger.open(root, keys), 4)
    rewrite(root, lines(root)[:2])
    forger = Ledger.open(root, InMemoryKeySource(b"k" * 32))  # holds the key, not the mark
    add(forger, 2)
    forger.close()

    with pytest.raises(LedgerRolledBack, match="entry 3 is not the entry the keychain recorded"):
        Ledger.open(root, keys)


def test_a_batch_moves_the_mark_when_it_lands(tmp_path: Path) -> None:
    root = tmp_path / "ledger"
    keys = InMemoryKeySource(b"k" * 32)
    ledger = Ledger.open(root, keys)
    with ledger.batch():
        add(ledger, 4)
    rewrite(root, lines(root)[:3])

    with pytest.raises(LedgerRolledBack, match="records entry 3"):
        Ledger.open(root, keys)


def test_an_unreadable_mark_fails_closed(tmp_path: Path) -> None:
    root = tmp_path / "ledger"
    keys = InMemoryKeySource(b"k" * 32)
    add(Ledger.open(root, keys), 1)
    keys._marks = {ledger_id: "not a mark" for ledger_id in keys._marks}

    with pytest.raises(LedgerRolledBack, match="unreadable"):
        Ledger.open(root, keys)


def test_a_mark_that_cannot_be_written_never_fails_the_entry_and_shows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The entry is durable before the mark is written; saying it failed would be false (#104)."""
    root = tmp_path / "ledger"
    keys = InMemoryKeySource(b"k" * 32)
    ledger = Ledger.open(root, keys)
    add(ledger, 1)

    def broken(*_: object) -> None:
        msg = "the keychain refused"
        raise RuntimeError(msg)

    monkeypatch.setattr(keys, "write_mark", broken)
    add(ledger, 2)
    monkeypatch.undo()

    reopened = Ledger.open(root, keys)
    assert reopened.verify() == 3
    assert reopened.mark_behind == 2, "a lagging mark must be visible, not silent"


def test_a_ledger_grown_normally_opens_and_its_mark_keeps_up(tmp_path: Path) -> None:
    """The control: the mark never refuses a ledger that only grew."""
    root = tmp_path / "ledger"
    keys = InMemoryKeySource(b"k" * 32)
    add(Ledger.open(root, keys), 3)
    again = Ledger.open(root, keys)
    add(again, 2)
    assert Ledger.open(root, keys).verify() == 5


def test_each_ledger_folder_keeps_its_own_mark(tmp_path: Path) -> None:
    """A second SLETCHY_HOME on the same keychain is not mistaken for a cut-down first."""
    keys = InMemoryKeySource(b"k" * 32)
    add(Ledger.open(tmp_path / "a" / "ledger", keys), 3)
    add(Ledger.open(tmp_path / "b" / "ledger", keys), 1)

    assert Ledger.open(tmp_path / "a" / "ledger", keys).verify() == 3
    assert Ledger.open(tmp_path / "b" / "ledger", keys).verify() == 1


def test_status_and_setup_refuse_a_ledger_the_keychain_remembers_as_longer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    class Keychain(InMemoryKeySource):
        def provision(self, *, overwrite: bool = False) -> None:
            return

    keys = Keychain(b"k" * 32)
    monkeypatch.setenv(paths.ENV_HOME, str(tmp_path / "var"))
    monkeypatch.setattr(cli_main, "KeyringKeySource", lambda *a, **k: keys)
    assert main(["init"]) == EXIT_OK
    assert main(["flags", "set", "cli_verbose", "on"]) == EXIT_OK
    for segment in paths.ledger_dir().glob("segment-*.ndjson"):
        segment.unlink()
    capsys.readouterr()

    assert main(["status"]) == EXIT_CORRUPT
    assert "shorter than it was" in capsys.readouterr().out
    assert main(["init"]) == EXIT_CORRUPT
    assert "shorter than it was" in capsys.readouterr().err


# ── a sealed segment is checked by its fingerprint (#116) ────────────────────


def rotated(tmp_path: Path) -> tuple[Path, list[Path]]:
    ledger = Ledger.open(tmp_path / "ledger", InMemoryKeySource(b"k" * 32), max_segment_bytes=2048)
    add(ledger, 40)
    ledger.close()
    root = tmp_path / "ledger"
    return root, sorted(root.glob("segment-*.ndjson"))


def reopen(root: Path) -> Ledger:
    return Ledger.open(root, InMemoryKeySource(b"k" * 32), max_segment_bytes=2048)


def test_an_entry_changed_inside_a_sealed_segment_is_caught_at_open(tmp_path: Path) -> None:
    root, segments = rotated(tmp_path)
    first = segments[0]
    rows = first.read_text(encoding="utf-8").splitlines()
    rows[1] = rows[1].replace("test entry", "test entrY")
    first.write_text("\n".join(rows) + "\n", encoding="utf-8")

    with pytest.raises(BrokenChain, match="is not what its seal committed to"):
        reopen(root)


def test_a_sealed_segment_deleted_from_the_middle_is_caught_at_open(tmp_path: Path) -> None:
    root, segments = rotated(tmp_path)
    segments[1].unlink()

    with pytest.raises((BrokenChain, SequenceBroken)):
        reopen(root)


def test_two_sealed_segments_swapped_are_caught_at_open(tmp_path: Path) -> None:
    root, segments = rotated(tmp_path)
    a, b = segments[0].read_bytes(), segments[1].read_bytes()
    segments[0].write_bytes(b)
    segments[1].write_bytes(a)

    with pytest.raises((BrokenChain, SequenceBroken)):
        reopen(root)


def test_a_seal_never_commits_to_an_entry_changed_while_its_segment_was_active(
    tmp_path: Path,
) -> None:
    """Sealing checks the segment first, so the fingerprint cannot launder a change."""
    root = tmp_path / "ledger"
    ledger = Ledger.open(root, InMemoryKeySource(b"k" * 32), max_segment_bytes=2048)
    active = root / "segment-00000.ndjson"
    while not active.exists() or active.stat().st_size < 2048:
        add(ledger, 1)
    rows = active.read_text(encoding="utf-8").splitlines()
    rows[1] = rows[1].replace("test entry", "test entrY")
    active.write_text("\n".join(rows) + "\n", encoding="utf-8")
    before = active.read_bytes()

    with pytest.raises(BadSignature):
        add(ledger, 1)  # the append that would seal the segment

    assert active.read_bytes() == before, "a seal or an entry was written over the change"
    assert not (root / "segment-00001.ndjson").exists()


def test_a_cleanly_rotated_ledger_opens_and_counts_every_entry(tmp_path: Path) -> None:
    """The control: the fast check accepts what it should."""
    root, segments = rotated(tmp_path)
    assert len(segments) >= 3
    opened = reopen(root)
    assert opened.length == opened.verify() == len(list(opened.entries()))


def test_a_mark_inside_a_sealed_segment_is_still_found(tmp_path: Path) -> None:
    """The keychain mark (#99) can point into a sealed segment if it lagged."""
    keys = InMemoryKeySource(b"k" * 32)
    root = tmp_path / "ledger"
    ledger = Ledger.open(root, keys, max_segment_bytes=2048)
    add(ledger, 40)
    early = next(e for e in ledger.entries() if e.seq == 3)
    keys.write_mark(ledger._mark_id, early.seq, entry_hash(early))
    ledger.close()

    opened = Ledger.open(root, keys, max_segment_bytes=2048)
    assert opened.mark_behind == opened.length - 1 - 3
