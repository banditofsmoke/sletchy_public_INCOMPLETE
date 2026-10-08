"""Ledger happy-path, sealing, rotation, and key-lifecycle tests."""

from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path

import pytest

from sletchy.kernel.contracts import (
    GENESIS_PREV_HASH,
    Decision,
    LedgerEntry,
    Plane,
    Subject,
    SubjectKind,
    Verdict,
)
from sletchy.kernel.ledger import (
    DEFAULT_MAX_SEGMENT_BYTES,
    SEAL_ACTION,
    InMemoryKeySource,
    Ledger,
    LedgerMissing,
    LedgerSealed,
    MarkStore,
    SigningKeyBackendUnavailable,
    SigningKeyMissing,
    entry_hash,
    signing_bytes,
)
from sletchy.kernel.ledger.keys import KeyringKeySource, sign, verify


def make_ledger(tmp_path: Path, *, max_segment_bytes: int = DEFAULT_MAX_SEGMENT_BYTES) -> Ledger:
    return Ledger.open(
        tmp_path / "ledger", InMemoryKeySource(b"k" * 32), max_segment_bytes=max_segment_bytes
    )


def add(ledger: Ledger, n: int = 1) -> None:
    for i in range(n):
        ledger.append(
            plane=Plane.WARDEN,
            actor_id="agent_a",
            action="warden.egress.request",
            subject=Subject(kind=SubjectKind.HOST, identifier=f"h{i}.example"),
            verdict=Verdict.default_deny(f"entry {i}"),
        )


# ── basics ───────────────────────────────────────────────────────────────────


def test_a_fresh_ledger_verifies_and_is_empty(tmp_path: Path) -> None:
    assert make_ledger(tmp_path).verify() == 0


def test_first_entry_is_genesis(tmp_path: Path) -> None:
    ledger = make_ledger(tmp_path)
    entry = ledger.append(
        plane=Plane.KERNEL,
        actor_id="kernel",
        action="kernel.flag.flip",
        subject=Subject(kind=SubjectKind.FLAG, identifier="egress"),
        verdict=Verdict.default_deny("first"),
    )
    assert entry.seq == 0
    assert entry.prev_hash == GENESIS_PREV_HASH
    assert entry.is_genesis


def test_sequence_is_contiguous(tmp_path: Path) -> None:
    ledger = make_ledger(tmp_path)
    add(ledger, 10)
    assert [e.seq for e in ledger.entries()] == list(range(10))


def test_verify_returns_the_count(tmp_path: Path) -> None:
    ledger = make_ledger(tmp_path)
    add(ledger, 7)
    assert ledger.verify() == 7


@pytest.mark.slow
def test_a_thousand_entries_verify(tmp_path: Path) -> None:
    """Slow by design: every append fsyncs, so this measures real durable throughput.

    ~56ms per append on this host. Fine for decisions, too slow for high-frequency
    events; group commit is tracked separately rather than silently assumed.
    """
    ledger = make_ledger(tmp_path)
    add(ledger, 1000)
    assert ledger.verify() == 1000


def test_entries_survive_a_reopen(tmp_path: Path) -> None:
    """The chain is durable, not an in-memory illusion."""
    add(make_ledger(tmp_path), 5)

    reopened = make_ledger(tmp_path)
    assert reopened.verify() == 5

    add(reopened, 2)
    assert make_ledger(tmp_path).verify() == 7


def test_appending_after_reopen_continues_the_chain(tmp_path: Path) -> None:
    add(make_ledger(tmp_path), 3)
    reopened = make_ledger(tmp_path)
    add(reopened, 1)

    entries = list(reopened.entries())
    assert entries[3].seq == 3
    assert entries[3].prev_hash == entry_hash(entries[2])


def test_timestamps_are_timezone_aware(tmp_path: Path) -> None:
    ledger = make_ledger(tmp_path)
    add(ledger)
    entry = next(iter(ledger.entries()))
    assert entry.ts_wall.tzinfo is not None
    assert entry.ts_wall <= datetime.now(UTC)


def test_payload_hash_is_recorded_when_given(tmp_path: Path) -> None:
    ledger = make_ledger(tmp_path)
    entry = ledger.append(
        plane=Plane.MIND,
        actor_id="agent_a",
        action="mind.model.call",
        subject=Subject(kind=SubjectKind.MODEL, identifier="llama3"),
        verdict=Verdict.default_deny("no policy yet"),
        payload_hash="b" * 64,
    )
    assert entry.payload_hash == "b" * 64
    assert ledger.verify() == 1


# ── sealing and rotation ─────────────────────────────────────────────────────


def test_seal_writes_a_terminal_entry(tmp_path: Path) -> None:
    ledger = make_ledger(tmp_path)
    add(ledger, 3)
    seal = ledger.seal()

    assert seal.action == SEAL_ACTION
    assert seal.seq == 3
    assert seal.payload_hash is not None
    assert ledger.verify() == 4


def test_the_chain_crosses_a_segment_boundary(tmp_path: Path) -> None:
    """The seal is what carries the chain across files."""
    ledger = make_ledger(tmp_path)
    add(ledger, 2)
    seal = ledger.seal()
    add(ledger, 2)

    entries = list(ledger.entries())
    assert len(entries) == 5
    assert entries[3].prev_hash == entry_hash(seal)
    assert ledger.verify() == 5


def test_two_segment_files_exist_after_sealing(tmp_path: Path) -> None:
    ledger = make_ledger(tmp_path)
    add(ledger, 2)
    ledger.seal()
    add(ledger, 1)

    segments = sorted((tmp_path / "ledger").glob("segment-*.ndjson"))
    assert [p.name for p in segments] == ["segment-00000.ndjson", "segment-00001.ndjson"]


def test_appending_to_a_sealed_segment_is_refused(tmp_path: Path) -> None:
    ledger = make_ledger(tmp_path)
    add(ledger, 1)
    ledger.seal()
    ledger._segment -= 1  # force the sealed segment back as active

    with pytest.raises(LedgerSealed):
        add(ledger, 1)


def test_an_append_reads_one_line_however_long_the_segment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Counted, not timed (#115). Each append used to parse the whole active segment.

    An append reads the last line twice: once to check no other writer was here
    (#95), once to check for a seal. What matters is that the count does not grow
    with the segment: 30 entries and 300 cost the same, and both cost at most two.
    """
    real = LedgerEntry.model_validate_json
    parsed: list[object] = []

    def counting(data: str | bytes | bytearray, *args: object, **kw: object) -> LedgerEntry:
        parsed.append(data)
        return real(data)

    counts = {}
    for size in (30, 300):
        ledger = make_ledger(tmp_path / str(size))
        with ledger.batch():
            add(ledger, size)
        parsed.clear()
        monkeypatch.setattr(LedgerEntry, "model_validate_json", counting)
        add(ledger, 1)
        monkeypatch.undo()
        counts[size] = len(parsed)

    assert counts[30], "the seal check parsed nothing, so this count proves nothing"
    assert counts[300] == counts[30] <= 2, f"lines parsed per append by segment size: {counts}"
    assert make_ledger(tmp_path / "300").verify() == 301


@pytest.mark.parametrize("block", [1, 7, 64, 4096])
def test_the_seal_check_finds_the_last_line_across_a_block_boundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, block: int
) -> None:
    """The tail is read backwards in blocks; a last line spanning several is still whole."""
    monkeypatch.setattr("sletchy.kernel.ledger.chain._TAIL_BLOCK", block)
    ledger = make_ledger(tmp_path)
    for n in range(12):
        ledger.append(
            plane=Plane.WARDEN,
            actor_id="agent_a",
            action="warden.egress.request",
            subject=Subject(kind=SubjectKind.HOST, identifier="h.example"),
            verdict=Verdict(decision=Decision.DENY, reason="x" * (40 * n + 1), rule_id=None),
        )
        last = ledger._tail_entry(ledger._active_path())
        assert last is not None
        assert last.seq == n
    ledger.seal()
    ledger._segment -= 1
    assert ledger._is_sealed(ledger._segment), "a seal at the end of a segment was missed"


def test_rotation_happens_automatically_at_the_size_cap(tmp_path: Path) -> None:
    ledger = make_ledger(tmp_path, max_segment_bytes=2048)
    add(ledger, 20)

    segments = sorted((tmp_path / "ledger").glob("segment-*.ndjson"))
    assert len(segments) > 1, "expected the ledger to rotate"
    assert ledger.verify() == len(list(ledger.entries()))


def test_reopening_a_rotated_ledger_continues_correctly(tmp_path: Path) -> None:
    """Seals are counted apart: since #116 a full segment is sealed just before the next
    entry rather than just after the last one, so when a seal lands is not the point."""

    def real(ledger: Ledger) -> int:
        return sum(1 for e in ledger.entries() if e.action != SEAL_ACTION)

    ledger = make_ledger(tmp_path, max_segment_bytes=2048)
    add(ledger, 20)

    reopened = make_ledger(tmp_path, max_segment_bytes=2048)
    assert reopened.verify() == len(list(reopened.entries()))
    assert real(reopened) == 20
    add(reopened, 3)
    final = make_ledger(tmp_path, max_segment_bytes=2048)
    assert real(final) == 23
    assert final.verify() == len(list(final.entries())) == final.length


# ── the signing key ──────────────────────────────────────────────────────────


def test_signatures_verify_under_the_right_key(tmp_path: Path) -> None:
    ledger = make_ledger(tmp_path)
    add(ledger, 2)
    for entry in ledger.entries():
        assert verify(b"k" * 32, signing_bytes(entry), entry.signature)


def test_a_missing_keychain_key_raises_and_does_not_create_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The single most important rule in keys.py.

    Generating a key on the read path would make every existing entry unverifiable
    while making every new entry verify perfectly - indistinguishable from a
    successful forgery.
    """
    import keyring

    calls: list[tuple[str, str, str]] = []
    monkeypatch.setattr(keyring, "get_password", lambda s, a: None)
    monkeypatch.setattr(keyring, "set_password", lambda s, a, v: calls.append((s, a, v)))

    with pytest.raises(SigningKeyMissing, match="sletchy init"):
        KeyringKeySource().get()

    assert calls == [], "the read path must never write a key"


def test_provision_refuses_to_overwrite_an_existing_key(monkeypatch: pytest.MonkeyPatch) -> None:
    import keyring

    monkeypatch.setattr(keyring, "get_password", lambda s, a: "ab" * 32)
    monkeypatch.setattr(keyring, "set_password", lambda s, a, v: None)

    with pytest.raises(ValueError, match="already exists"):
        KeyringKeySource().provision()


def test_in_memory_key_source_refuses_outside_a_test_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A test-only convenience that could be reached in production is a backdoor."""
    import sys

    monkeypatch.delitem(sys.modules, "pytest", raising=False)
    monkeypatch.delenv("SLETCHY_ALLOW_INMEMORY_KEY", raising=False)

    with pytest.raises(RuntimeError, match="test-only"):
        InMemoryKeySource(b"k" * 32)


def test_signature_comparison_is_constant_time() -> None:
    """Guards against someone replacing compare_digest with ==."""
    import inspect

    from sletchy.kernel.ledger import keys

    source = inspect.getsource(keys.verify)
    assert "compare_digest" in source


# ── canonical form ───────────────────────────────────────────────────────────


def test_signing_bytes_exclude_the_signature(tmp_path: Path) -> None:
    ledger = make_ledger(tmp_path)
    add(ledger, 1)
    entry = next(iter(ledger.entries()))
    assert entry.signature.encode() not in signing_bytes(entry)


def test_canonical_bytes_are_ascii(tmp_path: Path) -> None:
    """A non-ASCII reason must not make the bytes depend on host encoding."""
    ledger = make_ledger(tmp_path)
    ledger.append(
        plane=Plane.SOC,
        actor_id="soc",
        action="soc.detect.raise",
        subject=Subject(kind=SubjectKind.HOST, identifier="café.example"),
        verdict=Verdict.default_deny("naïve résumé - em dash"),
    )
    entry = next(iter(ledger.entries()))
    signing_bytes(entry).decode("ascii")  # raises if not pure ASCII
    assert ledger.verify() == 1


def test_hashing_is_stable_across_calls(tmp_path: Path) -> None:
    ledger = make_ledger(tmp_path)
    add(ledger, 1)
    entry = next(iter(ledger.entries()))
    assert entry_hash(entry) == entry_hash(entry)


def test_sign_is_deterministic() -> None:
    assert sign(b"k" * 32, b"data") == sign(b"k" * 32, b"data")
    assert sign(b"k" * 32, b"data") != sign(b"j" * 32, b"data")


# ── LAW 0: nothing is written outside the ledger root ───────────────────────


@pytest.mark.law_zero
def test_writes_stay_inside_the_ledger_root(tmp_path: Path) -> None:
    root = tmp_path / "ledger"
    ledger = Ledger.open(root, InMemoryKeySource(b"k" * 32))
    add(ledger, 5)
    ledger.seal()
    add(ledger, 2)

    written = {p for p in tmp_path.rglob("*") if p.is_file()}
    assert written, "expected the ledger to have written something"
    for path in written:
        assert root in path.parents, f"{path} was written outside the ledger root"


@pytest.mark.law_zero
def test_ledger_creates_only_its_own_directory(tmp_path: Path) -> None:
    root = tmp_path / "nested" / "ledger"
    Ledger.open(root, InMemoryKeySource(b"k" * 32))
    assert root.is_dir()
    assert set(os.listdir(tmp_path)) == {"nested"}


# ── durability and throughput (#18) ─────────────────────────────────────────


def test_a_batch_records_everything_it_buffered(tmp_path: Path) -> None:
    ledger = make_ledger(tmp_path)
    with ledger.batch():
        add(ledger, 5)

    assert make_ledger(tmp_path).verify() == 5


def test_a_batch_is_not_durable_until_it_exits(tmp_path: Path) -> None:
    """The property that makes batch() dangerous, asserted so it is not a surprise."""
    ledger = make_ledger(tmp_path)
    with ledger.batch():
        add(ledger, 3)
        on_disk = Ledger.open(tmp_path / "ledger", InMemoryKeySource(b"k" * 32))
        assert on_disk.verify() == 0, "entries must not be visible mid-batch"

    assert make_ledger(tmp_path).verify() == 3


def test_a_batch_that_raises_still_records_what_it_buffered(tmp_path: Path) -> None:
    """A crash that loses the reason for a state change is worse than a partial log."""
    ledger = make_ledger(tmp_path)
    with pytest.raises(RuntimeError), ledger.batch():
        add(ledger, 2)
        msg = "boom"
        raise RuntimeError(msg)

    assert make_ledger(tmp_path).verify() == 2


def test_batches_do_not_nest(tmp_path: Path) -> None:
    """A nested batch would hide the outer one's durability barrier."""
    ledger = make_ledger(tmp_path)
    with ledger.batch(), pytest.raises(LedgerSealed, match="do not nest"):
        with ledger.batch():
            pass


def test_append_outside_a_batch_is_durable_immediately(tmp_path: Path) -> None:
    """The default path is unchanged: an entry is on disk before append returns."""
    ledger = make_ledger(tmp_path)
    add(ledger, 1)
    assert Ledger.open(tmp_path / "ledger", InMemoryKeySource(b"k" * 32)).verify() == 1


def test_the_batch_docstring_warns_against_gating_an_action() -> None:
    """The one rule that keeps batch() from breaking LAW 1 lives in its docstring.

    If someone rewrites it into a general fast path, this fails.
    """
    doc = Ledger.batch.__doc__ or ""
    assert "Never use this to gate an action" in doc
    assert "LAW 1" in doc


def test_the_handle_is_reused_across_appends(tmp_path: Path) -> None:
    ledger = make_ledger(tmp_path)
    add(ledger, 1)
    first = ledger._handle
    add(ledger, 1)
    assert ledger._handle is first, "the append handle should not be reopened per entry"


def test_close_is_idempotent(tmp_path: Path) -> None:
    ledger = make_ledger(tmp_path)
    add(ledger, 1)
    ledger.close()
    ledger.close()
    add(ledger, 1)
    assert make_ledger(tmp_path).verify() == 2


@pytest.mark.slow
def test_a_batch_fsyncs_once_where_plain_appends_fsync_each(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Counted, not timed (#112).

    This was a timing test with a 2x floor, and on a shared CI runner where fsync is
    cheap both sides were noise: it failed once at "0.2x" on a change that never
    touched the ledger. What batching promises is one durability barrier instead of
    thirty, so that is what is counted. The wrapper still calls the real fsync, so
    the entries are on disk and the reopened chain verifies.
    """
    real_fsync = os.fsync
    calls: list[int] = []

    def counting_fsync(fd: int) -> None:
        calls.append(fd)
        real_fsync(fd)

    monkeypatch.setattr(os, "fsync", counting_fsync)

    single = make_ledger(tmp_path / "a")
    add(single, 30)
    single.close()
    assert len(calls) == 30, "a plain append is durable before it returns, so each one fsyncs"

    calls.clear()
    batched = make_ledger(tmp_path / "b")
    with batched.batch():
        add(batched, 30)
    batched.close()
    assert len(calls) == 1, f"a batch of 30 fsynced {len(calls)} times; it promises once"

    assert make_ledger(tmp_path / "a").verify() == 30
    assert make_ledger(tmp_path / "b").verify() == 30


def test_open_without_create_never_makes_a_ledger(tmp_path: Path) -> None:
    """A read path opens what exists, or says nothing is there (#102)."""
    missing = tmp_path / "nowhere" / "ledger"
    with pytest.raises(LedgerMissing, match="not set up"):
        Ledger.open(missing, InMemoryKeySource(b"k" * 32), create=False)
    assert not (tmp_path / "nowhere").exists()

    make_ledger(tmp_path).close()
    assert (
        Ledger.open(tmp_path / "ledger", InMemoryKeySource(b"k" * 32), create=False).verify() == 0
    )


def test_the_mark_is_kept_in_the_keychain_beside_the_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """The real key source, against a stand-in for the keychain (#99). Nothing real is touched."""
    import keyring

    store: dict[tuple[str, str], str] = {}
    monkeypatch.setattr(keyring, "get_password", lambda s, a: store.get((s, a)))
    monkeypatch.setattr(keyring, "set_password", lambda s, a, v: store.__setitem__((s, a), v))
    source = KeyringKeySource()

    assert isinstance(source, MarkStore)
    assert source.read_mark("abc") is None
    source.write_mark("abc", 7, "a" * 64)
    assert store == {("sletchy", "ledger-high-water-abc"): "7:" + "a" * 64}
    assert source.read_mark("abc") == (7, "a" * 64)


def test_an_unreachable_keychain_cannot_vouch_for_the_ledgers_length(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import keyring

    def unreachable(*_: object) -> None:
        msg = "no backend"
        raise RuntimeError(msg)

    monkeypatch.setattr(keyring, "get_password", unreachable)
    with pytest.raises(SigningKeyBackendUnavailable, match="length cannot be checked"):
        KeyringKeySource().read_mark("abc")


# ── what an open reads (#116) ────────────────────────────────────────────────


def sealed_ledger(tmp_path: Path, entries: int = 60) -> Ledger:
    """Several sealed segments of about 2 KB, then an active one."""
    ledger = make_ledger(tmp_path, max_segment_bytes=2048)
    add(ledger, entries)
    return ledger


def count_parses(monkeypatch: pytest.MonkeyPatch) -> list[object]:
    real = LedgerEntry.model_validate_json
    parsed: list[object] = []

    def counting(data: str | bytes | bytearray, *args: object, **kw: object) -> LedgerEntry:
        parsed.append(data)
        return real(data)

    monkeypatch.setattr(LedgerEntry, "model_validate_json", counting)
    return parsed


def test_an_open_reads_sealed_segments_by_fingerprint_not_entry_by_entry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Counted, not timed. Opening used to parse every entry twice, on every click."""
    sealed_ledger(tmp_path).close()
    root = tmp_path / "ledger"
    segments = sorted(root.glob("segment-*.ndjson"))
    total = sum(1 for _ in make_ledger(tmp_path, max_segment_bytes=2048).entries())
    active = len(segments[-1].read_text(encoding="utf-8").splitlines())
    assert len(segments) >= 4, "the fixture did not rotate enough to prove anything"

    parsed = count_parses(monkeypatch)
    opened = make_ledger(tmp_path, max_segment_bytes=2048)

    assert opened.length == total
    # Three lines per sealed segment (its first entry, the entry before its seal, the
    # seal), every line of the active one, and a few tail reads.
    assert len(parsed) <= 3 * (len(segments) - 1) + active + 6, (
        f"an open parsed {len(parsed)} lines of a {total}-entry ledger"
    )
    assert len(parsed) < total


def test_ledger_verify_still_checks_every_entry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control: the full check `sletchy ledger verify` runs is not made cheaper."""
    ledger = sealed_ledger(tmp_path)
    total = ledger.length

    parsed = count_parses(monkeypatch)
    assert ledger.verify() == total
    assert len(parsed) >= total
