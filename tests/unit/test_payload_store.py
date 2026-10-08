"""Content-addressed payload store."""

from __future__ import annotations

from pathlib import Path

import pytest

from sletchy.kernel.contracts import Plane, Subject, SubjectKind, Verdict
from sletchy.kernel.ledger import (
    InMemoryKeySource,
    Ledger,
    PayloadMissing,
    PayloadStore,
    PayloadTooLarge,
    content_hash,
)

BODY = b"a prompt someone would rather not keep forever"


def store(tmp_path: Path, **kw: int) -> PayloadStore:
    return PayloadStore.open(tmp_path / "payloads", **kw)


# ── basics ───────────────────────────────────────────────────────────────────


def test_put_returns_the_content_hash(tmp_path: Path) -> None:
    assert store(tmp_path).put(BODY) == content_hash(BODY)


def test_round_trip(tmp_path: Path) -> None:
    s = store(tmp_path)
    assert s.get(s.put(BODY)) == BODY


def test_identical_content_is_stored_once(tmp_path: Path) -> None:
    s = store(tmp_path)
    first, second = s.put(BODY), s.put(BODY)

    assert first == second
    assert list(s.digests()) == [first]


def test_different_content_gets_different_addresses(tmp_path: Path) -> None:
    s = store(tmp_path)
    assert s.put(b"one") != s.put(b"two")
    assert len(list(s.digests())) == 2


def test_empty_content_is_storable(tmp_path: Path) -> None:
    """A zero-length body is a real body, not a missing one."""
    s = store(tmp_path)
    digest = s.put(b"")
    assert s.has(digest)
    assert s.get(digest) == b""


def test_missing_content_raises_a_distinguishable_error(tmp_path: Path) -> None:
    with pytest.raises(PayloadMissing):
        store(tmp_path).get("f" * 64)


def test_has_reports_presence_without_reading(tmp_path: Path) -> None:
    s = store(tmp_path)
    assert not s.has("f" * 64)
    assert s.has(s.put(BODY))


# ── the store computes hashes; it never accepts one ──────────────────────────


def test_put_takes_only_content(tmp_path: Path) -> None:
    """A caller able to name the address of content it did not supply could
    associate a ledger entry with a body someone else wrote."""
    import inspect

    params = set(inspect.signature(PayloadStore.put).parameters)
    assert params == {"self", "data"}


# ── the size cap is checked before anything is written ───────────────────────


def test_oversized_content_is_refused(tmp_path: Path) -> None:
    s = store(tmp_path, max_bytes=16)
    with pytest.raises(PayloadTooLarge, match="Nothing was written"):
        s.put(b"x" * 17)


def test_a_refused_payload_leaves_nothing_behind(tmp_path: Path) -> None:
    """Checked *before* the write, not after - otherwise the disk fills anyway."""
    s = store(tmp_path, max_bytes=16)
    with pytest.raises(PayloadTooLarge):
        s.put(b"x" * 17)

    assert list(s.digests()) == []
    assert s.total_bytes() == 0


def test_content_at_exactly_the_cap_is_accepted(tmp_path: Path) -> None:
    s = store(tmp_path, max_bytes=16)
    assert s.has(s.put(b"x" * 16))


# ── deletion, and the property that makes it worth having ────────────────────


def test_deleting_a_payload_leaves_the_chain_verifying(tmp_path: Path) -> None:
    """The load-bearing test for this whole module.

    The chain commits to `payload_hash`, not to the bytes. So a body can be
    destroyed and the record that something happened survives - which is what makes
    "forget this conversation" a real operation.
    """
    ledger = Ledger.open(tmp_path / "ledger", InMemoryKeySource(b"k" * 32))
    payloads = store(tmp_path)

    digest = payloads.put(BODY)
    ledger.append(
        plane=Plane.MIND,
        actor_id="agent_a",
        action="mind.model.call",
        subject=Subject(kind=SubjectKind.MODEL, identifier="llama3"),
        verdict=Verdict.default_deny("recorded"),
        payload_hash=digest,
    )
    assert ledger.verify() == 1

    assert payloads.delete(digest)

    assert Ledger.open(tmp_path / "ledger", InMemoryKeySource(b"k" * 32)).verify() == 1
    with pytest.raises(PayloadMissing):
        payloads.get(digest)


def test_delete_reports_whether_anything_was_removed(tmp_path: Path) -> None:
    s = store(tmp_path)
    digest = s.put(BODY)

    assert s.delete(digest) is True
    assert s.delete(digest) is False


# ── garbage collection ───────────────────────────────────────────────────────


def test_gc_removes_unreferenced_payloads(tmp_path: Path) -> None:
    s = store(tmp_path)
    keep, drop = s.put(b"referenced"), s.put(b"orphan")

    assert s.collect_garbage({keep}) == 1
    assert s.has(keep)
    assert not s.has(drop)


def test_gc_with_everything_referenced_removes_nothing(tmp_path: Path) -> None:
    s = store(tmp_path)
    digests = {s.put(b"one"), s.put(b"two")}
    assert s.collect_garbage(digests) == 0


def test_gc_takes_the_referenced_set_explicitly(tmp_path: Path) -> None:
    """The store must not depend on the chain.

    A caller that gets the set wrong deletes its own data, rather than the store
    silently corrupting a view it does not own.
    """
    import inspect

    params = set(inspect.signature(PayloadStore.collect_garbage).parameters)
    assert params == {"self", "referenced"}


# ── atomicity ────────────────────────────────────────────────────────────────


def test_no_temp_file_survives_a_successful_write(tmp_path: Path) -> None:
    s = store(tmp_path)
    s.put(BODY)
    assert list((tmp_path / "payloads").rglob("*.tmp")) == []


def test_a_stray_temp_file_is_not_readable_as_content(tmp_path: Path) -> None:
    """A torn write must not be visible under its final hash.

    Simulates a crash mid-write: the temp file exists, the final name does not.
    """
    s = store(tmp_path)
    digest = content_hash(BODY)
    shard = tmp_path / "payloads" / digest[:2]
    shard.mkdir(parents=True)
    (shard / (digest[2:] + ".tmp")).write_bytes(b"half a bo")

    assert not s.has(digest)
    with pytest.raises(PayloadMissing):
        s.get(digest)
    assert list(s.digests()) == []


# ── layout and LAW 0 ─────────────────────────────────────────────────────────


def test_content_is_sharded_by_prefix(tmp_path: Path) -> None:
    """Keeps one directory from growing to tens of thousands of entries."""
    s = store(tmp_path)
    digest = s.put(BODY)
    assert (tmp_path / "payloads" / digest[:2] / digest[2:]).is_file()


def test_digests_round_trip_through_the_listing(tmp_path: Path) -> None:
    s = store(tmp_path)
    written = {s.put(b"one"), s.put(b"two"), s.put(b"three")}
    assert set(s.digests()) == written


def test_total_bytes_counts_what_is_stored(tmp_path: Path) -> None:
    s = store(tmp_path)
    s.put(b"x" * 10)
    s.put(b"y" * 20)
    assert s.total_bytes() == 30


@pytest.mark.law_zero
def test_writes_stay_inside_the_store_root(tmp_path: Path) -> None:
    root = tmp_path / "payloads"
    s = PayloadStore.open(root)
    s.put(BODY)
    s.put(b"another")

    for path in tmp_path.rglob("*"):
        if path.is_file():
            assert root in path.parents
