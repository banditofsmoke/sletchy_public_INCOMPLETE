"""Someone floods the payload store to fill the disk. It stops at a ceiling (LAW 0 section 5).

#101 gave the ledger a ceiling and a free-space floor. The bodies the ledger only hashes
live beside it, in the payload store, and had neither: each body was capped at 32 MB,
and nothing capped the total. Every sandbox launch, outcome and refusal stores one, so a
loop of sandbox runs grew `var/payloads` without limit, under the per-body cap every
time.

Now the store refuses, before writing, anything past 3 GB in total (LAW 0 keeps all of
`var/` within 5 GB, and the ledger may take 1 GB), and anything that would leave the
drive below the same 2 GB floor the ledger keeps. When it refuses:

- **a launch does not happen**, and the refusal is recorded: its command line could not
  be kept, and a launch with an incomplete record does not run
- **an outcome or a refusal is still recorded**, without its body, and says so: losing
  that entry would be worse than losing its details

Ceilings here are a few kilobytes, set through the same arguments the real ones use.
"""

from __future__ import annotations

from collections import namedtuple
from pathlib import Path

import pytest

from sletchy.kernel.contracts import IsolationBackend, IsolationProfile
from sletchy.kernel.ledger import (
    MAX_PAYLOAD_STORE_BYTES,
    InMemoryKeySource,
    Ledger,
    PayloadStore,
    PayloadStoreFull,
)
from sletchy.kernel.ledger import chain as chain_mod
from sletchy.warden.isolation import SandboxRecorder
from sletchy.warden.isolation.base import LaunchResult
from sletchy.warden.isolation.recorder import (
    COMPLETE_ACTION,
    LAUNCH_ACTION,
    REFUSED_ACTION,
)

pytestmark = [pytest.mark.adversarial, pytest.mark.law_zero]

CEILING = 4_000
Usage = namedtuple("Usage", "total used free")


def store(tmp_path: Path, **kw: int) -> PayloadStore:
    return PayloadStore.open(tmp_path / "payloads", max_total_bytes=kw.get("ceiling", CEILING))


def body(n: int, size: int = 1_000) -> bytes:
    return f"{n:08d}".encode() * (size // 8)


def nearly_full(monkeypatch: pytest.MonkeyPatch, free: int) -> None:
    monkeypatch.setattr(
        "sletchy.kernel.ledger.store.shutil.disk_usage",
        lambda _: Usage(10**12, 10**12 - free, free),
    )


# ── the store's own ceiling ──────────────────────────────────────────────────


def test_the_defaults_are_law_zeros_numbers() -> None:
    """3 GB of payloads, and the same 2 GB floor as the ledger."""
    assert MAX_PAYLOAD_STORE_BYTES == 3 * 1024**3
    assert MAX_PAYLOAD_STORE_BYTES + chain_mod.MAX_LEDGER_BYTES <= 5 * 1024**3
    assert PayloadStore(Path("unused"))._min_free == chain_mod.MIN_FREE_BYTES


def test_a_flood_stops_at_the_ceiling_and_writes_nothing_past_it(tmp_path: Path) -> None:
    payloads = store(tmp_path)
    written = 0
    with pytest.raises(PayloadStoreFull, match="ceiling"):
        while written < 200:  # 4 fit under CEILING; 200 is far past it
            payloads.put(body(written))
            written += 1

    assert written == 4
    assert payloads.total_bytes() <= CEILING
    assert not list((tmp_path / "payloads").rglob("*.tmp"))


def test_a_body_already_stored_is_accepted_when_full(tmp_path: Path) -> None:
    """Storing the same content twice needs no room, so it is never refused."""
    payloads = store(tmp_path)
    first = payloads.put(body(0, 3_500))
    with pytest.raises(PayloadStoreFull):
        payloads.put(body(1, 1_000))
    assert payloads.put(body(0, 3_500)) == first


def test_deleting_a_body_makes_room_again(tmp_path: Path) -> None:
    payloads = store(tmp_path)
    first = payloads.put(body(0, 3_500))
    with pytest.raises(PayloadStoreFull):
        payloads.put(body(1, 1_000))

    assert payloads.delete(first)
    payloads.put(body(1, 1_000))


def test_what_is_already_on_disk_counts_towards_the_ceiling(tmp_path: Path) -> None:
    """A new process opening a full store is not given a fresh allowance."""
    store(tmp_path).put(body(0, 3_500))
    reopened = store(tmp_path)
    with pytest.raises(PayloadStoreFull, match="ceiling"):
        reopened.put(body(1, 1_000))


# ── the disk ─────────────────────────────────────────────────────────────────


def test_nothing_is_written_that_would_leave_the_drive_under_two_gb(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    payloads = store(tmp_path, ceiling=10**9)
    nearly_full(monkeypatch, chain_mod.MIN_FREE_BYTES + 100)

    with pytest.raises(PayloadStoreFull, match="free on the drive"):
        payloads.put(body(0))
    assert list(payloads.digests()) == []


def test_room_above_the_floor_is_still_usable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Positive control: the floor refuses only what would cross it."""
    payloads = store(tmp_path, ceiling=10**9)
    nearly_full(monkeypatch, chain_mod.MIN_FREE_BYTES + 10_000)
    payloads.put(body(0))


def test_a_drive_whose_free_space_cannot_be_read_refuses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Could not look is not "plenty of room" (L009)."""
    payloads = store(tmp_path, ceiling=10**9)

    def cannot(_: object) -> Usage:
        msg = "the drive did not answer"
        raise OSError(msg)

    monkeypatch.setattr("sletchy.kernel.ledger.store.shutil.disk_usage", cannot)
    with pytest.raises(PayloadStoreFull, match="could not read the free space"):
        payloads.put(body(0))


# ── what the Warden does when the store is full ──────────────────────────────


def recorder(tmp_path: Path) -> tuple[SandboxRecorder, Ledger]:
    ledger = Ledger.open(tmp_path / "ledger", InMemoryKeySource(b"k" * 32))
    full = PayloadStore.open(tmp_path / "payloads", max_total_bytes=0)
    return SandboxRecorder(ledger=ledger, actor_id="flood", payloads=full), ledger


def test_a_launch_whose_command_cannot_be_kept_is_refused_and_recorded(tmp_path: Path) -> None:
    rec, ledger = recorder(tmp_path)
    profile = IsolationProfile.model_validate({"backend": IsolationBackend.WINJOB})

    with pytest.raises(PayloadStoreFull):
        rec.launching(
            command=["tool.exe", "--flag"],
            backend=IsolationBackend.WINJOB,
            profile=profile,
            workspace=str(tmp_path),
        )

    actions = [e.action for e in ledger.entries()]
    assert LAUNCH_ACTION not in actions, "a launch was recorded as going ahead"
    refusal = next(e for e in ledger.entries() if e.action == REFUSED_ACTION)
    assert "not launched" in refusal.verdict.reason
    assert "payload store" in refusal.verdict.reason
    assert refusal.payload_hash is None


def test_an_outcome_is_still_recorded_when_its_details_cannot_be_kept(tmp_path: Path) -> None:
    rec, ledger = recorder(tmp_path)
    result = LaunchResult(
        exit_code=0,
        stdout="",
        stderr="",
        timed_out=False,
        killed_by_limit=False,
        backend=IsolationBackend.WINJOB,
        diagnostics={},
    )

    entry = rec.finished(command=["tool.exe"], result=result)

    assert entry.action == COMPLETE_ACTION
    assert entry.payload_hash is None
    assert entry.verdict.reason == "exited 0 (details not kept: the payload store is full)"
    assert [e.action for e in ledger.entries()] == [COMPLETE_ACTION]


def test_a_refusal_is_still_recorded_when_its_details_cannot_be_kept(tmp_path: Path) -> None:
    rec, _ = recorder(tmp_path)
    entry = rec.refused(command=["tool.exe"], reason="policy said no")
    assert entry.action == REFUSED_ACTION
    assert entry.verdict.reason.startswith("policy said no")
    assert entry.payload_hash is None
