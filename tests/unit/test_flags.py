"""Flag registry and store - LAW 8."""

from __future__ import annotations

from pathlib import Path

import pytest

from sletchy.kernel.contracts import Flag, FlagRisk
from sletchy.kernel.flags import (
    DEFAULT_FLAGS,
    FlagRegistry,
    FlagRegistryInvalid,
    FlagStore,
    ReasonRequired,
    UnknownFlag,
)
from sletchy.kernel.ledger import InMemoryKeySource, Ledger


def store(tmp_path: Path, registry: FlagRegistry | None = None) -> FlagStore:
    ledger = Ledger.open(tmp_path / "ledger", InMemoryKeySource(b"k" * 32))
    return FlagStore.open(ledger, tmp_path / "flags.json", registry)


# ── LAW 8: a fresh install is inert ──────────────────────────────────────────


@pytest.mark.law_zero
def test_every_dangerous_flag_is_off_on_a_fresh_install(tmp_path: Path) -> None:
    """Enumerates the WHOLE registry, not a hand-picked sample.

    A sampled version of this test would pass forever while a newly added
    dangerous flag defaulted on.
    """
    s = store(tmp_path)
    dangerous = s.registry.dangerous()

    assert dangerous, "expected the registry to declare some dangerous flags"
    for flag in dangerous:
        assert not s.is_on(flag.name), f"{flag.name} is DANGEROUS and defaults on"


@pytest.mark.law_zero
def test_the_shipped_registry_declares_the_expected_dangerous_surface(tmp_path: Path) -> None:
    """If a capability stops being flag-gated, this test notices."""
    names = {f.name for f in store(tmp_path).registry.dangerous()}
    for expected in (
        "egress_enabled",
        "fs_outside_var",
        "senses_microphone",
        "senses_camera",
        "senses_screen",
        "forge_training",
        "vault_deploy_mainnet",
        "honeypot_bind_beyond_loopback",
    ):
        assert expected in names, f"{expected} is no longer a dangerous flag"


def test_a_dangerous_flag_defaulting_on_cannot_be_registered() -> None:
    """The registry re-checks what Flag's own validator already refuses.

    Two independent checks, so a flag reaching the registry by some other route
    still cannot default on.
    """
    sneaky = Flag.model_construct(
        name="sneaky", risk=FlagRisk.DANGEROUS, default=True, description="bypasses the validator"
    )
    with pytest.raises(FlagRegistryInvalid, match="LAW 8"):
        FlagRegistry((sneaky,))


def test_duplicate_flags_are_refused() -> None:
    flag = Flag(name="dup", risk=FlagRisk.SAFE, description="d")
    with pytest.raises(FlagRegistryInvalid, match="duplicate"):
        FlagRegistry((flag, flag))


def test_safe_flags_may_default_on(tmp_path: Path) -> None:
    assert store(tmp_path).is_on("cli_colour")


# ── unknown flags ────────────────────────────────────────────────────────────


def test_an_unknown_flag_raises_on_read(tmp_path: Path) -> None:
    """Never silently False - a typo would look identical to 'off on purpose'."""
    with pytest.raises(UnknownFlag, match="no ad-hoc flags"):
        store(tmp_path).is_on("egres_enabled")


def test_an_unknown_flag_raises_on_write(tmp_path: Path) -> None:
    with pytest.raises(UnknownFlag):
        store(tmp_path).set("not_a_flag", True, reason="x")


# ── flipping ─────────────────────────────────────────────────────────────────


def test_turning_on_a_dangerous_flag_requires_a_reason(tmp_path: Path) -> None:
    s = store(tmp_path)
    with pytest.raises(ReasonRequired, match="DANGEROUS"):
        s.set("egress_enabled", True)
    assert not s.is_on("egress_enabled")


def test_a_blank_reason_is_not_a_reason(tmp_path: Path) -> None:
    with pytest.raises(ReasonRequired):
        store(tmp_path).set("egress_enabled", True, reason="   ")


@pytest.mark.parametrize("reason", ["​", "⁠‍", "\x00", "‮"])
def test_an_invisible_reason_is_not_a_reason(tmp_path: Path, reason: str) -> None:
    """`str.strip()` keeps a zero-width space, so one passed as a reason until #96."""
    s = store(tmp_path)
    with pytest.raises(ReasonRequired):
        s.set("egress_enabled", True, reason=reason)
    assert not s.is_on("egress_enabled")


def test_turning_off_never_requires_a_reason(tmp_path: Path) -> None:
    """The safe direction must never be obstructed - obstruction gets skipped."""
    s = store(tmp_path)
    s.set("egress_enabled", True, reason="calling a hosted model")
    s.set("egress_enabled", False)
    assert not s.is_on("egress_enabled")


def test_flipping_with_a_reason_works(tmp_path: Path) -> None:
    s = store(tmp_path)
    s.set("egress_enabled", True, reason="calling a hosted model")
    assert s.is_on("egress_enabled")


def test_a_safe_flag_needs_no_reason(tmp_path: Path) -> None:
    s = store(tmp_path)
    s.set("cli_verbose", True)
    assert s.is_on("cli_verbose")


# ── persistence ──────────────────────────────────────────────────────────────


def test_a_flip_survives_a_restart(tmp_path: Path) -> None:
    s = store(tmp_path)
    s.set("mind_local_models", True, reason="ollama running")

    reopened = store(tmp_path)
    assert reopened.is_on("mind_local_models")


def test_only_deviations_are_stored(tmp_path: Path) -> None:
    """Deleting the file returns a fresh-install posture, not an undefined one."""
    import json

    s = store(tmp_path)
    s.set("mind_local_models", True, reason="ollama running")
    assert json.loads((tmp_path / "flags.json").read_text()) == {"mind_local_models": True}

    s.set("mind_local_models", False)
    assert json.loads((tmp_path / "flags.json").read_text()) == {}


@pytest.mark.law_zero
def test_deleting_the_state_file_returns_to_defaults(tmp_path: Path) -> None:
    s = store(tmp_path)
    s.set("egress_enabled", True, reason="temporary")
    (tmp_path / "flags.json").unlink()

    assert not store(tmp_path).is_on("egress_enabled")


@pytest.mark.law_zero
def test_a_corrupt_state_file_falls_back_to_defaults(tmp_path: Path) -> None:
    """Failing 'open' here fails closed: every dangerous flag returns to off."""
    s = store(tmp_path)
    s.set("egress_enabled", True, reason="temporary")
    (tmp_path / "flags.json").write_text("{ not json", encoding="utf-8")

    assert not store(tmp_path).is_on("egress_enabled")


def test_an_unknown_name_in_the_state_file_is_ignored(tmp_path: Path) -> None:
    (tmp_path / "flags.json").write_text('{"ghost_flag": true}', encoding="utf-8")
    assert "ghost_flag" not in store(tmp_path).snapshot()


# ── reset, for panic ─────────────────────────────────────────────────────────


@pytest.mark.law_zero
def test_reset_returns_every_flag_to_its_default(tmp_path: Path) -> None:
    s = store(tmp_path)
    s.set("egress_enabled", True, reason="a")
    s.set("senses_microphone", True, reason="b")
    s.set("cli_colour", False)

    changed = s.reset_all()

    assert changed == 3
    assert s.snapshot() == s.registry.defaults()


def test_reset_reports_zero_when_nothing_changed(tmp_path: Path) -> None:
    """`panic` should report honestly rather than claim a reset that was a no-op."""
    assert store(tmp_path).reset_all() == 0


# ── LAW 1: flips are recorded ────────────────────────────────────────────────


def test_a_flip_is_recorded_with_who_and_why(tmp_path: Path) -> None:
    ledger = Ledger.open(tmp_path / "ledger", InMemoryKeySource(b"k" * 32))
    s = FlagStore.open(ledger, tmp_path / "flags.json")
    s.set("egress_enabled", True, reason="calling a hosted model", actor_id="someone")

    entry = next(e for e in ledger.entries() if e.action == "kernel.flag.flip")
    assert entry.actor_id == "someone"
    assert entry.subject.identifier == "egress_enabled"
    assert "calling a hosted model" in entry.verdict.reason
    assert entry.ts_wall is not None


def test_a_refused_flip_is_not_recorded_as_a_flip(tmp_path: Path) -> None:
    """A flip that did not happen must not appear in history as if it did."""
    ledger = Ledger.open(tmp_path / "ledger", InMemoryKeySource(b"k" * 32))
    s = FlagStore.open(ledger, tmp_path / "flags.json")

    with pytest.raises(ReasonRequired):
        s.set("egress_enabled", True)

    assert [e for e in ledger.entries() if e.action == "kernel.flag.flip"] == []


def test_reset_is_recorded(tmp_path: Path) -> None:
    ledger = Ledger.open(tmp_path / "ledger", InMemoryKeySource(b"k" * 32))
    s = FlagStore.open(ledger, tmp_path / "flags.json")
    s.set("egress_enabled", True, reason="a")
    s.reset_all(reason="panic")

    entry = next(e for e in ledger.entries() if e.action == "kernel.flag.reset")
    assert "1 changed" in entry.verdict.reason
    assert ledger.verify() > 0


# ── the registry is the only definition source ───────────────────────────────


def test_the_registry_is_enumerable_for_the_ui(tmp_path: Path) -> None:
    """The UI panel is generated from this; a hand-written list would drift."""
    s = store(tmp_path)
    snapshot = s.snapshot()

    assert set(snapshot) == {f.name for f in DEFAULT_FLAGS}
    assert len(snapshot) == len(s.registry)


def test_every_flag_carries_a_description() -> None:
    for flag in DEFAULT_FLAGS:
        assert flag.description.strip(), f"{flag.name} has no description"
        assert flag.description.endswith("."), f"{flag.name}: description should be a sentence"


@pytest.mark.law_zero
def test_writes_stay_inside_the_given_directory(tmp_path: Path) -> None:
    s = store(tmp_path)
    s.set("egress_enabled", True, reason="a")
    s.reset_all()

    for path in tmp_path.rglob("*"):
        if path.is_file():
            assert tmp_path in path.parents
