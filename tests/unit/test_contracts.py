"""Contract tests.

These assert the *laws*, not the field names. A test that only checks a model has a
field is worth little; a test that checks a DANGEROUS flag cannot default on is
checking something a reviewer would otherwise have to catch by eye.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from sletchy.kernel.contracts import (
    GENESIS_PREV_HASH,
    Action,
    Actor,
    ActorKind,
    AgentEvent,
    AgentEventType,
    Capability,
    Decision,
    FilesystemMount,
    Flag,
    FlagRisk,
    IsolationBackend,
    IsolationProfile,
    LedgerEntry,
    NetworkPolicy,
    Plane,
    PolicyRule,
    ResourceLimits,
    SecretRef,
    Subject,
    SubjectKind,
    Verdict,
)

H0 = "0" * 64
H1 = "a" * 64
NOW = datetime(2026, 8, 13, 12, 0, tzinfo=UTC)


# ── base behaviour (LAW 2 / LAW 6) ───────────────────────────────────────────


def test_unknown_field_is_rejected() -> None:
    """Silently dropping an unknown field is how a tightened policy loosens."""
    with pytest.raises(ValidationError):
        Actor(id="a", kind=ActorKind.AGENT, plane=Plane.MIND, sneaky=True)  # type: ignore[call-arg]


def test_contracts_are_frozen() -> None:
    """A capability mutable after a policy check is widenable after a policy check."""
    actor = Actor(id="a", kind=ActorKind.AGENT, plane=Plane.MIND)
    with pytest.raises(ValidationError):
        actor.trust = 100  # type: ignore[misc]


# ── trust (salvaged from GDN's AIAgent.trust_score) ──────────────────────────


@pytest.mark.parametrize(
    ("given", "expected"), [(-50, 0), (0, 0), (73, 73), (100, 100), (999, 100)]
)
def test_trust_saturates_rather_than_raising(given: int, expected: int) -> None:
    """Detection rules sum arbitrary deltas; overshoot should clamp, not crash."""
    actor = Actor(id="a", kind=ActorKind.AGENT, plane=Plane.MIND)
    assert actor.with_trust(given).trust == expected


# ── action prefix matching (LAW 3 in miniature) ─────────────────────────────


def test_action_matches_its_own_prefix() -> None:
    assert Action(name="warden.egress.request").matches("warden.egress")
    assert Action(name="warden.egress.request").matches("warden.egress.request")


def test_broader_action_does_not_satisfy_narrower_rule() -> None:
    """A grant for `warden.egress` must not cover `warden.egress.raw_socket`."""
    assert not Action(name="warden.egress").matches("warden.egress.request")


def test_action_prefix_is_segment_aware() -> None:
    """`warden.egress` must not match `warden.egressive` by string prefix."""
    assert not Action(name="warden.egressive.thing").matches("warden.egress")


# ── policy (LAW 2) ───────────────────────────────────────────────────────────


def test_decision_tighten_picks_the_stricter() -> None:
    assert Decision.ALLOW.tighten(Decision.DENY) is Decision.DENY
    assert Decision.DENY.tighten(Decision.ALLOW) is Decision.DENY
    assert Decision.ALLOW.tighten(Decision.ASK) is Decision.ASK
    assert Decision.DENY.tighten(Decision.ASK) is Decision.DENY


def test_decision_tighten_is_commutative() -> None:
    """Merge order must not change the outcome, or merges become order-dependent."""
    for a in Decision:
        for b in Decision:
            assert a.tighten(b) is b.tighten(a)


def test_no_decision_combination_produces_allow_from_a_deny() -> None:
    for other in Decision:
        assert Decision.DENY.tighten(other) is Decision.DENY


def test_rule_defaults_to_deny() -> None:
    assert PolicyRule(id="r").decision is Decision.DENY


def test_allow_rule_without_a_reason_is_rejected() -> None:
    """An unexplained ALLOW is a hole nobody can review."""
    with pytest.raises(ValidationError, match="no reason"):
        PolicyRule(id="r", decision=Decision.ALLOW)


def test_allow_rule_with_a_reason_is_fine() -> None:
    rule = PolicyRule(id="r", decision=Decision.ALLOW, reason="model endpoint")
    assert rule.decision is Decision.ALLOW


@pytest.mark.parametrize("pattern", ["*.groq.com.evil", "*a*", "**"])
def test_only_a_single_trailing_wildcard_is_allowed(pattern: str) -> None:
    """Richer globbing invites rules matching more than their author intended."""
    with pytest.raises(ValidationError, match="trailing"):
        PolicyRule(id="r", subject_pattern=pattern)


def test_default_deny_is_available_without_a_rule() -> None:
    v = Verdict.default_deny()
    assert v.decision is Decision.DENY
    assert not v.allowed
    assert v.rule_id is None


def test_verdict_requires_a_reason() -> None:
    with pytest.raises(ValidationError):
        Verdict(decision=Decision.DENY, reason="")


# ── capability (LAW 3) ───────────────────────────────────────────────────────


def make_cap(**overrides: object) -> Capability:
    base: dict[str, object] = {
        "id": "cap",
        "action": "warden.egress.request",
        "subject_kind": SubjectKind.HOST,
        "subject_pattern": "api.groq.com",
        "actor_id": "agent_a",
        "context_id": "ctx_1",
        "issued_at": NOW,
        "expires_at": NOW + timedelta(minutes=5),
        "signature": H1,
    }
    return Capability.model_validate(base | overrides)


def test_capability_permits_the_exact_grant() -> None:
    assert make_cap().permits(
        action="warden.egress.request",
        subject_kind=SubjectKind.HOST,
        subject_identifier="api.groq.com",
        actor_id="agent_a",
        context_id="ctx_1",
        now=NOW,
    )


@pytest.mark.parametrize(
    "wrong",
    [
        {"action": "warden.egress.raw_socket"},
        {"subject_identifier": "evil.com"},
        {"actor_id": "agent_b"},
        {"context_id": "ctx_2"},
        {"subject_kind": SubjectKind.PATH},
    ],
)
def test_capability_refuses_every_mismatched_dimension(wrong: dict[str, object]) -> None:
    args: dict[str, object] = {
        "action": "warden.egress.request",
        "subject_kind": SubjectKind.HOST,
        "subject_identifier": "api.groq.com",
        "actor_id": "agent_a",
        "context_id": "ctx_1",
        "now": NOW,
    }
    assert not make_cap().permits(**(args | wrong))  # type: ignore[arg-type]


def test_expired_capability_is_refused() -> None:
    assert not make_cap().permits(
        action="warden.egress.request",
        subject_kind=SubjectKind.HOST,
        subject_identifier="api.groq.com",
        actor_id="agent_a",
        context_id="ctx_1",
        now=NOW + timedelta(minutes=6),
    )


def test_capability_action_is_not_prefix_matched() -> None:
    """Unlike a policy rule, a grant is exact - `warden.egress` never covers more."""
    cap = make_cap(action="warden.egress")
    assert not cap.permits(
        action="warden.egress.request",
        subject_kind=SubjectKind.HOST,
        subject_identifier="api.groq.com",
        actor_id="agent_a",
        context_id="ctx_1",
        now=NOW,
    )


def test_capability_lifetime_is_bounded() -> None:
    """A long-lived capability is ambient authority wearing a costume."""
    with pytest.raises(ValidationError, match="lifetime exceeds"):
        make_cap(expires_at=NOW + timedelta(days=1))


def test_capability_cannot_expire_before_issue() -> None:
    with pytest.raises(ValidationError, match="expires at or before"):
        make_cap(expires_at=NOW - timedelta(seconds=1))


def test_capability_wildcard_covers_a_subdomain_prefix() -> None:
    cap = make_cap(subject_pattern="api.")
    assert cap.covers_subject("api.groq.com") is False
    assert make_cap(subject_pattern="api.*").covers_subject("api.groq.com")


# ── isolation ladder (ADR-0002) ─────────────────────────────────────────────


def test_backend_strength_is_ordered() -> None:
    ladder = [
        IsolationBackend.INPROC,
        IsolationBackend.SUBPROC,
        IsolationBackend.WINJOB,
        IsolationBackend.CONTAINER,
        IsolationBackend.VM,
    ]
    assert [b.strength for b in ladder] == sorted(b.strength for b in ladder)


def test_weaker_backend_does_not_satisfy_a_minimum() -> None:
    """A capability whose minimum cannot be met does not run - it never downgrades."""
    assert not IsolationBackend.SUBPROC.satisfies(IsolationBackend.WINJOB)
    assert IsolationBackend.CONTAINER.satisfies(IsolationBackend.WINJOB)
    assert IsolationBackend.WINJOB.satisfies(IsolationBackend.WINJOB)


# ── tighten-only merge (LAW 3) ──────────────────────────────────────────────


def test_resource_tighten_takes_the_minimum_of_every_dimension() -> None:
    a = ResourceLimits(memory_mb=2048, cpu_percent=80, wall_clock_seconds=600)
    b = ResourceLimits(memory_mb=512, cpu_percent=25, wall_clock_seconds=900)
    merged = a.tighten(b)
    assert (merged.memory_mb, merged.cpu_percent, merged.wall_clock_seconds) == (512, 25, 600)


def test_network_tighten_is_an_intersection() -> None:
    a = NetworkPolicy(allow_egress=("api.groq.com", "ollama.local"), allow_ports=(443, 11434))
    b = NetworkPolicy(allow_egress=("ollama.local", "evil.com"), allow_ports=(11434,))
    merged = a.tighten(b)
    assert merged.allow_egress == ("ollama.local",)
    assert merged.allow_ports == (11434,)


def test_a_host_only_one_side_declares_is_dropped() -> None:
    """'Policy did not mention it' must never mean 'policy allowed it'."""
    declared = NetworkPolicy(allow_egress=("api.groq.com",))
    policy = NetworkPolicy(allow_egress=())
    assert declared.tighten(policy).allow_egress == ()


def test_mount_tighten_prefers_readonly_and_the_smaller_quota() -> None:
    a = FilesystemMount(path="/work", access="rw", max_size_mb=512)
    b = FilesystemMount(path="/work", access="ro", max_size_mb=64)
    merged = a.tighten(b)
    assert merged.access == "ro"
    assert merged.max_size_mb == 64


def test_profile_tighten_never_widens_any_dimension() -> None:
    declared = IsolationProfile(
        backend=IsolationBackend.SUBPROC,
        mounts=(FilesystemMount(path="/work", access="rw"),),
        network=NetworkPolicy(allow_egress=("api.groq.com", "evil.com")),
        resources=ResourceLimits(memory_mb=4096),
    )
    policy = IsolationProfile(
        backend=IsolationBackend.WINJOB,
        mounts=(FilesystemMount(path="/work", access="ro"),),
        network=NetworkPolicy(allow_egress=("api.groq.com",)),
        resources=ResourceLimits(memory_mb=512),
    )

    merged = declared.tighten(policy)

    assert merged.backend is IsolationBackend.WINJOB  # stronger wins
    assert merged.network.allow_egress == ("api.groq.com",)
    assert merged.resources.memory_mb == 512
    assert merged.mounts[0].access == "ro"
    assert merged.is_tighter_than_or_equal_to(declared)
    assert merged.is_tighter_than_or_equal_to(policy)


def test_tighten_is_commutative_on_profiles() -> None:
    a = IsolationProfile(network=NetworkPolicy(allow_egress=("x.com", "y.com")))
    b = IsolationProfile(network=NetworkPolicy(allow_egress=("y.com",)))
    assert a.tighten(b) == b.tighten(a)


def test_a_mount_only_one_side_declares_is_dropped() -> None:
    a = IsolationProfile(mounts=(FilesystemMount(path="/work"), FilesystemMount(path="/scratch")))
    b = IsolationProfile(mounts=(FilesystemMount(path="/work"),))
    assert {m.path for m in a.tighten(b).mounts} == {"/work"}


def test_duplicate_mount_paths_are_rejected() -> None:
    with pytest.raises(ValidationError, match="duplicate mount"):
        IsolationProfile(mounts=(FilesystemMount(path="/work"), FilesystemMount(path="/work")))


def test_there_is_no_loosen_operation() -> None:
    """If this ever fails, someone added the one method that would undo LAW 3."""
    for model in (IsolationProfile, NetworkPolicy, ResourceLimits, FilesystemMount, Decision):
        assert not hasattr(model, "loosen"), f"{model.__name__} grew a loosen()"
        assert not hasattr(model, "widen"), f"{model.__name__} grew a widen()"


# ── ledger (LAW 1) ───────────────────────────────────────────────────────────


def make_entry(**overrides: object) -> LedgerEntry:
    base: dict[str, object] = {
        "seq": 0,
        "ts_wall": NOW,
        "ts_mono": 1_000,
        "plane": Plane.WARDEN,
        "actor_id": "agent_a",
        "action": "warden.egress.request",
        "subject": Subject(kind=SubjectKind.HOST, identifier="api.groq.com"),
        "verdict": Verdict.default_deny(),
        "prev_hash": GENESIS_PREV_HASH,
        "signature": H1,
    }
    return LedgerEntry.model_validate(base | overrides)


def test_genesis_entry_is_valid() -> None:
    assert make_entry().is_genesis


def test_seq_zero_must_carry_the_genesis_hash() -> None:
    with pytest.raises(ValidationError, match="genesis"):
        make_entry(seq=0, prev_hash=H1)


def test_only_seq_zero_may_carry_the_genesis_hash() -> None:
    """Otherwise a truncated chain could re-present entry N as a fresh genesis."""
    with pytest.raises(ValidationError, match="genesis"):
        make_entry(seq=5, prev_hash=GENESIS_PREV_HASH)


def test_naive_timestamp_is_rejected() -> None:
    with pytest.raises(ValidationError, match="timezone-aware"):
        make_entry(ts_wall=datetime(2026, 8, 13, 12, 0))


def test_malformed_hash_is_rejected() -> None:
    for bad in ("not-a-hash", "A" * 64, "a" * 63):
        with pytest.raises(ValidationError):
            make_entry(seq=1, prev_hash=bad, signature=H1)


def test_payload_hash_is_optional_so_a_body_can_be_deleted() -> None:
    """The chain must still verify after a sensitive body is dropped."""
    assert make_entry(payload_hash=None).payload_hash is None
    assert make_entry(payload_hash=H1).payload_hash == H1


# ── secrets (the reason the secret scanner exists) ──────────────────────────


def test_secret_ref_has_no_value_or_default_field() -> None:
    """The absence of these fields IS the control."""
    fields = set(SecretRef.model_fields)
    assert "value" not in fields
    assert "default" not in fields
    assert "fallback" not in fields


def test_secret_ref_cannot_be_given_a_value() -> None:
    with pytest.raises(ValidationError):
        SecretRef(name="groq", value="gsk_whatever")  # type: ignore[call-arg]


def test_secret_ref_str_leaks_nothing() -> None:
    assert str(SecretRef(name="groq_api_key")) == "SecretRef(sletchy/groq_api_key)"


# ── flags (LAW 8) ────────────────────────────────────────────────────────────


def test_dangerous_flag_cannot_default_on() -> None:
    with pytest.raises(ValidationError, match="LAW 8"):
        Flag(name="egress", risk=FlagRisk.DANGEROUS, default=True, description="network out")


def test_dangerous_flag_defaults_off() -> None:
    assert not Flag(name="egress", risk=FlagRisk.DANGEROUS, description="network out").default


def test_safe_flag_may_default_on() -> None:
    assert Flag(name="color", risk=FlagRisk.SAFE, default=True, description="colour output").default


# ── events (LAW 5) ───────────────────────────────────────────────────────────


def test_the_vocabulary_is_exactly_eleven() -> None:
    """Growing this requires an ADR. The test is the speed bump."""
    assert len(AgentEventType) == 11


def test_policy_event_must_cite_the_ledger() -> None:
    """A security decision the user cannot trace back to the ledger is a claim."""
    with pytest.raises(ValidationError, match="ledger_seq"):
        AgentEvent(type=AgentEventType.POLICY, data={"decision": "deny"})


def test_policy_event_with_a_ledger_seq_is_fine() -> None:
    ev = AgentEvent(type=AgentEventType.POLICY, data={"decision": "deny"}, ledger_seq=42)
    assert ev.ledger_seq == 42


def test_non_policy_events_do_not_need_a_ledger_seq() -> None:
    assert AgentEvent(type=AgentEventType.CONTENT, data={"text": "hi"}).ledger_seq is None


@pytest.mark.parametrize(
    ("event_type", "terminal"),
    [
        (AgentEventType.COMPLETE, True),
        (AgentEventType.ERROR, True),
        (AgentEventType.CONTENT, False),
        (AgentEventType.STATUS, False),
    ],
)
def test_terminal_events(event_type: AgentEventType, terminal: bool) -> None:
    assert AgentEvent(type=event_type, ledger_seq=1).is_terminal is terminal


# ── schema generation (LAW 6) ───────────────────────────────────────────────


@pytest.mark.parametrize(
    "model",
    [Actor, Capability, LedgerEntry, IsolationProfile, PolicyRule, Flag, AgentEvent],
)
def test_every_contract_generates_json_schema(model: type) -> None:
    """Derived artifacts are generated, never hand-written."""
    schema = model.model_json_schema()  # type: ignore[attr-defined]
    assert schema["type"] == "object"
    assert "properties" in schema


@pytest.mark.parametrize(
    "instance",
    [
        Actor(id="a", kind=ActorKind.AGENT, plane=Plane.MIND),
        PolicyRule(id="r"),
        Flag(name="f", risk=FlagRisk.SAFE, description="d"),
        NetworkPolicy(allow_egress=("api.groq.com",)),
    ],
)
def test_contracts_round_trip(instance: object) -> None:
    dumped = instance.model_dump_json()  # type: ignore[attr-defined]
    assert type(instance).model_validate_json(dumped) == instance  # type: ignore[attr-defined]
