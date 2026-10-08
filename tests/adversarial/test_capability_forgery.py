"""Adversarial tests for capabilities.

The attacker here holds a *genuine* capability. That is the interesting case: forging
one from nothing is hard, but lifting a real one out of one execution and offering it
in another is exactly what a compromised agent would try.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from sletchy.kernel.capability import (
    CapabilityDenied,
    CapabilityExpired,
    CapabilityForged,
    CapabilityIssuer,
    CapabilityMismatch,
    CapabilityRevoked,
    CapabilityVerifier,
    RevocationList,
)
from sletchy.kernel.contracts import (
    Action,
    Actor,
    ActorKind,
    Capability,
    Decision,
    Plane,
    PolicyRule,
    Subject,
    SubjectKind,
)
from sletchy.kernel.ledger import InMemoryKeySource, Ledger
from sletchy.kernel.policy import PolicyEngine, PolicyGate, PolicySet

pytestmark = pytest.mark.adversarial

AGENT = Actor(id="agent_a", kind=ActorKind.AGENT, plane=Plane.MIND, trust=50)
EGRESS = Action(name="warden.egress.request")
GROQ = Subject(kind=SubjectKind.HOST, identifier="api.groq.com")
CTX = "ctx_1"

CAP_KEY = b"c" * 32
LEDGER_KEY = b"l" * 32


class Rig:
    """Issuer + verifier over one ledger, with a policy that allows egress."""

    def __init__(self, tmp_path: Path, *rules: PolicyRule) -> None:
        self.ledger = Ledger.open(tmp_path / "ledger", InMemoryKeySource(LEDGER_KEY))
        gate = PolicyGate(PolicyEngine(PolicySet(rules)), self.ledger)
        self.revocations = RevocationList.from_ledger(self.ledger)
        self.issuer = CapabilityIssuer(gate, InMemoryKeySource(CAP_KEY), self.ledger)
        self.verifier = CapabilityVerifier(
            InMemoryKeySource(CAP_KEY), self.ledger, self.revocations
        )

    def issue(self, **kw: object) -> Capability:
        args: dict[str, object] = {
            "plane": Plane.WARDEN,
            "actor": AGENT,
            "action": EGRESS,
            "subject": GROQ,
            "context_id": CTX,
        }
        return self.issuer.issue(**(args | kw))  # type: ignore[arg-type]

    def check(self, capability: Capability, **kw: object) -> None:
        args: dict[str, object] = {
            "action": "warden.egress.request",
            "subject_kind": SubjectKind.HOST,
            "subject_identifier": "api.groq.com",
            "actor_id": "agent_a",
            "context_id": CTX,
        }
        self.verifier.check(capability, **(args | kw))  # type: ignore[arg-type]


def allow_egress(rule_id: str = "egress", **kw: object) -> PolicyRule:
    base: dict[str, object] = {
        "id": rule_id,
        "decision": Decision.ALLOW,
        "reason": "test fixture",
        "action": "warden.egress",
    }
    return PolicyRule.model_validate(base | kw)


def rig(tmp_path: Path) -> Rig:
    return Rig(tmp_path, allow_egress())


# ── no self-grant ────────────────────────────────────────────────────────────


def test_policy_deny_refuses_to_mint(tmp_path: Path) -> None:
    """An agent cannot get a capability policy did not authorise."""
    r = Rig(tmp_path)  # empty policy
    with pytest.raises(CapabilityDenied) as exc:
        r.issue()
    assert exc.value.verdict.decision is Decision.DENY


def test_an_unanswered_ask_does_not_mint(tmp_path: Path) -> None:
    """LAW 7: a human gate nobody has answered is a refusal, not a pending allow."""
    r = Rig(tmp_path, PolicyRule(id="confirm", decision=Decision.ASK, action="warden.egress"))
    with pytest.raises(CapabilityDenied) as exc:
        r.issue()
    assert exc.value.verdict.decision is Decision.ASK


def test_there_is_no_self_grant_api() -> None:
    """The issuer's only mint path requires a PolicyGate.

    If a function appears that mints without asking policy, an agent that can reach
    it can authorise itself.
    """
    import inspect

    public = [n for n in dir(CapabilityIssuer) if not n.startswith("_")]
    assert public == ["issue"]
    assert "gate" in inspect.signature(CapabilityIssuer.__init__).parameters


def test_a_low_trust_actor_is_refused(tmp_path: Path) -> None:
    r = Rig(tmp_path, allow_egress(min_trust=80))
    with pytest.raises(CapabilityDenied):
        r.issue()


# ── forgery ──────────────────────────────────────────────────────────────────


def test_a_valid_capability_is_accepted(tmp_path: Path) -> None:
    r = rig(tmp_path)
    r.check(r.issue())  # does not raise


@pytest.mark.parametrize(
    "field",
    ["action", "subject_pattern", "actor_id", "context_id", "id"],
)
def test_altering_any_signed_field_breaks_the_signature(tmp_path: Path, field: str) -> None:
    """Every field is inside the signature; none can be changed for free."""
    r = rig(tmp_path)
    tampered = r.issue().model_copy(update={field: "tampered-value"})

    with pytest.raises(CapabilityForged):
        r.check(tampered, **{field: "tampered-value"} if field == "action" else {})


def test_extending_the_expiry_breaks_the_signature(tmp_path: Path) -> None:
    """The field an attacker most wants to change."""
    r = rig(tmp_path)
    capability = r.issue()
    tampered = capability.model_copy(
        update={"expires_at": capability.issued_at + timedelta(minutes=59)}
    )

    with pytest.raises(CapabilityForged):
        r.check(tampered)


def test_a_capability_minted_under_a_different_key_is_refused(tmp_path: Path) -> None:
    r = rig(tmp_path)
    capability = r.issue()

    foreign = CapabilityVerifier(InMemoryKeySource(b"x" * 32), r.ledger, r.revocations)
    with pytest.raises(CapabilityForged):
        foreign.check(
            capability,
            action="warden.egress.request",
            subject_kind=SubjectKind.HOST,
            subject_identifier="api.groq.com",
            actor_id="agent_a",
            context_id=CTX,
        )


def test_the_signature_is_checked_before_anything_else(tmp_path: Path) -> None:
    """A forged capability that is *also* expired must report forgery.

    Branching on an expiry an attacker chose means trusting attacker data. Getting
    this order wrong would still refuse the call, but would file an attack under
    "routine expiry" and lose the signal.
    """
    r = rig(tmp_path)
    capability = r.issue()
    tampered = capability.model_copy(
        update={
            "actor_id": "attacker",
            "expires_at": capability.issued_at + timedelta(seconds=1),
        }
    )

    with pytest.raises(CapabilityForged):
        r.check(
            tampered,
            actor_id="attacker",
            now=datetime.now(UTC) + timedelta(hours=1),
        )


# ── replay ───────────────────────────────────────────────────────────────────


def test_replay_in_another_context_is_refused(tmp_path: Path) -> None:
    """The core reason capabilities are context-bound."""
    r = rig(tmp_path)
    with pytest.raises(CapabilityMismatch, match="replay"):
        r.check(r.issue(), context_id="ctx_2")


def test_use_by_another_actor_is_refused(tmp_path: Path) -> None:
    r = rig(tmp_path)
    with pytest.raises(CapabilityMismatch, match="replay"):
        r.check(r.issue(), actor_id="agent_b")


# ── scope ────────────────────────────────────────────────────────────────────


def test_a_grant_does_not_cover_a_narrower_action(tmp_path: Path) -> None:
    """Unlike a policy rule, a grant is exact - no prefix widening."""
    r = rig(tmp_path)
    with pytest.raises(CapabilityMismatch):
        r.check(r.issue(), action="warden.egress.request.raw_socket")


def test_a_grant_does_not_cover_another_host(tmp_path: Path) -> None:
    r = rig(tmp_path)
    with pytest.raises(CapabilityMismatch):
        r.check(r.issue(), subject_identifier="attacker.example")


def test_a_grant_does_not_cover_another_subject_kind(tmp_path: Path) -> None:
    """A host grant must never satisfy a filesystem check."""
    r = rig(tmp_path)
    with pytest.raises(CapabilityMismatch):
        r.check(r.issue(), subject_kind=SubjectKind.PATH)


def test_the_issued_grant_is_the_narrowest_that_satisfies_the_request(tmp_path: Path) -> None:
    """A broad policy rule still mints a narrow capability.

    The rule below permits every action under `warden.egress`; the capability it
    produces covers exactly `warden.egress.request` on exactly `api.groq.com`.
    """
    r = Rig(tmp_path, allow_egress(action="warden.egress"))
    capability = r.issue()

    assert capability.action == "warden.egress.request"
    assert capability.subject_pattern == "api.groq.com"
    assert "*" not in capability.subject_pattern


# ── expiry ───────────────────────────────────────────────────────────────────


def test_an_expired_capability_is_refused(tmp_path: Path) -> None:
    r = rig(tmp_path)
    with pytest.raises(CapabilityExpired):
        r.check(r.issue(), now=datetime.now(UTC) + timedelta(hours=2))


def test_the_default_lifetime_is_short(tmp_path: Path) -> None:
    r = rig(tmp_path)
    capability = r.issue()
    assert capability.expires_at - capability.issued_at <= timedelta(minutes=5)


def test_a_ttl_beyond_the_ceiling_is_refused(tmp_path: Path) -> None:
    """A long-lived capability is ambient authority wearing a costume."""
    r = rig(tmp_path)
    with pytest.raises(ValueError, match="exceeds"):
        r.issue(ttl=timedelta(days=1))


# ── revocation ───────────────────────────────────────────────────────────────


def test_revocation_takes_effect_immediately(tmp_path: Path) -> None:
    r = rig(tmp_path)
    capability = r.issue()
    r.check(capability)  # fine before

    r.revocations.revoke(capability.id, reason="agent misbehaved")

    with pytest.raises(CapabilityRevoked):
        r.check(capability)


def test_revocation_survives_a_restart(tmp_path: Path) -> None:
    """Revocations are ledger entries, so they are rebuilt by scanning."""
    r = rig(tmp_path)
    capability = r.issue()
    r.revocations.revoke(capability.id, reason="frozen by the SOC")

    reopened = Ledger.open(tmp_path / "ledger", InMemoryKeySource(LEDGER_KEY))
    rebuilt = RevocationList.from_ledger(reopened)
    assert capability.id in rebuilt

    verifier = CapabilityVerifier(InMemoryKeySource(CAP_KEY), reopened, rebuilt)
    with pytest.raises(CapabilityRevoked):
        verifier.check(
            capability,
            action="warden.egress.request",
            subject_kind=SubjectKind.HOST,
            subject_identifier="api.groq.com",
            actor_id="agent_a",
            context_id=CTX,
        )


def test_a_revocation_cannot_be_deleted_without_breaking_the_chain(tmp_path: Path) -> None:
    """Resurrecting a capability means editing the ledger, which fails verification."""
    from sletchy.kernel.ledger import BadSignature

    r = rig(tmp_path)
    capability = r.issue()
    r.revocations.revoke(capability.id, reason="frozen")

    segment = tmp_path / "ledger" / "segment-00000.ndjson"
    rows = segment.read_text(encoding="utf-8").strip().splitlines()
    rows[-1] = rows[-1].replace(capability.id, "cap-" + "0" * 32)
    segment.write_text("\n".join(rows) + "\n", encoding="utf-8")

    with pytest.raises(BadSignature):
        Ledger.open(tmp_path / "ledger", InMemoryKeySource(LEDGER_KEY))


def test_freezing_an_actor_revokes_a_batch(tmp_path: Path) -> None:
    """What the SOC calls when a honeypot fires."""
    r = rig(tmp_path)
    caps = [r.issue(), r.issue(), r.issue()]

    count = r.revocations.revoke_all_for_actor(
        "agent_a", reason="honeypot decoy touched", ids=[c.id for c in caps]
    )

    assert count == 3
    for capability in caps:
        with pytest.raises(CapabilityRevoked):
            r.check(capability)


# ── LAW 1: every outcome is recorded ─────────────────────────────────────────


def test_issue_is_recorded(tmp_path: Path) -> None:
    r = rig(tmp_path)
    capability = r.issue()

    actions = [e.action for e in r.ledger.entries()]
    assert "kernel.capability.issue" in actions
    issued = next(e for e in r.ledger.entries() if e.action == "kernel.capability.issue")
    assert issued.subject.identifier == capability.id


def test_a_denied_issue_is_recorded(tmp_path: Path) -> None:
    r = Rig(tmp_path)
    with pytest.raises(CapabilityDenied):
        r.issue()

    entries = list(r.ledger.entries())
    assert len(entries) == 1
    assert entries[0].verdict.decision is Decision.DENY


def test_every_use_is_recorded(tmp_path: Path) -> None:
    r = rig(tmp_path)
    capability = r.issue()
    r.check(capability)
    r.check(capability)

    uses = [e for e in r.ledger.entries() if e.action == "kernel.capability.use"]
    assert len(uses) == 2
    assert all(e.verdict.decision is Decision.ALLOW for e in uses)


def test_a_refused_use_is_recorded_with_the_reason(tmp_path: Path) -> None:
    """The refused ones are the interesting ones."""
    r = rig(tmp_path)
    capability = r.issue()

    with pytest.raises(CapabilityMismatch):
        r.check(capability, context_id="ctx_2")

    refused = [
        e
        for e in r.ledger.entries()
        if e.action == "kernel.capability.use" and e.verdict.decision is Decision.DENY
    ]
    assert len(refused) == 1
    assert "CapabilityMismatch" in refused[0].verdict.reason


def test_the_ledger_still_verifies_after_all_of_it(tmp_path: Path) -> None:
    r = rig(tmp_path)
    capability = r.issue()
    r.check(capability)
    r.revocations.revoke(capability.id, reason="done")
    with pytest.raises(CapabilityRevoked):
        r.check(capability)

    assert r.ledger.verify() > 0


def test_check_returns_none_so_it_cannot_be_read_as_a_boolean() -> None:
    """`if verifier.check(...)` must not be writable as a truthiness test."""
    import inspect

    assert inspect.signature(CapabilityVerifier.check).return_annotation == "None"
