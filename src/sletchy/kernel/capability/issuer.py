"""Minting capabilities.

The single most important property of this module is what it **does not** offer:
there is no function an actor can call to obtain a capability for itself.

`CapabilityIssuer.issue()` requires a `PolicyGate`, asks it, and mints only on
ALLOW. An agent that wants a capability must convince *policy*, not the issuer - and
policy is a file the operator wrote. Anything else is prompt injection with extra
steps: an agent that can request its own authority can be talked into requesting the
wrong one.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from sletchy.kernel.capability.canonical import signing_bytes
from sletchy.kernel.capability.errors import CapabilityDenied
from sletchy.kernel.contracts import (
    DEFAULT_TTL,
    MAX_TTL,
    Capability,
    Decision,
    Subject,
    SubjectKind,
    Verdict,
)
from sletchy.kernel.ledger.keys import sign

if TYPE_CHECKING:
    from sletchy.kernel.contracts import Action, Actor, Plane
    from sletchy.kernel.ledger import KeySource, Ledger
    from sletchy.kernel.policy import PolicyGate

#: A separate keychain account from the ledger's. Key separation means a leaked
#: capability key does not also let an attacker forge audit history.
CAPABILITY_KEY_ACCOUNT = "capability-signing-key"

ISSUE_ACTION = "kernel.capability.issue"


class CapabilityIssuer:
    """Mints capabilities from policy allows. The only way one comes into existence."""

    __slots__ = ("_gate", "_keys", "_ledger")

    def __init__(self, gate: PolicyGate, key_source: KeySource, ledger: Ledger) -> None:
        self._gate = gate
        self._keys = key_source
        self._ledger = ledger

    def issue(
        self,
        *,
        plane: Plane,
        actor: Actor,
        action: Action,
        subject: Subject,
        context_id: str,
        ttl: timedelta = DEFAULT_TTL,
    ) -> Capability:
        """Ask policy, then mint if it allowed.

        Raises `CapabilityDenied` on DENY **or ASK**. An unanswered human gate is a
        refusal until the human answers (LAW 7) - the issuer must not mint on the
        strength of a question nobody has answered yet.

        The grant is the narrowest thing that satisfies the request: the exact
        action, and the subject's exact identifier as the pattern. Widening is the
        caller's problem to justify, not a default the issuer hands out.
        """
        if ttl > MAX_TTL:
            msg = f"requested ttl {ttl} exceeds the {MAX_TTL} ceiling"
            raise ValueError(msg)

        verdict = self._gate.decide(plane=plane, actor=actor, action=action, subject=subject)
        if verdict.decision is not Decision.ALLOW:
            raise CapabilityDenied(verdict)

        now = datetime.now(UTC)
        draft = Capability(
            id=f"cap-{uuid.uuid4().hex}",
            action=action.name,
            subject_kind=subject.kind,
            subject_pattern=subject.identifier,
            actor_id=actor.id,
            context_id=context_id,
            issued_at=now,
            expires_at=now + ttl,
            signature="0" * 64,
        )
        capability = draft.model_copy(
            update={"signature": sign(self._keys.get(), signing_bytes(draft))}
        )

        self._ledger.append(
            plane=plane,
            actor_id=actor.id,
            action=ISSUE_ACTION,
            subject=Subject(kind=SubjectKind.CAPABILITY, identifier=capability.id),
            verdict=Verdict(
                decision=Decision.ALLOW,
                reason=(
                    f"granted {action.name} on {subject.kind.value}:{subject.identifier} "
                    f"for {ttl.total_seconds():.0f}s (rule {verdict.rule_id})"
                ),
                rule_id=verdict.rule_id,
            ),
        )
        return capability
