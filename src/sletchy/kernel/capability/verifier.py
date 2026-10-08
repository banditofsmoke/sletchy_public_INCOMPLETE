"""Checking a capability at the moment of use.

Two rules shape this module.

**The signature is checked first.** Until it verifies, no field on the capability is
trustworthy - including the expiry an attacker would have set to the far future and
the `actor_id` they would have rewritten. Checking anything else first means
branching on attacker-controlled data.

**There is one check, and it takes every dimension.** `Capability.permits()` (from
#1) requires every argument as a keyword, so no caller can perform a partial check
by forgetting one. The verifier adds signature, revocation, and the ledger record.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from sletchy.kernel.capability.canonical import signing_bytes
from sletchy.kernel.capability.errors import (
    CapabilityExpired,
    CapabilityForged,
    CapabilityMismatch,
    CapabilityRevoked,
)
from sletchy.kernel.contracts import Decision, Plane, Subject, SubjectKind, Verdict
from sletchy.kernel.ledger.keys import verify

if TYPE_CHECKING:
    from sletchy.kernel.capability.revocation import RevocationList
    from sletchy.kernel.contracts import Capability
    from sletchy.kernel.contracts import SubjectKind as SubjectKindT
    from sletchy.kernel.ledger import KeySource, Ledger

USE_ACTION = "kernel.capability.use"


class CapabilityVerifier:
    """Verifies a capability against what is actually being attempted."""

    __slots__ = ("_keys", "_ledger", "_revocations")

    def __init__(self, key_source: KeySource, ledger: Ledger, revocations: RevocationList) -> None:
        self._keys = key_source
        self._ledger = ledger
        self._revocations = revocations

    def check(
        self,
        capability: Capability,
        *,
        action: str,
        subject_kind: SubjectKindT,
        subject_identifier: str,
        actor_id: str,
        context_id: str,
        now: datetime | None = None,
    ) -> None:
        """Raise unless this capability genuinely permits this exact attempt.

        Returns `None` on success, which is deliberate: a boolean return invites
        `if verifier.check(...)` written as a truthiness test that passes on `None`.
        Raising means a caller cannot accidentally treat a refusal as permission.

        Every outcome is recorded, refusals included - a refused use is the more
        interesting event.
        """
        moment = now or datetime.now(UTC)

        try:
            self._check(
                capability,
                action=action,
                subject_kind=subject_kind,
                subject_identifier=subject_identifier,
                actor_id=actor_id,
                context_id=context_id,
                now=moment,
            )
        except Exception as exc:
            self._record(capability, actor_id, Decision.DENY, f"{type(exc).__name__}: {exc}")
            raise

        self._record(
            capability,
            actor_id,
            Decision.ALLOW,
            f"used for {action} on {subject_kind.value}:{subject_identifier}",
        )

    def _check(
        self,
        capability: Capability,
        *,
        action: str,
        subject_kind: SubjectKindT,
        subject_identifier: str,
        actor_id: str,
        context_id: str,
        now: datetime,
    ) -> None:
        # Signature first. Nothing below may branch on attacker-controlled data.
        if not verify(self._keys.get(), signing_bytes(capability), capability.signature):
            msg = (
                f"capability {capability.id} does not verify. Nothing legitimate "
                "produces this - treat it as tampering or a foreign key."
            )
            raise CapabilityForged(msg)

        if capability.id in self._revocations:
            msg = f"capability {capability.id} was revoked"
            raise CapabilityRevoked(msg)

        if capability.is_expired(now):
            msg = (
                f"capability {capability.id} expired at "
                f"{capability.expires_at.isoformat()} (now {now.isoformat()})"
            )
            raise CapabilityExpired(msg)

        if capability.actor_id != actor_id or capability.context_id != context_id:
            msg = (
                f"capability {capability.id} was issued to "
                f"{capability.actor_id}/{capability.context_id} but presented by "
                f"{actor_id}/{context_id} - this is a replay"
            )
            raise CapabilityMismatch(msg)

        if not capability.permits(
            action=action,
            subject_kind=subject_kind,
            subject_identifier=subject_identifier,
            actor_id=actor_id,
            context_id=context_id,
            now=now,
        ):
            msg = (
                f"capability {capability.id} grants {capability.action} on "
                f"{capability.subject_kind.value}:{capability.subject_pattern}, "
                f"not {action} on {subject_kind.value}:{subject_identifier}"
            )
            raise CapabilityMismatch(msg)

    def _record(
        self, capability: Capability, actor_id: str, decision: Decision, reason: str
    ) -> None:
        self._ledger.append(
            plane=Plane.KERNEL,
            actor_id=actor_id,
            action=USE_ACTION,
            subject=Subject(kind=SubjectKind.CAPABILITY, identifier=capability.id),
            verdict=Verdict(decision=decision, reason=reason[:512], rule_id=None),
        )
