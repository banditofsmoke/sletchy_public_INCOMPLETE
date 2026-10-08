"""Revocation - killing a grant before its natural expiry.

Revocations are **ledger entries**, not a separate file. `RevocationList` is a
projection rebuilt by scanning the ledger, which buys three things:

- One source of truth. The revocation record and the audit record cannot disagree,
  because they are the same record.
- Tamper-evidence for free. Deleting a revocation to resurrect a capability means
  editing the chain, which fails verification.
- No separate durability problem. If the ledger survived, so did the revocation.

The cost is a full scan at startup. That is acceptable at this scale and is the
right trade against a second store that could drift.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from sletchy.kernel.contracts import Decision, Plane, Subject, SubjectKind, Verdict

if TYPE_CHECKING:
    from sletchy.kernel.ledger import Ledger

REVOKE_ACTION = "kernel.capability.revoke"


class RevocationList:
    """The set of revoked capability ids, projected from the ledger."""

    __slots__ = ("_ledger", "_revoked")

    def __init__(self, ledger: Ledger) -> None:
        self._ledger = ledger
        self._revoked: set[str] = set()

    @classmethod
    def from_ledger(cls, ledger: Ledger) -> RevocationList:
        """Rebuild by scanning. Called once at startup."""
        revocations = cls(ledger)
        for entry in ledger.entries():
            if entry.action == REVOKE_ACTION and entry.subject.kind is SubjectKind.CAPABILITY:
                revocations._revoked.add(entry.subject.identifier)
        return revocations

    def __contains__(self, capability_id: str) -> bool:
        return capability_id in self._revoked

    def __len__(self) -> int:
        return len(self._revoked)

    def revoke(self, capability_id: str, *, reason: str, actor_id: str = "kernel") -> None:
        """Revoke immediately.

        The ledger append happens **before** the in-memory set is updated. If the
        append fails, nothing is marked revoked and the exception propagates - a
        revocation that is not recorded has not happened, and pretending otherwise
        would leave the two views disagreeing.
        """
        self._ledger.append(
            plane=Plane.KERNEL,
            actor_id=actor_id,
            action=REVOKE_ACTION,
            subject=Subject(kind=SubjectKind.CAPABILITY, identifier=capability_id),
            verdict=Verdict(
                decision=Decision.DENY,
                reason=f"capability revoked: {reason}",
                rule_id=None,
            ),
        )
        self._revoked.add(capability_id)

    def revoke_all_for_actor(self, actor_id: str, *, reason: str, ids: list[str]) -> int:
        """Revoke a batch - what the SOC calls when it freezes a misbehaving actor.

        Takes explicit ids rather than deriving them, because the Kernel does not
        keep an index of live capabilities per actor and inventing one here would
        put mutable state in the trust root.
        """
        for capability_id in ids:
            self.revoke(capability_id, reason=reason, actor_id=actor_id)
        return len(ids)
