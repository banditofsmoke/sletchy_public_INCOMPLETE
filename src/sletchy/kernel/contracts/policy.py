"""Decisions, verdicts, and the rules that produce them.

The shapes here encode two laws:

LAW 2 (deny by default)
    `Decision` has no "unset" member. Every question has an answer, and the answer
    to a question nobody wrote a rule for is DENY.

LAW 3 (declare, then tighten, never loosen)
    `Decision` is ordered by strictness, and `Decision.tighten` is the only merge
    operation offered. There is deliberately no `loosen`.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Self

from pydantic import Field, model_validator

from sletchy.kernel.contracts.base import ACTION_PATTERN, Contract, Name
from sletchy.kernel.contracts.identity import ActorKind, Plane, SubjectKind

# Strictness order. Higher wins a tighten.
_STRICTNESS: dict[str, int] = {"allow": 0, "ask": 1, "deny": 2}


class Decision(StrEnum):
    """What policy concluded.

    `ASK` is a real decision, not a deferral - it means "a human must answer before
    this proceeds" (LAW 7), and it is recorded in the ledger as such.
    """

    ALLOW = "allow"
    ASK = "ask"
    DENY = "deny"

    @property
    def strictness(self) -> int:
        return _STRICTNESS[self.value]

    def tighten(self, other: Decision) -> Decision:
        """Return the stricter of two decisions.

        This is the *only* way to combine decisions. Ties go to the stricter side
        by construction, because `max` on strictness cannot produce something looser
        than either input. There is no counterpart that widens.
        """
        return self if self.strictness >= other.strictness else other


class PolicyRule(Contract):
    """One declarative rule over (actor, action, subject).

    A `None` field means "matches anything of this dimension". That makes broad
    rules easy to write - but note the default `decision` is DENY, so a broad rule
    written carelessly fails closed rather than open.
    """

    id: Name
    decision: Decision = Decision.DENY

    #: Match constraints. None = unconstrained on that dimension.
    actor_id: Name | None = None
    actor_kind: ActorKind | None = None
    actor_plane: Plane | None = None
    min_trust: Annotated[int, Field(ge=0, le=100)] | None = None

    #: Prefix-matched against the action, e.g. `warden.egress`.
    action: Annotated[str, Field(pattern=ACTION_PATTERN)] | None = None

    subject_kind: SubjectKind | None = None
    #: Exact match, or a single trailing `*` wildcard (`api.groq.com`, `*.groq.com`).
    subject_pattern: Annotated[str, Field(min_length=1, max_length=1024)] | None = None

    #: Higher wins when two rules both match. Ties fall back to the stricter decision.
    priority: Annotated[int, Field(ge=0, le=1000)] = 0

    #: Why this rule exists. Required for anything that allows - an unexplained
    #: ALLOW is a hole nobody can review.
    reason: Annotated[str, Field(max_length=512)] = ""

    @model_validator(mode="after")
    def _allow_requires_reason(self) -> Self:
        if self.decision is Decision.ALLOW and not self.reason.strip():
            msg = (
                f"rule {self.id!r} allows but gives no reason; "
                "every ALLOW must state why it exists (LAW 2)"
            )
            raise ValueError(msg)
        return self

    @model_validator(mode="after")
    def _wildcard_only_trails(self) -> Self:
        pattern = self.subject_pattern
        if pattern is None:
            return self
        if "*" in pattern.rstrip("*") or pattern.count("*") > 1:
            msg = (
                f"rule {self.id!r} subject_pattern {pattern!r}: only a single "
                "trailing '*' is supported - richer globbing invites rules that "
                "match more than their author intended"
            )
            raise ValueError(msg)
        return self


class Verdict(Contract):
    """The outcome of a policy question, and why.

    `rule_id` is optional precisely because the most important verdict - the
    default DENY when nothing matched - has no rule behind it. `reason` is not
    optional: a verdict a human cannot understand is not auditable.
    """

    decision: Decision
    reason: Annotated[str, Field(min_length=1, max_length=512)]
    rule_id: Name | None = None

    @property
    def allowed(self) -> bool:
        return self.decision is Decision.ALLOW

    @classmethod
    def default_deny(cls, detail: str = "no rule matched") -> Verdict:
        """The answer when policy is silent.

        Every path that cannot reach a rule must end here rather than at ALLOW.
        """
        return cls(decision=Decision.DENY, reason=f"default deny: {detail}")
