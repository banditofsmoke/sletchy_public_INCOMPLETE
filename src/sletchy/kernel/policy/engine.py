"""Evaluating a policy question, and recording the answer.

Two objects, deliberately separate:

`PolicyEngine`
    Pure. Takes (actor, action, subject), returns a `Verdict`. No I/O, no side
    effects, trivially testable, and safe to call speculatively.

`PolicyGate`
    The engine plus a ledger. `decide()` appends the verdict **before** returning
    it, so a caller cannot obtain a decision that was not recorded.

Callers use the gate. The engine exists as its testable core, not as an alternative
route around LAW 1 - anything acting on a bare `evaluate()` result is skipping the
audit trail, and review should treat that as a defect.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from sletchy.kernel.contracts import Action, Decision, Verdict

if TYPE_CHECKING:
    from sletchy.kernel.contracts import Actor, Plane, PolicyRule, Subject
    from sletchy.kernel.ledger import Ledger
    from sletchy.kernel.policy.loader import PolicySet

_MAX_REASON = 512


def _subject_matches(pattern: str, identifier: str) -> bool:
    """Exact match, or a single trailing `*`.

    Richer globbing is refused at contract level (#1) because a pattern that can
    match in the middle invites rules that cover more than their author intended.
    """
    if pattern.endswith("*"):
        return identifier.startswith(pattern[:-1])
    return identifier == pattern


def _truncate(text: str) -> str:
    return text if len(text) <= _MAX_REASON else text[: _MAX_REASON - 1] + "…"


class PolicyEngine:
    """Answers policy questions. Pure - no I/O, no side effects."""

    __slots__ = ("_policy",)

    def __init__(self, policy: PolicySet) -> None:
        self._policy = policy

    @property
    def policy(self) -> PolicySet:
        return self._policy

    def matching_rules(
        self, actor: Actor, action: Action, subject: Subject
    ) -> tuple[PolicyRule, ...]:
        """Every rule that applies. Exposed so `sletchy policy explain` can show its work."""
        return tuple(r for r in self._policy if self._matches(r, actor, action, subject))

    def evaluate(self, actor: Actor, action: Action, subject: Subject) -> Verdict:
        """Decide. Returns `default_deny()` when no rule matches.

        Selection: highest `priority` wins; among equal priorities the **stricter
        decision** wins. Ties therefore never resolve toward permission, which is
        what makes rule ordering safe to get wrong.
        """
        matches = self.matching_rules(actor, action, subject)
        if not matches:
            return Verdict.default_deny(
                f"no rule matched {actor.id}/{action.name}/{subject.kind.value}:{subject.identifier}"
            )

        top = max(r.priority for r in matches)
        contenders = [r for r in matches if r.priority == top]

        chosen = contenders[0]
        for rule in contenders[1:]:
            if rule.decision.tighten(chosen.decision) is not chosen.decision:
                chosen = rule

        detail = chosen.reason.strip() or "no reason recorded"
        contested = (
            f" ({len(contenders)} rules tied at priority {top})" if len(contenders) > 1 else ""
        )
        return Verdict(
            decision=chosen.decision,
            reason=_truncate(f"rule {chosen.id}: {detail}{contested}"),
            rule_id=chosen.id,
        )

    def _matches(self, rule: PolicyRule, actor: Actor, action: Action, subject: Subject) -> bool:
        if rule.actor_id is not None and rule.actor_id != actor.id:
            return False
        if rule.actor_kind is not None and rule.actor_kind is not actor.kind:
            return False
        if rule.actor_plane is not None and rule.actor_plane is not actor.plane:
            return False
        # Read from the actor passed in, never from a cached copy: trust moves, and a
        # rule gated on it must see the current value.
        if rule.min_trust is not None and actor.trust < rule.min_trust:
            return False
        if rule.action is not None and not action.matches(rule.action):
            return False
        if rule.subject_kind is not None and rule.subject_kind is not subject.kind:
            return False
        return not (
            rule.subject_pattern is not None
            and not _subject_matches(rule.subject_pattern, subject.identifier)
        )


class PolicyGate:
    """The engine plus the ledger. The only decision path callers should use."""

    __slots__ = ("_engine", "_ledger")

    def __init__(self, engine: PolicyEngine, ledger: Ledger) -> None:
        self._engine = engine
        self._ledger = ledger

    @property
    def engine(self) -> PolicyEngine:
        return self._engine

    def decide(
        self,
        *,
        plane: Plane,
        actor: Actor,
        action: Action,
        subject: Subject,
        payload_hash: str | None = None,
    ) -> Verdict:
        """Evaluate, record, then return.

        The append happens **before** the verdict reaches the caller, so there is no
        window in which a decision exists but is unrecorded. If the ledger append
        fails, the exception propagates and the caller gets no verdict at all -
        fail closed (LAW 2), and no action proceeds unlogged (LAW 1).
        """
        verdict = self._engine.evaluate(actor, action, subject)
        self._ledger.append(
            plane=plane,
            actor_id=actor.id,
            action=action.name,
            subject=subject,
            verdict=verdict,
            payload_hash=payload_hash,
        )
        return verdict

    def allows(
        self,
        *,
        plane: Plane,
        actor: Actor,
        action: Action,
        subject: Subject,
    ) -> bool:
        """Convenience for call sites that only branch on allow/not-allow.

        `ASK` is deliberately **not** allow: an unanswered human gate is a refusal
        until the human answers (LAW 7).
        """
        return self.decide(plane=plane, actor=actor, action=action, subject=subject).allowed


__all__ = ["Action", "Decision", "PolicyEngine", "PolicyGate"]
