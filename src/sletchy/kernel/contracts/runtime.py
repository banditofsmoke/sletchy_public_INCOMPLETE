"""Secret references, feature flags, and the streaming event vocabulary.

Three small contracts that share one property: they are the places where a careless
default would undo a law.

- `SecretRef` never carries a value, and offers no `default`. That absence is the
  fix for the exact pattern that leaked six keys across the archived projects.
- `Flag` defaults dangerous capabilities to off, and refuses to be constructed
  otherwise.
- `AgentEvent` is the whole streaming vocabulary. Adding a member is an ADR.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import Field, model_validator

from sletchy.kernel.contracts.base import Contract, Name

# ── secrets ──────────────────────────────────────────────────────────────────


class SecretRef(Contract):
    """A pointer to a secret in the OS keychain. Never the secret itself.

    There is deliberately no `default` field and no `value` field. A secret that can
    carry a fallback is a secret that will eventually ship one - that is precisely
    how an env lookup with a live key as its second argument put that key into eight
    files across three projects. Resolution fails closed; the absence of those two
    fields *is* the control. See docs/salvage/CREDENTIALS-TO-ROTATE.md.
    """

    name: Name
    #: Keychain service namespace. Scopes refs so two providers cannot collide.
    service: Name = "sletchy"

    def __str__(self) -> str:
        """Safe by construction - there is no value here to leak."""
        return f"SecretRef({self.service}/{self.name})"


# ── flags ────────────────────────────────────────────────────────────────────


class FlagRisk(StrEnum):
    """How much damage a flag can do when on.

    `DANGEROUS` is not a warning label - it is enforced. See `Flag._dangerous_off`.
    """

    #: Cosmetic or local-only. May default on.
    SAFE = "safe"
    #: Touches the filesystem inside `var/`, or spends local compute.
    ELEVATED = "elevated"
    #: Network, filesystem outside `var/`, mic, camera, screen, wallet, training.
    DANGEROUS = "dangerous"


class Flag(Contract):
    """One switchable capability.

    LAW 8 is enforced in the validator rather than trusted to reviewers: a
    DANGEROUS flag whose default is True cannot be constructed at all.
    """

    name: Name
    risk: FlagRisk
    default: bool = False
    description: Annotated[str, Field(min_length=1, max_length=256)]
    #: The words a non-technical person sees for this switch. Empty means "use the
    #: name"; every flag Sletchy ships has one, and a test enforces that.
    label: Annotated[str, Field(max_length=32)] = ""
    #: True only when some code in Sletchy actually reads this switch. A switch that
    #: nothing reads still exists - so that the feature starts *off* the day it is
    #: built - but a UI must never present it as doing something today. A test
    #: compares this against the source, so it cannot drift into a lie.
    wired: bool = False
    #: Which of the three human questions this switch answers (principles.md): does
    #: it save time, make money, or help someone connect with people. "safety" marks
    #: a switch that answers them only indirectly, as the floor beneath the rest.
    serves: tuple[Literal["time", "money", "connection", "safety"], ...] = ()

    @model_validator(mode="after")
    def _dangerous_off(self) -> Self:
        if self.risk is FlagRisk.DANGEROUS and self.default:
            msg = (
                f"flag {self.name!r} is DANGEROUS and defaults on; LAW 8 requires "
                "network / filesystem-outside-var / mic / camera / screen / wallet / "
                "training flags to be off on a fresh install"
            )
            raise ValueError(msg)
        return self


# ── events ───────────────────────────────────────────────────────────────────


class AgentEventType(StrEnum):
    """The entire streaming vocabulary. Eleven members, and that is the point.

    Adding one changes the contract every host must implement, so it requires an
    ADR. Extend an existing event's payload first (LAW 5).
    """

    CONTENT = "content"
    REASONING = "reasoning"
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"
    INTERRUPT = "interrupt"
    ARTIFACT = "artifact"
    PLAN = "plan"
    STATUS = "status"
    #: Sletchy's addition to the inherited ten: a security decision was made about
    #: this execution. Carries `ledger_seq` so any surface can show *why* Sletchy
    #: refused, inline with the conversation.
    POLICY = "policy"
    COMPLETE = "complete"
    ERROR = "error"


class AgentEvent(Contract):
    """One event on the single stream every execution produces.

    Hosts are pure translation over this - no state, no side effects (LAW 5).

    `data` is `Mapping[str, object]` rather than `Any` so the kernel stays free of
    explicit `Any` under mypy strict; hosts narrow it per event type.
    """

    type: AgentEventType
    data: dict[str, object] = Field(default_factory=dict)

    #: Attribution. Set when more than one agent participates in a thread.
    actor_id: Name | None = None
    #: The ledger entry this event corresponds to. Required on POLICY events -
    #: a security decision the user cannot trace back to the ledger is a claim,
    #: not a record.
    ledger_seq: Annotated[int, Field(ge=0)] | None = None

    @model_validator(mode="after")
    def _policy_events_cite_the_ledger(self) -> Self:
        if self.type is AgentEventType.POLICY and self.ledger_seq is None:
            msg = "POLICY events must carry ledger_seq so the decision is traceable (LAW 1)"
            raise ValueError(msg)
        return self

    @property
    def is_terminal(self) -> bool:
        return self.type in (AgentEventType.COMPLETE, AgentEventType.ERROR)
