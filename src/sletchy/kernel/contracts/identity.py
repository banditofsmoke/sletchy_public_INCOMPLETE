"""Who did what to which thing.

Every ledger entry and every policy question is a triple of (actor, action,
subject). Keeping those three as first-class contracts - rather than loose strings -
is what lets policy match on structure instead of on substring guesswork.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated

from pydantic import Field

from sletchy.kernel.contracts.base import ACTION_PATTERN, Contract, Name


class Plane(StrEnum):
    """The seven planes. Ordered from trust root outward.

    Membership here is what the ledger records as the origin of an entry, and what
    import-linter enforces as a dependency layer.
    """

    KERNEL = "kernel"
    WARDEN = "warden"
    SOC = "soc"
    MIND = "mind"
    SENSES = "senses"
    FORGE = "forge"
    VAULT = "vault"


class ActorKind(StrEnum):
    """What sort of thing is acting.

    `HUMAN` matters because LAW 7 gates irreversible actions on a human, and the
    ledger has to be able to prove which entries were human-initiated.
    """

    HUMAN = "human"
    AGENT = "agent"
    TOOL = "tool"
    PLANE = "plane"
    DEPENDENCY = "dependency"


class Actor(Contract):
    """Something that can take an action.

    Actors are not trusted by virtue of existing (LAW 4). `trust` is a budget that
    moves on evidence, and capabilities gate on it - see `soc/detect/trust.py`.
    """

    id: Name
    kind: ActorKind
    plane: Plane

    #: 0-100. Starts neutral. The SOC moves it; nothing else may.
    trust: Annotated[int, Field(ge=0, le=100)] = 50

    def with_trust(self, value: int) -> Actor:
        """Return a copy at a new trust level, clamped to [0, 100].

        Clamping rather than raising is deliberate: trust adjustments arrive from
        detection rules summing arbitrary deltas, and a rule that overshoots should
        saturate, not crash the SOC.
        """
        return self.model_copy(update={"trust": max(0, min(100, value))})


class Action(Contract):
    """A verb, namespaced by plane: `warden.egress.request`, `kernel.flag.flip`.

    Dot-separated so policy can match a prefix - `warden.egress` covers every egress
    action without enumerating them.
    """

    name: Annotated[str, Field(pattern=ACTION_PATTERN)]

    @property
    def segments(self) -> tuple[str, ...]:
        return tuple(self.name.split("."))

    def matches(self, pattern: str) -> bool:
        """True when `pattern` is this action or one of its prefixes.

        `warden.egress.request`.matches(`warden.egress`) is True.
        `warden.egress`.matches(`warden.egress.request`) is False - a broader action
        never satisfies a narrower rule. That asymmetry is LAW 3 in miniature.
        """
        if pattern == self.name:
            return True
        return self.name.startswith(pattern + ".")


class SubjectKind(StrEnum):
    """The class of thing being acted upon.

    A capability names exactly one action on exactly one *kind* of subject, so this
    enum bounds how wide any single grant can be.
    """

    HOST = "host"
    PATH = "path"
    SECRET = "secret"  # noqa: S105 - a subject *kind*, not a credential
    TOOL = "tool"
    MODEL = "model"
    FLAG = "flag"
    PROCESS = "process"
    CAPABILITY = "capability"
    LEDGER = "ledger"
    CONTRACT = "contract"
    MEMORY = "memory"


class Subject(Contract):
    """What an action is done to.

    `identifier` is deliberately free-form - a hostname, a path, a tool name - but
    `kind` is not. Policy matches on `kind` first, so a rule about paths can never
    accidentally match a hostname.
    """

    kind: SubjectKind
    identifier: Annotated[str, Field(min_length=1, max_length=1024)]
