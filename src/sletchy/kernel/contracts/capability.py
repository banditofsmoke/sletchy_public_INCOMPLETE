"""Capabilities - short-lived, scoped, signed grants.

The rule that shapes this whole module: **a capability names exactly one action on
exactly one subject kind.** If a grant needs an "and", it is two capabilities. That
is what keeps a capability auditable - you can read one and know precisely what it
permits, without cross-referencing anything.

Agents never construct these. The Kernel issues them from policy; anything else is
prompt injection with extra steps.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated, Self

from pydantic import Field, model_validator

from sletchy.kernel.contracts.base import ACTION_PATTERN, Contract, Hash, Name
from sletchy.kernel.contracts.identity import SubjectKind

#: Capabilities are minted per execution and expire fast. A long-lived capability
#: is an ambient authority wearing a costume.
DEFAULT_TTL = timedelta(minutes=5)
MAX_TTL = timedelta(hours=1)


class Capability(Contract):
    """One signed permission, bound to one execution context."""

    id: Name

    #: Exact action. Unlike PolicyRule.action this is NOT prefix-matched - a grant
    #: for `warden.egress` must not silently cover `warden.egress.raw_socket`.
    action: Annotated[str, Field(pattern=ACTION_PATTERN)]

    subject_kind: SubjectKind
    #: Exact match, or a single trailing `*`.
    subject_pattern: Annotated[str, Field(min_length=1, max_length=1024)]

    #: Who may use it, and in which execution. Both are checked at use time; a
    #: capability replayed in another context is rejected.
    actor_id: Name
    context_id: Name

    issued_at: datetime
    expires_at: datetime

    #: HMAC over the canonical serialisation, keyed from the OS keychain.
    signature: Hash

    @model_validator(mode="after")
    def _sane_lifetime(self) -> Self:
        if self.expires_at <= self.issued_at:
            msg = f"capability {self.id!r} expires at or before it was issued"
            raise ValueError(msg)
        if self.expires_at - self.issued_at > MAX_TTL:
            msg = (
                f"capability {self.id!r} lifetime exceeds {MAX_TTL}; long-lived "
                "capabilities are ambient authority, not grants"
            )
            raise ValueError(msg)
        if self.issued_at.tzinfo is None or self.expires_at.tzinfo is None:
            msg = f"capability {self.id!r} timestamps must be timezone-aware"
            raise ValueError(msg)
        return self

    @model_validator(mode="after")
    def _wildcard_only_trails(self) -> Self:
        pattern = self.subject_pattern
        if "*" in pattern.rstrip("*") or pattern.count("*") > 1:
            msg = (
                f"capability {self.id!r} subject_pattern {pattern!r}: only a single "
                "trailing '*' is supported"
            )
            raise ValueError(msg)
        return self

    def is_expired(self, now: datetime | None = None) -> bool:
        return (now or datetime.now(UTC)) >= self.expires_at

    def covers_subject(self, identifier: str) -> bool:
        """True when `identifier` falls inside this grant's subject pattern."""
        if self.subject_pattern.endswith("*"):
            return identifier.startswith(self.subject_pattern[:-1])
        return identifier == self.subject_pattern

    def permits(
        self,
        *,
        action: str,
        subject_kind: SubjectKind,
        subject_identifier: str,
        actor_id: str,
        context_id: str,
        now: datetime | None = None,
    ) -> bool:
        """The full check, in one place so no caller can perform a partial one.

        Deliberately returns a plain bool and takes every dimension as a required
        keyword: a caller cannot forget to check expiry or context, because there is
        no way to call this that skips them.
        """
        return (
            not self.is_expired(now)
            and self.action == action
            and self.subject_kind is subject_kind
            and self.actor_id == actor_id
            and self.context_id == context_id
            and self.covers_subject(subject_identifier)
        )
