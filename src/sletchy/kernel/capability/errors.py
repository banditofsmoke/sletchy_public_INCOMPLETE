"""Capability failures.

Split finely on purpose. "The capability did not work" is not a useful audit line -
*expired*, *revoked*, *forged*, and *wrong context* are four very different events,
and only one of them is routine.

A forged or replayed capability is an attack signal the SOC should act on. An
expired one is a caller that needs to re-request. Collapsing them into one error
would throw away that distinction at exactly the point it is cheapest to keep.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sletchy.kernel.contracts import Verdict


class CapabilityError(Exception):
    """Base for every capability failure."""


class CapabilityDenied(CapabilityError):
    """Policy refused to grant. Carries the verdict so the caller can say why."""

    def __init__(self, verdict: Verdict) -> None:
        self.verdict = verdict
        super().__init__(f"policy refused to grant: {verdict.reason}")


class CapabilityInvalid(CapabilityError):
    """Base for a capability that exists but must not be honoured."""


class CapabilityExpired(CapabilityInvalid):
    """Past its expiry. Routine - the caller should request a fresh one."""


class CapabilityRevoked(CapabilityInvalid):
    """Explicitly revoked before its natural expiry."""


class CapabilityForged(CapabilityInvalid):
    """The signature does not verify.

    **Not routine.** Nothing legitimate produces this: it means either a tampered
    capability or one minted under a different key. Treat every occurrence as an
    attack signal.
    """


class CapabilityMismatch(CapabilityInvalid):
    """Genuine and unexpired, but presented for something it does not cover.

    A wrong `context_id` or `actor_id` specifically means **replay** - a real
    capability lifted from one execution and offered in another.
    """
