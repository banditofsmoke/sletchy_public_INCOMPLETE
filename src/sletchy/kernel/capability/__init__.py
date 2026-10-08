"""Capabilities - short-lived, scoped, signed grants.

A policy check that happens once and is then assumed is ambient authority.
Capabilities make the check happen **at the moment of use**, and make the grant
expire on its own.

Three properties, each enforced structurally rather than by discipline:

1. **No self-grant.** `CapabilityIssuer.issue()` requires a `PolicyGate` and mints
   only on ALLOW. There is no function an actor can call to authorise itself.
2. **One grant, one action, one subject kind.** If it needs an "and", it is two
   capabilities - so a capability can be read and understood on its own.
3. **Revocation is immediate**, and is a ledger entry rather than a side file, so
   the revocation record and the audit record cannot disagree.
"""

from sletchy.kernel.capability.canonical import (
    CAPABILITY_CANONICAL_VERSION,
    signing_bytes,
)
from sletchy.kernel.capability.errors import (
    CapabilityDenied,
    CapabilityError,
    CapabilityExpired,
    CapabilityForged,
    CapabilityInvalid,
    CapabilityMismatch,
    CapabilityRevoked,
)
from sletchy.kernel.capability.issuer import (
    CAPABILITY_KEY_ACCOUNT,
    ISSUE_ACTION,
    CapabilityIssuer,
)
from sletchy.kernel.capability.revocation import REVOKE_ACTION, RevocationList
from sletchy.kernel.capability.verifier import USE_ACTION, CapabilityVerifier

__all__ = [
    "CAPABILITY_CANONICAL_VERSION",
    "CAPABILITY_KEY_ACCOUNT",
    "ISSUE_ACTION",
    "REVOKE_ACTION",
    "USE_ACTION",
    "CapabilityDenied",
    "CapabilityError",
    "CapabilityExpired",
    "CapabilityForged",
    "CapabilityInvalid",
    "CapabilityIssuer",
    "CapabilityMismatch",
    "CapabilityRevoked",
    "CapabilityVerifier",
    "RevocationList",
    "signing_bytes",
]
