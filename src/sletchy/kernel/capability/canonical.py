"""Canonical byte form of a capability.

Same reasoning as the ledger's canonical form: signing and verification must agree
on exactly which bytes represent a capability, and that agreement must not depend on
a third-party library's serialisation staying stable.

Built explicitly, field by field. Every field except the signature is covered - a
field outside the signature is a field an attacker can change for free.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sletchy.kernel.contracts import Capability

#: Bumped only when the canonical form changes. A capability carrying an unknown
#: version fails to verify rather than being read under the wrong schema.
CAPABILITY_CANONICAL_VERSION = 1


def signing_bytes(capability: Capability) -> bytes:
    """The bytes a capability's signature is computed over.

    Covers every field except `signature` itself. Notably it includes `actor_id`
    and `context_id`, which is what makes a lifted capability useless in another
    execution: changing either invalidates the signature rather than merely failing
    a comparison that someone might later be tempted to relax.
    """
    pairs = [
        ("v", CAPABILITY_CANONICAL_VERSION),
        ("id", capability.id),
        ("action", capability.action),
        ("subject_kind", capability.subject_kind.value),
        ("subject_pattern", capability.subject_pattern),
        ("actor_id", capability.actor_id),
        ("context_id", capability.context_id),
        ("issued_at", capability.issued_at.isoformat()),
        ("expires_at", capability.expires_at.isoformat()),
    ]
    return json.dumps(pairs, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode(
        "ascii"
    )
