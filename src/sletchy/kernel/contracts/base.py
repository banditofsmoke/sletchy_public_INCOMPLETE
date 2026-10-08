"""The base every contract inherits, and the primitive types they share.

Two settings on `Contract` carry the weight, and neither is a style preference:

``extra="forbid"``
    An unknown field is an error, not something to ignore. LAW 2 (deny by default)
    applies to schemas as much as to egress: if a caller sends a field we do not
    recognise, we do not know what it meant, so we refuse. Silently dropping it is
    how a tightened policy quietly becomes a loose one.

``frozen=True``
    Contracts are values, not state. A `Capability` that can be mutated after a
    policy check is a capability that can be widened after a policy check.
"""

from __future__ import annotations

import re
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field

# ── primitives ───────────────────────────────────────────────────────────────

#: Lowercase hex SHA-256. The ledger chains on these, so the shape is pinned.
HASH_PATTERN = r"^[0-9a-f]{64}$"
Hash = Annotated[str, Field(pattern=HASH_PATTERN)]

#: `plane.noun.verb` - e.g. `warden.egress.request`, `kernel.flag.flip`.
#: Dots are the only separator so an action can be prefix-matched by policy.
ACTION_PATTERN = r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*){1,3}$"

#: Stable, human-readable identifier: an actor id, a flag name, a secret ref.
NAME_PATTERN = r"^[a-z][a-z0-9_-]{0,63}$"
Name = Annotated[str, Field(pattern=NAME_PATTERN)]

_HASH_RE = re.compile(HASH_PATTERN)


def is_hash(value: str) -> bool:
    """True when `value` is a well-formed lowercase hex SHA-256 digest."""
    return _HASH_RE.match(value) is not None


class Contract(BaseModel):
    """Base for every kernel contract.

    Subclasses are immutable and reject unknown fields. Both are load-bearing -
    see the module docstring.
    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        validate_default=True,
        use_enum_values=False,
    )
