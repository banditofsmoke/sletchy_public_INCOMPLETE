"""Canonical byte form of a ledger entry.

Signing and hashing must agree on *exactly* which bytes represent an entry, forever.
If that representation ever shifts - a field reordered, a datetime formatted
differently, a Pydantic upgrade changing its dump - every previously signed entry
stops verifying, and the ledger halts Sletchy.

So the canonical form is built here **explicitly**, field by field, in a fixed order.
It deliberately does not use `model_dump_json()`: that would make the chain's
integrity depend on a third-party library's serialisation staying byte-stable across
versions, which is not a promise Pydantic makes and not one we should rely on.

Two forms:

- `signing_bytes` - everything except the signature. This is what gets HMAC'd.
- `entry_bytes` - everything *including* the signature. This is what gets hashed
  into the next entry's `prev_hash`, so the chain commits to signatures too. Without
  that, an attacker could swap a valid entry's signature for another valid one and
  the chain would not notice.
"""

from __future__ import annotations

import hashlib
import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sletchy.kernel.contracts import LedgerEntry

#: Bumped only when the canonical form changes shape. A stored entry carrying an
#: unknown version is a hard failure, never a best-effort parse.
CANONICAL_VERSION = 1


def _fields(entry: LedgerEntry) -> list[tuple[str, object]]:
    """The signed fields, in fixed order.

    A list of pairs rather than a dict, so the order is the code's own and does not
    depend on dict insertion semantics or on anyone's `sort_keys`.
    """
    return [
        ("v", CANONICAL_VERSION),
        ("seq", entry.seq),
        # isoformat() on a timezone-aware datetime is stable and round-trips.
        ("ts_wall", entry.ts_wall.isoformat()),
        ("ts_mono", entry.ts_mono),
        ("plane", entry.plane.value),
        ("actor_id", entry.actor_id),
        ("action", entry.action),
        ("subject_kind", entry.subject.kind.value),
        ("subject_id", entry.subject.identifier),
        ("decision", entry.verdict.decision.value),
        ("reason", entry.verdict.reason),
        ("rule_id", entry.verdict.rule_id),
        ("payload_hash", entry.payload_hash),
        ("prev_hash", entry.prev_hash),
    ]


def _encode(pairs: list[tuple[str, object]]) -> bytes:
    """Compact, ASCII-escaped JSON array of pairs.

    `ensure_ascii=True` matters: it means a non-ASCII character in a reason string
    produces the same bytes regardless of the host's filesystem or locale encoding.
    """
    return json.dumps(
        pairs,
        ensure_ascii=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii")


def signing_bytes(entry: LedgerEntry) -> bytes:
    """The bytes an entry's signature is computed over. Excludes the signature."""
    return _encode(_fields(entry))


def entry_bytes(entry: LedgerEntry) -> bytes:
    """The bytes an entry hashes to. Includes the signature."""
    return _encode([*_fields(entry), ("signature", entry.signature)])


def entry_hash(entry: LedgerEntry) -> str:
    """SHA-256 of the full entry, as lowercase hex.

    This is what the *next* entry carries as `prev_hash`.
    """
    return hashlib.sha256(entry_bytes(entry)).hexdigest()


def content_hash(data: bytes) -> str:
    """SHA-256 of arbitrary content, as lowercase hex. Used for `payload_hash`."""
    return hashlib.sha256(data).hexdigest()
