"""The ledger entry - the shape of every recorded fact.

This module defines the *contract*, not the chain machinery (that is #2). What
matters here is that the shape makes tampering detectable and makes an entry
readable on its own.

Entries are small and fixed. Bodies - prompts, responses, artifacts - live in a
content-addressed side store and appear here only as `payload_hash`, so a sensitive
body can be deleted without breaking verification: the hash still commits, the body
is simply gone.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Self

from pydantic import Field, model_validator

from sletchy.kernel.contracts.base import ACTION_PATTERN, Contract, Hash, Name
from sletchy.kernel.contracts.identity import Plane, Subject
from sletchy.kernel.contracts.policy import Verdict

#: `prev_hash` of the first entry in a segment. All zeroes, so a genesis entry is
#: unmistakable and cannot be confused with a real digest.
GENESIS_PREV_HASH = "0" * 64


class LedgerEntry(Contract):
    """One append-only, hash-chained record.

    Every field is required except `payload_hash`. An entry that cannot say who did
    what, to what, and with what outcome is not worth appending.
    """

    #: Monotonic within a segment, starting at 0.
    seq: Annotated[int, Field(ge=0)]

    #: Wall clock, for humans. Timezone-aware, always.
    ts_wall: datetime
    #: Monotonic nanoseconds, for ordering. Survives clock changes, which wall does
    #: not - so this, not `ts_wall`, is the ordering authority.
    ts_mono: Annotated[int, Field(ge=0)]

    plane: Plane
    actor_id: Name
    action: Annotated[str, Field(pattern=ACTION_PATTERN)]
    subject: Subject
    verdict: Verdict

    #: Hash of the body in the content-addressed store, or None when there is none.
    payload_hash: Hash | None = None

    #: Hash of the preceding entry. GENESIS_PREV_HASH for seq 0 - which is 64 zeroes
    #: and therefore already a well-formed digest, so no union widening is needed
    #: here. A `Hash | str` union would silently disable validation on this field.
    prev_hash: Hash

    #: HMAC over this entry's canonical serialisation.
    signature: Hash

    @model_validator(mode="after")
    def _genesis_is_consistent(self) -> Self:
        """seq 0 and the genesis prev_hash imply each other.

        Without this, an attacker who truncates the chain could re-present entry N
        as a fresh genesis. Binding the two makes that shape invalid on its face.
        """
        is_genesis_seq = self.seq == 0
        is_genesis_hash = self.prev_hash == GENESIS_PREV_HASH
        if is_genesis_seq != is_genesis_hash:
            msg = (
                f"entry seq={self.seq} prev_hash={self.prev_hash[:12]}...: "
                "seq 0 must carry the genesis prev_hash, and only seq 0 may"
            )
            raise ValueError(msg)
        return self

    @model_validator(mode="after")
    def _timestamp_is_aware(self) -> Self:
        if self.ts_wall.tzinfo is None:
            msg = f"entry seq={self.seq}: ts_wall must be timezone-aware"
            raise ValueError(msg)
        return self

    @property
    def is_genesis(self) -> bool:
        return self.seq == 0
