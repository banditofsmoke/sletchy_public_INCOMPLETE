"""The ledger - Sletchy's spine.

Append-only, hash-chained, signed. Every decision, tool call, model call, egress
attempt, flag flip, and capability grant lands here **before** it takes effect.

Two properties this module exists to guarantee:

1. **Tamper-evidence.** Each entry commits to the hash of its predecessor, and that
   hash covers the predecessor's signature too. Editing, truncating, or reordering
   any entry breaks verification for every entry after it.
2. **No quiet recovery.** There is no repair function and none may be added. A
   ledger that fails verification halts Sletchy (LAW 0 §7).

See ADR-0003 for why this is the spine rather than a protocol.
"""

from sletchy.kernel.ledger.canonical import (
    CANONICAL_VERSION,
    content_hash,
    entry_bytes,
    entry_hash,
    signing_bytes,
)
from sletchy.kernel.ledger.chain import (
    DEFAULT_MAX_SEGMENT_BYTES,
    LOCK_WAIT_SECONDS,
    MAX_LEDGER_BYTES,
    MIN_FREE_BYTES,
    SEAL_ACTION,
    Ledger,
)
from sletchy.kernel.ledger.errors import (
    BadSignature,
    BrokenChain,
    LedgerBusy,
    LedgerCorrupt,
    LedgerError,
    LedgerFull,
    LedgerMissing,
    LedgerRolledBack,
    LedgerSealed,
    MalformedEntry,
    SequenceBroken,
    SigningKeyBackendUnavailable,
    SigningKeyMissing,
    TornFinalEntry,
)
from sletchy.kernel.ledger.keys import (
    InMemoryKeySource,
    KeyringKeySource,
    KeySource,
    MarkStore,
    sign,
    verify,
)
from sletchy.kernel.ledger.store import (
    DEFAULT_MAX_PAYLOAD_BYTES,
    MAX_PAYLOAD_STORE_BYTES,
    PayloadMissing,
    PayloadStore,
    PayloadStoreFull,
    PayloadTooLarge,
)

__all__ = [
    "CANONICAL_VERSION",
    "DEFAULT_MAX_PAYLOAD_BYTES",
    "DEFAULT_MAX_SEGMENT_BYTES",
    "LOCK_WAIT_SECONDS",
    "MAX_LEDGER_BYTES",
    "MAX_PAYLOAD_STORE_BYTES",
    "MIN_FREE_BYTES",
    "SEAL_ACTION",
    "BadSignature",
    "BrokenChain",
    "InMemoryKeySource",
    "KeySource",
    "KeyringKeySource",
    "Ledger",
    "LedgerBusy",
    "LedgerCorrupt",
    "LedgerError",
    "LedgerFull",
    "LedgerMissing",
    "LedgerRolledBack",
    "LedgerSealed",
    "MalformedEntry",
    "MarkStore",
    "PayloadMissing",
    "PayloadStore",
    "PayloadStoreFull",
    "PayloadTooLarge",
    "SequenceBroken",
    "SigningKeyBackendUnavailable",
    "SigningKeyMissing",
    "TornFinalEntry",
    "content_hash",
    "entry_bytes",
    "entry_hash",
    "sign",
    "signing_bytes",
    "verify",
]
