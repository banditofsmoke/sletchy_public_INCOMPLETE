"""Ledger failures.

Each error names the *specific* thing that went wrong. A single generic
`LedgerError` would let a test assert "something raised" while the chain failed for
a different reason than the test intended - which is how a tamper test quietly stops
testing tampering.
"""

from __future__ import annotations


class LedgerError(Exception):
    """Base for every ledger failure."""


class SigningKeyMissing(LedgerError):
    """No signing key is available.

    Deliberately fatal. The ledger never generates a key on the read path: a fresh
    key would make every existing entry unverifiable while making every *new* entry
    look perfectly valid, which is indistinguishable from a successful forgery.
    """


class SigningKeyBackendUnavailable(SigningKeyMissing):
    """The OS keychain itself cannot be reached.

    A subclass of `SigningKeyMissing` because every caller that must fail closed on
    a missing key must also fail closed on an unreachable one - but distinct,
    because "the vault is locked" and "the vault lacks this" call for different
    operator responses. Raised on a headless CI runner with no keyring backend, and
    on a host whose credential service is broken.
    """


class LedgerMissing(LedgerError):
    """There is no ledger here, and the caller asked not to create one.

    Not corruption - there was nothing to verify. A read command run from the wrong
    folder used to create an empty ledger there and report it as "0 entries, chain
    verified", beside the real one (#102). Read paths now open with `create=False`
    and say Sletchy is not set up where they looked.
    """


class LedgerCorrupt(LedgerError):
    """Verification failed. Carries the sequence number where it broke."""

    def __init__(self, message: str, *, seq: int | None = None) -> None:
        self.seq = seq
        location = f" at seq={seq}" if seq is not None else ""
        super().__init__(f"{message}{location}")


class LedgerRolledBack(LedgerCorrupt):
    """The ledger is shorter than, or different from, what the keychain says it was (#99).

    Cutting entries off the end leaves a chain that verifies on its own terms; only a
    record kept outside it can show entries once followed. That record lives beside the
    signing key, so cutting history now needs the same keychain access as forging it.
    """


class BrokenChain(LedgerCorrupt):
    """An entry's `prev_hash` does not match the hash of its predecessor."""


class BadSignature(LedgerCorrupt):
    """An entry's signature does not verify under the current key."""


class SequenceBroken(LedgerCorrupt):
    """Sequence numbers are not contiguous and ascending from 0."""


class MalformedEntry(LedgerCorrupt):
    """A stored line is not a valid `LedgerEntry`."""


class TornFinalEntry(MalformedEntry):
    """A segment's last line has no line ending: the write of it never finished (#98).

    Every write ends its line, so this is what a crash or a power cut part-way through
    an append leaves - and also what someone cutting the file leaves, so it is still
    corruption, and Sletchy still refuses to run and still repairs nothing (LAW 1). It is
    reported as its own thing because the operator's next step is different: the entry
    being written never finished, so the action it would have recorded never happened.
    """


class LedgerBusy(LedgerError):
    """Another Sletchy process held the write lock for longer than this one would wait.

    Raised by `append()`, so the action it would have recorded does not happen (LAW 1).
    The lock is the operating system's and dies with its holder, so this means a writer
    is alive and busy, never that one crashed and left a lock behind (#95).
    """


class LedgerFull(LedgerError):
    """The ledger may not grow any further, so nothing more may happen (#101).

    Raised by `append()` before anything is written, so the action it would have
    recorded does not happen (LAW 1). Two ceilings: the ledger's own size (LAW 0
    section 5), and the free space left on its drive, so Sletchy never fills the disk.
    """


class LedgerSealed(LedgerError):
    """Attempted to append to a segment that has already been sealed."""
