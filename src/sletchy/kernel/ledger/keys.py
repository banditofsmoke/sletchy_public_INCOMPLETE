"""The ledger's signing key.

One rule dominates this module: **the read path never creates a key.**

A ledger that generates a key when it cannot find one would make every existing
entry fail verification while making every new entry verify perfectly. That is
exactly what a successful forgery looks like from the inside - so the two cases must
never be confused, and "key missing" is fatal rather than recoverable.

Key creation is a separate, explicit, operator-initiated act (`provision()`, reached
via `sletchy init` in #8), and it refuses to overwrite an existing key.
"""

from __future__ import annotations

import hmac
import os
import secrets
import sys
from hashlib import sha256
from typing import Protocol, runtime_checkable

from sletchy.kernel.ledger.errors import SigningKeyBackendUnavailable, SigningKeyMissing

KEY_BYTES = 32
_SERVICE = "sletchy"
_ACCOUNT = "ledger-signing-key"
#: A ledger's high-water mark lives beside the key: one per ledger folder (#99).
_MARK_ACCOUNT = "ledger-high-water-{}"


@runtime_checkable
class KeySource(Protocol):
    """Somewhere a signing key can be read from."""

    def get(self) -> bytes:
        """Return the key, or raise `SigningKeyMissing`. Never creates one."""
        ...


@runtime_checkable
class MarkStore(Protocol):
    """Somewhere outside `var/` that remembers how long a ledger has been (#99).

    A ledger cannot prove, from inside itself, that entries once followed its last one.
    The mark is `seq` and entry hash of the newest durable entry, written after each one.
    """

    def read_mark(self, ledger_id: str) -> tuple[int, str] | None:
        """The mark, None if there has never been one, or `ValueError` if unreadable."""
        ...

    def write_mark(self, ledger_id: str, seq: int, digest: str) -> None: ...


def mark_account(ledger_id: str) -> str:
    """The keychain account name a ledger's mark is stored under."""
    return _MARK_ACCOUNT.format(ledger_id)


def parse_mark(stored: str) -> tuple[int, str]:
    """`"<seq>:<entry hash>"`, or `ValueError`. A mark is never guessed at."""
    seq, _, digest = stored.partition(":")
    if not seq.isdigit() or len(digest) != 64 or digest.strip("0123456789abcdef"):
        msg = f"not a high-water mark: {stored[:80]!r}"
        raise ValueError(msg)
    return int(seq), digest


class KeyringKeySource:
    """The real source: the OS keychain (Windows Credential Manager via `keyring`).

    The key never touches a config file, an environment variable, or the repo. It is
    read on demand and held only for the duration of a signing call.
    """

    def __init__(self, service: str = _SERVICE, account: str = _ACCOUNT) -> None:
        self._service = service
        self._account = account

    def get(self) -> bytes:
        try:
            import keyring
        except ImportError as exc:  # pragma: no cover - dependency is declared
            msg = "keyring is not installed; the ledger cannot read its signing key"
            raise SigningKeyMissing(msg) from exc

        try:
            stored = keyring.get_password(self._service, self._account)
        except Exception as exc:
            # keyring raises its own exception types (NoKeyringError on a headless
            # host, backend-specific errors elsewhere). Letting those escape means
            # every caller has to know about a third-party hierarchy - and `sletchy
            # panic`, which must survive a broken host, would crash on exactly the
            # kind of machine it exists for.
            msg = (
                f"the OS keychain is unreachable ({type(exc).__name__}). Sletchy "
                "cannot verify or sign the ledger without it."
            )
            raise SigningKeyBackendUnavailable(msg) from exc

        if stored is None:
            msg = (
                f"no ledger signing key in the OS keychain ({self._service}/{self._account}). "
                "Run `sletchy init` to provision one. The ledger will not generate a key "
                "on read: a fresh key would make every existing entry unverifiable while "
                "making new entries look valid."
            )
            raise SigningKeyMissing(msg)
        return bytes.fromhex(stored)

    def provision(self, *, overwrite: bool = False) -> None:
        """Create a key. Explicit, operator-initiated, and not on any read path.

        Refuses to overwrite unless asked, because replacing the key invalidates
        every entry ever signed with the old one.
        """
        import keyring

        if not overwrite and keyring.get_password(self._service, self._account) is not None:
            msg = (
                "a ledger signing key already exists; overwriting it would make every "
                "existing entry unverifiable. Pass overwrite=True only if that is "
                "genuinely what you intend."
            )
            raise ValueError(msg)
        keyring.set_password(self._service, self._account, secrets.token_bytes(KEY_BYTES).hex())

    def read_mark(self, ledger_id: str) -> tuple[int, str] | None:
        import keyring

        try:
            stored = keyring.get_password(self._service, mark_account(ledger_id))
        except Exception as exc:
            msg = (
                f"the OS keychain is unreachable ({type(exc).__name__}), so the ledger's "
                "length cannot be checked"
            )
            raise SigningKeyBackendUnavailable(msg) from exc
        return None if stored is None else parse_mark(stored)

    def write_mark(self, ledger_id: str, seq: int, digest: str) -> None:
        import keyring

        keyring.set_password(self._service, mark_account(ledger_id), f"{seq}:{digest}")


class InMemoryKeySource:
    """A key held in memory. **Tests only.**

    Refuses to load outside a test run for the same reason the `inproc` isolation
    backend does: a convenience that bypasses a security boundary will eventually be
    reached for in production, and the cheapest place to stop that is at import.
    """

    def __init__(self, key: bytes | None = None) -> None:
        if "pytest" not in sys.modules and not os.environ.get("SLETCHY_ALLOW_INMEMORY_KEY"):
            msg = (
                "InMemoryKeySource is test-only and was constructed outside a test run. "
                "Use KeyringKeySource. If this is a deliberate offline verification of an "
                "exported chain, set SLETCHY_ALLOW_INMEMORY_KEY=1 explicitly."
            )
            raise RuntimeError(msg)
        self._key = key if key is not None else secrets.token_bytes(KEY_BYTES)
        self._marks: dict[str, str] = {}

    def get(self) -> bytes:
        return self._key

    def read_mark(self, ledger_id: str) -> tuple[int, str] | None:
        stored = self._marks.get(ledger_id)
        return None if stored is None else parse_mark(stored)

    def write_mark(self, ledger_id: str, seq: int, digest: str) -> None:
        self._marks[ledger_id] = f"{seq}:{digest}"


def sign(key: bytes, data: bytes) -> str:
    """HMAC-SHA256 of `data` under `key`, as lowercase hex."""
    return hmac.new(key, data, sha256).hexdigest()


def verify(key: bytes, data: bytes, signature: str) -> bool:
    """Constant-time signature check.

    `compare_digest` rather than `==`: a byte-by-byte comparison leaks, through
    timing, how much of a forged signature was correct, which turns forgery into a
    guided search instead of a brute-force one.
    """
    return hmac.compare_digest(sign(key, data), signature)
