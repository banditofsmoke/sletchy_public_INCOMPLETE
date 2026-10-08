"""Content-addressed storage for the bodies the chain only hashes.

Chain entries are verified on every startup, so they must stay small and
fixed-shape. Prompts, responses, and artifacts are neither. Keeping them here,
addressed by the SHA-256 of their content, buys a property worth having on its own:

**A body can be destroyed and the chain still verifies.** The entry commits to
`payload_hash`, not to the bytes - so the record that something happened survives
the deletion of what was said. That is what makes "forget this conversation" a real
operation rather than a promise.

Two rules shape the API:

- **The store computes hashes; it never accepts one.** There is no `put(hash, data)`.
  A caller that could name the address of content it did not supply could associate
  a ledger entry with a body someone else wrote.
- **Writes are atomic.** Content is written to a temp file, fsynced, then renamed
  into place, so a crash mid-write cannot leave a torn object readable under its
  final hash. A half-written payload that verifies is worse than a missing one.
- **The store has a ceiling, and never fills the disk** (LAW 0 section 5). Each body
  is capped, the whole store is capped, and nothing is written that would leave the
  drive below the same free-space floor the ledger keeps. Every check runs before a
  byte is written.
"""

from __future__ import annotations

import os
import shutil
from typing import TYPE_CHECKING

from sletchy.kernel.ledger.canonical import content_hash
from sletchy.kernel.ledger.chain import MIN_FREE_BYTES
from sletchy.kernel.ledger.errors import LedgerError

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

#: Refuse anything larger. A single runaway payload should not be able to fill the
#: disk, and the cap is checked *before* any bytes are written.
DEFAULT_MAX_PAYLOAD_BYTES = 32 * 1024 * 1024

#: LAW 0 section 5: everything under `var/` stays within 5 GB. The ledger may take 1 GB
#: (#101); the payloads take at most this, which leaves 1 GB for everything else
#: Sletchy keeps there. Before this there was no total at all: a stream of sandbox
#: runs, each under the per-body cap, could fill the disk.
MAX_PAYLOAD_STORE_BYTES = 3 * 1024**3


class PayloadTooLarge(LedgerError):
    """Content exceeds the configured cap. Nothing was written."""


class PayloadStoreFull(LedgerError):
    """The store is at its ceiling, or the drive is at its floor. Nothing was written."""


class PayloadMissing(LedgerError):
    """No content stored under that hash.

    Distinguishable from a generic lookup failure on purpose: a payload deleted by
    a forget operation is expected, and a caller should be able to tell that apart
    from a bug.
    """


class PayloadStore:
    """Content-addressed blob storage under a single directory."""

    __slots__ = ("_max_bytes", "_max_total", "_min_free", "_root", "_total")

    def __init__(
        self,
        root: Path,
        *,
        max_bytes: int = DEFAULT_MAX_PAYLOAD_BYTES,
        max_total_bytes: int = MAX_PAYLOAD_STORE_BYTES,
        min_free_bytes: int = MIN_FREE_BYTES,
    ) -> None:
        self._root = root
        self._max_bytes = max_bytes
        self._max_total = max_total_bytes
        self._min_free = min_free_bytes
        # Counted from disk on the first write, not on open: opening is on every
        # command's path, and only the writer needs the figure.
        self._total: int | None = None

    @classmethod
    def open(
        cls,
        root: Path,
        *,
        max_bytes: int = DEFAULT_MAX_PAYLOAD_BYTES,
        max_total_bytes: int = MAX_PAYLOAD_STORE_BYTES,
        min_free_bytes: int = MIN_FREE_BYTES,
    ) -> PayloadStore:
        root.mkdir(parents=True, exist_ok=True)
        return cls(
            root,
            max_bytes=max_bytes,
            max_total_bytes=max_total_bytes,
            min_free_bytes=min_free_bytes,
        )

    def put(self, data: bytes) -> str:
        """Store content and return its hash.

        Idempotent: storing identical content twice writes one copy and returns the
        same hash. There is deliberately no way to supply the hash - see the module
        docstring.
        """
        if len(data) > self._max_bytes:
            msg = (
                f"payload is {len(data)} bytes, over the {self._max_bytes} cap. "
                "Nothing was written."
            )
            raise PayloadTooLarge(msg)

        digest = content_hash(data)
        path = self._path(digest)
        if path.exists():
            return digest  # already stored: no room needed, so never refused

        self._ensure_room(len(data))
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".tmp")
        with tmp.open("wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        tmp.replace(path)
        self._total = (self._total or 0) + len(data)
        return digest

    def _ensure_room(self, nbytes: int) -> None:
        """Refuse, before writing, a body past the store's ceiling or the drive's floor."""
        try:
            free = shutil.disk_usage(self._root).free
        except OSError as exc:
            # Could not look is not "plenty of room" (L009).
            msg = f"could not read the free space on the drive holding {self._root}: {exc}"
            raise PayloadStoreFull(msg) from exc
        if free - nbytes < self._min_free:
            msg = (
                f"only {_size(free)} free on the drive holding the payloads. Sletchy stops "
                f"writing below {_size(self._min_free)} so it never fills the disk. Nothing "
                "was written"
            )
            raise PayloadStoreFull(msg)
        if self._total is None:
            self._total = self.total_bytes()
        if self._total + nbytes > self._max_total:
            msg = (
                f"the payload store has reached its ceiling of {_size(self._max_total)} "
                "(LAW 0 section 5). Nothing was written"
            )
            raise PayloadStoreFull(msg)

    def get(self, digest: str) -> bytes:
        """Read content back, or raise `PayloadMissing`."""
        try:
            return self._path(digest).read_bytes()
        except OSError as exc:
            msg = f"no payload stored under {digest[:12]}..."
            raise PayloadMissing(msg) from exc

    def has(self, digest: str) -> bool:
        return self._path(digest).exists()

    def delete(self, digest: str) -> bool:
        """Forget a body. The chain still verifies afterwards.

        Returns whether anything was removed, so a caller can report honestly
        instead of claiming a deletion that was a no-op.
        """
        path = self._path(digest)
        if not path.exists():
            return False
        size = path.stat().st_size
        path.unlink()
        if self._total is not None:
            self._total = max(0, self._total - size)
        return True

    def digests(self) -> Iterator[str]:
        for shard in sorted(self._root.iterdir()) if self._root.exists() else []:
            if shard.is_dir():
                for path in sorted(shard.iterdir()):
                    if path.suffix != ".tmp":
                        yield shard.name + path.name

    def collect_garbage(self, referenced: set[str]) -> int:
        """Remove payloads no live ledger entry references.

        Takes the referenced set explicitly rather than scanning the ledger itself:
        the store must not depend on the chain, and a caller that gets the set wrong
        deletes its own data rather than silently corrupting someone else's view.
        """
        removed = 0
        for digest in list(self.digests()):
            if digest not in referenced:
                removed += int(self.delete(digest))
        return removed

    def total_bytes(self) -> int:
        return sum(self._path(d).stat().st_size for d in self.digests())

    def _path(self, digest: str) -> Path:
        # Two-character shard prefix keeps any one directory from growing to tens of
        # thousands of entries, which several filesystems handle badly.
        return self._root / digest[:2] / digest[2:]


def _size(nbytes: int) -> str:
    return f"{nbytes / 1024**3:.1f} GB" if nbytes >= 1024**3 else f"{nbytes / 1024**2:.1f} MB"
