"""The hash-chained, signed, append-only ledger.

The whole of LAW 1 rests on one structural choice: **`append()` computes `prev_hash`
itself from stored state.** A caller cannot supply it, cannot skip it, and has no
other way to write. There is no "raw write" helper, no bulk-import path, and no
debug mode that bypasses signing - because every one of those, once it exists, is
the path a hurried change will take.

There is also **no repair function**, permanently. See `verify()`.

Durability note: `append()` fsyncs. Every entry is on disk before the call returns,
which is what lets a caller gate an action on it (LAW 1). That costs ~30 ms on this
host - the disk, not the code - so a burst of already-decided facts can be recorded
through `batch()`, which fsyncs once at the end. **`batch()` must never be used to
gate an action**; see its docstring.

One writer at a time (#95): every append, seal and batch holds an operating-system
lock on `ledger.lock` beside the segments, and before writing it checks that the last
entry on disk is the last one this object knows. If another process appended in the
meantime, the chain is verified again and the append continues from what is really
there. Two `Ledger` objects used to append from their own stale snapshots: both wrote
`seq=0`, and the forked chain never verified again. Reads take no lock.

Ordering note: `seq` is the ordering authority. `ts_mono` is recorded for
intra-run forensics (it detects wall-clock manipulation *within* a process) but is
deliberately not asserted across the chain, because a process restart legitimately
resets the monotonic clock. Asserting it would make a normal restart look like
tampering, which is the worst possible false positive for an audit log.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import sys
import time
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from pydantic import ValidationError

from sletchy.kernel.contracts import (
    GENESIS_PREV_HASH,
    LedgerEntry,
    Plane,
    Subject,
    SubjectKind,
    Verdict,
)
from sletchy.kernel.contracts.policy import Decision
from sletchy.kernel.ledger.canonical import content_hash, entry_hash, signing_bytes
from sletchy.kernel.ledger.errors import (
    BadSignature,
    BrokenChain,
    LedgerBusy,
    LedgerFull,
    LedgerMissing,
    LedgerRolledBack,
    LedgerSealed,
    MalformedEntry,
    SequenceBroken,
    TornFinalEntry,
)
from sletchy.kernel.ledger.keys import KeySource, MarkStore, mark_account, sign, verify

if TYPE_CHECKING:
    from collections.abc import Iterator
    from typing import BinaryIO, TextIO

#: Rotate at 4 MB (#116). An ordinary open checks a sealed segment by its fingerprint and
#: parses only the active one, so this is the knob on how slow a cold start can get:
#: about 8,500 entries at 0.11 ms each, measured. It was 500 MB, a million entries.
DEFAULT_MAX_SEGMENT_BYTES = 4 * 1024 * 1024

SEAL_ACTION = "kernel.ledger.seal"
_SEGMENT_GLOB = "segment-*.ndjson"

#: How long an append waits for another Sletchy process to finish writing. A writer
#: holds the lock for one append (about 30 ms, the fsync) or one batch.
LOCK_WAIT_SECONDS = 5.0
_LOCK_NAME = "ledger.lock"
_LOCK_POLL_SECONDS = 0.01

#: LAW 0 section 5: the most disk the ledger may take (#101, my decision, 2026-10-03). About two
#: million entries at the 490 bytes one measured: years of ordinary use, and under a day
#: of a hostile loop, which is what it is for.
MAX_LEDGER_BYTES = 1024**3
#: Never write if it would leave the drive with less than this free (#101).
MIN_FREE_BYTES = 2 * 1024**3
#: Past the ceiling, an entry that makes Sletchy safer - switching something off, a
#: reset, panic, a seal - may still use this much, so stopping can always be recorded.
#: It never overrides MIN_FREE_BYTES.
SAFER_RESERVE_BYTES = 16 * 1024**2
#: How much of a segment's end is read at a time to find its last line. An entry is
#: about 490 bytes, so one block nearly always holds it.
_TAIL_BLOCK = 4096


def _torn(path: Path, complete: int) -> str:
    """What an unfinished last write is, in the words the operator needs (#98)."""
    return (
        f"the last write to {path.name} did not finish: its final line is cut off, after "
        f"{complete} complete entries in that file. A crash or power cut while writing "
        "leaves this, and so does someone cutting the file. The entry being written never "
        "finished, so what it would have recorded never happened. To go on, restore "
        "var/ledger from a copy, or move that last line out of the file by hand and keep it"
    )


#: What `full()` asks room for: a little more than a measured entry (490 bytes).
_TYPICAL_ENTRY_BYTES = 1024


def _size_of(entry: LedgerEntry) -> int:
    return len(entry.model_dump_json().encode("utf-8")) + 1


def _size(nbytes: int) -> str:
    return f"{nbytes / 1024**3:.1f} GB" if nbytes >= 1024**3 else f"{nbytes / 1024**2:.1f} MB"


def _segment_path(root: Path, index: int) -> Path:
    return root / f"segment-{index:05d}.ndjson"


def _segment_index(path: Path) -> int:
    return int(path.stem.split("-")[1])


class Ledger:
    """An append-only, hash-chained, signed record of everything that happened.

    Construct with `Ledger.open()`, which verifies before returning. A `Ledger`
    object that exists is one whose chain verified.
    """

    def __init__(
        self,
        root: Path,
        key_source: KeySource,
        *,
        max_segment_bytes: int = DEFAULT_MAX_SEGMENT_BYTES,
        lock_wait: float = LOCK_WAIT_SECONDS,
        max_bytes: int | None = None,
        min_free_bytes: int | None = None,
    ) -> None:
        self._root = root
        self._lock_wait = lock_wait
        # Read at construction, not as default arguments, so a ceiling is one constant.
        self._max_bytes = MAX_LEDGER_BYTES if max_bytes is None else max_bytes
        self._min_free = MIN_FREE_BYTES if min_free_bytes is None else min_free_bytes
        #: Bytes in every segment on disk, and bytes buffered by a batch not yet written.
        self._size = 0
        self._pending = 0
        #: Where this ledger's length is remembered outside `var/` (#99), and which ledger
        #: this is: one mark per folder, so a second `SLETCHY_HOME` keeps its own.
        self._marks = key_source if isinstance(key_source, MarkStore) else None
        self._mark_id = hashlib.sha256(str(root.resolve()).lower().encode("utf-8")).hexdigest()[:16]
        #: How many entries the mark lags the chain by, as of the last verify. Normally 0;
        #: a mark that could not be written leaves it above 0, and `status` says so.
        self.mark_behind = 0
        #: The lock file, held open once used; locked only while writing.
        self._lock_file: BinaryIO | None = None
        self._lock_depth = 0
        self._keys = key_source
        self._max_segment_bytes = max_segment_bytes
        self._last: LedgerEntry | None = None
        self._next_seq = 0
        self._segment = 0
        #: Held open across appends. Opening a file per append cost ~40% of the
        #: write time on NTFS; the handle is reopened on segment rotation.
        self._handle: TextIO | None = None
        self._handle_path: Path | None = None
        #: When set, appends buffer here instead of writing. See `batch()`.
        self._buffer: list[LedgerEntry] | None = None

    # ── lifecycle ────────────────────────────────────────────────────────────

    @classmethod
    def open(
        cls,
        root: Path,
        key_source: KeySource,
        *,
        max_segment_bytes: int = DEFAULT_MAX_SEGMENT_BYTES,
        lock_wait: float = LOCK_WAIT_SECONDS,
        create: bool = True,
        max_bytes: int | None = None,
        min_free_bytes: int | None = None,
    ) -> Ledger:
        """Open and **verify before returning**.

        A corrupt chain raises. It is not repaired, not truncated to the last good
        entry, and not started fresh alongside the old one.

        `create=False` is for every path that only reads, or that acts on a ledger it
        expects to exist: a missing ledger raises `LedgerMissing` instead of becoming
        an empty one (#102). Only setting Sletchy up creates a ledger.
        """
        if not create and not root.exists():
            msg = (
                f"Sletchy is not set up here: there is no ledger at {root}. Run "
                "`sletchy init` to set it up in this folder, or set SLETCHY_HOME to the "
                "folder Sletchy lives in"
            )
            raise LedgerMissing(msg)
        root.mkdir(parents=True, exist_ok=True)
        ledger = cls(
            root,
            key_source,
            max_segment_bytes=max_segment_bytes,
            lock_wait=lock_wait,
            max_bytes=max_bytes,
            min_free_bytes=min_free_bytes,
        )
        ledger._load()
        return ledger

    def _load(self) -> None:
        """Check the chain and take its end as the point to append from.

        Reads the chain once (#116). It used to verify every entry and then parse every
        entry again to find the last one, on every command and every click.

        The end is the last entry that check read, never a second look at the file
        (#149). A second look, without the write lock, could see an entry another
        process appended in between, and a healthy chain was called `SequenceBroken`:
        twice in eight full test runs on one busy day.
        """
        checked, self._last = self._read_once()
        self._next_seq = 0 if self._last is None else self._last.seq + 1
        if self._next_seq != checked:
            msg = f"the chain checks to {checked} entries but ends at seq={self._next_seq - 1}"
            raise SequenceBroken(msg, seq=self._next_seq - 1)
        self._segment = self._active_segment_index()
        self._size = sum(path.stat().st_size for path in self._segments())

    @property
    def length(self) -> int:
        """How many entries the chain holds: the open checked them, and appends since."""
        return self._next_seq

    # ── writing ──────────────────────────────────────────────────────────────

    def append(
        self,
        *,
        plane: Plane,
        actor_id: str,
        action: str,
        subject: Subject,
        verdict: Verdict,
        payload_hash: str | None = None,
        safer: bool = False,
    ) -> LedgerEntry:
        """Append one entry. The only write path there is.

        `seq`, `prev_hash`, and `signature` are computed here from stored state.
        None of them is accepted from the caller - that is what makes "nothing
        happens off-ledger" structural rather than aspirational.

        Raises `LedgerBusy` if another process holds the write lock for longer than
        `lock_wait`; nothing is written, so the action this would gate must not run.

        Raises `LedgerFull` past the ceiling or below the free-space floor (#101), again
        before anything is written. `safer=True` is for an entry that makes Sletchy
        safer - switching something off, a reset - which may use a small reserve past
        the ceiling, never past the floor, so stopping can always be recorded.
        """
        with self._writing():
            if self._is_sealed(self._segment):
                msg = f"segment {self._segment} is sealed; rotate before appending"
                raise LedgerSealed(msg)

            # Rotation comes before this entry, not after it: sealing checks the segment
            # (#116), and a problem found then must refuse this entry, not report a
            # failure after it is already durable (#104). Skipped inside a batch, whose
            # entries are not on disk yet. A seal with no room waits for one (#101).
            if (
                self._buffer is None
                and self._active_path().exists()
                and self._active_path().stat().st_size >= self._max_segment_bytes
                and self.full(safer=True) is None
            ):
                self._seal()

            entry = self._build(
                plane=plane,
                actor_id=actor_id,
                action=action,
                subject=subject,
                verdict=verdict,
                payload_hash=payload_hash,
            )
            self._ensure_room(_size_of(entry), safer=safer)
            self._write(entry)
        return entry

    def seal(self) -> LedgerEntry:
        """Close the active segment with a terminal entry committing to its whole hash.

        The seal is an ordinary entry - same shape, same signature, same chaining -
        so nothing special has to be trusted about it. The next segment's first
        entry chains from the seal, which is what carries the chain across the file
        boundary.
        """
        with self._writing():
            return self._seal()

    def _seal(self) -> LedgerEntry:
        path = self._active_path()
        # Every entry is checked before the seal commits to them (#116). An ordinary open
        # trusts a sealed segment's fingerprint, so a seal must never commit to bytes that
        # were changed while the segment was still active.
        if path.exists():
            previous = _segment_path(self._root, self._segment - 1)
            prev = self._tail_entry(previous) if self._segment > 0 else None
            key = self._keys.get()
            for written in self._read_segment(path):
                self._check_entry(written, prev, key)
                prev = written
        digest = content_hash(path.read_bytes() if path.exists() else b"")

        entry = self._build(
            plane=Plane.KERNEL,
            actor_id="kernel",
            action=SEAL_ACTION,
            subject=Subject(kind=SubjectKind.LEDGER, identifier=path.name),
            verdict=Verdict(
                decision=Decision.ALLOW,
                reason=f"segment sealed at seq={self._next_seq}",
                rule_id=None,
            ),
            payload_hash=digest,
        )
        self._ensure_room(_size_of(entry), safer=True)
        self._write(entry)
        self._segment += 1
        self.close()  # the next append opens the new segment
        return entry

    # ── room (#101) ──────────────────────────────────────────────────────────

    def full(self, *, safer: bool = False) -> str | None:
        """Why an entry of ordinary size would be refused now, or None if it would not.

        What `status` and the window show, so a full ledger is said plainly before the
        next action is refused.
        """
        try:
            self._ensure_room(_TYPICAL_ENTRY_BYTES, safer=safer)
        except LedgerFull as exc:
            return str(exc)
        return None

    def _ensure_room(self, nbytes: int, *, safer: bool) -> None:
        """Refuse, before writing, an entry past the ceiling or below the floor."""
        try:
            free = shutil.disk_usage(self._root).free
        except OSError as exc:
            # Could not look is not "plenty of room" (L009).
            msg = f"could not read the free space on the drive holding {self._root}: {exc}"
            raise LedgerFull(msg) from exc
        if free - nbytes < self._min_free:
            msg = (
                f"only {_size(free)} free on the drive holding the ledger. Sletchy stops "
                f"writing below {_size(self._min_free)} so it never fills the disk; nothing "
                "was recorded, so nothing was done"
            )
            raise LedgerFull(msg)
        limit = self._max_bytes + (SAFER_RESERVE_BYTES if safer else 0)
        if self._size + self._pending + nbytes > limit:
            if safer:
                msg = (
                    f"the ledger is past its {_size(self._max_bytes)} ceiling and the reserve "
                    "kept for switching things off is used up too. Nothing was recorded"
                )
            else:
                msg = (
                    f"the ledger has reached its ceiling of {_size(self._max_bytes)} (LAW 0 "
                    "section 5). Nothing was recorded, so nothing was done. Switching things "
                    "off and Stop everything still work"
                )
            raise LedgerFull(msg)

    # ── reading and verifying ────────────────────────────────────────────────

    def entries(self) -> Iterator[LedgerEntry]:
        """Every entry, in order, across every segment."""
        for path in self._segments():
            yield from self._read_segment(path)

    def verify(self) -> int:
        """Verify every entry of the entire chain. Returns the number checked.

        What `sletchy ledger verify` runs. An ordinary open checks a sealed segment by
        the fingerprint its seal signed instead (#116), which catches the same changes;
        this re-checks every signature as well.

        **There is deliberately no counterpart to this that fixes anything.** No
        repair, no rebuild, no truncate-to-last-valid. A quietly repaired audit log
        is worse than no audit log: it presents forged history with the same
        confidence as real history. On failure Sletchy stops and says where.
        """
        key = self._keys.get()
        mark = self._read_mark()
        marked: str | None = None
        prev: LedgerEntry | None = None
        count = 0

        for entry in self.entries():
            self._check_entry(entry, prev, key)
            if mark is not None and entry.seq == mark[0]:
                marked = entry_hash(entry)
            prev = entry
            count += 1

        self._check_mark(mark, count, marked)
        return count

    def _check_entry(self, entry: LedgerEntry, prev: LedgerEntry | None, key: bytes) -> None:
        """One link: its `seq`, its `prev_hash` and its signature."""
        expected_seq = 0 if prev is None else prev.seq + 1
        if entry.seq != expected_seq:
            msg = f"expected seq={expected_seq}, found seq={entry.seq}"
            raise SequenceBroken(msg, seq=entry.seq)

        expected_prev = GENESIS_PREV_HASH if prev is None else entry_hash(prev)
        if entry.prev_hash != expected_prev:
            msg = (
                f"prev_hash {entry.prev_hash[:12]}... does not match the hash of "
                f"entry {expected_seq - 1} ({expected_prev[:12]}...)"
            )
            raise BrokenChain(msg, seq=entry.seq)

        if not verify(key, signing_bytes(entry), entry.signature):
            msg = "signature does not verify"
            raise BadSignature(msg, seq=entry.seq)

    # ── what an ordinary open checks (#116) ──────────────────────────────────

    def _read_once(self) -> tuple[int, LedgerEntry | None]:
        """One consistent read of the chain: how many entries, and the last (#149).

        Without the write lock, a last line can be cut off because another process is
        writing it at that moment. That is not a crash, and calling it `TornFinalEntry`
        would raise a false alarm. So a cut-off last line is read again **holding the
        write lock**, when no append can be in flight: if it is still cut off, it is a
        real one, reported as before. Waiting for the lock is bounded by `lock_wait`,
        and raises `LedgerBusy`, as an append would. Holding the lock already, there is
        nothing to wait for.
        """
        try:
            return self._check_on_open()
        except TornFinalEntry:
            if self._lock_depth:
                raise
        self._acquire()
        self._lock_depth = 1
        try:
            return self._check_on_open()
        finally:
            self._lock_depth = 0
            self._release()

    def _check_on_open(self) -> tuple[int, LedgerEntry | None]:
        """Check the chain the way every open does. Returns how many entries, and the last.

        The active segment is checked entry by entry, as `verify()` does. A sealed one
        is read once, as bytes: their SHA-256 must be the fingerprint its seal signed,
        and its first entry and its seal are checked as links. Changing, removing or
        reordering anything inside it changes the fingerprint, and the seal cannot be
        re-signed without the key - so this catches what `verify()` catches, at a
        fraction of the cost (#116). A sealed segment the keychain mark points inside
        is still checked entry by entry, to find the marked entry.
        """
        key = self._keys.get()
        mark = self._read_mark()
        marked: str | None = None
        prev: LedgerEntry | None = None
        count = 0
        for path in self._segments():
            ends = self._fingerprinted(path, prev, key)
            if ends is not None:
                first, seal = ends
                if mark is not None and first.seq <= mark[0] < seal.seq:
                    ends = None
                elif mark is not None and mark[0] == seal.seq:
                    marked = entry_hash(seal)
            if ends is None:
                for entry in self._read_segment(path):
                    self._check_entry(entry, prev, key)
                    if mark is not None and entry.seq == mark[0]:
                        marked = entry_hash(entry)
                    prev = entry
                    count += 1
                continue
            prev = ends[1]
            count = ends[1].seq + 1
        self._check_mark(mark, count, marked)
        return count, prev

    def _fingerprinted(
        self, path: Path, prev: LedgerEntry | None, key: bytes
    ) -> tuple[LedgerEntry, LedgerEntry] | None:
        """A sealed segment's first entry and seal, after checking it by fingerprint.

        None when the segment is not sealed, or not cleanly so: then the caller checks
        it entry by entry, which raises the precise error for whatever is wrong.
        """
        if self._handle is not None and self._handle_path == path:
            self._handle.flush()
        data = path.read_bytes()
        if not data.endswith(b"\n"):
            return None
        cut = data.rfind(b"\n", 0, len(data) - 1) + 1  # where the last line starts
        try:
            seal = LedgerEntry.model_validate_json(data[cut:])
        except ValidationError:
            return None
        if seal.action != SEAL_ACTION:
            return None
        if content_hash(data[:cut]) != seal.payload_hash:
            msg = (
                f"{path.name} is not what its seal committed to: something in it changed "
                "after it was sealed"
            )
            raise BrokenChain(msg, seq=seal.seq)
        if cut == 0:
            self._check_entry(seal, prev, key)
            return seal, seal
        try:
            first = LedgerEntry.model_validate_json(data[: data.index(b"\n") + 1])
            before = LedgerEntry.model_validate_json(data[data.rfind(b"\n", 0, cut - 1) + 1 : cut])
        except ValidationError:
            return None
        self._check_entry(first, prev, key)
        self._check_entry(seal, before, key)
        return first, seal

    # ── the high-water mark (#99) ────────────────────────────────────────────

    def _read_mark(self) -> tuple[int, str] | None:
        if self._marks is None:
            return None
        try:
            return self._marks.read_mark(self._mark_id)
        except ValueError as exc:
            msg = (
                f"the keychain's record of this ledger's length is unreadable ({exc}), so "
                "nothing can show the ledger was not cut short"
            )
            raise LedgerRolledBack(msg) from exc

    def _check_mark(self, mark: tuple[int, str] | None, count: int, marked: str | None) -> None:
        """Fail if the chain is shorter than, or differs from, what the keychain recorded."""
        self.mark_behind = 0
        if mark is None:
            return
        seq, digest = mark
        if count <= seq:
            ends = f"entry {count - 1}" if count else "nothing at all"
            msg = (
                f"the ledger is shorter than it was: the keychain records entry {seq}, and "
                f"the chain ends at {ends}. Entries were cut from the end, or this folder was "
                "replaced with an older copy. Nothing was changed. If it was restored from a "
                "copy on purpose, Sletchy will not run on it until that record is removed by "
                "hand from Windows Credential Manager (generic credential 'sletchy', account "
                f"'{mark_account(self._mark_id)}')"
            )
            raise LedgerRolledBack(msg, seq=count)
        if marked != digest:
            msg = (
                f"entry {seq} is not the entry the keychain recorded: the history from there "
                "was replaced"
            )
            raise LedgerRolledBack(msg, seq=seq)
        self.mark_behind = count - 1 - seq

    def _remember(self, entry: LedgerEntry) -> None:
        """Record the newest durable entry outside `var/`. After the fsync, never before.

        A mark ahead of the disk would make a crash look like tampering, so it follows
        the write. If it cannot be written the entry is already durable, and reporting
        failure now would say less than happened (#104); the mark lags instead, and the
        next open says so through `mark_behind`.
        """
        if self._marks is None:
            return
        try:
            self._marks.write_mark(self._mark_id, entry.seq, entry_hash(entry))
        except Exception:
            # Deliberately broad: keychain backends raise their own types, and nothing
            # here may turn a durable entry into a reported failure. `mark_behind` is how
            # a lagging mark is seen.
            return

    # ── internals ────────────────────────────────────────────────────────────

    def _build(
        self,
        *,
        plane: Plane,
        actor_id: str,
        action: str,
        subject: Subject,
        verdict: Verdict,
        payload_hash: str | None,
    ) -> LedgerEntry:
        prev_hash = GENESIS_PREV_HASH if self._last is None else entry_hash(self._last)

        # Build once unsigned to get the canonical bytes, then again with the
        # signature. `signature` is excluded from signing_bytes(), so the
        # placeholder below never affects what is signed.
        draft = LedgerEntry(
            seq=self._next_seq,
            ts_wall=datetime.now(UTC),
            ts_mono=time.monotonic_ns(),
            plane=plane,
            actor_id=actor_id,
            action=action,
            subject=subject,
            verdict=verdict,
            payload_hash=payload_hash,
            prev_hash=prev_hash,
            signature="0" * 64,
        )
        signature = sign(self._keys.get(), signing_bytes(draft))
        return draft.model_copy(update={"signature": signature})

    def _write(self, entry: LedgerEntry) -> None:
        """Append one line. Durable before returning, unless inside a `batch()`."""
        if self._buffer is not None:
            self._buffer.append(entry)
            self._pending += _size_of(entry)
        else:
            fh = self._open_handle()
            fh.write(entry.model_dump_json() + "\n")
            fh.flush()
            os.fsync(fh.fileno())
            self._size += _size_of(entry)
            self._remember(entry)

        self._last = entry
        self._next_seq = entry.seq + 1

    def _open_handle(self) -> TextIO:
        """The append handle for the active segment, opened once and reused.

        Opening a file per append cost ~40% of the write time on NTFS. The handle is
        released on rotation so the next append opens the new segment.
        """
        path = self._active_path()
        if self._handle is None or self._handle_path != path:
            self.close()
            path.parent.mkdir(parents=True, exist_ok=True)
            self._handle = path.open("a", encoding="utf-8", newline="\n")
            self._handle_path = path
        return self._handle

    def close(self) -> None:
        """Release the append handle and the lock file. Safe to call repeatedly."""
        if self._handle is not None:
            self._handle.close()
            self._handle = None
            self._handle_path = None
        if self._lock_file is not None and not self._lock_depth:
            self._lock_file.close()
            self._lock_file = None

    # ── one writer at a time (#95) ───────────────────────────────────────────

    @contextmanager
    def _writing(self) -> Iterator[None]:
        """Hold the write lock, and start from what is on disk, not from a snapshot.

        Re-entrant within this object, so a seal inside an append, or appends inside
        a batch, do not take it twice. The outermost holder catches up first.
        """
        if self._lock_depth:
            self._lock_depth += 1
            try:
                yield
            finally:
                self._lock_depth -= 1
            return
        self._acquire()
        self._lock_depth = 1
        try:
            self._catch_up()
            yield
        finally:
            self._lock_depth = 0
            self._release()

    def _catch_up(self) -> None:
        """If another process appended since this object last looked, verify and follow.

        The common case costs one line: the last entry on disk is the one this object
        wrote or read last. Anything else means another writer was here, and the
        whole chain is verified again - so an entry it wrote is checked before this
        one chains from it, and this object never writes from a stale `seq`.
        """
        on_disk = self._disk_tail()
        if on_disk is None and self._last is None:
            return
        if (
            on_disk is not None
            and self._last is not None
            and entry_hash(on_disk) == entry_hash(self._last)
        ):
            return
        if self._handle is not None:
            self._handle.close()
            self._handle = None
            self._handle_path = None
        self._load()

    def _disk_tail(self) -> LedgerEntry | None:
        for path in reversed(self._segments()):
            last = self._tail_entry(path)
            if last is not None:
                return last
        return None

    def _acquire(self) -> None:
        if self._lock_file is None:
            self._lock_file = (self._root / _LOCK_NAME).open("a+b")
        deadline = time.monotonic() + self._lock_wait
        while not _try_lock(self._lock_file):
            if time.monotonic() >= deadline:
                msg = (
                    f"another Sletchy process is writing the record and held it for "
                    f"more than {self._lock_wait:g} s; nothing was recorded, so nothing "
                    "was done. Try again"
                )
                raise LedgerBusy(msg)
            time.sleep(_LOCK_POLL_SECONDS)

    def _release(self) -> None:
        if self._lock_file is not None:
            try:
                _unlock(self._lock_file)
            except OSError:
                # Closing the handle releases the lock on every platform.
                self._lock_file.close()
                self._lock_file = None

    @contextmanager
    def batch(self) -> Iterator[Ledger]:
        """Record a burst of already-decided facts with one fsync at the end.

        **Never use this to gate an action.** Inside the block an entry exists in
        memory but not on disk, so a crash loses it - and LAW 1 requires the record
        to exist *before* the action takes effect. If anything inside this block
        acts on the world, the block is wrong; use plain `append()`, which fsyncs.

        What it is for: facts that are already true and cannot be undone by losing
        the record - memory rollups, a replayed import, detection findings computed
        from the ledger itself. If the process dies mid-batch, the work those
        entries described is lost with them, so nothing is left claiming to have
        happened when it did not.

        The buffer is written and fsynced on exit **including when the block
        raises**: a crash that loses the reason for a state change is worse than a
        partial log.
        """
        if self._buffer is not None:
            msg = "batches do not nest; the inner one would hide the outer's barrier"
            raise LedgerSealed(msg)

        # The lock is held for the whole batch: its entries take their `seq` as they
        # are buffered, so no other writer may append until they are on disk.
        with self._writing():
            self._buffer = []
            try:
                yield self
            finally:
                buffered, self._buffer = self._buffer, None
                if buffered:
                    fh = self._open_handle()
                    fh.write("".join(e.model_dump_json() + "\n" for e in buffered))
                    fh.flush()
                    os.fsync(fh.fileno())
                    self._remember(buffered[-1])
                self._size += self._pending
                self._pending = 0

    def _read_segment(self, path: Path) -> Iterator[LedgerEntry]:
        # Our own buffered writes must be visible to any read of the active segment.
        if self._handle is not None and self._handle_path == path:
            self._handle.flush()
        # Bytes, not text: a crash can cut a line inside a multi-byte character, and
        # decoding the file as text raised a bare UnicodeDecodeError for it (#98).
        with path.open("rb") as fh:
            complete = 0
            for lineno, line in enumerate(fh, 1):
                if not line.strip():
                    continue
                ended = line.endswith(b"\n")
                try:
                    entry = LedgerEntry.model_validate_json(line)
                except ValidationError as exc:
                    if not ended:
                        raise TornFinalEntry(_torn(path, complete)) from exc
                    msg = f"{path.name} line {lineno} is not a valid entry: {exc.error_count()} errors"
                    raise MalformedEntry(msg) from exc
                if not ended:
                    # Whole, but its line was never ended: the next append would run into
                    # it and corrupt both. Still an unfinished write.
                    raise TornFinalEntry(_torn(path, complete))
                complete += 1
                yield entry

    def _segments(self) -> list[Path]:
        return sorted(self._root.glob(_SEGMENT_GLOB), key=_segment_index)

    def _active_segment_index(self) -> int:
        segments = self._segments()
        if not segments:
            return 0
        last = segments[-1]
        # A sealed segment is closed; the active one is the next index.
        return _segment_index(last) + 1 if self._is_sealed_path(last) else _segment_index(last)

    def _active_path(self) -> Path:
        return _segment_path(self._root, self._segment)

    def _is_sealed(self, index: int) -> bool:
        return self._is_sealed_path(_segment_path(self._root, index))

    def _is_sealed_path(self, path: Path) -> bool:
        last = self._tail_entry(path)
        return last is not None and last.action == SEAL_ACTION

    def _tail_entry(self, path: Path) -> LedgerEntry | None:
        """The last entry of a segment, read from the end of the file: one line.

        `append()` asks this on every call. It used to parse the whole active
        segment to learn whether its last line was a seal, which made each append
        slower than the one before: 40 ms at 1,000 entries, 741 ms at 40,000 (#115).
        """
        if self._handle is not None and self._handle_path == path:
            self._handle.flush()
        if not path.exists():
            return None
        with path.open("rb") as fh:
            pos = fh.seek(0, os.SEEK_END)
            block = b""
            while pos > 0 and b"\n" not in block.rstrip():
                step = min(_TAIL_BLOCK, pos)
                pos -= step
                fh.seek(pos)
                block = fh.read(step) + block
        line = block.rstrip().rsplit(b"\n", 1)[-1]
        if not line:
            return None
        try:
            return LedgerEntry.model_validate_json(line)
        except ValidationError as exc:
            msg = f"{path.name} last line is not a valid entry: {exc.error_count()} errors"
            raise MalformedEntry(msg) from exc


def _try_lock(handle: BinaryIO) -> bool:
    """Take the lock without waiting. The OS drops it when the holder dies."""
    if sys.platform == "win32":
        import msvcrt

        handle.seek(0)
        try:
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError:
            return False
        return True
    import fcntl  # pragma: no cover - POSIX; flock, because lockf does not exclude its own process

    try:  # pragma: no cover
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:  # pragma: no cover
        return False
    return True  # pragma: no cover


def _unlock(handle: BinaryIO) -> None:
    if sys.platform == "win32":
        import msvcrt

        handle.seek(0)
        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        return
    import fcntl  # pragma: no cover

    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)  # pragma: no cover
