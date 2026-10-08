"""The undo journal - what Sletchy changed outside `var/`, so `panic` can revert it.

[LAW 0 §2](../../../docs/LAW/00-do-no-harm.md) requires every host change to be
undoable by one documented command. Most changes are undone by the code that made
them, in a `finally`. This file exists for the case that rail does not cover: the
process is killed between making a change and undoing it.

Each record is written **before** the change it describes takes effect. A journal
entry with no corresponding change is harmless - reverting it is a no-op. A change
with no entry is unrevertable, which is the failure this ordering prevents.

**This is not the ledger, and must not be mistaken for it.** The ledger is the
audit record of what Sletchy decided; this is an operational to-do list for
`panic`, holding only what is needed to reverse a change. It is deliberately
readable without a signing key, because `panic` has to work when everything else
is broken - including when the keychain is unavailable.

Two planes use it and neither may import the other: `warden` writes entries,
`cli.panic` reverts them. The schema is shared here so it cannot drift (LAW 6).
"""

from __future__ import annotations

import os
from pathlib import Path

from sletchy.kernel.contracts import HostChange
from sletchy.kernel.paths import runtime_dir

__all__ = [
    "JOURNAL_NAME",
    "HostChange",
    "forget",
    "journal_path",
    "pending",
    "record",
    "unreadable",
]

JOURNAL_NAME = "host-changes.ndjson"

#: How the journal is read and rewritten. A line holding bytes that are not UTF-8 -
#: a torn write, a stray edit - must fail to parse on its own, not make the whole
#: file unreadable, and `forget()` must write it back byte for byte.
_ERRORS = "surrogateescape"


def journal_path() -> Path:
    """Where the journal lives. Under `var/run/`, which `panic` may clear."""
    return runtime_dir() / JOURNAL_NAME


def record(change: HostChange) -> None:
    """Append one record. Call this **before** making the change it describes."""
    path = journal_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(change.model_dump_json() + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def pending() -> tuple[HostChange, ...]:
    """Every record still outstanding.

    A malformed line is skipped rather than raising. `panic` is the command run
    when things are already wrong, so one corrupt line must not stop it reverting
    the others - that would be failing destructive (LAW 0 §7).
    """
    return tuple(change for _, change in _read() if change is not None)


def unreadable() -> tuple[int, ...]:
    """The line numbers, from 1, of journal lines that do not parse.

    `pending()` skips them so one bad line cannot stop panic reverting the rest, and
    `forget()` keeps them. Neither says they exist, and an unreadable line may
    describe a profile or a grant still on the host - so panic and the self-check
    report each one, rather than counting it as nothing to undo (L009, #103).
    """
    return tuple(lineno for lineno, change in _read() if change is None)


def _read() -> list[tuple[int, HostChange | None]]:
    """Every non-blank line with its number, parsed, or None where it does not parse."""
    path = journal_path()
    if not path.is_file():
        return []
    lines: list[tuple[int, HostChange | None]] = []
    for lineno, line in enumerate(path.read_text(encoding="utf-8", errors=_ERRORS).splitlines(), 1):
        if not line.strip():
            continue
        try:
            # ValidationError and JSONDecodeError are both ValueError.
            lines.append((lineno, HostChange.model_validate_json(line)))
        except ValueError:
            lines.append((lineno, None))
    return lines


def forget(context_id: str) -> None:
    """Drop one record, once its changes have actually been reverted.

    Matches on the parsed `context_id` rather than on a substring, so a record can
    never be half-matched by text appearing in some other field. A line that does
    not parse is **kept**: it may describe a change nobody can revert yet, and
    dropping it would turn an unreadable record into a silently abandoned one.
    """
    path = journal_path()
    if not path.is_file():
        return

    kept: list[str] = []
    for line in path.read_text(encoding="utf-8", errors=_ERRORS).splitlines():
        if not line.strip():
            continue
        try:
            if HostChange.model_validate_json(line).context_id != context_id:
                kept.append(line)
        except ValueError:
            kept.append(line)

    if kept:
        path.write_text("\n".join(kept) + "\n", encoding="utf-8", errors=_ERRORS)
    else:
        path.unlink(missing_ok=True)
