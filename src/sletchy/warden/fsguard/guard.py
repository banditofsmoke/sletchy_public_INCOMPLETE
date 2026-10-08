"""Canonicalise, then confine: every path Sletchy handles itself, checked before it is used.

`winjob` denies the filesystem from outside, with an AppContainer, and that is the strong
control. **This is for the paths Sletchy handles in its own process**, where no container
is in the way: a tool argument, a payload destination, an operator-supplied workspace
(#68, roadmap 2.6).

Two passes, in this order, because the order is the point:

1. **Read the text, before the disk is touched.** Every Windows spelling that means
   something other than "a file under this folder" is refused by name: device paths
   (`\\\\.\\`, `\\\\?\\`), shares, drive-relative paths (`C:foo`), alternate data streams
   (`file:hidden`), reserved device names (`NUL`, `COM1`, `CON.txt`), trailing dots and
   spaces the filesystem strips, and invisible characters that disguise a name
2. **Resolve, then compare.** `..`, junctions, symbolic links and 8.3 short names are
   resolved by the operating system first, and only the resolved path is compared with
   the root, by path components and without regard to case, never as a string prefix:
   a folder named `sletchy-evil` beside the root `sletchy` is not inside it

A path that fails either pass **raises**. It is never clamped, trimmed or moved inside the
root: rewriting a hostile path into a valid one destroys the signal and performs a write
nobody asked for (#68, out of scope permanently).

**With no root declared, everything is refused** (LAW 2). Every refusal is appended to the
ledger before it is raised (LAW 1), naming the rule that fired, so an operator can tell a
traversal attempt from a typo.

What this does not close is written in `tests/adversarial/COVERAGE.md`: the race between
resolving a path and using it, which only a handle-based design closes.
"""

from __future__ import annotations

import os
import unicodedata
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath
from typing import TYPE_CHECKING

from sletchy.kernel.contracts import Decision, Plane, Subject, SubjectKind, Verdict

if TYPE_CHECKING:
    from collections.abc import Iterable

    from sletchy.kernel.ledger import Ledger

REFUSED_ACTION = "warden.fsguard.refused"

#: Names Windows opens as devices, whatever folder they appear in and whatever extension
#: follows: `NUL.txt` is the null device. The superscript digits are devices too.
RESERVED_NAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
    | {f"COM{d}" for d in "0123456789\u00b9\u00b2\u00b3"}
    | {f"LPT{d}" for d in "0123456789\u00b9\u00b2\u00b3"}
)

#: The rules, by name. A refusal always names exactly one.
RULES = (
    "no_root",
    "empty",
    "invisible_character",
    "device_path",
    "share",
    "drive_relative",
    "stream",
    "device_name",
    "trailing_dot_or_space",
    "outside_root",
    "quota_bytes",
    "quota_files",
)


class PathRefused(ValueError):
    """A path Sletchy will not use, and the one rule that refused it."""

    def __init__(self, rule: str, given: str, detail: str) -> None:
        if rule not in RULES:  # pragma: no cover - a programming error, not an input
            msg = f"unknown rule {rule!r}"
            raise ValueError(msg)
        self.rule = rule
        self.given = given
        super().__init__(f"{rule}: {detail}")


@dataclass(frozen=True)
class Root:
    """A folder paths may be confined to, with its ceilings. Resolved when declared."""

    name: str
    path: Path
    max_bytes: int
    max_files: int

    @classmethod
    def declare(cls, name: str, path: Path, *, max_bytes: int, max_files: int) -> Root:
        """The root's own path is canonical before anything is compared with it.

        It must already exist as a folder: a root that is a file, or nothing, would make
        every comparison meaningless.
        """
        resolved = Path(path).resolve(strict=True)
        if not resolved.is_dir():
            msg = f"a root must be a folder: {resolved}"
            raise NotADirectoryError(msg)
        if max_bytes < 0 or max_files < 0:
            msg = "a root's ceilings are zero or more"
            raise ValueError(msg)
        return cls(name=name, path=resolved, max_bytes=max_bytes, max_files=max_files)


# ── pass 1: the text ─────────────────────────────────────────────────────────


def _invisible(ch: str) -> bool:
    """Control and format characters: NUL, right-to-left overrides, zero-width joiners."""
    return unicodedata.category(ch) in ("Cc", "Cf")


def check_text(given: str) -> None:
    """Refuse, by name, every spelling that is not simply a path under a folder."""
    if not given or not given.strip():
        raise PathRefused("empty", given, "an empty path names nothing")
    if any(_invisible(ch) for ch in given):
        raise PathRefused(
            "invisible_character", given, "a control or invisible character can disguise a name"
        )
    text = given.replace("/", "\\")
    if text.startswith(("\\\\?\\", "\\\\.\\", "\\??\\")):
        raise PathRefused("device_path", given, "device and raw paths skip every normal rule")
    if text.startswith("\\\\"):
        raise PathRefused("share", given, "a network or administrative share is not local")
    pure = PureWindowsPath(text)
    # `\foo` is "foo at this drive's root" only on Windows. On a POSIX host (Linux CI),
    # `/tmp/x` is an ordinary absolute path; the drive-letter form is refused everywhere.
    driveless_root = bool(pure.root and not pure.drive) and os.name == "nt"
    if (pure.drive and not pure.root) or driveless_root:
        raise PathRefused(
            "drive_relative",
            given,
            "relative to a drive's current folder or root, not to anything declared",
        )
    rest = text[2:] if pure.drive else text
    if ":" in rest:
        raise PathRefused("stream", given, "a colon after the drive names an alternate data stream")
    for part in pure.parts[1:] if pure.drive else pure.parts:
        if part in (".", ".."):
            continue
        if part.endswith((".", " ")):
            raise PathRefused(
                "trailing_dot_or_space",
                given,
                f"{part!r}: Windows strips trailing dots and spaces, so the name is not what it says",
            )
        stem = part.split(".", 1)[0].rstrip(" ").upper()
        if stem in RESERVED_NAMES:
            raise PathRefused("device_name", given, f"{part!r} opens the {stem} device, not a file")


# ── pass 2: resolve, then compare ────────────────────────────────────────────


def _parts(path: Path) -> tuple[str, ...]:
    return tuple(os.path.normcase(part) for part in path.parts)


def within(path: Path, root: Path) -> bool:
    """Component-wise containment, case-insensitive on Windows. Never a string prefix."""
    inner, outer = _parts(path), _parts(root)
    return inner[: len(outer)] == outer


def confine(root: Root, given: str | os.PathLike[str]) -> Path:
    """`given` resolved, if and only if it lies inside `root`; otherwise `PathRefused`.

    A relative path is taken relative to the root, never to the current folder.
    """
    text = os.fspath(given)
    check_text(text)
    candidate = Path(text)
    if not candidate.is_absolute():
        candidate = root.path / candidate
    resolved = candidate.resolve(strict=False)
    if not within(resolved, root.path):
        raise PathRefused(
            "outside_root", text, f"resolves to {resolved}, which is outside the {root.name} root"
        )
    return resolved


def usage(root: Root) -> tuple[int, int]:
    """Bytes and files under the root, without following links out of it.

    A junction is not a symbolic link to Python: `is_dir(follow_symlinks=False)` is true
    for one, and the first version of this walked through a junction and counted a folder
    outside the root. Links and junctions are skipped, never entered.
    """
    total = files = 0
    stack = [root.path]
    while stack:
        with os.scandir(stack.pop()) as entries:
            for entry in entries:
                if entry.is_symlink() or entry.is_junction():
                    continue
                if entry.is_dir(follow_symlinks=False):
                    stack.append(Path(entry.path))
                elif entry.is_file(follow_symlinks=False):
                    total += entry.stat(follow_symlinks=False).st_size
                    files += 1
    return total, files


def ensure_room(root: Root, adding_bytes: int, adding_files: int = 1) -> None:
    """Refuse, before a write, one that would take the root past either ceiling."""
    total, files = usage(root)
    if total + adding_bytes > root.max_bytes:
        raise PathRefused(
            "quota_bytes",
            str(root.path),
            f"{adding_bytes} more bytes would pass the {root.name} root's ceiling of {root.max_bytes}",
        )
    if files + adding_files > root.max_files:
        raise PathRefused(
            "quota_files",
            str(root.path),
            f"{adding_files} more files would pass the {root.name} root's ceiling of {root.max_files}",
        )


# ── the guard: roots, and a record of every refusal ──────────────────────────


class FsGuard:
    """The declared roots, and the ledger every refusal is written to before it is raised.

    A guard cannot be built without a ledger, for the reason `SandboxRecorder` cannot: a
    refusal nobody can find later is a decision made off the record (LAW 1). Paths that
    pass are not recorded here; the action that uses them is.
    """

    def __init__(self, roots: Iterable[Root], *, ledger: Ledger, actor_id: str) -> None:
        self._roots = {root.name: root for root in roots}
        self._ledger = ledger
        self._actor = actor_id

    def confine(self, root_name: str, given: str | os.PathLike[str]) -> Path:
        root = self._root(root_name, os.fspath(given))
        try:
            return confine(root, given)
        except PathRefused as refusal:
            self._record(refusal)
            raise

    def ensure_room(self, root_name: str, adding_bytes: int, adding_files: int = 1) -> None:
        root = self._root(root_name, root_name)
        try:
            ensure_room(root, adding_bytes, adding_files)
        except PathRefused as refusal:
            self._record(refusal)
            raise

    def _root(self, name: str, given: str) -> Root:
        root = self._roots.get(name)
        if root is None:
            refusal = PathRefused("no_root", given, f"no root named {name!r} is declared")
            self._record(refusal)
            raise refusal
        return root

    def _record(self, refusal: PathRefused) -> None:
        shown = refusal.given if len(refusal.given) <= 200 else refusal.given[:197] + "..."
        reason = str(refusal)
        self._ledger.append(
            plane=Plane.WARDEN,
            actor_id=self._actor,
            action=REFUSED_ACTION,
            subject=Subject(kind=SubjectKind.PATH, identifier=shown or "<empty>"),
            verdict=Verdict(
                decision=Decision.DENY,
                reason=reason if len(reason) <= 512 else reason[:509] + "...",
                rule_id=refusal.rule,
            ),
        )
