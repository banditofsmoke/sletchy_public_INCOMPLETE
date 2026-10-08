r"""The grant guard: which directories a recursive ACL change may ever touch.

`icacls /T` rewrites permissions across a whole tree. The Warden grants a sandbox's
AppContainer SID access to its workspace that way, and `sletchy panic` revokes it the
same way when a run was killed before its own cleanup ran.

**Why this lives in the Kernel.** It began in `warden/isolation/_win32.py`, beside the
grant. Panic could not import it (`cli` may not import `warden`), so panic re-implemented
revoke without it, and one forged line in the undo journal had panic walk the user's
home folder and `C:\` with `/T` (#94). A guard two planes must agree on belongs at the
bottom of the stack where both can depend on it - the same reasoning that moved
[`paths.py`](paths.py) here. Pure path logic: no Win32 call, nothing that writes.
"""

from __future__ import annotations

import os
from pathlib import Path

__all__ = ["MAX_GRANT_ENTRIES", "UnsafeGrantTarget", "assert_grantable"]

#: A grant walks the tree with `/T`. Anything this large is not a sandbox
#: workspace, and re-ACLing it would be slow, loud, and hard to reverse. Counted
#: with an early exit, so the check costs nothing on a real workspace.
MAX_GRANT_ENTRIES = 10_000

#: The fewest path components below a drive root a workspace may have. `C:\` and
#: `C:\Users` are refused; `C:\Users\x\work` is not.
_MIN_DEPTH = 3


class UnsafeGrantTarget(OSError):
    """The path handed in is not something we will ever re-ACL."""


def _protected_roots() -> tuple[Path, ...]:
    """Directories a recursive ACL change must never be pointed at.

    Read from the environment rather than written down. A hardcoded system path
    is wrong on any install that moved it, and unreachable by uninstall - which
    is why `test_nothing_writes_to_a_hardcoded_absolute_path` refuses one, and
    why it caught the first draft of this very docstring.
    """
    names = (
        "SYSTEMROOT",
        "SYSTEMDRIVE",
        "PROGRAMFILES",
        "PROGRAMFILES(X86)",
        "PROGRAMDATA",
        "USERPROFILE",
        "LOCALAPPDATA",
        "APPDATA",
        "PUBLIC",
        "TEMP",
    )
    roots = []
    for name in names:
        value = os.environ.get(name)
        if value:
            try:
                roots.append(Path(value).resolve())
            except OSError:
                continue
    return tuple(roots)


def assert_grantable(path: Path) -> None:
    """Refuse to re-ACL anything that is not plainly a sandbox workspace.

    `icacls /T` is recursive. Handed a drive root or a home directory it would
    rewrite permissions across the whole tree - slow, extremely visible, and the
    kind of mistake [LAW 0](../../../docs/LAW/00-do-no-harm.md) exists to make
    impossible on a machine with no spare.

    Checked **here**, at the primitive that does the damage, rather than only at
    the caller that chooses the path: the component that enforces a limit should
    not be the one that declared it (principle #3), and every future caller gets
    the check for free.

    Fails closed. An unreadable or ambiguous path is refused, not granted.

    **Why this does not delegate to `warden.fsguard`** (#68): it cannot, and should not.
    The Kernel imports nothing from the Warden, and this guard must stay where both
    `panic` and the Warden can reach it (L011). Its question is also different: fsguard
    asks "is this path inside a declared root?", while this asks "is this folder safe to
    re-ACL recursively, wherever it is?". A workspace is first confined by fsguard, then
    checked here before the grant.
    """
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        msg = f"refusing to grant on an unresolvable path: {path} ({exc})"
        raise UnsafeGrantTarget(msg) from exc

    if not resolved.is_dir():
        msg = f"refusing to grant on something that is not a directory: {resolved}"
        raise UnsafeGrantTarget(msg)

    text = str(resolved)
    if text.startswith("\\\\"):
        msg = f"refusing to grant on a UNC path: {resolved}"
        raise UnsafeGrantTarget(msg)

    if len(resolved.parts) < _MIN_DEPTH:
        msg = (
            f"refusing to grant on {resolved}: too close to a drive root. A "
            "workspace lives inside a directory, not at the top of a volume."
        )
        raise UnsafeGrantTarget(msg)

    for root in _protected_roots():
        if resolved == root or root.is_relative_to(resolved):
            msg = (
                f"refusing to grant on {resolved}: it is, or contains, the "
                f"protected directory {root}."
            )
            raise UnsafeGrantTarget(msg)

    seen = 0
    for _ in resolved.rglob("*"):
        seen += 1
        if seen > MAX_GRANT_ENTRIES:
            msg = (
                f"refusing to grant on {resolved}: more than {MAX_GRANT_ENTRIES} "
                "entries. That is not a sandbox workspace, and a recursive ACL "
                "change across it is not something to do by accident."
            )
            raise UnsafeGrantTarget(msg)
