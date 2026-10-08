"""The environment a sandboxed child process is allowed to see.

**Allowlist, not blocklist.** A blocklist of dangerous variables is unwinnable -
every new tool invents its own credential variable, and the list is always one
release behind. The child gets what it was explicitly given plus a tiny set of
variables without which nothing runs at all.

This is L5 from `docs/LAW/isolation.md`, and it is the reason a compromised
dependency cannot read a sibling capability's credentials out of the environment:
they were never there.
"""

from __future__ import annotations

import os

#: The minimum a process needs to start on Windows. Everything else is opt-in.
#:
#: `SYSTEMROOT` is not optional - Python's socket module fails to initialise
#: without it, in a way that looks like a network bug rather than a missing
#: variable.
_BASE_ALLOW: frozenset[str] = frozenset(
    {
        "SYSTEMROOT",
        "SYSTEMDRIVE",
        "WINDIR",
        "COMSPEC",
        "PATHEXT",
        "NUMBER_OF_PROCESSORS",
        "PROCESSOR_ARCHITECTURE",
        # POSIX equivalents, for the CI lane and a future port.
        "LANG",
        "LC_ALL",
        "TZ",
    }
)

#: Never forwarded, even if a caller explicitly names them. This is a backstop
#: *behind* the allowlist, not the primary control - it exists so that a mistake in
#: an `extra` list cannot hand a child an import hook or a preload.
_NEVER_FORWARD: frozenset[str] = frozenset(
    {
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "LD_AUDIT",
        "DYLD_INSERT_LIBRARIES",
        "PYTHONSTARTUP",
        "PYTHONPATH",
        "PYTHONHOME",
        "PYTHONEXECUTABLE",
        "PYTHONWARNINGS",
        "PYTHONBREAKPOINT",
        "PYTHONINSPECT",
        "SITECUSTOMIZE",
        "BASH_ENV",
        "ENV",
    }
)


def child_env(
    *,
    extra: dict[str, str] | None = None,
    path: str | None = None,
    parent: dict[str, str] | None = None,
) -> dict[str, str]:
    """Build the environment for a sandboxed child.

    `extra` is what the capability declared it needs - typically nothing, sometimes
    a resolved secret the caller decided to pass. Anything in `_NEVER_FORWARD` is
    dropped from `extra` too: a variable that can inject code into a child is not
    something a declaration should be able to opt into.

    `BASH_FUNC_*`-style function exports are dropped by prefix, because the name is
    attacker-chosen and cannot be enumerated.
    """
    source = os.environ if parent is None else parent
    env = {k: v for k, v in source.items() if k.upper() in _BASE_ALLOW}

    # PATH is supplied explicitly rather than inherited: an inherited PATH is how a
    # sandboxed process finds an interpreter it was never meant to reach.
    env["PATH"] = path if path is not None else ""

    for key, value in (extra or {}).items():
        if key.upper() in _NEVER_FORWARD or _is_function_export(key):
            continue
        env[key] = value

    return env


def _is_function_export(name: str) -> bool:
    """Shellshock-style exported functions, named however the attacker likes."""
    return name.startswith(("BASH_FUNC_", "() {"))


def stripped_from(parent: dict[str, str]) -> tuple[str, ...]:
    """What `child_env` would drop. For `sletchy status` and for tests.

    Reporting what was removed is more useful than reporting what survived: the
    surviving set is short and boring, and the dropped set is where the credentials
    were.
    """
    kept = set(child_env(parent=parent))
    return tuple(sorted(k for k in parent if k not in kept))
