"""The programs the conformance suite runs inside each sandbox.

Every backend runs the **same** commands, so a difference in outcome is a
difference in confinement rather than a difference in what was asked.

## Why not `sys.executable`

The suite used to probe with Python. `winjob` cannot: an AppContainer executes the
image fine, but then cannot read the interpreter's own files, so Python dies at
startup with `failed to locate pyvenv.cfg: Access is denied`. Every filesystem
assertion would then be measuring "can the child read the standard library",
which is the ADR-0005 §4 confound wearing a different hat - a probe that fails for
a reason unrelated to the thing under test.

So the probe is the platform's shell, which is present and executable inside every
backend including a zero-capability container.

## Why full paths, and no shell features

Sandboxed children get `PATH=""` from the Kernel's env allowlist, so **every**
external binary must be named absolutely - the interpreter itself and anything it
runs. On Windows that is only the interpreter, because `echo`, `type` and `for`
are `cmd` builtins; on POSIX, `cat` and `sleep` are separate binaries and have to
be resolved here, on the host, before the child loses its `PATH`.

Commands are otherwise kept to interpreter builtins: an AppContainer denies
`waitfor`, `timeout` and `ping` the services they need even when the binaries
themselves launch, and a probe that fails for its own reasons is worse than no
probe.
"""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

WINDOWS = sys.platform == "win32"

#: The one interpreter every backend can reach. Full path: PATH is empty inside a
#: sandbox by design.
SHELL = (
    os.environ.get("COMSPEC")
    or str(Path(os.environ.get("SYSTEMROOT", "")) / "System32" / "cmd.exe")
    if WINDOWS
    else "/bin/sh"
)

#: Text the environment probe looks for. Defined once so a test cannot assert on a
#: value the probe never sets.
SECRET_VALUE = "must-not-reach-the-child"
SECRET_NAME = "SLETCHY_CONFORMANCE_SECRET"


#: The Windows spin loop. A cmd builtin, because it is the only delay primitive a
#: zero-capability container can actually run.
_SPIN = ["for", "/L", "%i", "in", "(1,1,2000000000)", "do", "@rem"]


def _posix_bin(name: str) -> str:
    """Resolve a POSIX helper binary to an absolute path.

    Called on the host, where `PATH` still exists. The child will not have one.
    Falling back to the bare name keeps the failure legible (`sh: cat: not found`)
    rather than turning it into an import error.
    """
    found = shutil.which(name)
    if found:
        return found
    for candidate in (f"/bin/{name}", f"/usr/bin/{name}"):
        if Path(candidate).exists():
            return candidate
    return name


def _shell(*arguments: str) -> list[str]:
    """One command, quoted once.

    Windows arguments are passed **separately**, never pre-quoted into a single
    string. Both `subprocess` and `CreateProcess` join argv with `list2cmdline`,
    so a string that already contains quotes comes out double-quoted and `cmd`
    reads it as a filename. That mistake made an unconfined backend look confined -
    a false pass in the safe-looking direction, which is the worst kind.
    """
    return [SHELL, "/c", *arguments] if WINDOWS else [SHELL, "-c", " ".join(arguments)]


def exit_with(code: int) -> list[str]:
    """Exit with a specific code, touching nothing else.

    The positive control. It must succeed for any other result to mean anything.
    """
    return _shell("exit", str(code))


def print_text(text: str) -> list[str]:
    return _shell("echo", text)


def read_file(path: Path | str) -> list[str]:
    """Read a file, exiting non-zero when denied."""
    if WINDOWS:
        return _shell("type", str(path))
    return _shell(_posix_bin("cat"), f"'{path}'")


def print_env(name: str = SECRET_NAME) -> list[str]:
    """Echo one environment variable.

    `cmd` prints the literal `%NAME%` when the variable is unset, and `sh` prints
    an empty line. Both are distinguishable from the secret, which is all the
    assertion needs.
    """
    return _shell("echo", f"[%{name}%]") if WINDOWS else _shell("echo", f'"[${name}]"')


def hang() -> list[str]:
    """A process that will not finish on its own inside any test's patience.

    On Windows this spins rather than sleeps: `timeout`, `waitfor` and `ping` are
    all unusable inside an AppContainer - the binaries launch and then fail on the
    services they need - and a "sleep" that returns immediately would turn the
    wall-clock test into one that always passes. The job object's CPU hard cap
    keeps the spin from being felt.
    """
    return _shell(*_SPIN) if WINDOWS else _shell(_posix_bin("sleep"), "3600")


def spawn_detached_child() -> list[str]:
    """Start a grandchild that outlives its parent, then exit immediately.

    Used to prove the job kills a whole tree rather than one process. The parent
    returns at once, so anything still alive afterwards is the detached grandchild.

    **No title argument.** An earlier version passed `""` as an empty title;
    `list2cmdline` escaped it to `\\"\\"`, `start` read `\\\\` as the program name,
    and Windows put a modal "cannot find" dialog on the operator's desktop. That
    dialog was a live process *inside the job*, so the tree-kill assertion passed
    while measuring a stuck error box. `start` only treats its first token as a
    title when that token is quoted, so omitting it entirely is both correct and
    unambiguous.
    """
    if WINDOWS:
        return _shell("start", "/b", SHELL, "/c", *_SPIN)
    return _shell(_posix_bin("sleep"), "3600", "&", "exit", "0")
