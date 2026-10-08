"""The quarantine run: what a dependency does when it is first imported (#34).

LAW 4 says nothing is trusted, imports included. `docs/supply/DEPENDENCIES.md` says
why each package is here; this measures what it does. The package is imported in a
fresh Python process with an audit hook (PEP 578) installed before anything else, in
an empty temporary folder, and the hook:

- **refuses**, and records: any connection, lookup or datagram; starting any program;
  writing, deleting or renaming anything outside the quarantine folder; writing the
  registry
- **records**: files read outside Python's own folders and the quarantine folder;
  native libraries loaded through `ctypes`; registry keys opened; environment changes

The result is a `Profile`: what was attempted, and what was refused. A package whose
import attempts anything in the refused list is flagged, because nothing Sletchy ships
declares a need for any of it at import time.

## What it does not see

- **Native code.** An audit hook sees what Python does. A compiled extension calling the
  operating system directly is invisible to it. Three shipped packages are compiled
- **Anything after import.** One execution path, once: a payload waiting for a date, a
  host or a call is not triggered (#34's known gaps)
- **A sandbox.** Python cannot yet run inside the `winjob` container, which cannot read
  the virtual environment. The refusals here are the hook's, in the child process, not
  the operating system's
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

#: Runs in the child before the import. Kept free of anything the hook watches, so
#: installing it cannot trip it.
HARNESS = r"""
import json, os, sys
QUARANTINE = os.path.realpath(sys.argv[1])
MODULE = sys.argv[2]
if len(sys.argv) > 3 and sys.argv[3]:
    sys.path.insert(0, sys.argv[3])
PYTHON = [os.path.realpath(p) for p in {sys.prefix, sys.base_prefix, sys.exec_prefix, sys.base_exec_prefix}]
events = []
inside = False

def under(path, roots):
    try:
        real = os.path.realpath(os.fspath(path))
    except (TypeError, ValueError, OSError):
        return False
    return any(real == r or real.startswith(r + os.sep) for r in roots)

REFUSE = {
    "socket.connect", "socket.bind", "socket.sendto", "socket.sendmsg",
    "socket.getaddrinfo", "socket.gethostbyname", "socket.gethostbyaddr",
    "subprocess.Popen", "os.system", "os.exec", "os.spawn", "os.posix_spawn",
    "os.fork", "os.forkpty", "os.startfile", "_winapi.CreateProcess",
    "winreg.CreateKey", "winreg.SetValue", "winreg.DeleteKey", "winreg.DeleteValue",
    "winreg.SaveKey", "winreg.LoadKey",
}
CHANGES = {"os.remove", "os.rename", "os.rmdir", "os.mkdir", "shutil.rmtree", "os.truncate", "os.chmod"}
RECORD = {"ctypes.dlopen", "winreg.OpenKey", "os.putenv", "os.unsetenv"}

def hook(event, args):
    global inside
    if inside:
        return
    inside = True
    try:
        detail = None
        refuse = False
        if event in REFUSE:
            refuse, detail = True, repr(args[:2])[:200]
        elif event in CHANGES:
            target = args[0] if args else None
            if not under(target, [QUARANTINE]):
                refuse, detail = True, repr(target)[:200]
        elif event == "open":
            path, mode = args[0], args[1]
            writing = isinstance(mode, str) and any(c in mode for c in "wax+")
            if isinstance(args[2], int) and args[2] & (os.O_WRONLY | os.O_RDWR | os.O_CREAT):
                writing = True
            if isinstance(path, int):
                return
            if writing and not under(path, [QUARANTINE]):
                refuse, detail = True, repr(path)[:200]
            elif not writing and not under(path, PYTHON + [QUARANTINE]):
                detail = repr(path)[:200]
                event = "read"
        elif event in RECORD:
            detail = repr(args[:1])[:200]
        if detail is not None:
            events.append({"event": event, "detail": detail, "refused": refuse})
        if refuse:
            raise PermissionError("refused by the Sletchy quarantine: " + event)
    finally:
        inside = False

sys.addaudithook(hook)
os.chdir(QUARANTINE)
error = None
try:
    __import__(MODULE)
except BaseException as exc:
    error = type(exc).__name__ + ": " + str(exc)[:200]
inside = True
sys.stdout.write("\n" + json.dumps({"events": events, "error": error}) + "\n")
"""


@dataclass(frozen=True)
class Event:
    event: str
    detail: str
    refused: bool


@dataclass(frozen=True)
class Profile:
    module: str
    events: tuple[Event, ...] = field(default_factory=tuple)
    #: The import failed: an exception, or the child never reported.
    error: str | None = None

    @property
    def refused(self) -> tuple[Event, ...]:
        return tuple(e for e in self.events if e.refused)

    @property
    def clean(self) -> bool:
        return self.error is None and not self.refused

    def summary(self) -> str:
        if self.error and not self.refused:
            return f"{self.module}: the import failed ({self.error})"
        if self.refused:
            kinds = sorted({e.event for e in self.refused})
            return f"{self.module}: attempted {len(self.refused)} refused action(s): {', '.join(kinds)}"
        reads = sum(1 for e in self.events if e.event == "read")
        libraries = sum(1 for e in self.events if e.event == "ctypes.dlopen")
        return (
            f"{self.module}: imported with no network, no programs started and no writes; "
            f"{reads} file(s) read outside Python, {libraries} native library(ies) loaded"
        )


def profile(
    module: str,
    *,
    path: Path | None = None,
    python: str = sys.executable,
    timeout: float = 60.0,
) -> Profile:
    """Import `module` once, in quarantine, and say what it did.

    `path` is one more folder to import from, for a module that is not installed.
    Python starts isolated (`-I`) and writes no bytecode (`-B`), so its own caching is
    not mistaken for the package writing.
    """
    with tempfile.TemporaryDirectory(prefix="sletchy-quarantine-") as folder:
        try:
            result = subprocess.run(  # noqa: S603 - our own interpreter and harness
                [python, "-I", "-B", "-c", HARNESS, folder, module, str(path or "")],
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=folder,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return Profile(module=module, error=f"did not finish in {timeout:.0f} s")
    last = (result.stdout or "").strip().splitlines()[-1:] or [""]
    try:
        report = json.loads(last[0])
    except ValueError:
        return Profile(module=module, error=f"no report (exit {result.returncode})")
    return Profile(
        module=module,
        events=tuple(
            Event(event=str(e["event"]), detail=str(e["detail"]), refused=bool(e["refused"]))
            for e in report.get("events", [])
        ),
        error=report.get("error"),
    )


def main(argv: list[str] | None = None) -> int:
    """`python -m sletchy.warden.supply.quarantine MODULE...`: profile each, print, never record."""
    modules = argv if argv is not None else sys.argv[1:]
    if not modules:
        print("usage: python -m sletchy.warden.supply.quarantine MODULE [MODULE...]")
        return 2
    worst = 0
    for module in modules:
        result = profile(module)
        print(result.summary())
        for event in result.events:
            mark = "REFUSED" if event.refused else "seen   "
            print(f"  {mark} {event.event:<22} {event.detail}")
        worst = max(worst, 0 if result.clean else 1)
    return worst


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
