"""What starts with the machine, and what about it is wrong (#146).

`sletchy-soc startup` reads the four places Windows starts programs from without being
asked (see `_startup.py`) and names three patterns, each seen on the operator's
machine on 2026-10-04:

- **a program that is not there**: an automatic service whose program was removed
  with the rest of an uninstalled product, still set to start, as the most powerful
  account, at every boot
- **administrator rights at every logon**: a scheduled task that starts a program
  from outside the Windows folder with the highest rights, silently, each time
- **a program from a user-writable folder**: what anything the user runs could
  replace, set to start by itself. The commonest way malware stays

The list is the whole machine's, so it is read only when the dangerous flag
`soc_watch_machine` is on. Command lines are masked with the secret shapes before they
are shown or recorded, because secrets travel in arguments (ADR-0011).
"""

from __future__ import annotations

import re
import sys
from collections.abc import Callable, Iterable
from pathlib import Path, PureWindowsPath
from typing import Annotated, Literal

from pydantic import Field

from sletchy.kernel.contracts.base import Contract
from sletchy.kernel.secrets.shapes import masked
from sletchy.soc.sensors.model import Finding, shown
from sletchy.soc.sensors.rules import USER_WRITABLE
from sletchy.soc.sensors.snapshot import SensorUnavailable

Kind = Literal["registry", "folder", "service", "task"]


class Autostart(Contract):
    """One thing set to start without being asked. `where` says whose, or with what rights."""

    kind: Kind
    where: Annotated[str, Field(max_length=256)]
    name: Annotated[str, Field(max_length=1024)]
    command: Annotated[str, Field(max_length=32768)]


class StartupLook(Contract):
    entries: tuple[Autostart, ...]
    unreadable: Annotated[int, Field(ge=0)]
    windows_folder: str


def clean(command: str) -> str:
    """Secrets masked and control characters escaped, at full length: the rules read the
    path in it, and a path cut short would look like a missing program."""
    return shown(masked(command)[0], 32768)


_UNQUOTED_EXE = re.compile(r"^(.+?\.exe)(?=\s|$)", re.IGNORECASE)


def program_of(command: str, windows: str) -> str | None:
    """The program a command starts, as an absolute path where one can be told."""
    text = command.strip()
    if not text:
        return None
    if text.startswith('"'):
        end = text.find('"', 1)
        exe = text[1:end] if end > 0 else text[1:]
    else:
        match = _UNQUOTED_EXE.match(text)
        exe = match.group(1) if match else text.split()[0]
    for variable, value in (("%systemroot%", windows), ("%windir%", windows)):
        if exe.lower().startswith(variable):
            exe = value + exe[len(variable) :]
    if exe.lower().startswith("\\systemroot\\"):
        exe = windows + exe[len("\\systemroot") :]
    elif exe.lower().startswith("system32\\"):
        exe = windows + "\\" + exe
    elif exe.startswith("\\??\\"):
        exe = exe[4:]
    return exe


def _absolute(path: str) -> bool:
    return PureWindowsPath(path).is_absolute()


def missing_program(look: StartupLook, *, exists: Callable[[str], bool]) -> list[Finding]:
    found = []
    for entry in look.entries:
        if entry.kind == "folder":
            continue
        program = program_of(entry.command, look.windows_folder)
        if program is None or not _absolute(program) or "%" in program or exists(program):
            continue
        found.append(
            Finding(
                rule="autostart_program_missing",
                identifier=shown(f"{entry.kind}:{entry.name}", 1024),
                summary=shown(
                    f'The {entry.kind} "{entry.name}" is set to start by itself ({entry.where}), '
                    f"but its program is not there: {program}. It is probably left from something "
                    "uninstalled. Anything that could put a file at that path would be started by it",
                    480,
                ),
            )
        )
    return found


def admin_at_logon(look: StartupLook) -> list[Finding]:
    home = look.windows_folder.lower().rstrip("\\") + "\\"
    found = []
    for entry in look.entries:
        if entry.kind != "task" or not entry.where.startswith("administrator rights"):
            continue
        program = program_of(entry.command, look.windows_folder) or ""
        if not program or program.lower().startswith(home):
            continue
        found.append(
            Finding(
                rule="autostart_admin_at_logon",
                identifier=shown(f"task:{entry.name}", 1024),
                summary=shown(
                    f'The scheduled task "{entry.name}" starts {program} with administrator rights '
                    "whenever the machine starts or someone logs on, with nothing on screen to say so",
                    480,
                ),
            )
        )
    return found


def from_user_folder(look: StartupLook, *, signed: Callable[[str], bool]) -> list[Finding]:
    """Only programs no publisher Windows trusts has signed: many ordinary programs
    install for one user into their own folders, signed, and naming each of them every
    day would teach the operator to ignore the finding that matters."""
    found = []
    for entry in look.entries:
        if entry.kind == "folder":
            continue  # a Startup folder is in the user's profile by design
        program = (program_of(entry.command, look.windows_folder) or "").lower()
        folder = str(PureWindowsPath(program).parent).lower() + "\\"
        if not program or not any(part in folder for part in USER_WRITABLE):
            continue
        path = program_of(entry.command, look.windows_folder) or ""
        if signed(path):
            continue
        found.append(
            Finding(
                rule="autostart_from_user_folder",
                identifier=shown(f"{entry.kind}:{entry.name}", 1024),
                summary=shown(
                    f'The {entry.kind} "{entry.name}" starts a program from a folder anything you '
                    f"run could write to ({path}), and no publisher Windows trusts has signed it. "
                    "That is how most unwanted programs stay on a machine; if you do not know it, look it up",
                    480,
                ),
            )
        )
    return found


def findings(
    look: StartupLook,
    *,
    exists: Callable[[str], bool] | None = None,
    signed: Callable[[str], bool] | None = None,
) -> list[Finding]:
    check = exists or (lambda path: Path(path).is_file())
    if signed is None:
        signed = _signed_on_this_machine
    return [
        *missing_program(look, exists=check),
        *admin_at_logon(look),
        *from_user_folder(look, signed=signed),
    ]


def _signed_on_this_machine(path: str) -> bool:
    if sys.platform != "win32" or not Path(path).is_file():
        return False
    from sletchy.soc.sensors import _startup

    return _startup.signed(path)


def take() -> StartupLook:
    if sys.platform != "win32":
        msg = "the startup sensor is written for Windows only, so far"
        raise SensorUnavailable(msg)
    from sletchy.soc.sensors import _startup, _win32

    entries: list[Autostart] = []
    unreadable = 0
    for read in (_startup.run_keys, _startup.startup_folders, _startup.services, _startup.tasks):
        found, missed = read()
        entries += found
        unreadable += missed
    return StartupLook(
        entries=tuple(
            Autostart(
                kind=e.kind,
                where=shown(e.where, 256),
                name=shown(e.name, 1024),
                command=clean(e.command),
            )
            for e in entries
        ),
        unreadable=unreadable,
        windows_folder=_win32.windows_folder(),
    )


def of_kind(entries: Iterable[Autostart], kind: Kind) -> list[Autostart]:
    return sorted((e for e in entries if e.kind == kind), key=lambda e: e.name.lower())
