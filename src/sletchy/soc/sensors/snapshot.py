"""One look at the machine, narrowed to what the operator allowed (#146).

**Without the dangerous flag `soc_watch_machine`, only Sletchy's own processes are
looked at** (ADR-0011 decision 5): a process running a program from Sletchy's own
folder, this process, and every process any of them started. That covers the window,
the Kernel, and anything a sandbox launched. Everything else on the machine is not
read into the snapshot at all, rather than read and hidden.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path, PureWindowsPath

from sletchy.soc.sensors.model import Proc, Snapshot, Sock

#: Sletchy's own folder: `src/sletchy/` is two levels below it.
SLETCHY_ROOT = Path(__file__).resolve().parents[4]


class SensorUnavailable(RuntimeError):
    """This platform has no sensor yet. Said, never guessed (L009)."""


def _inside(path: str, root: str) -> bool:
    folder = root.lower().rstrip("\\/") + "\\"
    return str(PureWindowsPath(path)).lower().startswith(folder)


def own(processes: Iterable[Proc], *, root: str, me: int) -> set[int]:
    """The pids that are Sletchy's: run from `root`, this process, and their descendants."""
    procs = list(processes)
    mine = {p.pid for p in procs if p.pid == me or (p.path is not None and _inside(p.path, root))}
    by_pid = {p.pid: p for p in procs}
    children: dict[int, list[Proc]] = {}
    for p in procs:
        children.setdefault(p.parent, []).append(p)
    todo = list(mine)
    while todo:
        parent = by_pid[todo.pop()]
        for child in children.get(parent.pid, ()):
            # A pid is reused after its process exits, so a child that started before
            # its "parent" did belongs to an earlier process with the same pid.
            if child.pid in mine or child.pid == parent.pid:
                continue
            if child.started and parent.started and child.started < parent.started:
                continue
            mine.add(child.pid)
            todo.append(child.pid)
    return mine


def narrow(
    processes: Iterable[Proc], sockets: Iterable[Sock], *, whole_machine: bool, root: str, me: int
) -> tuple[tuple[Proc, ...], tuple[Sock, ...]]:
    procs = tuple(processes)
    socks = tuple(sockets)
    if whole_machine:
        return procs, socks
    mine = own(procs, root=root, me=me)
    return tuple(p for p in procs if p.pid in mine), tuple(s for s in socks if s.pid in mine)


def take(*, whole_machine: bool) -> Snapshot:
    """Read the machine. Raises `SensorUnavailable` where there is no sensor yet."""
    if sys.platform != "win32":
        msg = "the process and network sensors are written for Windows only, so far"
        raise SensorUnavailable(msg)
    from sletchy.soc.sensors import _win32

    procs, socks = narrow(
        _win32.read_processes(),
        _win32.read_sockets(),
        whole_machine=whole_machine,
        root=str(SLETCHY_ROOT),
        me=os.getpid(),
    )
    return Snapshot(
        taken_at=datetime.now(UTC),
        processes=procs,
        sockets=socks,
        whole_machine=whole_machine,
        windows_folder=_win32.windows_folder(),
    )
