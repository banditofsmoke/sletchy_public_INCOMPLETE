"""What counts as wrong, as pure functions of a snapshot (#146).

Each rule names something an operator should hear about in words, and nothing here
acts on it: the SOC explains, the operator decides (ADR-0011). Rules read only the
snapshot, so every one of them is tested with planted cases on any platform.

A rule can be fooled, and says so in `tests/adversarial/COVERAGE.md`: a program that
copies a system name into a system folder passes the first rule, and a port Sletchy
does not know is not flagged by the second.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from pathlib import PureWindowsPath

from sletchy.soc.sensors.model import Finding, Proc, Snapshot, Sock, shown

#: Windows' own programs, which malware most often names itself after. Each one belongs
#: in the Windows folder; a copy anywhere else is worth a sentence to the operator.
SYSTEM_PROGRAMS = frozenset(
    {
        "svchost.exe",
        "lsass.exe",
        "csrss.exe",
        "services.exe",
        "winlogon.exe",
        "wininit.exe",
        "smss.exe",
        "dwm.exe",
        "conhost.exe",
        "dllhost.exe",
        "spoolsv.exe",
        "taskhostw.exe",
        "runtimebroker.exe",
        "sihost.exe",
        "explorer.exe",
        "ctfmon.exe",
        "wmiprvse.exe",
        "searchindexer.exe",
        "fontdrvhost.exe",
    }
)

#: Ports a database or a remote-control service listens on. Open to every interface,
#: anyone on the same network can try to log in.
EXPOSED_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    1433: "SQL Server",
    1521: "Oracle",
    3306: "MySQL",
    3389: "Remote Desktop",
    5432: "PostgreSQL",
    5900: "VNC",
    5984: "CouchDB",
    6379: "Redis",
    9200: "Elasticsearch",
    11211: "Memcached",
    27017: "MongoDB",
    33060: "MySQL X",
}

#: Folders an ordinary user, or anything running as them, can write to.
USER_WRITABLE = ("\\appdata\\", "\\temp\\", "\\downloads\\", "\\users\\public\\")


def _folder(path: str) -> str:
    return str(PureWindowsPath(path).parent).lower().rstrip("\\") + "\\"


def system_name_elsewhere(snapshot: Snapshot) -> list[Finding]:
    """A Windows program's name, running from outside the Windows folder."""
    home = snapshot.windows_folder.lower().rstrip("\\") + "\\"
    findings = []
    for proc in snapshot.processes:
        if proc.name.lower() not in SYSTEM_PROGRAMS or proc.path is None:
            continue
        if not _folder(proc.path).startswith(home):
            findings.append(
                Finding(
                    rule="system_name_elsewhere",
                    identifier=shown(proc.path, 1024),
                    summary=shown(
                        f"{proc.name} is a Windows program's name, but this copy runs from "
                        f"{proc.path}, outside {snapshot.windows_folder}",
                        480,
                    ),
                )
            )
    return findings


def _owners(snapshot: Snapshot) -> dict[int, Proc]:
    return {proc.pid: proc for proc in snapshot.processes}


def _owner_name(owners: dict[int, Proc], sock: Sock) -> str:
    proc = owners.get(sock.pid)
    return proc.name if proc and proc.name else f"process {sock.pid}"


def exposed_service(snapshot: Snapshot) -> list[Finding]:
    """A database or remote-control port listening on every network interface."""
    owners = _owners(snapshot)
    seen: set[tuple[int, str]] = set()
    findings = []
    for sock in snapshot.sockets:
        service = EXPOSED_SERVICES.get(sock.local_port)
        if not (sock.listening and sock.on_every_interface and service):
            continue
        owner = _owner_name(owners, sock)
        if (sock.local_port, owner) in seen:  # the IPv4 and IPv6 listeners are one finding
            continue
        seen.add((sock.local_port, owner))
        findings.append(
            Finding(
                rule="exposed_service",
                identifier=shown(f"tcp/{sock.local_port} {owner}", 1024),
                summary=shown(
                    f"{owner} listens for {service} on port {sock.local_port} on every network "
                    "interface, so anything on the same network can try to connect. Listening on "
                    "127.0.0.1 only would keep it to this machine",
                    480,
                ),
            )
        )
    return findings


def listener_in_user_folder(snapshot: Snapshot) -> list[Finding]:
    """A program run from a user-writable folder, listening beyond this machine."""
    owners = _owners(snapshot)
    seen: set[str] = set()
    findings = []
    for sock in snapshot.sockets:
        proc = owners.get(sock.pid)
        if not (sock.listening and not sock.loopback_only and proc and proc.path):
            continue
        if not any(part in _folder(proc.path) for part in USER_WRITABLE) or proc.path in seen:
            continue
        seen.add(proc.path)
        findings.append(
            Finding(
                rule="listener_in_user_folder",
                identifier=shown(proc.path, 1024),
                summary=shown(
                    f"{proc.name} runs from a folder any program you run can write to "
                    f"({proc.path}), and listens on port {sock.local_port} beyond this machine",
                    480,
                ),
            )
        )
    return findings


Rule = Callable[[Snapshot], list[Finding]]
RULES: tuple[Rule, ...] = (system_name_elsewhere, exposed_service, listener_in_user_folder)


def findings(snapshot: Snapshot, rules: Iterable[Rule] = RULES) -> list[Finding]:
    return [finding for rule in rules for finding in rule(snapshot)]
