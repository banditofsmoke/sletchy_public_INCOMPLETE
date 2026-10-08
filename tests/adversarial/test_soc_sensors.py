"""The SOC's first sensor: processes and ports, read-only, in words (#146).

Three kinds of test, and the reason for each:

- **planted cases**, on any platform: the rules and the narrowing are pure functions of a
  snapshot, so a fake `svchost.exe` in Downloads or a database open to the network is
  built in memory, never on the machine
- **the sensor reads this machine correctly**, on Windows: positive controls against
  facts known in advance (this process's own pid, parent and name; port 135, which
  Windows always listens on, read back in the right byte order)
- **LAW 0**: every Win32 call the sensor binds is a query, and the one handle it opens
  on another process can only read that process's name
"""

from __future__ import annotations

import argparse
import ast
import os
import sys
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

import pytest

from sletchy.kernel.contracts.identity import Plane
from sletchy.kernel.contracts.runtime import FlagRisk
from sletchy.kernel.flags.registry import FlagRegistry
from sletchy.kernel.ledger import InMemoryKeySource, Ledger
from sletchy.soc import cli as soc_cli
from sletchy.soc.findings import MAX_PER_RUN, OVER_CEILING_ACTION, record
from sletchy.soc.sensors import rules
from sletchy.soc.sensors.model import (
    EVERY_INTERFACE,
    Finding,
    Proc,
    Snapshot,
    Sock,
    TcpState,
    shown,
)
from sletchy.soc.sensors.snapshot import SLETCHY_ROOT, narrow, own

pytestmark = pytest.mark.adversarial

WINDOWS = sys.platform == "win32"
needs_windows = pytest.mark.skipif(not WINDOWS, reason="the sensor reads Windows")
SENSOR_SOURCE = (
    Path(__file__).resolve().parents[2] / "src" / "sletchy" / "soc" / "sensors" / "_win32.py"
)
T0 = datetime(2026, 10, 4, 6, 0, tzinfo=UTC)


def proc(pid: int, name: str, path: str | None, parent: int = 1, started: datetime = T0) -> Proc:
    return Proc(
        pid=pid,
        parent=parent,
        name=name,
        path=path,
        memory_bytes=10 * 1024 * 1024,
        cpu_seconds=1.0,
        threads=1,
        handles=1,
        started=started,
    )


ANY_V4, ANY_V6 = EVERY_INTERFACE


def listener(port: int, pid: int, address: str = ANY_V4) -> Sock:
    return Sock(
        protocol="tcp",
        local_address=address,
        local_port=port,
        remote_address=None,
        remote_port=None,
        state=TcpState.LISTEN,
        pid=pid,
    )


def snap(processes: list[Proc], sockets: list[Sock] | None = None) -> Snapshot:
    return Snapshot(
        taken_at=T0,
        processes=tuple(processes),
        sockets=tuple(sockets or ()),
        whole_machine=True,
        windows_folder="C:\\Windows",
    )


# ── the rules, with planted cases ────────────────────────────────────────────


def test_a_system_name_running_from_the_wrong_folder_is_a_finding() -> None:
    found = rules.system_name_elsewhere(
        snap([proc(10, "svchost.exe", "C:\\Users\\someone\\Downloads\\svchost.exe")])
    )
    assert [f.rule for f in found] == ["system_name_elsewhere"]
    assert "Downloads" in found[0].summary


@pytest.mark.parametrize(
    "path",
    [
        "C:\\Windows\\System32\\svchost.exe",
        "C:\\WINDOWS\\system32\\SVCHOST.EXE",
        "C:\\Windows\\SysWOW64\\svchost.exe",
        "C:\\Windows\\explorer.exe",
    ],
)
def test_a_system_program_in_its_own_folder_is_not(path: str) -> None:
    name = path.rsplit("\\", 1)[1]
    assert rules.system_name_elsewhere(snap([proc(10, name, path)])) == []


def test_a_path_that_could_not_be_read_is_never_called_wrong() -> None:
    """L009: could not look is not something there. It is counted, not flagged."""
    assert rules.system_name_elsewhere(snap([proc(10, "svchost.exe", None)])) == []


def test_a_folder_named_like_windows_is_not_windows() -> None:
    """`C:\\Windows-update\\` starts with `C:\\Windows` as text, not as a folder."""
    found = rules.system_name_elsewhere(
        snap([proc(10, "lsass.exe", "C:\\Windows-update\\lsass.exe")])
    )
    assert len(found) == 1


def test_a_database_open_to_every_network_is_a_finding_once() -> None:
    processes = [proc(20, "mysqld.exe", "C:\\db\\mysqld.exe")]
    sockets = [listener(3306, 20, ANY_V4), listener(3306, 20, ANY_V6)]
    found = rules.exposed_service(snap(processes, sockets))
    assert len(found) == 1, "the IPv4 and IPv6 listeners are one finding"
    assert "MySQL" in found[0].summary and "127.0.0.1" in found[0].summary


@pytest.mark.parametrize(
    ("port", "address"),
    [(3306, "127.0.0.1"), (3306, "::1"), (49664, ANY_V4), (5432, "192.0.2.10")],
)
def test_a_listener_kept_to_this_machine_or_on_an_unknown_port_is_not(
    port: int, address: str
) -> None:
    processes = [proc(20, "x.exe", "C:\\x\\x.exe")]
    assert rules.exposed_service(snap(processes, [listener(port, 20, address)])) == []


def test_a_program_in_a_user_folder_listening_beyond_this_machine_is_a_finding() -> None:
    path = "C:\\Users\\someone\\AppData\\Roaming\\thing\\thing.exe"
    found = rules.listener_in_user_folder(snap([proc(30, "thing.exe", path)], [listener(4444, 30)]))
    assert [f.rule for f in found] == ["listener_in_user_folder"]


def test_the_same_program_listening_only_on_loopback_is_not() -> None:
    path = "C:\\Users\\someone\\AppData\\Local\\chat\\chat.exe"
    sockets = [listener(6463, 30, "127.0.0.1")]
    assert rules.listener_in_user_folder(snap([proc(30, "chat.exe", path)], sockets)) == []


def test_a_hostile_process_name_cannot_write_to_the_terminal() -> None:
    """A process names itself. Escape codes and newlines in a name are shown, not run (#96)."""
    name = "svchost.exe\x1b[2J\nFAKE: all clear"
    found = rules.system_name_elsewhere(snap([proc(10, "svchost.exe", f"C:\\Temp\\{name}")]))
    assert found and all(ch.isprintable() for ch in found[0].summary + found[0].identifier)
    view = "\n".join(soc_cli.render_processes(snap([proc(10, name, "C:\\Temp\\x.exe")]), top=5))
    assert "\x1b" not in view and "\nFAKE" not in view


def test_shown_bounds_length() -> None:
    assert len(shown("a" * 5000, 200)) == 200


# ── only Sletchy's own, unless the operator says otherwise ──────────────────


def test_without_the_flag_only_sletchys_own_processes_are_seen() -> None:
    root = "F:\\sletchy"
    processes = [
        proc(100, "python.exe", "F:\\sletchy\\.venv\\Scripts\\python.exe", parent=1),
        proc(101, "curl.exe", "C:\\Windows\\System32\\curl.exe", parent=100),  # launched by it
        proc(200, "chrome.exe", "C:\\Program Files\\chrome.exe", parent=1),
        proc(300, "python.exe", None, parent=50),  # this process
    ]
    sockets = [listener(5000, 101, "127.0.0.1"), listener(443, 200)]
    procs, socks = narrow(processes, sockets, whole_machine=False, root=root, me=300)
    assert sorted(p.pid for p in procs) == [100, 101, 300]
    assert [s.pid for s in socks] == [101]
    everything, _ = narrow(processes, sockets, whole_machine=True, root=root, me=300)
    assert len(everything) == 4


def test_a_reused_parent_pid_does_not_make_a_stranger_sletchys() -> None:
    """A pid is reused after its process ends. A process that started before its
    supposed parent belongs to an earlier owner of that pid."""
    later = T0 + timedelta(hours=1)
    processes = [
        proc(100, "python.exe", "F:\\sletchy\\python.exe", parent=1, started=later),
        proc(150, "stranger.exe", "C:\\x\\stranger.exe", parent=100, started=T0),
    ]
    assert own(processes, root="F:\\sletchy", me=999) == {100}


def test_a_folder_named_like_sletchys_is_not_sletchys() -> None:
    processes = [proc(100, "x.exe", "F:\\sletchy-evil\\x.exe")]
    assert own(processes, root="F:\\sletchy", me=999) == set()


def test_sletchys_own_folder_is_the_repository() -> None:
    assert (SLETCHY_ROOT / "pyproject.toml").is_file()
    assert (SLETCHY_ROOT / "src" / "sletchy").is_dir()


def test_watching_the_whole_machine_is_a_dangerous_flag_and_off() -> None:
    flag = FlagRegistry().get(soc_cli.WATCH_FLAG)
    assert flag.risk is FlagRisk.DANGEROUS
    assert flag.default is False


# ── findings reach the ledger, snapshots never do ───────────────────────────


@pytest.fixture
def ledger(tmp_path: Path) -> Ledger:
    return Ledger.open(tmp_path / "ledger", InMemoryKeySource(b"k" * 32))


def finding(n: int) -> Finding:
    return Finding(rule="exposed_service", identifier=f"tcp/{n} x.exe", summary=f"finding {n}")


def test_a_finding_is_recorded_once_a_day(ledger: Ledger, tmp_path: Path) -> None:
    seen = tmp_path / "soc" / "recorded.json"
    day = date(2026, 10, 4)
    first = record(ledger, [finding(1)], today=day, seen_file=seen)
    again = record(ledger, [finding(1)], today=day, seen_file=seen)
    tomorrow = record(ledger, [finding(1)], today=day + timedelta(days=1), seen_file=seen)
    assert (len(first.recorded), len(again.recorded), len(tomorrow.recorded)) == (1, 0, 1)
    assert len(again.already_today) == 1
    entries = list(ledger.entries())
    assert [e.action for e in entries] == ["soc.finding.exposed_service"] * 2
    assert all(e.plane is Plane.SOC for e in entries)


def test_a_flood_of_findings_cannot_fill_the_ledger(ledger: Ledger, tmp_path: Path) -> None:
    flood = [finding(n) for n in range(500)]
    outcome = record(ledger, flood, today=date(2026, 10, 4), seen_file=tmp_path / "seen.json")
    entries = list(ledger.entries())
    assert len(outcome.recorded) == MAX_PER_RUN
    assert len(entries) == MAX_PER_RUN + 1, "the ceiling, plus one entry saying so"
    assert entries[-1].action == OVER_CEILING_ACTION
    assert "490" in entries[-1].verdict.reason


def test_a_lost_record_of_what_was_recorded_costs_one_repeat_not_a_flood(
    ledger: Ledger, tmp_path: Path
) -> None:
    seen = tmp_path / "seen.json"
    record(ledger, [finding(1)], today=date(2026, 10, 4), seen_file=seen)
    seen.write_text("{not json", encoding="utf-8")
    outcome = record(ledger, [finding(1)], today=date(2026, 10, 4), seen_file=seen)
    assert len(outcome.recorded) == 1


def args(view: str, *, dry_run: bool = False) -> argparse.Namespace:
    return argparse.Namespace(view=view, top=25, dry_run=dry_run)


def planted() -> Snapshot:
    return snap(
        [
            proc(20, "mysqld.exe", "C:\\db\\mysqld.exe"),
            proc(21, "svchost.exe", "C:\\Temp\\svchost.exe"),
        ],
        [listener(3306, 20)],
    )


def test_a_look_records_only_its_findings(ledger: Ledger, monkeypatch: pytest.MonkeyPatch) -> None:
    lines: list[str] = []
    code = soc_cli.run(args("processes"), ledger, look=lambda **_: planted(), out=lines.append)
    assert code == 0
    actions = [e.action for e in ledger.entries()]
    assert sorted(actions) == ["soc.finding.exposed_service", "soc.finding.system_name_elsewhere"]
    assert "Recorded 2" in "\n".join(lines)


def test_a_dry_run_records_nothing(ledger: Ledger) -> None:
    lines: list[str] = []
    assert (
        soc_cli.run(
            args("network", dry_run=True), ledger, look=lambda **_: planted(), out=lines.append
        )
        == 0
    )
    assert list(ledger.entries()) == []
    assert "Dry run: nothing was recorded." in lines


def test_without_the_flag_it_asks_for_sletchys_own_only(ledger: Ledger) -> None:
    asked: list[bool] = []

    def look(*, whole_machine: bool) -> Snapshot:
        asked.append(whole_machine)
        return planted()

    soc_cli.run(args("processes", dry_run=True), ledger, look=look, out=lambda _: None)
    assert asked == [False]


def test_where_connections_go_is_never_shown_or_recorded(ledger: Ledger) -> None:
    connection = Sock(
        protocol="tcp",
        local_address="198.51.100.5",
        local_port=50000,
        remote_address="203.0.113.7",
        remote_port=443,
        state=TcpState.ESTABLISHED,
        pid=20,
    )
    lines: list[str] = []
    snapshot = snap([proc(20, "app.exe", "C:\\app\\app.exe")], [connection])
    soc_cli.run(args("network"), ledger, look=lambda **_: snapshot, out=lines.append)
    assert "203.0.113.7" not in "\n".join(lines)
    assert all("203.0.113.7" not in e.model_dump_json() for e in ledger.entries())


# ── LAW 0: it looks, and it can only look ───────────────────────────────────

#: Every Win32 function the sensor may bind. Each reads; none changes anything.
QUERIES = {
    "NtQuerySystemInformation",
    "OpenProcess",
    "QueryFullProcessImageNameW",
    "CloseHandle",
    "GetSystemWindowsDirectoryW",
    "GetExtendedTcpTable",
    "GetExtendedUdpTable",
    "EvtQuery",
    "EvtNext",
    "EvtRender",
    "EvtClose",
}


@pytest.mark.law_zero
def test_every_win32_call_the_sensor_binds_is_a_query() -> None:
    """Read from the source, so it holds on Linux CI too, where the module cannot load."""
    tree = ast.parse(SENSOR_SOURCE.read_text("utf-8"))
    bound = {
        call.args[1].value
        for call in ast.walk(tree)
        if isinstance(call, ast.Call)
        and isinstance(call.func, ast.Name)
        and call.func.id == "_bind"
        and isinstance(call.args[1], ast.Constant)
    }
    assert bound == QUERIES
    assert "WinDLL(" in SENSOR_SOURCE.read_text("utf-8")
    dlls = {"_k32", "_ntdll", "_iphlp", "_wevtapi"}
    other = [
        node.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id in dlls
    ]
    assert other == [], "every binding goes through _bind, so the list above is complete"


@pytest.mark.law_zero
def test_the_one_handle_it_opens_can_only_read_a_name() -> None:
    """`PROCESS_QUERY_LIMITED_INFORMATION`: no memory reads, no suspend, no terminate."""
    tree = ast.parse(SENSOR_SOURCE.read_text("utf-8"))
    opens = [
        call
        for call in ast.walk(tree)
        if isinstance(call, ast.Call)
        and isinstance(call.func, ast.Name)
        and call.func.id == "_OpenProcess"
    ]
    assert len(opens) == 1
    access = opens[0].args[0]
    assert isinstance(access, ast.Name) and access.id == "PROCESS_QUERY_LIMITED_INFORMATION"
    assert "PROCESS_QUERY_LIMITED_INFORMATION = 0x1000" in SENSOR_SOURCE.read_text("utf-8")


@pytest.mark.law_zero
def test_the_soc_never_asks_for_elevation() -> None:
    source = "\n".join(p.read_text("utf-8") for p in SENSOR_SOURCE.parents[1].rglob("*.py")).lower()
    for call in (
        "runas",
        "shellexecute",
        "sedebugprivilege",
        "adjusttokenprivileges",
        "openprocesstoken",
    ):
        assert call not in source, call


# ── the sensor reads this machine correctly ─────────────────────────────────


@needs_windows
def test_the_process_record_layout_is_the_one_windows_uses() -> None:
    import ctypes

    from sletchy.soc.sensors import _win32

    record = _win32._SystemProcessInformation
    offsets = {
        name: getattr(record, name).offset
        for name in ("ImageName", "UniqueProcessId", "WorkingSetSize")
    }
    assert ctypes.sizeof(ctypes.c_void_p) == 8, "the layout below is the 64-bit one"
    assert offsets == {"ImageName": 56, "UniqueProcessId": 80, "WorkingSetSize": 144}


@needs_windows
def test_the_sensor_reads_this_process_correctly() -> None:
    """Positive control: facts known before looking."""
    from sletchy.soc.sensors import _win32

    processes = {p.pid: p for p in _win32.read_processes()}
    me = processes[os.getpid()]
    assert me.name.lower().startswith("python")
    assert me.parent == os.getppid()
    assert me.path is not None and me.path.lower().endswith(".exe")
    assert 10 * 1024 * 1024 < me.memory_bytes < 8 * 1024**3
    assert me.cpu_seconds > 0
    assert me.started is not None and me.started <= datetime.now(UTC)


@needs_windows
def test_the_socket_reader_reads_ports_the_right_way_round() -> None:
    """Windows always listens on 135. Read with the bytes swapped, it would be 34560."""
    from sletchy.soc.sensors import _win32

    sockets = _win32.read_sockets()
    assert any(s.listening and s.local_port == 135 for s in sockets)
    assert not any(s.listening and s.local_port == 34560 for s in sockets)


@needs_windows
def test_a_snapshot_of_the_real_machine_says_what_it_could_not_read() -> None:
    """#146's definition of done: the real machine, unelevated, with its count of the
    unreadable. Read-only; nothing is recorded."""
    from sletchy.soc.sensors.snapshot import take

    snapshot = take(whole_machine=True)
    unreadable = sum(1 for p in snapshot.processes if p.path is None)
    assert len(snapshot.processes) > 20
    assert 0 < unreadable < len(snapshot.processes), "some are always closed to an ordinary user"
    assert any(s.listening for s in snapshot.sockets)
    own_only = take(whole_machine=False)
    assert os.getpid() in {p.pid for p in own_only.processes}
    assert len(own_only.processes) < len(snapshot.processes)
