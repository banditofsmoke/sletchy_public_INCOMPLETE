"""The Win32 surface the SOC's sensors read, and nothing else (#146).

Every function bound here is a query. `BOUND` lists them, and a LAW 0 test holds the
list to an allowlist of read-only calls, so a binding that could change the machine
fails the build before it is ever called. The one handle this module opens on another
process asks for `PROCESS_QUERY_LIMITED_INFORMATION` and nothing more: enough to read
its path, never enough to read its memory, suspend it or end it.

Four sources, each chosen because it needs no elevation:

1. `NtQuerySystemInformation(SystemProcessInformation)`: every process, with its
   parent, memory, CPU time and start time, without opening any of them. It is what
   Task Manager reads. Measured on 10.0.19045: it lists every process, where opening
   each one unelevated read the path of only 65 of 210 (2026-10-04)
2. `QueryFullProcessImageNameW`: a process's executable path, where Windows lets an
   ordinary user open it. Where it does not, the path is `None`, shown as "could not
   read", never guessed (L009)
3. `GetExtendedTcpTable` and `GetExtendedUdpTable`: every socket and its owning
   process
4. `EvtQuery`, `EvtNext`, `EvtRender` and `EvtClose`: entries of the System log,
   for `sletchy-soc events`

This module raises `ImportError` off Windows rather than degrading.
"""

from __future__ import annotations

import ctypes
import ipaddress
import sys
from collections.abc import Callable
from ctypes import wintypes
from datetime import UTC, datetime, timedelta
from typing import Any

if sys.platform != "win32":  # pragma: no cover - imported only on Windows
    raise ImportError("sletchy.soc.sensors._win32 is Windows-only")

from sletchy.soc.sensors.model import Proc, Sock, TcpState

#: Every Win32 function this module binds. Held to a read-only allowlist by
#: `test_soc_sensors.py::test_every_win32_call_the_sensor_binds_is_a_query`.
BOUND: list[str] = []

_ntdll = ctypes.WinDLL("ntdll")
_k32 = ctypes.WinDLL("kernel32", use_last_error=True)
_iphlp = ctypes.WinDLL("iphlpapi")


def _bind(dll: ctypes.WinDLL, name: str, argtypes: list[Any], restype: Any) -> Any:
    function = getattr(dll, name)
    function.argtypes = argtypes
    function.restype = restype  # every binding has one (L004)
    BOUND.append(name)
    return function


_NtQuerySystemInformation = _bind(
    _ntdll,
    "NtQuerySystemInformation",
    [ctypes.c_int, ctypes.c_void_p, wintypes.ULONG, ctypes.POINTER(wintypes.ULONG)],
    ctypes.c_long,
)
_OpenProcess = _bind(
    _k32, "OpenProcess", [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD], wintypes.HANDLE
)
_QueryFullProcessImageNameW = _bind(
    _k32,
    "QueryFullProcessImageNameW",
    [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)],
    wintypes.BOOL,
)
_CloseHandle = _bind(_k32, "CloseHandle", [wintypes.HANDLE], wintypes.BOOL)
_GetSystemWindowsDirectoryW = _bind(
    _k32, "GetSystemWindowsDirectoryW", [wintypes.LPWSTR, wintypes.UINT], wintypes.UINT
)
_GetExtendedTcpTable = _bind(
    _iphlp,
    "GetExtendedTcpTable",
    [
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.BOOL,
        wintypes.ULONG,
        ctypes.c_int,
        wintypes.ULONG,
    ],
    wintypes.DWORD,
)
_GetExtendedUdpTable = _bind(
    _iphlp,
    "GetExtendedUdpTable",
    [
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.BOOL,
        wintypes.ULONG,
        ctypes.c_int,
        wintypes.ULONG,
    ],
    wintypes.DWORD,
)

#: The only access this module ever asks of another process.
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

_SYSTEM_PROCESS_INFORMATION_CLASS = 5
_STATUS_INFO_LENGTH_MISMATCH = 0xC0000004
_ERROR_INSUFFICIENT_BUFFER = 122
_AF_INET, _AF_INET6 = 2, 23
_TCP_TABLE_OWNER_PID_ALL = 5
_UDP_TABLE_OWNER_PID = 1
_EPOCH_1601 = datetime(1601, 1, 1, tzinfo=UTC)


class _UnicodeString(ctypes.Structure):
    _fields_ = [
        ("Length", wintypes.USHORT),
        ("MaximumLength", wintypes.USHORT),
        ("Buffer", ctypes.c_void_p),
    ]


class _SystemProcessInformation(ctypes.Structure):
    """The fixed head of each record. The layout is the one the kernel has kept since
    Windows Vista; `test_the_process_record_layout_is_the_one_windows_uses` checks
    the offsets that matter, and the real-machine test checks a known process."""

    _fields_ = [
        ("NextEntryOffset", wintypes.ULONG),
        ("NumberOfThreads", wintypes.ULONG),
        ("WorkingSetPrivateSize", ctypes.c_longlong),
        ("HardFaultCount", wintypes.ULONG),
        ("NumberOfThreadsHighWatermark", wintypes.ULONG),
        ("CycleTime", ctypes.c_ulonglong),
        ("CreateTime", ctypes.c_longlong),
        ("UserTime", ctypes.c_longlong),
        ("KernelTime", ctypes.c_longlong),
        ("ImageName", _UnicodeString),
        ("BasePriority", ctypes.c_long),
        ("UniqueProcessId", ctypes.c_void_p),
        ("InheritedFromUniqueProcessId", ctypes.c_void_p),
        ("HandleCount", wintypes.ULONG),
        ("SessionId", wintypes.ULONG),
        ("UniqueProcessKey", ctypes.c_void_p),
        ("PeakVirtualSize", ctypes.c_size_t),
        ("VirtualSize", ctypes.c_size_t),
        ("PageFaultCount", wintypes.ULONG),
        ("PeakWorkingSetSize", ctypes.c_size_t),
        ("WorkingSetSize", ctypes.c_size_t),
    ]


def _system_process_records() -> ctypes.Array[ctypes.c_char]:
    """The kernel's buffer itself. Each record's name points into it, so the records
    must be read from this object while it is alive, never from a copy."""
    size = 1 << 20
    for _ in range(8):
        buffer = ctypes.create_string_buffer(size)
        needed = wintypes.ULONG(0)
        status = (
            _NtQuerySystemInformation(
                _SYSTEM_PROCESS_INFORMATION_CLASS, buffer, size, ctypes.byref(needed)
            )
            & 0xFFFFFFFF
        )
        if status == 0:
            return buffer
        if status != _STATUS_INFO_LENGTH_MISMATCH:
            msg = f"NtQuerySystemInformation failed: 0x{status:08X}"
            raise OSError(msg)
        size = max(size * 2, needed.value + (64 << 10))
    msg = "the process list kept growing faster than it could be read"
    raise OSError(msg)


def _path_of(pid: int) -> str | None:
    """The executable's path, or None where Windows does not let an ordinary user look."""
    handle = _OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return None
    try:
        buffer = ctypes.create_unicode_buffer(32768)
        size = wintypes.DWORD(32768)
        if not _QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)):
            return None
        return buffer.value or None
    finally:
        _CloseHandle(handle)


def read_processes() -> list[Proc]:
    buffer = _system_process_records()
    base = ctypes.addressof(buffer)
    end = base + len(buffer)
    processes: list[Proc] = []
    offset = 0
    while True:
        if base + offset + ctypes.sizeof(_SystemProcessInformation) > end:
            msg = "a process record runs past the end of the list"
            raise OSError(msg)
        record = _SystemProcessInformation.from_address(base + offset)
        pid = int(record.UniqueProcessId or 0)
        name_length = record.ImageName.Length // 2
        name_at = record.ImageName.Buffer or 0
        if name_at and name_length and base <= name_at and name_at + 2 * name_length <= end:
            name = ctypes.wstring_at(name_at, name_length)
        else:
            name = "System Idle Process" if pid == 0 else ""
        started = None
        if record.CreateTime > 0:
            started = _EPOCH_1601 + timedelta(microseconds=record.CreateTime // 10)
        processes.append(
            Proc(
                pid=pid,
                parent=int(record.InheritedFromUniqueProcessId or 0),
                name=name,
                path=_path_of(pid) if pid > 4 else None,
                memory_bytes=int(record.WorkingSetSize),
                cpu_seconds=(record.UserTime + record.KernelTime) / 10_000_000,
                threads=int(record.NumberOfThreads),
                handles=int(record.HandleCount),
                started=started,
            )
        )
        if record.NextEntryOffset == 0:
            return processes
        offset += record.NextEntryOffset


def windows_folder() -> str:
    buffer = ctypes.create_unicode_buffer(260)
    if not _GetSystemWindowsDirectoryW(buffer, 260):
        raise ctypes.WinError(ctypes.get_last_error())
    return buffer.value


# ── sockets ──────────────────────────────────────────────────────────────────


class _TcpRow4(ctypes.Structure):
    _fields_ = [
        ("state", wintypes.DWORD),
        ("local_addr", wintypes.DWORD),
        ("local_port", wintypes.DWORD),
        ("remote_addr", wintypes.DWORD),
        ("remote_port", wintypes.DWORD),
        ("pid", wintypes.DWORD),
    ]


class _TcpRow6(ctypes.Structure):
    _fields_ = [
        ("local_addr", ctypes.c_ubyte * 16),
        ("local_scope", wintypes.DWORD),
        ("local_port", wintypes.DWORD),
        ("remote_addr", ctypes.c_ubyte * 16),
        ("remote_scope", wintypes.DWORD),
        ("remote_port", wintypes.DWORD),
        ("state", wintypes.DWORD),
        ("pid", wintypes.DWORD),
    ]


class _UdpRow4(ctypes.Structure):
    _fields_ = [
        ("local_addr", wintypes.DWORD),
        ("local_port", wintypes.DWORD),
        ("pid", wintypes.DWORD),
    ]


class _UdpRow6(ctypes.Structure):
    _fields_ = [
        ("local_addr", ctypes.c_ubyte * 16),
        ("local_scope", wintypes.DWORD),
        ("local_port", wintypes.DWORD),
        ("pid", wintypes.DWORD),
    ]


def _rows(
    function: Callable[..., int], family: int, table_class: int, row: type[ctypes.Structure]
) -> list[Any]:
    """Every row of one socket table, each copied out of the buffer it arrived in."""
    size = wintypes.DWORD(0)
    for _ in range(8):
        buffer = ctypes.create_string_buffer(max(size.value, 4))
        result = function(buffer, ctypes.byref(size), False, family, table_class, 0)
        if result == 0:
            break
        if result != _ERROR_INSUFFICIENT_BUFFER:
            raise ctypes.WinError(result)
    else:
        msg = "the socket table kept growing faster than it could be read"
        raise OSError(msg)
    count = ctypes.c_uint32.from_buffer(buffer).value
    # A DWORD count, then the rows, aligned to the row's own alignment.
    first = ctypes.sizeof(wintypes.DWORD)
    first += (-first) % ctypes.alignment(row)
    if first + count * ctypes.sizeof(row) > len(buffer):
        msg = "the socket table claims more rows than it holds"
        raise OSError(msg)
    return [row.from_buffer_copy(buffer, first + i * ctypes.sizeof(row)) for i in range(count)]


def _port(value: int) -> int:
    """Ports arrive in network byte order in the low 16 bits."""
    return ((value & 0xFF) << 8) | ((value >> 8) & 0xFF)


def _v4(value: int) -> str:
    return str(ipaddress.IPv4Address(value.to_bytes(4, "little")))


def _v6(raw: Any) -> str:
    return str(ipaddress.IPv6Address(bytes(raw)))


def _tcp(r: Any, address: Callable[[Any], str]) -> Sock:
    state = TcpState.of(r.state)
    listening = state is TcpState.LISTEN
    return Sock(
        protocol="tcp",
        local_address=address(r.local_addr),
        local_port=_port(r.local_port),
        remote_address=None if listening else address(r.remote_addr),
        remote_port=None if listening else _port(r.remote_port),
        state=state,
        pid=int(r.pid),
    )


def _udp(r: Any, address: Callable[[Any], str]) -> Sock:
    return Sock(
        protocol="udp",
        local_address=address(r.local_addr),
        local_port=_port(r.local_port),
        remote_address=None,
        remote_port=None,
        state=TcpState.NONE,
        pid=int(r.pid),
    )


def read_sockets() -> list[Sock]:
    tcp, udp = _GetExtendedTcpTable, _GetExtendedUdpTable
    return [
        *(_tcp(r, _v4) for r in _rows(tcp, _AF_INET, _TCP_TABLE_OWNER_PID_ALL, _TcpRow4)),
        *(_tcp(r, _v6) for r in _rows(tcp, _AF_INET6, _TCP_TABLE_OWNER_PID_ALL, _TcpRow6)),
        *(_udp(r, _v4) for r in _rows(udp, _AF_INET, _UDP_TABLE_OWNER_PID, _UdpRow4)),
        *(_udp(r, _v6) for r in _rows(udp, _AF_INET6, _UDP_TABLE_OWNER_PID, _UdpRow6)),
    ]


# ── the System log (#146, `sletchy-soc events`) ──────────────────────────────

_wevtapi = ctypes.WinDLL("wevtapi", use_last_error=True)

_EvtQuery = _bind(
    _wevtapi,
    "EvtQuery",
    [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD],
    wintypes.HANDLE,
)
_EvtNext = _bind(
    _wevtapi,
    "EvtNext",
    [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ],
    wintypes.BOOL,
)
_EvtRender = _bind(
    _wevtapi,
    "EvtRender",
    [
        wintypes.HANDLE,
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD),
    ],
    wintypes.BOOL,
)
_EvtClose = _bind(_wevtapi, "EvtClose", [wintypes.HANDLE], wintypes.BOOL)

_EVT_QUERY_CHANNEL_PATH = 0x1
_EVT_QUERY_REVERSE_DIRECTION = 0x200
_EVT_RENDER_EVENT_XML = 1
_ERROR_NO_MORE_ITEMS = 259
_INFINITE = 0xFFFFFFFF
_BATCH = 64


def _render(event: int | None) -> str:
    used = wintypes.DWORD(0)
    count = wintypes.DWORD(0)
    size = 4096
    for _ in range(4):
        buffer = ctypes.create_string_buffer(size)
        if _EvtRender(
            None,
            event,
            _EVT_RENDER_EVENT_XML,
            size,
            buffer,
            ctypes.byref(used),
            ctypes.byref(count),
        ):
            return buffer.raw[: used.value].decode("utf-16-le").rstrip("\x00")
        if ctypes.get_last_error() != _ERROR_INSUFFICIENT_BUFFER:
            raise ctypes.WinError(ctypes.get_last_error())
        size = used.value + 2
    msg = "an event kept growing while it was rendered"
    raise OSError(msg)


def read_events(channel: str, xpath: str, cap: int) -> tuple[list[str], bool]:
    """Each matching event as XML, newest first; and whether `cap` cut the list short.

    An empty list is only "nothing matched" when the query itself succeeded: a query
    that fails raises, so it can never be read as "no crashes" (L009).
    """
    query = _EvtQuery(None, channel, xpath, _EVT_QUERY_CHANNEL_PATH | _EVT_QUERY_REVERSE_DIRECTION)
    if not query:
        raise ctypes.WinError(ctypes.get_last_error())
    events: list[str] = []
    try:
        handles = (wintypes.HANDLE * _BATCH)()
        while len(events) < cap:
            returned = wintypes.DWORD(0)
            if not _EvtNext(query, _BATCH, handles, _INFINITE, 0, ctypes.byref(returned)):
                error = ctypes.get_last_error()
                if error == _ERROR_NO_MORE_ITEMS:
                    return events, False
                raise ctypes.WinError(error)
            for i in range(returned.value):
                try:
                    if len(events) < cap:
                        events.append(_render(handles[i]))
                finally:
                    _EvtClose(handles[i])
        return events, True
    finally:
        _EvtClose(query)
