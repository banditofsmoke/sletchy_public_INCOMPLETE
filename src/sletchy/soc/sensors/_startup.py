"""What starts with the machine, read without changing it (#146, `sletchy-soc startup`).

**This file is the one place in shipped code allowed to name the registry's startup
keys** (the operator's decision, 2026-10-04). The LAW 0 scan refuses that path
everywhere else, because writing there makes a program start at boot. Here it is only
read, and two tests hold that true: every call bound below is a read, and no other
LAW 0 rule fires anywhere in this file (`test_law_zero.py`, `READ_ONLY_SENSORS`).

Four places, each read the way an ordinary user can:

1. **The startup keys**: `Run` and `RunOnce`, for this user and for the machine, in
   both registry views, through `RegOpenKeyExW` with `KEY_READ` only
2. **The Startup folders**: this user's and everyone's, listed
3. **Automatic services**: each service's own registry key (start type, program,
   account). No service control manager is opened
4. **Scheduled tasks that run at logon or boot**: through the Task Scheduler's own
   read interface, in a PowerShell query that only reads, the way `sletchy panic`
   counts firewall rules. Its task files cannot be listed by an ordinary user

What cannot be read is counted and said, never guessed (L009). This module raises
`ImportError` off Windows.
"""

from __future__ import annotations

import ctypes
import json
import os
import shutil
import subprocess
import sys
from ctypes import wintypes
from pathlib import Path
from typing import Any

if sys.platform != "win32":  # pragma: no cover - imported only on Windows
    raise ImportError("sletchy.soc.sensors._startup is Windows-only")

from sletchy.soc.sensors.startup import Autostart

#: Every Win32 function this module binds. Held to a read-only allowlist by
#: `test_soc_startup.py::test_every_call_the_startup_reader_binds_is_a_read`.
BOUND: list[str] = []

_advapi32 = ctypes.WinDLL("advapi32")


def _bind(dll: ctypes.WinDLL, name: str, argtypes: list[Any], restype: Any) -> Any:
    function = getattr(dll, name)
    function.argtypes = argtypes
    function.restype = restype  # every binding has one (L004)
    BOUND.append(name)
    return function


_HKEY = wintypes.HANDLE
_RegOpenKeyExW = _bind(
    _advapi32,
    "RegOpenKeyExW",
    [_HKEY, wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(_HKEY)],
    wintypes.LONG,
)
_RegEnumValueW = _bind(
    _advapi32,
    "RegEnumValueW",
    [
        _HKEY,
        wintypes.DWORD,
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.DWORD),
    ],
    wintypes.LONG,
)
_RegEnumKeyExW = _bind(
    _advapi32,
    "RegEnumKeyExW",
    [
        _HKEY,
        wintypes.DWORD,
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ],
    wintypes.LONG,
)
_RegQueryValueExW = _bind(
    _advapi32,
    "RegQueryValueExW",
    [
        _HKEY,
        wintypes.LPCWSTR,
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.DWORD),
    ],
    wintypes.LONG,
)
_RegCloseKey = _bind(_advapi32, "RegCloseKey", [_HKEY], wintypes.LONG)

# ── is a program signed by a publisher Windows trusts ────────────────────────

_wintrust = ctypes.WinDLL("wintrust")


class _GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", ctypes.c_ubyte * 8),
    ]


class _FileInfo(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("pcwszFilePath", wintypes.LPCWSTR),
        ("hFile", wintypes.HANDLE),
        ("pgKnownSubject", ctypes.c_void_p),
    ]


class _TrustData(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("pPolicyCallbackData", ctypes.c_void_p),
        ("pSIPClientData", ctypes.c_void_p),
        ("dwUIChoice", wintypes.DWORD),
        ("fdwRevocationChecks", wintypes.DWORD),
        ("dwUnionChoice", wintypes.DWORD),
        ("pFile", ctypes.POINTER(_FileInfo)),
        ("dwStateAction", wintypes.DWORD),
        ("hWVTStateData", wintypes.HANDLE),
        ("pwszURLReference", wintypes.LPCWSTR),
        ("dwProvFlags", wintypes.DWORD),
        ("dwUIContext", wintypes.DWORD),
        ("pSignatureSettings", ctypes.c_void_p),
    ]


_WinVerifyTrust = _bind(
    _wintrust,
    "WinVerifyTrust",
    [wintypes.HANDLE, ctypes.POINTER(_GUID), ctypes.POINTER(_TrustData)],
    wintypes.LONG,
)

#: WINTRUST_ACTION_GENERIC_VERIFY_V2: verify a file's Authenticode signature.
_VERIFY_V2 = _GUID(
    0x00AAC56B, 0xCD44, 0x11D0, (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE)
)
_NO_WINDOW = wintypes.HANDLE(-1)
_UI_NONE, _REVOKE_NONE, _CHOICE_FILE = 2, 0, 1
_VERIFY, _CLOSE = 1, 2
#: Never go online: no revocation lookup, and only what is already cached. A check
#: that fetched a revocation list would be Sletchy reaching the internet unasked.
NO_NETWORK = 0x10 | 0x1000  # WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL


def signed(path: str) -> bool:
    """True when the file carries a signature from a publisher Windows trusts.

    It says who signed a program, not whether the program is safe. Checked offline.
    """
    info = _FileInfo(ctypes.sizeof(_FileInfo), path, None, None)
    data = _TrustData(
        cbStruct=ctypes.sizeof(_TrustData),
        dwUIChoice=_UI_NONE,
        fdwRevocationChecks=_REVOKE_NONE,
        dwUnionChoice=_CHOICE_FILE,
        pFile=ctypes.pointer(info),
        dwStateAction=_VERIFY,
        dwProvFlags=NO_NETWORK,
    )
    try:
        status: int = _WinVerifyTrust(_NO_WINDOW, ctypes.byref(_VERIFY_V2), ctypes.byref(data))
        return status == 0
    finally:
        data.dwStateAction = _CLOSE
        _WinVerifyTrust(_NO_WINDOW, ctypes.byref(_VERIFY_V2), ctypes.byref(data))


#: The only access this module asks of a registry key.
KEY_READ = 0x20019
_KEY_WOW64_64KEY = 0x0100
_HKCU = _HKEY(0x80000001)
_HKLM = _HKEY(0x80000002)
_ERROR_SUCCESS, _ERROR_NO_MORE_ITEMS, _ERROR_MORE_DATA = 0, 259, 234
_REG_SZ, _REG_EXPAND_SZ, _REG_DWORD = 1, 2, 4

_STARTUP_KEYS = (
    ("this user", _HKCU, "Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
    ("this user, once", _HKCU, "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),
    ("every user", _HKLM, "Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
    ("every user, once", _HKLM, "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),
    ("every user, 32-bit", _HKLM, "Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run"),
)
_SERVICES = "SYSTEM\\CurrentControlSet\\Services"
_AUTOMATIC = 2
_WIN32_SERVICE = 0x10 | 0x20  # own process, or shared; drivers are not services here


class Unreadable(Exception):
    """A place that could not be read. Counted, never taken for empty."""


def _open(root: Any, path: str) -> Any:
    key = _HKEY()
    status = _RegOpenKeyExW(root, path, 0, KEY_READ | _KEY_WOW64_64KEY, ctypes.byref(key))
    if status == 2:  # the key does not exist: nothing is set to start from here
        return None
    if status != _ERROR_SUCCESS:
        raise Unreadable(f"{path}: error {status}")
    return key


def _values(key: Any) -> list[tuple[str, int, bytes]]:
    found: list[tuple[str, int, bytes]] = []
    index = 0
    while True:
        name = ctypes.create_unicode_buffer(16384)
        name_len = wintypes.DWORD(16384)
        kind = wintypes.DWORD(0)
        size = wintypes.DWORD(65536)
        data = ctypes.create_string_buffer(65536)
        status = _RegEnumValueW(
            key,
            index,
            name,
            ctypes.byref(name_len),
            None,
            ctypes.byref(kind),
            data,
            ctypes.byref(size),
        )
        if status == _ERROR_NO_MORE_ITEMS:
            return found
        if status != _ERROR_SUCCESS:
            raise Unreadable(f"value {index}: error {status}")
        found.append((name.value, kind.value, data.raw[: size.value]))
        index += 1


def _subkeys(key: Any) -> list[str]:
    names: list[str] = []
    index = 0
    while True:
        name = ctypes.create_unicode_buffer(512)
        name_len = wintypes.DWORD(512)
        status = _RegEnumKeyExW(key, index, name, ctypes.byref(name_len), None, None, None, None)
        if status == _ERROR_NO_MORE_ITEMS:
            return names
        if status != _ERROR_SUCCESS:
            raise Unreadable(f"subkey {index}: error {status}")
        names.append(name.value)
        index += 1


def _query(key: Any, value: str) -> tuple[int, bytes] | None:
    kind = wintypes.DWORD(0)
    size = wintypes.DWORD(65536)
    data = ctypes.create_string_buffer(65536)
    status = _RegQueryValueExW(key, value, None, ctypes.byref(kind), data, ctypes.byref(size))
    if status != _ERROR_SUCCESS:
        return None
    return kind.value, data.raw[: size.value]


def _text(kind: int, raw: bytes) -> str | None:
    if kind not in (_REG_SZ, _REG_EXPAND_SZ):
        return None
    return raw.decode("utf-16-le", errors="replace").split("\x00", 1)[0]


def run_keys() -> tuple[list[Autostart], int]:
    entries: list[Autostart] = []
    unreadable = 0
    for scope, root, path in _STARTUP_KEYS:
        try:
            key = _open(root, path)
            if key is None:
                continue
            try:
                for name, kind, raw in _values(key):
                    command = _text(kind, raw)
                    if command is not None:
                        entries.append(
                            Autostart(kind="registry", where=scope, name=name, command=command)
                        )
            finally:
                _RegCloseKey(key)
        except Unreadable:
            unreadable += 1
    return entries, unreadable


def startup_folders() -> tuple[list[Autostart], int]:
    entries: list[Autostart] = []
    unreadable = 0
    folders = (
        (
            "this user",
            os.environ.get("APPDATA", ""),
            "Microsoft\\Windows\\Start Menu\\Programs\\Startup",
        ),
        (
            "every user",
            os.environ.get("PROGRAMDATA", ""),
            "Microsoft\\Windows\\Start Menu\\Programs\\StartUp",
        ),
    )
    for scope, base, rest in folders:
        if not base:
            unreadable += 1
            continue
        folder = Path(base) / rest
        try:
            names = sorted(p.name for p in folder.iterdir() if p.name.lower() != "desktop.ini")
        except FileNotFoundError:
            continue
        except OSError:
            unreadable += 1
            continue
        entries += [
            Autostart(kind="folder", where=scope, name=n, command=str(folder / n)) for n in names
        ]
    return entries, unreadable


def services() -> tuple[list[Autostart], int]:
    entries: list[Autostart] = []
    unreadable = 0
    try:
        root = _open(_HKLM, _SERVICES)
    except Unreadable:
        return [], 1
    if root is None:
        return [], 1
    try:
        names = _subkeys(root)
    finally:
        _RegCloseKey(root)
    for name in names:
        try:
            key = _open(_HKLM, f"{_SERVICES}\\{name}")
        except Unreadable:
            unreadable += 1
            continue
        if key is None:
            continue
        try:
            start, kind, image, account = (
                _query(key, v) for v in ("Start", "Type", "ImagePath", "ObjectName")
            )
        finally:
            _RegCloseKey(key)
        if not start or not kind or start[0] != _REG_DWORD or kind[0] != _REG_DWORD:
            continue
        if int.from_bytes(start[1][:4], "little") != _AUTOMATIC:
            continue
        if not int.from_bytes(kind[1][:4], "little") & _WIN32_SERVICE:
            continue
        command = _text(*image) if image else None
        entries.append(
            Autostart(
                kind="service",
                where=(_text(*account) if account else None) or "LocalSystem",
                name=name,
                command=command or "",
            )
        )
    return entries, unreadable


#: Read-only: the Task Scheduler's own interface, every folder this user may see, and
#: only tasks with a boot or logon trigger. Nothing is created, changed or run. A task's
#: run level is least privilege or the highest available, and nothing else, so "runs
#: elevated" is read as "not least privilege": the query never names the elevated level,
#: which the LAW 0 catalogue and the test shield refuse in any command.
TASKS_SCRIPT = (
    "$ErrorActionPreference = 'SilentlyContinue'; "
    "$s = New-Object -ComObject Schedule.Service; $s.Connect(); $out = @(); $denied = 0; "
    "function Walk($f) { "
    "  foreach ($t in @($f.GetTasks(1))) { "
    "    $x = [xml]$t.Xml; $tr = @($x.Task.Triggers.ChildNodes | ForEach-Object { $_.LocalName }); "
    "    if ($tr -contains 'BootTrigger' -or $tr -contains 'LogonTrigger') { "
    "      $a = @($x.Task.Actions.Exec | ForEach-Object { ($_.Command + ' ' + $_.Arguments).Trim() }); "
    "      $script:out += [pscustomobject]@{ path = $t.Path; enabled = $t.Enabled; "
    "        highest = ([string]$x.Task.Principals.Principal.RunLevel -notin @('', 'LeastPrivilege')); "
    "        user = [string]$x.Task.Principals.Principal.UserId; actions = $a } } }; "
    "  foreach ($sub in @($f.GetFolders(0))) { try { Walk $sub } catch { $script:denied++ } } }; "
    "Walk ($s.GetFolder('\\')); "
    "[pscustomobject]@{ tasks = $out; denied = $denied } | ConvertTo-Json -Depth 4 -Compress"
)


def tasks() -> tuple[list[Autostart], int]:
    if shutil.which("powershell") is None:
        return [], 1
    try:
        result = subprocess.run(  # noqa: S603
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", TASKS_SCRIPT],  # noqa: S607
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        data = json.loads(result.stdout or "null")
    except (subprocess.SubprocessError, ValueError):
        return [], 1
    if result.returncode != 0 or not isinstance(data, dict):
        return [], 1
    found = data.get("tasks") or []
    if isinstance(found, dict):  # one task: ConvertTo-Json gives an object, not a list
        found = [found]
    entries = []
    for task in found:
        actions = task.get("actions") or []
        if isinstance(actions, str):
            actions = [actions]
        entries.append(
            Autostart(
                kind="task",
                where=("administrator rights" if task.get("highest") else "ordinary rights")
                + ("" if task.get("enabled", True) else ", disabled"),
                name=str(task.get("path", "")),
                command="; ".join(str(a) for a in actions),
            )
        )
    return entries, int(data.get("denied") or 0)
