"""The Win32 surface `winjob` needs, and nothing else.

Thin by design: structures, bindings, and four small wrappers. **No policy lives
here** - what to limit and what to deny is `winjob`'s decision, and mixing the two
would make the enforcement logic untestable without a real container.

Everything here was measured on Windows 10 Pro 10.0.19045 before it was written;
the findings are in [ADR-0005](../../../../docs/adr/0005-appcontainer-findings.md)
and the four this module depends on that ADR-0005 left open are recorded in
`tests/adversarial/COVERAGE.md`.

Three behaviours are not obvious and are load-bearing:

1. **The job is attached at creation**, via `PROC_THREAD_ATTRIBUTE_JOB_LIST`, in
   the same attribute list as the AppContainer. There is no `CREATE_SUSPENDED`
   window in which the child exists outside its limits, because a window in a
   security boundary is a race ([LAW 0 §5](../../../../docs/LAW/00-do-no-harm.md)).
2. **Output comes back through a handle the parent opened.** A contained child
   cannot open the null device, so anything that redirects inside the sandbox
   measures its own plumbing rather than the sandbox (ADR-0005 §4).
3. **An explicit environment block must carry `LOCALAPPDATA`.** The AppContainer
   launch path resolves the container's redirected app-data folder from it, and
   without it `CreateProcess` fails with `ERROR_ENVVAR_NOT_FOUND` - a failure that
   looks nothing like its cause.

This module raises `ImportError` off Windows rather than degrading, so a caller
cannot half-use it on a platform where none of it applies.
"""

from __future__ import annotations

import ctypes
import msvcrt
import subprocess
import sys
import threading
import uuid
from ctypes import wintypes
from pathlib import Path
from typing import IO

from sletchy.kernel.contracts import SANDBOX_LANES, lane_lock_name
from sletchy.kernel.grantguard import UnsafeGrantTarget, assert_grantable

if sys.platform != "win32":  # pragma: no cover - import-time platform gate
    msg = "sletchy.warden.isolation._win32 requires Windows"
    raise ImportError(msg)

# ── constants ────────────────────────────────────────────────────────────────

PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES = 0x00020009
PROC_THREAD_ATTRIBUTE_JOB_LIST = 0x0002000D
EXTENDED_STARTUPINFO_PRESENT = 0x00080000
CREATE_NO_WINDOW = 0x08000000
CREATE_UNICODE_ENVIRONMENT = 0x00000400
STARTF_USESTDHANDLES = 0x00000100
HANDLE_FLAG_INHERIT = 0x00000001
WAIT_OBJECT_0 = 0x00000000
WAIT_ABANDONED = 0x00000080
WAIT_TIMEOUT = 0x00000102
STILL_ACTIVE = 259

JobObjectBasicAccountingInformation = 1
JobObjectExtendedLimitInformation = 9
JobObjectCpuRateControlInformation = 15

JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008
JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION = 0x00000400
JOB_OBJECT_LIMIT_JOB_MEMORY = 0x00000200
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
JOB_OBJECT_CPU_RATE_CONTROL_ENABLE = 0x00000001
JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP = 0x00000004

TOKEN_ASSIGN_PRIMARY = 0x0001
TOKEN_DUPLICATE = 0x0002
TOKEN_QUERY = 0x0008
DISABLE_MAX_PRIVILEGE = 0x0001

#: Every profile Sletchy creates carries this prefix, so a sweep can find them
#: without a journal and nothing outside the prefix is ever touched.
PROFILE_PREFIX = "Sletchy"

#: `HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS)`, which `CreateAppContainerProfile`
#: returns for a name that already has a profile.
HRESULT_ALREADY_EXISTS = 0x800700B7

# ── structures ───────────────────────────────────────────────────────────────


class SECURITY_CAPABILITIES(ctypes.Structure):
    _fields_ = (
        ("AppContainerSid", ctypes.c_void_p),
        ("Capabilities", ctypes.c_void_p),
        ("CapabilityCount", wintypes.DWORD),
        ("Reserved", wintypes.DWORD),
    )


class STARTUPINFOW(ctypes.Structure):
    _fields_ = (
        ("cb", wintypes.DWORD),
        ("lpReserved", wintypes.LPWSTR),
        ("lpDesktop", wintypes.LPWSTR),
        ("lpTitle", wintypes.LPWSTR),
        ("dwX", wintypes.DWORD),
        ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD),
        ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD),
        ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD),
        ("cbReserved2", wintypes.WORD),
        ("lpReserved2", ctypes.c_void_p),
        ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE),
        ("hStdError", wintypes.HANDLE),
    )


class STARTUPINFOEXW(ctypes.Structure):
    _fields_ = (("StartupInfo", STARTUPINFOW), ("lpAttributeList", ctypes.c_void_p))


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = (
        ("hProcess", wintypes.HANDLE),
        ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
    )


class IO_COUNTERS(ctypes.Structure):
    _fields_ = tuple(
        (name, ctypes.c_ulonglong)
        for name in (
            "ReadOperationCount",
            "WriteOperationCount",
            "OtherOperationCount",
            "ReadTransferCount",
            "WriteTransferCount",
            "OtherTransferCount",
        )
    )


class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = (
        ("PerProcessUserTimeLimit", wintypes.LARGE_INTEGER),
        ("PerJobUserTimeLimit", wintypes.LARGE_INTEGER),
        ("LimitFlags", wintypes.DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", wintypes.DWORD),
        ("Affinity", ctypes.POINTER(ctypes.c_ulong)),
        ("PriorityClass", wintypes.DWORD),
        ("SchedulingClass", wintypes.DWORD),
    )


class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = (
        ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
        ("IoInfo", IO_COUNTERS),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    )


class _CPU_RATE_UNION(ctypes.Union):
    _fields_ = (("CpuRate", wintypes.DWORD), ("Weight", wintypes.DWORD))


class JOBOBJECT_CPU_RATE_CONTROL_INFORMATION(ctypes.Structure):
    _anonymous_ = ("rate",)
    _fields_ = (("ControlFlags", wintypes.DWORD), ("rate", _CPU_RATE_UNION))


class JOBOBJECT_BASIC_ACCOUNTING_INFORMATION(ctypes.Structure):
    _fields_ = (
        ("TotalUserTime", wintypes.LARGE_INTEGER),
        ("TotalKernelTime", wintypes.LARGE_INTEGER),
        ("ThisPeriodTotalUserTime", wintypes.LARGE_INTEGER),
        ("ThisPeriodTotalKernelTime", wintypes.LARGE_INTEGER),
        ("TotalPageFaultCount", wintypes.DWORD),
        ("TotalProcesses", wintypes.DWORD),
        ("ActiveProcesses", wintypes.DWORD),
        ("TotalTerminatedProcesses", wintypes.DWORD),
    )


# ── bindings ─────────────────────────────────────────────────────────────────
#
# argtypes are set on every call. Without them ctypes defaults to a 32-bit int
# return, which silently truncates a 64-bit handle - the class of bug that turns a
# security control into a no-op that still reports success.

_k32 = ctypes.WinDLL("kernel32", use_last_error=True)
_userenv = ctypes.WinDLL("userenv", use_last_error=True)
_advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)

_k32.CreateProcessW.argtypes = [
    wintypes.LPCWSTR,
    wintypes.LPWSTR,
    ctypes.c_void_p,
    ctypes.c_void_p,
    wintypes.BOOL,
    wintypes.DWORD,
    ctypes.c_void_p,
    wintypes.LPCWSTR,
    ctypes.c_void_p,
    ctypes.c_void_p,
]
_k32.CreateProcessW.restype = wintypes.BOOL
_k32.InitializeProcThreadAttributeList.argtypes = [
    ctypes.c_void_p,
    wintypes.DWORD,
    wintypes.DWORD,
    ctypes.POINTER(ctypes.c_size_t),
]
_k32.InitializeProcThreadAttributeList.restype = wintypes.BOOL
_k32.UpdateProcThreadAttribute.argtypes = [
    ctypes.c_void_p,
    wintypes.DWORD,
    ctypes.c_size_t,
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.c_void_p,
    ctypes.c_void_p,
]
_k32.UpdateProcThreadAttribute.restype = wintypes.BOOL
_k32.DeleteProcThreadAttributeList.argtypes = [ctypes.c_void_p]
_k32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
_k32.CreateJobObjectW.restype = wintypes.HANDLE
_k32.SetInformationJobObject.argtypes = [
    wintypes.HANDLE,
    ctypes.c_int,
    ctypes.c_void_p,
    wintypes.DWORD,
]
_k32.SetInformationJobObject.restype = wintypes.BOOL
_k32.QueryInformationJobObject.argtypes = [
    wintypes.HANDLE,
    ctypes.c_int,
    ctypes.c_void_p,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
]
_k32.QueryInformationJobObject.restype = wintypes.BOOL
_k32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
_k32.TerminateJobObject.restype = wintypes.BOOL
_k32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
_k32.WaitForSingleObject.restype = wintypes.DWORD
_k32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
_k32.GetExitCodeProcess.restype = wintypes.BOOL
_k32.CloseHandle.argtypes = [wintypes.HANDLE]
_k32.CloseHandle.restype = wintypes.BOOL
_k32.SetHandleInformation.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD]
_k32.SetHandleInformation.restype = wintypes.BOOL
_k32.GetCurrentProcess.argtypes = []
_k32.GetCurrentProcess.restype = wintypes.HANDLE
_k32.LocalFree.argtypes = [ctypes.c_void_p]
_k32.LocalFree.restype = ctypes.c_void_p
_k32.CreateMutexW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
_k32.CreateMutexW.restype = wintypes.HANDLE
_k32.ReleaseMutex.argtypes = [wintypes.HANDLE]
_k32.ReleaseMutex.restype = wintypes.BOOL

_userenv.CreateAppContainerProfile.argtypes = [
    wintypes.LPCWSTR,
    wintypes.LPCWSTR,
    wintypes.LPCWSTR,
    ctypes.c_void_p,
    wintypes.DWORD,
    ctypes.POINTER(ctypes.c_void_p),
]
_userenv.CreateAppContainerProfile.restype = ctypes.c_long
_userenv.DeleteAppContainerProfile.argtypes = [wintypes.LPCWSTR]
_userenv.DeleteAppContainerProfile.restype = ctypes.c_long
_userenv.GetAppContainerFolderPath.argtypes = [
    wintypes.LPCWSTR,
    ctypes.POINTER(wintypes.LPWSTR),
]
_userenv.GetAppContainerFolderPath.restype = ctypes.c_long

_advapi32.ConvertSidToStringSidW.argtypes = [
    ctypes.c_void_p,
    ctypes.POINTER(wintypes.LPWSTR),
]
_advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
_advapi32.FreeSid.argtypes = [ctypes.c_void_p]
_advapi32.FreeSid.restype = ctypes.c_void_p
_advapi32.OpenProcessToken.argtypes = [
    wintypes.HANDLE,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.HANDLE),
]
_advapi32.OpenProcessToken.restype = wintypes.BOOL
_advapi32.CreateRestrictedToken.argtypes = [
    wintypes.HANDLE,
    wintypes.DWORD,
    wintypes.DWORD,
    ctypes.c_void_p,
    wintypes.DWORD,
    ctypes.c_void_p,
    wintypes.DWORD,
    ctypes.c_void_p,
    ctypes.POINTER(wintypes.HANDLE),
]
_advapi32.CreateRestrictedToken.restype = wintypes.BOOL
_advapi32.CreateProcessAsUserW.argtypes = [
    wintypes.HANDLE,
    wintypes.LPCWSTR,
    wintypes.LPWSTR,
    ctypes.c_void_p,
    ctypes.c_void_p,
    wintypes.BOOL,
    wintypes.DWORD,
    ctypes.c_void_p,
    wintypes.LPCWSTR,
    ctypes.c_void_p,
    ctypes.c_void_p,
]
_advapi32.CreateProcessAsUserW.restype = wintypes.BOOL


#: A raw Win32 handle. Aliased so callers can name one without importing ctypes.
Handle = wintypes.HANDLE


class Win32Error(OSError):
    """A Win32 call failed. Carries the call name and the raw code."""

    def __init__(self, call: str, code: int) -> None:
        super().__init__(f"{call} failed: WinError {code}")
        self.call = call
        self.code = code


class ProfileExists(Win32Error):
    """A profile of this name is already on the machine: a lane left behind (#33)."""


def new_context_id() -> str:
    """A per-execution id: lowercase and letter-led, for the journal and the capture file."""
    return f"s{uuid.uuid4().hex[:16]}"


# ── lanes ────────────────────────────────────────────────────────────────────


class Lane:
    """One of the fixed container names, held by one run at a time (#33, ADR-0013).

    Held through a named mutex, not a file, for two reasons. The mutex is the same
    one for every Sletchy on this logon session, whichever `var/` it uses, so two
    test suites side by side cannot draw the same lane. And Windows releases a
    mutex whose holder dies, so a crash never leaves a lane held: it can only leave
    a profile behind, which `take()` does not see and `winjob` checks next.

    A mutex belongs to the thread that took it, so a lane is taken and released on
    one thread. `winjob.run` does both. A thread may take a mutex it already holds,
    which a lane must not allow: the lanes this process holds are also kept in a set,
    and a second take of one of them is "in use".
    """

    def __init__(self, name: str) -> None:
        if name not in SANDBOX_LANES:
            msg = f"{name!r} is not a sandbox lane"
            raise ValueError(msg)
        self.name = name
        self._handle: wintypes.HANDLE | None = None

    @property
    def held(self) -> bool:
        return self._handle is not None

    def take(self) -> bool:
        """Take the lane now, or return False if another run holds it. Never waits."""
        if self._handle is not None:
            return True
        handle = _k32.CreateMutexW(None, False, lane_lock_name(self.name))
        if not handle:
            raise Win32Error("CreateMutexW", ctypes.get_last_error())
        state = _k32.WaitForSingleObject(handle, 0)
        # Abandoned is a holder that died without releasing: the lane is ours now.
        if state in (WAIT_OBJECT_0, WAIT_ABANDONED):
            with _HELD_LOCK:
                if self.name not in _HELD:
                    _HELD.add(self.name)
                    self._handle = handle
                    return True
            # This thread already held it: the wait succeeded only because a mutex
            # counts its owner's takes.
            _k32.ReleaseMutex(handle)
            _k32.CloseHandle(handle)
            return False
        _k32.CloseHandle(handle)
        if state == WAIT_TIMEOUT:
            return False
        raise Win32Error("WaitForSingleObject", ctypes.get_last_error())

    def release(self) -> None:
        """Let the next run have it. Safe to call when not held."""
        if self._handle is None:
            return
        handle, self._handle = self._handle, None
        with _HELD_LOCK:
            _HELD.discard(self.name)
        _k32.ReleaseMutex(handle)
        _k32.CloseHandle(handle)


#: The lanes this process holds. See `Lane`.
_HELD: set[str] = set()
_HELD_LOCK = threading.Lock()


# ── AppContainer profile ─────────────────────────────────────────────────────


class AppContainerProfile:
    """A per-execution AppContainer profile.

    Ephemerality *is* isolation: the profile is created for one run and deleted
    when it ends, so nothing accumulates and nothing is shared between executions.
    The name is a lane's and comes back on a later run, so the SID does too; what
    must not come back is anything granted to it, which is why the grant is revoked
    and the profile deleted before the lane is let go. Creation and deletion both
    need no elevation and write only under the user's own `LOCALAPPDATA`
    (ADR-0005 §2).

    Raises `ProfileExists` when the name already has a profile: one left behind by
    a run that never reached its `finally`.
    """

    def __init__(self, name: str, context_id: str) -> None:
        self.context_id = context_id
        self.name = name
        self._sid = ctypes.c_void_p()
        self.created = False

        hresult = _userenv.CreateAppContainerProfile(
            self.name,
            f"Sletchy sandbox {context_id}",
            "Ephemeral Sletchy execution container; deleted when the run ends",
            None,
            0,
            ctypes.byref(self._sid),
        )
        if hresult & 0xFFFFFFFF == HRESULT_ALREADY_EXISTS:
            raise ProfileExists("CreateAppContainerProfile", HRESULT_ALREADY_EXISTS)
        if hresult != 0:
            raise Win32Error("CreateAppContainerProfile", hresult & 0xFFFFFFFF)
        self.created = True
        self.sid_string = self._to_string(self._sid)

    @staticmethod
    def _to_string(sid: ctypes.c_void_p) -> str:
        buffer = wintypes.LPWSTR()
        if not _advapi32.ConvertSidToStringSidW(sid, ctypes.byref(buffer)):
            raise Win32Error("ConvertSidToStringSidW", ctypes.get_last_error())
        try:
            return buffer.value or ""
        finally:
            _k32.LocalFree(buffer)

    @property
    def sid(self) -> ctypes.c_void_p:
        return self._sid

    def folder(self) -> Path | None:
        buffer = wintypes.LPWSTR()
        if _userenv.GetAppContainerFolderPath(self.sid_string, ctypes.byref(buffer)) != 0:
            return None
        try:
            return Path(buffer.value) if buffer.value else None
        finally:
            _k32.LocalFree(buffer)

    def close(self) -> None:
        """Delete the profile and release the SID. Safe to call repeatedly.

        The delete goes **first**, before `FreeSid`. That ordering is not
        cosmetic: during the spike a crash in the SID cleanup left the profile
        behind, and putting the irreversible-if-skipped step first is what made
        the next crash harmless (ADR-0005 §2).
        """
        if self.created:
            _userenv.DeleteAppContainerProfile(self.name)
            self.created = False
        if self._sid:
            _advapi32.FreeSid(self._sid)
            self._sid = ctypes.c_void_p()


# ── job object ───────────────────────────────────────────────────────────────


class JobObject:
    """A job with hard limits, created **before** any process exists.

    Nothing here assigns an existing process to a job. The handle is passed to
    `spawn()` as a creation attribute, so a child is inside its limits from its
    first instruction. `AssignProcessToJobObject` is deliberately not bound in
    this module - the only way to get a process into a Sletchy job is to create it
    there.
    """

    def __init__(self) -> None:
        handle = _k32.CreateJobObjectW(None, None)
        if not handle:
            raise Win32Error("CreateJobObjectW", ctypes.get_last_error())
        self.handle: wintypes.HANDLE = handle
        self._closed = False

    def apply(self, *, memory_mb: int, cpu_percent: int, max_processes: int) -> None:
        """Set every ceiling. Called before `spawn`, never after."""
        limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        limits.BasicLimitInformation.LimitFlags = (
            JOB_OBJECT_LIMIT_JOB_MEMORY
            | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
            # The whole tree dies with the job. BREAKAWAY_OK is deliberately not
            # set: a child that can leave the job can outlive the sandbox.
            | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION
        )
        limits.BasicLimitInformation.ActiveProcessLimit = max_processes
        limits.JobMemoryLimit = memory_mb * 1024 * 1024
        if not _k32.SetInformationJobObject(
            self.handle,
            JobObjectExtendedLimitInformation,
            ctypes.byref(limits),
            ctypes.sizeof(limits),
        ):
            raise Win32Error("SetInformationJobObject(extended)", ctypes.get_last_error())

        cpu = JOBOBJECT_CPU_RATE_CONTROL_INFORMATION()
        cpu.ControlFlags = JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP
        # Expressed in hundredths of a percent.
        cpu.CpuRate = max(1, min(10_000, cpu_percent * 100))
        if not _k32.SetInformationJobObject(
            self.handle,
            JobObjectCpuRateControlInformation,
            ctypes.byref(cpu),
            ctypes.sizeof(cpu),
        ):
            raise Win32Error("SetInformationJobObject(cpu)", ctypes.get_last_error())

    def _accounting(self) -> JOBOBJECT_BASIC_ACCOUNTING_INFORMATION | None:
        info = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION()
        returned = wintypes.DWORD()
        if not _k32.QueryInformationJobObject(
            self.handle,
            JobObjectBasicAccountingInformation,
            ctypes.byref(info),
            ctypes.sizeof(info),
            ctypes.byref(returned),
        ):
            return None
        return info

    def active_processes(self) -> int:
        info = self._accounting()
        return 0 if info is None else int(info.ActiveProcesses)

    def cpu_time_ns(self) -> int:
        """User CPU consumed by everything in the job, in 100ns ticks.

        Exists so a test can tell a process that is *running* from one that is
        merely *alive*. A malformed probe once left a modal error dialog sitting
        in a job, and "one process is alive" read as a successful containment
        result. Burning CPU is much harder to fake by accident.
        """
        info = self._accounting()
        return 0 if info is None else int(info.TotalUserTime)

    def terminate(self) -> None:
        if not self._closed:
            _k32.TerminateJobObject(self.handle, 1)

    def close(self) -> None:
        """Close the handle, which kills anything still inside the job."""
        if not self._closed:
            _k32.CloseHandle(self.handle)
            self._closed = True


# ── restricted token ─────────────────────────────────────────────────────────


def restricted_token() -> wintypes.HANDLE:
    """A copy of our own token with every removable privilege dropped.

    `DISABLE_MAX_PRIVILEGE` strips the lot rather than naming individual ones: a
    named list is a blocklist, and a blocklist of privileges ages badly.

    Using it needs no new right, because a restricted derivative of the caller's
    own token is the one case `CreateProcessAsUser` accepts unprivileged.
    """
    own = wintypes.HANDLE()
    if not _advapi32.OpenProcessToken(
        _k32.GetCurrentProcess(),
        TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY,
        ctypes.byref(own),
    ):
        raise Win32Error("OpenProcessToken", ctypes.get_last_error())
    try:
        restricted = wintypes.HANDLE()
        if not _advapi32.CreateRestrictedToken(
            own, DISABLE_MAX_PRIVILEGE, 0, None, 0, None, 0, None, ctypes.byref(restricted)
        ):
            raise Win32Error("CreateRestrictedToken", ctypes.get_last_error())
        return restricted
    finally:
        _k32.CloseHandle(own)


# ── environment ──────────────────────────────────────────────────────────────


def environment_block(env: dict[str, str]) -> ctypes.Array[ctypes.c_wchar]:
    """A `CreateProcess` environment block: sorted, NUL-separated, NUL-NUL ended.

    Sorted because `CreateProcess` documents that ordering, and built element by
    element because `create_unicode_buffer` is the wrong tool for a string that
    contains NULs.
    """
    text = "\0".join(sorted(f"{key}={value}" for key, value in env.items())) + "\0\0"
    buffer = (ctypes.c_wchar * len(text))()
    for index, char in enumerate(text):
        buffer[index] = char
    return buffer


# ── launch ───────────────────────────────────────────────────────────────────


def command_line(argv: list[str]) -> str:
    """Join argv the way Windows will split it again.

    `CreateProcess` takes one string, so the quoting has to match the rules the
    child's own parser applies. `list2cmdline` is that algorithm, already correct
    for embedded quotes and trailing backslashes.
    """
    return subprocess.list2cmdline(argv)


def inheritable_handle(file_object: IO[bytes]) -> int:
    """Mark an open file's handle inheritable and return it.

    The child never opens this file. It receives an already-open handle, which is
    why capture works at all inside a container that may open nothing.
    """
    handle = msvcrt.get_osfhandle(file_object.fileno())
    if not _k32.SetHandleInformation(handle, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT):
        raise Win32Error("SetHandleInformation", ctypes.get_last_error())
    return int(handle)


def close_handle(handle: wintypes.HANDLE) -> None:
    if handle:
        _k32.CloseHandle(handle)


class Launched:
    """A running child, and the handles needed to wait on it."""

    def __init__(self, process: wintypes.HANDLE, thread: wintypes.HANDLE, pid: int) -> None:
        self.process = process
        self.thread = thread
        self.pid = pid

    def wait(self, timeout_seconds: float) -> bool:
        """True when the child exited, False when the timeout expired first."""
        milliseconds = max(0, int(timeout_seconds * 1000))
        return bool(_k32.WaitForSingleObject(self.process, milliseconds) != WAIT_TIMEOUT)

    def exit_code(self) -> int | None:
        code = wintypes.DWORD()
        if not _k32.GetExitCodeProcess(self.process, ctypes.byref(code)):
            return None
        value = int(code.value)
        return None if value == STILL_ACTIVE else value

    def close(self) -> None:
        for handle in (self.thread, self.process):
            if handle:
                _k32.CloseHandle(handle)


def spawn(
    command_line: str,
    *,
    sid: ctypes.c_void_p,
    job: JobObject,
    token: wintypes.HANDLE,
    cwd: str,
    env: dict[str, str],
    stdout_handle: int,
) -> Launched:
    """Create a process that is inside the container and the job from birth.

    Both the AppContainer and the job go into one attribute list, so there is no
    ordering to get wrong and no interval in which the child is running under
    neither.
    """
    size = ctypes.c_size_t(0)
    _k32.InitializeProcThreadAttributeList(None, 2, 0, ctypes.byref(size))
    buffer = (ctypes.c_ubyte * size.value)()
    attributes = ctypes.cast(buffer, ctypes.c_void_p)
    if not _k32.InitializeProcThreadAttributeList(attributes, 2, 0, ctypes.byref(size)):
        raise Win32Error("InitializeProcThreadAttributeList", ctypes.get_last_error())

    capabilities = SECURITY_CAPABILITIES(
        AppContainerSid=sid, Capabilities=None, CapabilityCount=0, Reserved=0
    )
    job_list = (wintypes.HANDLE * 1)(job.handle)

    try:
        if not _k32.UpdateProcThreadAttribute(
            attributes,
            0,
            ctypes.c_size_t(PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES),
            ctypes.byref(capabilities),
            ctypes.sizeof(capabilities),
            None,
            None,
        ):
            raise Win32Error("UpdateProcThreadAttribute(container)", ctypes.get_last_error())

        if not _k32.UpdateProcThreadAttribute(
            attributes,
            0,
            ctypes.c_size_t(PROC_THREAD_ATTRIBUTE_JOB_LIST),
            job_list,
            ctypes.sizeof(job_list),
            None,
            None,
        ):
            raise Win32Error("UpdateProcThreadAttribute(job)", ctypes.get_last_error())

        startup = STARTUPINFOEXW()
        startup.StartupInfo.cb = ctypes.sizeof(STARTUPINFOEXW)
        startup.lpAttributeList = attributes
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES
        startup.StartupInfo.hStdOutput = stdout_handle
        startup.StartupInfo.hStdError = stdout_handle
        startup.StartupInfo.hStdInput = None

        block = environment_block(env)
        information = PROCESS_INFORMATION()

        created = _advapi32.CreateProcessAsUserW(
            token,
            None,
            ctypes.create_unicode_buffer(command_line),
            None,
            None,
            True,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
            ctypes.cast(block, ctypes.c_void_p),
            cwd,
            ctypes.byref(startup),
            ctypes.byref(information),
        )
        if not created:
            raise Win32Error("CreateProcessAsUserW", ctypes.get_last_error())

        return Launched(information.hProcess, information.hThread, int(information.dwProcessId))
    finally:
        _k32.DeleteProcThreadAttributeList(attributes)


# ── path access ──────────────────────────────────────────────────────────────
#
# An AppContainer is denied everything it has no ACE for, including a directory
# the parent just created for it. Granting is therefore not a loosening of the
# sandbox - it is how the sandbox is given its one usable area.
#
# `icacls` rather than the ACL APIs on purpose. `SetNamedSecurityInfo` takes a
# whole DACL, so a mistake in assembling one *replaces* a directory's permissions
# rather than adding to them. On the operator's only machine that is a worse
# failure than the subprocess it avoids, and `panic` already shells out to `netsh`
# for the same reason.

_ICACLS_TIMEOUT = 60

# The grant guard lives in the Kernel, so `panic` refuses exactly what the Warden
# refuses (#94). It began here; `cli` may not import `warden`, and a guard two
# planes disagree about is how panic came to walk a drive root.


def _icacls(*arguments: str) -> tuple[bool, str]:
    try:
        result = subprocess.run(  # noqa: S603
            ["icacls", *arguments],  # noqa: S607
            capture_output=True,
            text=True,
            timeout=_ICACLS_TIMEOUT,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return False, f"{type(exc).__name__}: {exc}"
    return result.returncode == 0, (result.stdout or "") + (result.stderr or "")


def grant_path(path: Path, sid_string: str, *, write: bool = True) -> None:
    """Give one container SID access to one directory tree.

    Additive: `icacls /grant` adds an ACE and leaves every existing one alone.
    The target is validated **before** `icacls` runs - a refusal must cost the
    host nothing at all.
    """
    assert_grantable(path)
    rights = "(OI)(CI)(M)" if write else "(OI)(CI)(RX)"
    ok, output = _icacls(str(path), "/grant", f"*{sid_string}:{rights}", "/T", "/C", "/Q")
    if not ok:
        msg = f"could not grant {sid_string} on {path}: {output.strip()[:200]}"
        raise Win32Error(msg, 0)


def revoke_path(path: Path, sid_string: str) -> bool:
    """Remove that ACE again. Missing path or missing ACE both count as done.

    Guarded by the same rule as the grant. A path we would have refused to grant
    is a path we never granted, so declining to walk it removes nothing that
    exists - and it keeps a bad journal entry from turning a cleanup into a
    recursive ACL change.
    """
    if not path.exists():
        return True
    try:
        assert_grantable(path)
    except UnsafeGrantTarget:
        return False
    ok, _ = _icacls(str(path), "/remove:g", f"*{sid_string}", "/T", "/C", "/Q")
    return ok


def api_available() -> bool:
    """Whether every entry point `winjob` needs is present on this host."""
    required = (
        (_userenv, ("CreateAppContainerProfile", "DeleteAppContainerProfile")),
        (_k32, ("CreateJobObjectW", "SetInformationJobObject", "UpdateProcThreadAttribute")),
        (_advapi32, ("CreateRestrictedToken", "CreateProcessAsUserW")),
    )
    for library, functions in required:
        for function in functions:
            if not hasattr(library, function):
                return False
    return True
