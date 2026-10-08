#!/usr/bin/env python3
"""SPIKE probe: what does AppContainer actually do on this Windows build?

Throwaway. This does **not** become the `winjob` backend - it exists to produce a
findings document (#12), after which it can be deleted.

## Why this has to run on the real host

The question is what AppContainer does on *this* machine, on *this* build. Docker
cannot answer it: Linux containers have no AppContainer at all, and Windows
containers have their own separate isolation. Only the host can be measured.

## Safety design

Phases, safest first, and each one has to be asked for explicitly:

- **0 - inspect.** Reads the build number and checks which API entry points exist.
  Writes nothing. Creates nothing. Zero risk.
- **1 - lifecycle.** Creates one AppContainer profile with a distinctive name,
  proves it exists, deletes it, and proves it is gone. Reversible by construction,
  and cleanup runs in a `finally`.
- **2 - enforcement.** Launches a harmless child (`cmd /c` reading a file) inside
  the container and observes what it is denied.

Standing rails, all phases:

- **No elevation.** The probe refuses to run elevated - an elevated result would
  not describe how Sletchy actually runs.
- **No drivers, no services, no Test Signing Mode, no system settings.**
  ADR-0001; nothing here goes near them.
- **Everything it creates is named `SletchySpike-*`** and deleted in `finally`.
  Phase 1 re-checks afterwards and reports residue as a failure.
- **No network.** Phase 2's network probe attempts a *loopback* connection only.
"""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import platform
import sys
import tempfile
import uuid
from ctypes import wintypes
from pathlib import Path
from typing import Any

PROFILE_PREFIX = "SletchySpike"


def fail(message: str) -> None:
    print(f"REFUSING: {message}", file=sys.stderr)
    raise SystemExit(2)


def guard() -> None:
    """Rails that apply to every phase."""
    if sys.platform != "win32":
        fail("this probe measures Windows APIs and must run on Windows")
    if ctypes.windll.shell32.IsUserAnAdmin() != 0:
        fail(
            "running elevated. Sletchy runs as a normal user, so an elevated result "
            "would not describe how it actually behaves. Re-run from a normal shell."
        )


# ── phase 0: inspect ─────────────────────────────────────────────────────────

#: The entry points `winjob` would need. Absence of any one changes the design.
REQUIRED_EXPORTS: dict[str, tuple[str, ...]] = {
    "userenv": (
        "CreateAppContainerProfile",
        "DeleteAppContainerProfile",
        "DeriveAppContainerSidFromAppContainerName",
        "GetAppContainerFolderPath",
    ),
    "kernel32": (
        "CreateJobObjectW",
        "SetInformationJobObject",
        "AssignProcessToJobObject",
        "InitializeProcThreadAttributeList",
        "UpdateProcThreadAttribute",
        "CreateProcessW",
        "TerminateJobObject",
    ),
    "advapi32": (
        "CreateRestrictedToken",
        "CreateProcessAsUserW",
    ),
}


def phase0() -> dict[str, Any]:
    """Read-only. What does this machine have?"""
    report: dict[str, Any] = {
        "phase": 0,
        "windows": {
            "release": platform.release(),
            "version": platform.version(),
            "build": platform.win32_ver()[1],
            "edition": platform.win32_edition() if hasattr(platform, "win32_edition") else None,
            "machine": platform.machine(),
        },
        "python": sys.version.split()[0],
        "elevated": bool(ctypes.windll.shell32.IsUserAnAdmin()),
        "exports": {},
        "missing": [],
    }

    for dll_name, functions in REQUIRED_EXPORTS.items():
        try:
            dll = ctypes.WinDLL(f"{dll_name}.dll")
        except OSError as exc:
            report["exports"][dll_name] = f"UNAVAILABLE: {exc}"
            report["missing"].extend(f"{dll_name}.{fn}" for fn in functions)
            continue
        present = {}
        for fn in functions:
            try:
                getattr(dll, fn)
                present[fn] = True
            except AttributeError:
                present[fn] = False
                report["missing"].append(f"{dll_name}.{fn}")
        report["exports"][dll_name] = present

    return report


# ── phase 1: profile lifecycle ───────────────────────────────────────────────


def _sid_to_string(sid: ctypes.c_void_p) -> str:
    buf = wintypes.LPWSTR()
    if not ctypes.windll.advapi32.ConvertSidToStringSidW(sid, ctypes.byref(buf)):
        return "<unconvertible>"
    try:
        return buf.value or "<empty>"
    finally:
        ctypes.windll.kernel32.LocalFree(buf)


def phase1() -> dict[str, Any]:
    """Create one profile, prove it exists, delete it, prove it is gone."""
    userenv = ctypes.WinDLL("userenv.dll")
    name = f"{PROFILE_PREFIX}-{uuid.uuid4().hex[:8]}"
    report: dict[str, Any] = {"phase": 1, "profile_name": name}

    sid = ctypes.c_void_p()
    created = False
    try:
        hr = userenv.CreateAppContainerProfile(
            ctypes.c_wchar_p(name),
            ctypes.c_wchar_p(f"{name} (Sletchy spike, deleted immediately)"),
            ctypes.c_wchar_p("Throwaway profile created by scripts/spike/appcontainer_probe.py"),
            None,
            0,
            ctypes.byref(sid),
        )
        report["create_hresult"] = f"0x{hr & 0xFFFFFFFF:08X}"
        report["created"] = hr == 0
        created = hr == 0

        if created:
            report["sid"] = _sid_to_string(sid)
            folder = wintypes.LPWSTR()
            fhr = userenv.GetAppContainerFolderPath(
                ctypes.c_wchar_p(report["sid"]), ctypes.byref(folder)
            )
            report["folder_hresult"] = f"0x{fhr & 0xFFFFFFFF:08X}"
            report["folder"] = folder.value if fhr == 0 else None
            report["folder_exists"] = bool(report["folder"] and Path(report["folder"]).exists())
            report["folder_note"] = (
                "AppContainer profiles live under the USER's LocalAppData, not a system "
                "location. Creation writes there and to HKCU. Both are removed by "
                "DeleteAppContainerProfile."
            )
            if fhr == 0:
                ctypes.windll.kernel32.LocalFree(folder)
    finally:
        if created:
            dhr = userenv.DeleteAppContainerProfile(ctypes.c_wchar_p(name))
            report["delete_hresult"] = f"0x{dhr & 0xFFFFFFFF:08X}"
            report["deleted"] = dhr == 0
            # Prove it: deriving a SID for a deleted profile still succeeds (it is a
            # pure hash of the name), so residue is checked on the folder instead.
            leftover = report.get("folder")
            report["residue"] = bool(leftover and Path(leftover).exists())
        if sid:
            # FreeSid lives in advapi32, not kernel32. Getting this wrong crashed the
            # first run *after* the delete had already succeeded - which is why the
            # delete is in the same `finally` and goes first.
            ctypes.windll.advapi32.FreeSid(sid)

    return report


# ── phase 2: enforcement ─────────────────────────────────────────────────────


# Win32 constants for launching into an AppContainer.
PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES = 0x00020009
EXTENDED_STARTUPINFO_PRESENT = 0x00080000
CREATE_NO_WINDOW = 0x08000000


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


def _run_in_appcontainer(
    sid: ctypes.c_void_p, command: str, timeout_ms: int = 20000
) -> dict[str, Any]:
    """Launch `command` inside the AppContainer identified by `sid`.

    Reports **only** the exit code. Getting stdout out of an AppContainer needs
    handle inheritance the container may refuse, and a failed pipe read would look
    identical to a denial - exactly the ambiguity this phase exists to remove.
    """
    k32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)

    size = ctypes.c_size_t(0)
    k32.InitializeProcThreadAttributeList(None, 1, 0, ctypes.byref(size))
    buf = (ctypes.c_ubyte * size.value)()
    attr_list = ctypes.cast(buf, ctypes.c_void_p)

    if not k32.InitializeProcThreadAttributeList(attr_list, 1, 0, ctypes.byref(size)):
        return {"error": f"InitializeProcThreadAttributeList failed: {ctypes.get_last_error()}"}

    caps = SECURITY_CAPABILITIES(
        AppContainerSid=sid, Capabilities=None, CapabilityCount=0, Reserved=0
    )

    try:
        ok = k32.UpdateProcThreadAttribute(
            attr_list,
            0,
            ctypes.c_size_t(PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES),
            ctypes.byref(caps),
            ctypes.sizeof(caps),
            None,
            None,
        )
        if not ok:
            return {"error": f"UpdateProcThreadAttribute failed: {ctypes.get_last_error()}"}

        si = STARTUPINFOEXW()
        si.StartupInfo.cb = ctypes.sizeof(STARTUPINFOEXW)
        si.lpAttributeList = attr_list
        pi = PROCESS_INFORMATION()

        created = k32.CreateProcessW(
            None,
            ctypes.create_unicode_buffer(command),
            None,
            None,
            False,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW,
            None,
            None,
            ctypes.byref(si),
            ctypes.byref(pi),
        )
        if not created:
            return {"error": f"CreateProcessW failed: {ctypes.get_last_error()}"}

        try:
            k32.WaitForSingleObject(pi.hProcess, timeout_ms)
            code = wintypes.DWORD()
            k32.GetExitCodeProcess(pi.hProcess, ctypes.byref(code))
            return {"exit_code": code.value}
        finally:
            k32.CloseHandle(pi.hThread)
            k32.CloseHandle(pi.hProcess)
    finally:
        k32.DeleteProcThreadAttributeList(attr_list)


def phase2() -> dict[str, Any]:
    """Does an AppContainer with no capabilities actually deny anything?

    Two probes, and the second is what makes the first meaningful:

    - **outside** - read a file in the user's temp directory. Should be DENIED.
    - **inside**  - read a file in the container's own folder. Should SUCCEED.

    Without the second, "denied" is indistinguishable from "the process never
    ran", and a spike that cannot tell those apart proves nothing.
    """
    userenv = ctypes.WinDLL("userenv.dll")
    name = f"{PROFILE_PREFIX}-{uuid.uuid4().hex[:8]}"
    report: dict[str, Any] = {"phase": 2, "profile_name": name, "probes": {}}

    sid = ctypes.c_void_p()
    created = False
    outside_file: str | None = None

    try:
        hr = userenv.CreateAppContainerProfile(
            ctypes.c_wchar_p(name),
            ctypes.c_wchar_p(f"{name} (Sletchy spike)"),
            ctypes.c_wchar_p("Throwaway profile; deleted at the end of this run"),
            None,
            0,
            ctypes.byref(sid),
        )
        if hr != 0:
            report["error"] = f"CreateAppContainerProfile failed: 0x{hr & 0xFFFFFFFF:08X}"
            return report
        created = True
        report["sid"] = _sid_to_string(sid)

        folder = wintypes.LPWSTR()
        fhr = userenv.GetAppContainerFolderPath(
            ctypes.c_wchar_p(report["sid"]), ctypes.byref(folder)
        )
        if fhr != 0:
            report["error"] = "GetAppContainerFolderPath failed"
            return report
        ac_folder = Path(folder.value or "")
        ctypes.windll.kernel32.LocalFree(folder)
        report["folder"] = str(ac_folder)

        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write("outside the container\n")
            outside_file = fh.name

        inside_file = ac_folder / "inside.txt"
        inside_file.write_text("inside the container\n", encoding="utf-8")

        comspec = os.environ.get("COMSPEC", r"C:\Windows\System32\cmd.exe")

        # Control probe FIRST: touches no filesystem at all. If this does not come
        # back as 42, the interpreter itself cannot run in the container and every
        # other result below is meaningless.
        report["probes"]["control_exit_42"] = _run_in_appcontainer(sid, f'"{comspec}" /c exit 42')

        for label, target in (
            ("outside", outside_file),
            ("inside_parent_written", str(inside_file)),
        ):
            report["probes"][label] = _run_in_appcontainer(sid, f'"{comspec}" /c type "{target}"')

        # The container writes its OWN file and reads it back. This removes the
        # ACL-inheritance question: a file the parent dropped into the AC folder may
        # not carry an ACE for the container SID, but one the container created must.
        self_file = ac_folder / "self.txt"
        report["probes"]["inside_self_written"] = _run_in_appcontainer(
            sid, f'"{comspec}" /c echo contained> "{self_file}"'
        )
        # Parent-side check. Distinguishes "the write was denied" from "the write
        # succeeded but the read back was denied" - two very different findings.
        report["self_written_file_exists_from_parent"] = self_file.exists()
        report["probes"]["inside_read_back"] = _run_in_appcontainer(
            sid, f'"{comspec}" /c type "{self_file}"'
        )

        control = report["probes"]["control_exit_42"].get("exit_code")
        outside = report["probes"]["outside"].get("exit_code")
        inside = report["probes"]["inside_read_back"].get("exit_code")
        report["parent_written_file_readable"] = (
            report["probes"]["inside_parent_written"].get("exit_code") == 0
        )

        if control != 42:
            report["verdict"] = (
                f"INCONCLUSIVE - the control probe returned {control!r}, not 42. The "
                "interpreter cannot run inside the container at all, so no filesystem "
                "result below means anything."
            )
        elif outside is None or inside is None:
            report["verdict"] = "INCONCLUSIVE - a probe failed to launch"
        elif inside == 0 and outside != 0:
            report["verdict"] = "CONTAINED - the child ran, and was denied the outside file"
        elif inside == 0 and outside == 0:
            report["verdict"] = (
                "NOT CONTAINED - the child read a file outside its container. "
                "AppContainer with no capabilities is not denying filesystem reads "
                "on this build, and the isolation design must change."
            )
        else:
            report["verdict"] = (
                "INCONCLUSIVE - the child could not read a file it wrote itself, so "
                "'denied' cannot be distinguished from 'never ran'"
            )
    finally:
        if outside_file:
            Path(outside_file).unlink(missing_ok=True)
        if created:
            dhr = userenv.DeleteAppContainerProfile(ctypes.c_wchar_p(name))
            report["deleted"] = dhr == 0
            report["residue"] = bool(report.get("folder") and Path(report["folder"]).exists())
        if sid:
            ctypes.windll.advapi32.FreeSid(sid)

    return report


# ── entry point ──────────────────────────────────────────────────────────────


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--phase",
        type=int,
        choices=[0, 1, 2],
        required=True,
        help="0 = inspect (no writes) · 1 = create+delete a profile · 2 = enforcement",
    )
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args()

    guard()

    report = {0: phase0, 1: phase1, 2: phase2}[args.phase]()

    if args.json:
        print(json.dumps(report, indent=2, default=str))
    else:
        print(json.dumps(report, indent=2, default=str))

    if args.phase == 1 and report.get("residue"):
        print("\nRESIDUE LEFT BEHIND - investigate before running again", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
