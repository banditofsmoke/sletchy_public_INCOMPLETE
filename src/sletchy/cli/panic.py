"""`sletchy stop` (Stop everything) - the reversibility promise, made executable.

Its old name, `sletchy panic`, still works and is listed nowhere. The code keeps the
old name inside, where only a reader of the source sees it.

LAW 0 §2 says every change Sletchy makes to the host is undoable by one documented
command. This is that command, and it is tested as a first-class feature: a panic
button that has never been pressed is a rumour.

Four properties, each of which shaped the implementation:

**It works when the daemon is wedged.** Panic never asks a Sletchy process to
cooperate. It reads state from disk, kills by job object and pid file, and removes
firewall rules by group name. A hung daemon is the case panic exists for, so
depending on it would be exactly backwards.

**It never asks for confirmation.** A prompt is a failure mode in the command you
run when something is already wrong.

**It is non-destructive.** Panic *stops* things. It does not delete the ledger, the
payloads, or the keychain - those are evidence and credentials, and an emergency
stop that destroys either is worse than the emergency. It clears only `var/run/`.

**It reports honestly.** Every step returns what it actually did, including "nothing
to do", so the output never claims a reset that was a no-op.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from sletchy.cli.paths import FIREWALL_GROUP, runtime_dir
from sletchy.kernel.contracts import SANDBOX_LANES, lane_lock_name
from sletchy.kernel.flags import FlagWriteFailed
from sletchy.kernel.grantguard import UnsafeGrantTarget, assert_grantable
from sletchy.kernel.hostchanges import (
    JOURNAL_NAME,
    HostChange,
    forget,
    journal_path,
    pending,
    unreadable,
)

if TYPE_CHECKING:
    from sletchy.kernel.flags import FlagStore


@dataclass(frozen=True)
class PanicReport:
    """What panic actually did. Every field is a count or a plain fact."""

    flags_reset: int = 0
    firewall_rules_removed: int = 0
    firewall_rules_kept: int = 0
    processes_terminated: int = 0
    sandbox_changes_reverted: int = 0
    runtime_files_cleared: int = 0
    ledger_sealed: bool = False
    errors: tuple[str, ...] = field(default_factory=tuple)

    @property
    def clean(self) -> bool:
        return not self.errors

    def render(self) -> str:
        lines = [
            f"  flags reset            {self.flags_reset}",
            f"  firewall rules removed {self.firewall_rules_removed}",
            f"  firewall rules kept    {self.firewall_rules_kept}",
            f"  processes terminated   {self.processes_terminated}",
            f"  sandbox changes undone {self.sandbox_changes_reverted}",
            f"  runtime files cleared  {self.runtime_files_cleared}",
            f"  final ledger entry     {'written' if self.ledger_sealed else 'not written'}",
        ]
        if self.firewall_rules_kept:
            lines.append("")
            lines.append(f"  {KEPT_RULES_NOTE}")
        if self.errors:
            lines.append("")
            lines.extend(f"  ! {e}" for e in self.errors)
        return "\n".join(lines)


if not re.fullmatch(r"[A-Za-z0-9_-]+", FIREWALL_GROUP):  # pragma: no cover - a constant
    raise RuntimeError("FIREWALL_GROUP is interpolated into a script and must stay a plain word")

#: How long panic waits for another Sletchy process to finish writing the ledger
#: before it gives up on recording its flag reset and carries on with every other
#: step. A writer holds the lock for one append, so a second is plenty; panic must
#: not lose to a flood of appends, and must not stall behind one either (#95).
PANIC_LOCK_WAIT_SECONDS = 1.0

#: Read-only. Counts rules whose `Grouping` is exactly ours, through the documented
#: firewall COM API. Needs no elevation, and `Grouping` is the raw string Sletchy
#: sets, so the answer does not depend on the Windows display language.
COUNT_RULES_SCRIPT = (
    "$n = 0; foreach ($r in (New-Object -ComObject HNetCfg.FwPolicy2).Rules) "
    f"{{ if ($r.Grouping -eq '{FIREWALL_GROUP}') {{ $n++ }} }}; $n"
)

#: Removes by **group**, never by rule name: two rules can share a name, and a
#: name-based delete could take a rule that is not ours. Needs elevation.
REMOVE_RULES_SCRIPT = f"Remove-NetFirewallRule -Group '{FIREWALL_GROUP}' -ErrorAction Stop"

#: What an unelevated panic says about the rules it keeps. They only restrict
#: Sletchy's own sandboxes, so keeping them is never the unsafe direction, and a
#: warning on every press would teach the operator to stop reading warnings.
KEPT_RULES_NOTE = (
    f"The {FIREWALL_GROUP} firewall rules stay. They only stop Sletchy's own sandboxes "
    "reaching other computers. Removing them needs an administrator: "
    "sletchy install-rules --remove."
)


def _is_windows() -> bool:
    """One seam for the platform check, so tests can exercise the Windows path anywhere."""
    return sys.platform == "win32"


def _is_elevated() -> bool:
    """A question, never a request: Sletchy asks for no elevation (LAW 0 §3).

    Imported here, not at the top: `selfcheck` imports `rules`, which imports this
    module.
    """
    from sletchy.cli.selfcheck import is_elevated

    return is_elevated()


def _powershell(script: str, timeout: float) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],  # noqa: S607
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def _first_line(result: subprocess.CompletedProcess[str]) -> str:
    text = (result.stderr or "") + (result.stdout or "")
    line = next((ln.strip() for ln in text.splitlines() if ln.strip()), "no output")
    return line[:200]


def count_firewall_rules() -> int:
    """How many firewall rules are in the `Sletchy` group right now.

    Raises `OSError` when the count cannot be taken. A count that cannot be taken is
    never reported as zero: "I could not look" and "there is nothing" are different
    answers, and confusing them is how this function's predecessor reported a clean
    host for a step that had never once worked (L009).
    """
    if shutil.which("powershell") is None:
        raise OSError("powershell not found, so the firewall could not be queried")
    try:
        result = _powershell(COUNT_RULES_SCRIPT, timeout=60)
    except subprocess.SubprocessError as exc:
        raise OSError(f"firewall query did not finish: {type(exc).__name__}") from exc
    if result.returncode != 0:
        raise OSError(f"firewall query failed (exit {result.returncode}): {_first_line(result)}")
    try:
        return int((result.stdout or "").strip())
    except ValueError as exc:
        raise OSError(f"firewall query returned no count: {_first_line(result)}") from exc


def remove_firewall_rules(*, dry_run: bool = False) -> tuple[int, int, str | None]:
    """Remove every firewall rule in the `Sletchy` group, and prove it.

    Returns `(removed, kept, error)`.

    Removing by **group** is what makes this complete: panic does not need to know
    which rules exist, only that nothing outside the group was ever created
    ([LAW 0 §2](../../../docs/LAW/00-do-no-harm.md)).

    Three steps, because an exit code is not evidence: count, remove, count again.
    The rules removed are the difference between the two counts, and any rule still
    present afterwards is an error naming how many remain. A clean host costs one
    read-only query and needs no elevation.

    **Unelevated, the rules are kept, counted and never touched.** Removing them
    needs an administrator, so trying could only fail. They only restrict Sletchy's
    own sandboxes, so keeping them is the safe direction, and it is reported as a
    count, not an error: a warning on every press of Stop everything teaches the
    operator to ignore warnings (#179). A count that cannot be taken is still an
    error (L009). Elevated, a rule left after the removal is an error.

    In a dry run the first count is taken and returned as what panic would remove,
    or keep; nothing is changed.
    """
    if not _is_windows():
        return 0, 0, None  # no Windows Firewall, so nothing Sletchy could have added

    try:
        before = count_firewall_rules()
    except OSError as exc:
        return 0, 0, f"could not check for {FIREWALL_GROUP} firewall rules: {exc}"
    if before == 0:
        return 0, 0, None
    if not _is_elevated():
        return 0, before, None
    if dry_run:
        return before, 0, None

    try:
        removal = _powershell(REMOVE_RULES_SCRIPT, timeout=120)
        detail = None if removal.returncode == 0 else _first_line(removal)
    except subprocess.SubprocessError as exc:
        detail = f"removal did not finish: {type(exc).__name__}"

    try:
        after = count_firewall_rules()
    except OSError as exc:
        return 0, 0, f"removed rules but could not recount them: {exc}"

    removed = max(before - after, 0)
    if after:
        why = f" ({detail})" if detail else ""
        return (
            removed,
            0,
            (
                f"{after} firewall rule(s) in group {FIREWALL_GROUP!r} remain{why}, "
                "although this ran as an administrator"
            ),
        )
    return removed, 0, None


#: The prefix of every AppContainer profile Sletchy creates. Since #33 the Warden
#: names them for its lanes (`SANDBOX_LANES`, in the Kernel); a journal written
#: before then names `Sletchy-<context_id>`, and panic still reverts those. The
#: Warden's `_win32.PROFILE_PREFIX` is the other copy (`cli` may not import
#: `warden`); `test_panic_and_the_warden_agree_on_the_profile_name` holds them equal.
PROFILE_PREFIX = "Sletchy"

#: The prefix of every container the `container` backend names (#70). The Warden's
#: `container.NAME_PREFIX` is the other copy, held equal by
#: `test_panic_and_the_warden_agree_on_the_container_name`.
CONTAINER_PREFIX = "sletchy-"
CONTAINER_RUNTIME = "podman"

#: An AppContainer SID is `S-1-15-2-` and the seven sub-authorities Windows derives
#: from the profile name. Requiring all seven refuses every user, machine group and
#: well-known SID, including `ALL APPLICATION PACKAGES` (`S-1-15-2-1`), which has one.
APPCONTAINER_SID = re.compile(r"S-1-15-2(?:-\d{1,10}){7}")


def _refusal(change: HostChange) -> str | None:
    """Why panic will not act on this record, or None if Sletchy could have written it.

    The journal is readable without the signing key on purpose, so panic works when
    the keychain is gone. The cost is that anything able to write `var/` can write a
    record, and a record aims `icacls /T` and `DeleteAppContainerProfile` (#94). So a
    record is acted on only when it is exactly what the Warden would have written:

    - no profile, a sandbox lane, or exactly `Sletchy-<its own context_id>` (the
      names before lanes, #33)
    - no SID, or **the** SID Windows derives from that profile name - not merely one
      shaped like an AppContainer SID, which another app's container also is
    - every granted path that still exists passes the Warden's own grant guard, which
      now lives in the Kernel so the two cannot disagree

    Every check is read-only and runs before any host call, in a dry run too. A
    check that cannot be made refuses the record: it is kept for the next panic,
    never acted on in hope.
    """
    if change.kind == "container":
        named = f"{CONTAINER_PREFIX}{change.context_id}"
        if change.profile != named:
            return f"container {change.profile[:80]!r} is not Sletchy's (expected {named!r})"
        if change.sid or change.granted_paths:
            return "a container record carries no SID and no grants"
        return None
    expected = f"{PROFILE_PREFIX}-{change.context_id}"
    if change.profile and change.profile != expected and change.profile not in SANDBOX_LANES:
        return (
            f"profile {change.profile[:80]!r} is not Sletchy's "
            f"(expected a sandbox lane or {expected!r})"
        )
    if not change.sid:
        return None
    if not APPCONTAINER_SID.fullmatch(change.sid):
        return f"SID {change.sid[:80]!r} is not an AppContainer SID"
    name = change.profile or expected
    try:
        derived = _call_derive_sid(name)
    except OSError as exc:
        return f"could not check SID {change.sid!r} against {name!r}: {exc}"
    if change.sid != derived:
        return f"SID {change.sid!r} is not the one Windows gives {name!r} ({derived})"
    for raw in change.granted_paths:
        path = Path(raw)
        if not path.exists():
            continue  # nothing granted there any more, so nothing to walk
        try:
            assert_grantable(path)
        except UnsafeGrantTarget as exc:
            return f"the Warden's grant guard refuses this path: {exc}"
    return None


def revert_host_changes(*, dry_run: bool = False) -> tuple[int, tuple[str, ...]]:
    """Undo sandbox changes whose own `finally` never ran.

    `winjob` reverses everything it does as a run ends. This is for the case that
    cannot: the process was killed between making a change and undoing it. The
    journal records each change *before* it takes effect, so what is left here is
    exactly the set nobody else will clean up.

    **Deliberately reimplemented rather than delegating to the Warden.** `cli` may
    not import `warden`, and more importantly panic must work when Sletchy is
    wedged - a panic path that calls into the component that just died is a panic
    path that dies with it. The same reasoning already put `netsh` in this file.

    Reverting is idempotent: a profile that is already gone and an ACE that was
    never granted both report success, because panic runs when the state is
    unknown and "already clean" is the common case.

    **A change is forgotten only once its undo is proven.** If any step of a revert
    fails, its journal entry stays, the error is reported, and the next panic tries
    again. Forgetting a change whose undo failed would delete the only record of a
    modification still on the host, which is the one outcome LAW 0 §2 exists to
    prevent. In a dry run, the count is what *would* be reverted.

    **A line that does not parse is reported and kept** (#103), so a torn record
    never makes the report clean.

    **A record Sletchy could not have written is refused, reported and kept** (#94):
    see `_refusal`. Refusing is checked before any host call, in a dry run too, so a
    plan never counts a record the run would not touch.
    """
    changes = pending()
    # A line that cannot be read is not a line with nothing in it (L009, #103). It
    # is named, so the report is not clean, and kept - only the operator can say what it
    # was, and deleting it would abandon whatever it records.
    errors: list[str] = [
        f"journal line {lineno} could not be read and was kept ({journal_path()}); "
        "it may record a sandbox change still on this computer. Check, then delete "
        "that line by hand"
        for lineno in unreadable()
    ]
    if not changes:
        return 0, tuple(errors)

    acceptable: list[HostChange] = []
    for change in changes:
        why = _refusal(change)
        if why is None:
            acceptable.append(change)
        else:
            errors.append(f"refused journal record {change.context_id}: {why}; it was kept")
    if dry_run:
        return len(acceptable), tuple(errors)

    reverted = 0
    for change in acceptable:
        if change.kind == "container":
            try:
                _remove_container(change.profile)
            except (OSError, subprocess.SubprocessError) as exc:
                errors.append(f"could not revert {change.context_id}: {type(exc).__name__}: {exc}")
                continue
            forget(change.context_id)
            reverted += 1
            continue
        # A lane comes back on later runs, so a record left by a dead run can name
        # a lane a live one now holds. That run's profile and grant are not this
        # record's to undo: the lane is reverted only while panic holds it.
        lane = None
        if change.profile in SANDBOX_LANES and _is_windows():
            try:
                lane = _call_take_lane(change.profile)
            except OSError as exc:
                errors.append(
                    f"could not check whether {change.profile} is in use, so record "
                    f"{change.context_id} was kept: {exc}"
                )
                continue
            if lane is None:
                errors.append(
                    f"{change.profile} is held by a sandbox that is still running, so "
                    f"record {change.context_id} was not touched and was kept"
                )
                continue
        try:
            if change.sid and change.granted_paths:
                for raw in change.granted_paths:
                    _revoke_ace(Path(raw), change.sid)
            if change.profile:
                _delete_appcontainer_profile(change.profile)
        except (OSError, subprocess.SubprocessError) as exc:
            errors.append(f"could not revert {change.context_id}: {type(exc).__name__}: {exc}")
            continue
        finally:
            if lane is not None:
                _call_release_lane(lane)
        forget(change.context_id)
        reverted += 1
    return reverted, tuple(errors)


#: `WaitForSingleObject`'s answers that mean the caller now owns the mutex.
#: Abandoned is a holder that died without letting go.
_WAIT_OBJECT_0 = 0x00000000
_WAIT_ABANDONED = 0x00000080
_WAIT_TIMEOUT = 0x00000102


def _call_take_lane(lane: str) -> int | None:
    """Take a lane's mutex without waiting: its handle, or None if a run holds it.

    The Warden's `_win32.Lane` takes the same mutex; this is panic's own copy for
    the reason `_call_derive_sid` is. Raises `OSError` when it cannot answer.
    """
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateMutexW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
    kernel32.CreateMutexW.restype = wintypes.HANDLE
    kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    handle = kernel32.CreateMutexW(None, False, lane_lock_name(lane))
    if not handle:
        raise OSError(f"CreateMutexW failed: WinError {ctypes.get_last_error()}")
    state = kernel32.WaitForSingleObject(handle, 0)
    if state in (_WAIT_OBJECT_0, _WAIT_ABANDONED):
        return int(handle)
    kernel32.CloseHandle(handle)
    if state == _WAIT_TIMEOUT:
        return None
    raise OSError(f"WaitForSingleObject returned {state:#x}")


def _call_release_lane(handle: int) -> None:
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.ReleaseMutex.argtypes = [wintypes.HANDLE]
    kernel32.ReleaseMutex.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.ReleaseMutex(handle)
    kernel32.CloseHandle(handle)


def _revoke_ace(path: Path, sid: str) -> None:
    """Remove one container SID's ACE from a directory tree.

    A path that no longer exists has no ACE to remove, which is success. Anything
    else that stops the removal raises, so the caller keeps the journal entry.
    """
    if not path.exists():
        return
    if shutil.which("icacls") is None:
        raise OSError(f"icacls not found, so the grant on {path} could not be removed")
    result = subprocess.run(  # noqa: S603
        ["icacls", str(path), "/remove:g", f"*{sid}", "/T", "/C", "/Q"],  # noqa: S607
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if result.returncode != 0:
        raise OSError(f"icacls exit {result.returncode} on {path}: {_first_line(result)}")


#: Measured on 10.0.19045 (2026-10-02): deleting a profile that does not exist
#: returns S_OK, so "already gone" needs no special case. An empty name returns
#: E_INVALIDARG. Anything but S_OK is a failure.
S_OK = 0


def _call_derive_sid(name: str) -> str:
    """The SID Windows gives an AppContainer profile of this name, as a string.

    `DeriveAppContainerSidFromAppContainerName` computes it from the name alone: it
    reads nothing and creates nothing, and the profile need not exist. Measured on
    10.0.19045 (2026-10-03): it is SHA-256 of the lowercased name in UTF-16LE, taken
    as seven little-endian sub-authorities, which is what the tests' fake does and
    what `test_the_derivation_is_the_one_windows_uses` holds on Windows. Raises
    `OSError` when it cannot answer, including off Windows.
    """
    if not _is_windows():
        raise OSError("an AppContainer SID can only be derived on Windows")
    import ctypes
    from ctypes import wintypes

    userenv = ctypes.WinDLL("userenv", use_last_error=True)
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    derive = userenv.DeriveAppContainerSidFromAppContainerName
    derive.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_void_p)]
    derive.restype = ctypes.c_long
    to_string = advapi32.ConvertSidToStringSidW
    to_string.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    to_string.restype = wintypes.BOOL
    free_sid = advapi32.FreeSid
    free_sid.argtypes = [ctypes.c_void_p]
    free_sid.restype = ctypes.c_void_p
    local_free = kernel32.LocalFree
    local_free.argtypes = [ctypes.c_void_p]
    local_free.restype = ctypes.c_void_p

    sid = ctypes.c_void_p()
    hresult = int(derive(name, ctypes.byref(sid)))
    if hresult != S_OK:
        msg = f"DeriveAppContainerSidFromAppContainerName returned {hresult & 0xFFFFFFFF:#010x}"
        raise OSError(msg)
    try:
        text = wintypes.LPWSTR()
        if not to_string(sid, ctypes.byref(text)):
            raise OSError(f"ConvertSidToStringSidW failed: WinError {ctypes.get_last_error()}")
        try:
            return text.value or ""
        finally:
            local_free(ctypes.cast(text, ctypes.c_void_p))
    finally:
        free_sid(sid)


def _call_delete_profile(name: str) -> int:
    """The raw Win32 call, alone, so tests can stand in for it."""
    import ctypes

    userenv = ctypes.WinDLL("userenv", use_last_error=True)
    userenv.DeleteAppContainerProfile.argtypes = [ctypes.c_wchar_p]
    userenv.DeleteAppContainerProfile.restype = ctypes.c_long
    return int(userenv.DeleteAppContainerProfile(name))


def _delete_appcontainer_profile(name: str) -> None:
    """Delete an AppContainer profile by name, and raise if Windows says no.

    Needs no elevation and writes only under the user's own local app data - the
    same call the Warden makes, kept here so panic depends on nothing above the
    Kernel.
    """
    if not _is_windows():
        return
    hresult = _call_delete_profile(name)
    if hresult != S_OK:
        raise OSError(f"DeleteAppContainerProfile({name!r}) returned {hresult & 0xFFFFFFFF:#010x}")


def _remove_container(name: str) -> None:
    """Remove one of Sletchy's containers, running or not; already gone is success.

    Raises when it cannot be done or cannot be checked: with no runtime here, "could
    not look" is not "nothing there" (L009), so the record is kept.
    """
    runtime = shutil.which(CONTAINER_RUNTIME)
    if runtime is None:
        raise OSError(f"{CONTAINER_RUNTIME} not found, so container {name} could not be checked")
    result = subprocess.run(  # noqa: S603 - the runtime, removing a name checked above
        [runtime, "rm", "--force", "--ignore", name],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if result.returncode != 0:
        raise OSError(f"{CONTAINER_RUNTIME} rm exit {result.returncode}: {_first_line(result)}")


def clear_runtime(*, dry_run: bool = False) -> int:
    """Remove locks and pid files from `var/run/`.

    Deliberately the *only* directory panic deletes from. The ledger and payloads
    are evidence; the keychain holds credentials. An emergency stop that destroys
    either is worse than the emergency.

    **The host-change journal is never cleared here.** It lives in `var/run/` but it
    is not a lock: it is the record of changes still on the host. Entries leave it
    one at a time, as `revert_host_changes` proves each undo, and the file goes when
    the last one does.
    """
    run = runtime_dir()
    if not run.is_dir():
        return 0
    cleared = 0
    for path in run.iterdir():
        if path.is_file() and path.name != JOURNAL_NAME:
            if not dry_run:
                path.unlink(missing_ok=True)
            cleared += 1
    return cleared


def panic(
    flags: FlagStore | None = None,
    *,
    reason: str = "operator ran sletchy stop",
    dry_run: bool = False,
) -> PanicReport:
    """Return the host to a clean state. Idempotent, non-destructive, unattended.

    Each step is independent and its failure is collected rather than raised: a
    firewall that will not answer must not stop panic from resetting flags. The
    report says what failed, and the exit code reflects it.
    """
    errors: list[str] = []

    flags_reset = 0
    ledger_sealed = False
    if flags is not None:
        try:
            flags_reset = flags.reset_all(reason=reason) if not dry_run else 0
            ledger_sealed = not dry_run
        except FlagWriteFailed as exc:
            # The reset entry is in the ledger, and so is the entry saying the file
            # write failed (#104). The report says the entry was written, because it
            # was, and that no flag was reset, because none was.
            ledger_sealed = True
            errors.append(f"could not reset flags: {exc}")
        except Exception as exc:
            errors.append(f"could not reset flags: {type(exc).__name__}: {exc}")

    rules, kept, firewall_error = remove_firewall_rules(dry_run=dry_run)
    if firewall_error:
        errors.append(firewall_error)

    # Before clear_runtime, which deletes the journal these are read from.
    try:
        sandbox_reverted, sandbox_errors = revert_host_changes(dry_run=dry_run)
        errors.extend(sandbox_errors)
    except Exception as exc:
        sandbox_reverted = 0
        errors.append(f"could not revert sandbox changes: {type(exc).__name__}: {exc}")

    try:
        cleared = clear_runtime(dry_run=dry_run)
    except OSError as exc:
        cleared = 0
        errors.append(f"could not clear {runtime_dir()}: {exc}")

    return PanicReport(
        flags_reset=flags_reset,
        firewall_rules_removed=rules,
        firewall_rules_kept=kept,
        # Still zero, but no longer because nothing is launched - `winjob` launches
        # plenty. A sandboxed tree lives in a Job Object with KILL_ON_JOB_CLOSE and
        # no breakaway, so losing the launcher closes the last handle and the kernel
        # kills the tree. Panic arrives to find nothing running, which is the job
        # object doing its work rather than panic skipping it. Counting kills we did
        # not perform would be the dishonest option; the gap is in COVERAGE.md.
        processes_terminated=0,
        sandbox_changes_reverted=sandbox_reverted,
        runtime_files_cleared=cleared,
        ledger_sealed=ledger_sealed,
        errors=tuple(errors),
    )
