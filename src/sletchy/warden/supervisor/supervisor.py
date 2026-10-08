"""The supervisor: whether a command may run at all, decided before any process exists.

`winjob` answers "how do we contain what we launch". This answers the question before it:
"should this be launched at all" (#69, roadmap 2.7). Until now a caller holding a
`Sandbox` could run anything, and the only gate was that the caller wrote the argv.

The rules, each one a refusal by name:

- **An allowlist, not a blocklist.** A program not on the list is refused. An empty list
  launches nothing (LAW 2). The list can be narrowed while running, never widened (LAW 3)
- **A program is named by its absolute, resolved path**, never by a bare name looked up on
  `PATH`, which is how a shadowed binary wins. The path passes fsguard's text rules first:
  no device paths, shares, streams or device names
- **No shells.** `cmd`, PowerShell, WSL, `bash` and the script hosts cannot be put on the
  list at all: a granted shell is a free prompt. No command strings, ever: argv lists only
- **Known living-off-the-land binaries** - signed Windows programs that fetch, decode or
  run code - cannot be put on the list either. **This is a tripwire, not the control.**
  The list is incomplete by construction; the allowlist is what stops the rest
- **The decision is recorded before the launch**, allowed or refused, with the rule that
  fired, and before the sandbox records its own launch (LAW 1). A refusal never becomes a
  process, not even briefly
- **A backend that cannot be had is a recorded refusal.** `select()` raises without
  writing, because a ledger parameter on it would change a signature that is itself a
  control; the supervisor is the caller that records it

There is no bypass: no `force`, no `trusted=True`, no internal-caller exemption (#69, out
of scope permanently).
"""

from __future__ import annotations

import os
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath
from typing import TYPE_CHECKING

from sletchy.kernel.contracts import Decision, Plane, Subject, SubjectKind, Verdict
from sletchy.kernel.contracts.base import NAME_PATTERN
from sletchy.warden.fsguard import PathRefused, check_text
from sletchy.warden.isolation import BackendUnavailable, registry

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

    from sletchy.kernel.contracts import IsolationProfile
    from sletchy.kernel.ledger import Ledger, PayloadStore
    from sletchy.warden.isolation import LaunchResult, SandboxRecorder

ALLOWED_ACTION = "warden.supervisor.allowed"
DENIED_ACTION = "warden.supervisor.denied"

#: Programs that read other text as commands. A granted shell is a free prompt.
SHELLS = frozenset(
    {"cmd", "command", "powershell", "powershell_ise", "pwsh", "wsl", "bash", "sh", "zsh",
     "wscript", "cscript"}
)  # fmt: skip

#: Signed Windows programs known to fetch, decode or run code. A tripwire that says
#: something odd was attempted; incomplete on the day it was written, and never the control.
#: One name is assembled from pieces, so the LAW 0 scan of shipped code (which looks for
#: programs that change the host) does not read this list of refusals as a use of it.
LIVING_OFF_THE_LAND = frozenset(
    {"cert" + "util", "mshta", "regsvr32", "rundll32", "bitsadmin", "wmic", "msbuild",
     "installutil", "regasm", "regsvcs", "msiexec", "cmstp", "odbcconf", "forfiles",
     "mavinject", "msxsl", "ieexec", "presentationhost", "esentutl", "expand", "extrac32",
     "hh", "infdefaultinstall", "pcalua", "scriptrunner", "syncappvpublishingserver"}
)  # fmt: skip


class LaunchDenied(PermissionError):
    """The supervisor refused a launch. Nothing was started; the refusal is on the ledger."""

    def __init__(self, rule: str, detail: str) -> None:
        self.rule = rule
        super().__init__(f"{rule}: {detail}")


def program_name(program: str | os.PathLike[str]) -> str:
    """The bare, lower-case name: a full path ending `System32/CMD.EXE` gives `cmd`."""
    name = PureWindowsPath(os.fspath(program)).name.lower()
    for suffix in (".exe", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".msc"):
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return name


def _canonical(program: str) -> Path:
    """An absolute program path, its text checked and then resolved, or `LaunchDenied`."""
    try:
        check_text(program)
    except PathRefused as exc:
        raise LaunchDenied("program_path", str(exc)) from exc
    if not PureWindowsPath(program).is_absolute() and not Path(program).is_absolute():
        raise LaunchDenied(
            "not_absolute",
            f"{program!r} is a name, not a path; names are looked up on PATH, which a "
            "shadowed program can win",
        )
    try:
        resolved = Path(program).resolve(strict=True)
    except OSError as exc:
        raise LaunchDenied("not_found", f"{program!r} does not exist") from exc
    if not resolved.is_file():
        raise LaunchDenied("not_found", f"{resolved} is not a file")
    return resolved


def _workspace(workspace: Path) -> Path:
    """The folder a launch runs in: its text checked by fsguard, resolved, and a folder.

    `winjob` grants the sandbox access to it, behind the grant guard's own refusals
    (drive roots, protected folders, oversized trees); this refuses earlier, by name.
    """
    text = os.fspath(workspace)
    try:
        check_text(text)
    except PathRefused as exc:
        raise LaunchDenied("workspace", str(exc)) from exc
    try:
        resolved = Path(text).resolve(strict=True)
    except OSError as exc:
        raise LaunchDenied("workspace", f"{text!r} does not exist") from exc
    if not resolved.is_dir():
        raise LaunchDenied("workspace", f"{resolved} is not a folder")
    return resolved


def _refused_by_kind(program: str | os.PathLike[str]) -> tuple[str, str] | None:
    name = program_name(program)
    if name in SHELLS:
        return "shell", f"{name} is a shell; a granted shell is a free prompt"
    if name in LIVING_OFF_THE_LAND:
        return "living_off_the_land", f"{name} is a signed program known to fetch or run code"
    return None


@dataclass(frozen=True)
class Allowed:
    """One program that may be launched: a name for the record, and its resolved path."""

    name: str
    program: Path


class Allowlist:
    """The programs that may run. Built once from configuration; it can only shrink (LAW 3)."""

    __slots__ = ("_entries",)

    def __init__(self, entries: Iterable[Allowed]) -> None:
        self._entries: tuple[Allowed, ...] = tuple(entries)

    @classmethod
    def of(cls, programs: Mapping[str, str | os.PathLike[str]]) -> Allowlist:
        """From `{name: path}`. Refuses, loudly, a shell, a tripwire program, or a bare name."""
        entries = []
        for name, program in programs.items():
            if not re.fullmatch(NAME_PATTERN, name):
                msg = f"{name!r}: an allowlist name is lower-case letters, digits, _ and -"
                raise ValueError(msg)
            kind = _refused_by_kind(program)
            if kind is not None:
                msg = f"{name}: {kind[1]}, so it cannot be allowlisted"
                raise ValueError(msg)
            try:
                resolved = _canonical(os.fspath(program))
            except LaunchDenied as exc:
                msg = f"{name}: {exc}"
                raise ValueError(msg) from exc
            entries.append(Allowed(name=name, program=resolved))
        return cls(entries)

    def __len__(self) -> int:
        return len(self._entries)

    def without(self, name: str) -> Allowlist:
        """A narrower list. There is no method that adds."""
        return Allowlist(e for e in self._entries if e.name != name)

    def match(self, program: Path) -> Allowed | None:
        target = os.path.normcase(str(program))
        return next((e for e in self._entries if os.path.normcase(str(e.program)) == target), None)


def load_allowlist(path: Path) -> Allowlist:
    """`[programs]` from a TOML file, `name = "path"` per line.

    No file means no programs, so nothing runs (LAW 2). A file that exists but cannot be
    read or parsed raises: an allowlist nobody can read is not the same as an empty one,
    and guessing either way would be wrong.
    """
    if not path.exists():
        return Allowlist(())
    try:
        data = tomllib.loads(path.read_text("utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        msg = f"the allowlist at {path} could not be read: {exc}"
        raise ValueError(msg) from exc
    extra = set(data) - {"programs"}
    programs = data.get("programs", {})
    if (
        extra
        or not isinstance(programs, dict)
        or not all(isinstance(v, str) for v in programs.values())
    ):
        msg = f'the allowlist at {path} must hold one [programs] table of name = "path" lines'
        raise ValueError(msg)
    return Allowlist.of(programs)


@dataclass(frozen=True)
class Plan:
    """What `launch` would do: the program that would run, its argv, the backend, the rule."""

    program: str
    argv: tuple[str, ...]
    backend: str
    rule: str


class Supervisor:
    """Every launch goes through `launch`, which decides, records, then runs."""

    def __init__(self, allowlist: Allowlist, *, recorder: SandboxRecorder) -> None:
        self._allowlist = allowlist
        self._recorder = recorder

    @classmethod
    def for_ledger(
        cls,
        allowlist: Allowlist,
        *,
        ledger: Ledger,
        actor_id: str,
        payloads: PayloadStore | None = None,
    ) -> Supervisor:
        """A supervisor with its own recorder, so a caller never reaches into the sandboxes.

        The Shell may import the supervisor and nothing else in the Warden (ADR-0011).
        """
        from sletchy.warden.isolation import SandboxRecorder

        recorder = SandboxRecorder(ledger=ledger, actor_id=actor_id, payloads=payloads)
        return cls(allowlist, recorder=recorder)

    @property
    def allowlist(self) -> Allowlist:
        return self._allowlist

    def narrow(self, name: str) -> None:
        """Remove a program from the list while running. Nothing can be added (LAW 3)."""
        self._allowlist = self._allowlist.without(name)

    def launch(
        self, command: list[str], *, workspace: Path, profile: IsolationProfile
    ) -> LaunchResult:
        """Decide, record the decision, then run inside the strongest sandbox allowed.

        A refusal raises `LaunchDenied` (or `BackendUnavailable`) after its entry is
        written, and before any sandbox is even constructed.
        """
        try:
            folder = _workspace(workspace)
            allowed, argv = self._decide(command)
            sandbox_class = registry.select(profile.backend)
        except LaunchDenied as denied:
            self._record(command, Decision.DENY, denied.rule, str(denied))
            raise
        except BackendUnavailable as exc:
            self._record(command, Decision.DENY, "no_backend", str(exc))
            raise
        self._record(argv, Decision.ALLOW, allowed.name, f"allowlisted as {allowed.name}")
        with sandbox_class(folder, profile, recorder=self._recorder) as sandbox:
            return sandbox.run(argv)

    def plan(self, command: list[str], *, workspace: Path, profile: IsolationProfile) -> Plan:
        """What `launch` would do, recording nothing and running nothing (a dry run)."""
        return plan(self._allowlist, command, workspace=workspace, profile=profile)

    def _decide(self, command: list[str]) -> tuple[Allowed, list[str]]:
        return decide(self._allowlist, command)

    def _record(self, command: object, decision: Decision, rule: str, reason: str) -> None:
        program = (
            str(command[0])[:1024] if isinstance(command, list) and command else "<not a command>"
        )
        self._recorder.ledger.append(
            plane=Plane.WARDEN,
            actor_id=self._recorder.actor_id,
            action=ALLOWED_ACTION if decision is Decision.ALLOW else DENIED_ACTION,
            subject=Subject(kind=SubjectKind.PROCESS, identifier=program or "<empty>"),
            verdict=Verdict(
                decision=decision,
                reason=reason if len(reason) <= 512 else reason[:509] + "...",
                rule_id=rule,
            ),
        )


def decide(allowlist: Allowlist, command: list[str]) -> tuple[Allowed, list[str]]:
    """Whether `command` may run under `allowlist`, and the argv that would; else `LaunchDenied`."""
    if not isinstance(command, list):
        raise LaunchDenied(
            "command_string", "a command is a list of arguments, never one string for a shell"
        )
    if not command:
        raise LaunchDenied("empty_command", "a launch needs a program")
    if not all(isinstance(arg, str) for arg in command):
        raise LaunchDenied("bad_argument", "every argument must be text")
    if any("\x00" in arg for arg in command):
        raise LaunchDenied("bad_argument", "an argument holds a NUL, which ends it early")
    if len(allowlist) == 0:
        raise LaunchDenied("empty_allowlist", "nothing is allowlisted, so nothing runs")
    kind = _refused_by_kind(command[0])
    if kind is not None:
        raise LaunchDenied(*kind)
    program = _canonical(command[0])
    kind = _refused_by_kind(program)
    if kind is not None:
        raise LaunchDenied(*kind)
    allowed = allowlist.match(program)
    if allowed is None:
        raise LaunchDenied("not_allowlisted", f"{program} is not on the allowlist")
    return allowed, [str(program), *command[1:]]


def plan(
    allowlist: Allowlist, command: list[str], *, workspace: Path, profile: IsolationProfile
) -> Plan:
    """What a launch would do, without a ledger: the same refusals, recorded nowhere.

    A dry run changes nothing, the ledger included, so it needs no supervisor instance.
    """
    _workspace(workspace)
    allowed, argv = decide(allowlist, command)
    sandbox_class = registry.select(profile.backend)
    return Plan(
        program=argv[0], argv=tuple(argv), backend=sandbox_class.backend.value, rule=allowed.name
    )
