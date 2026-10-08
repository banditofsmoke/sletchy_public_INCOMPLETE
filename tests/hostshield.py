"""LAW 0, made physical for the test suite: what a test run may never do to this PC.

The suite runs on the operator's only computer, many times a day. Until now its
safety rested on every test remembering to redirect `SLETCHY_HOME`, stub the
firewall step and use an in-memory key. A test that forgets any one of them would
write to the real `var/`, try the real firewall, or touch the real keychain, and
nothing would stop it. This module is the thing that stops it.

Two uses, one list (LAW 6):

- **At run time**, `tests/conftest.py` installs `Shield`, which refuses a host-changing
  command, a connection off this machine, a window or browser popping up, and any
  real keychain access, **before** it happens. Every Python process a test starts
  installs `ChildShield` as it starts, through `shield_site/sitecustomize.py` (L016).
- **Statically**, `test_law_zero.py` scans everything Sletchy ships (Python, the
  window's Rust and TypeScript, the scripts and the launcher) for the same
  operations, because a shipped program is not run inside this shield.

Every entry in `HOST_CHANGES` names the LAW 0 clause it enforces and carries an
example it must catch, and the tests prove each one does (L001: a check that has
never been seen to fail is a hypothesis).
"""

from __future__ import annotations

import ast
import io
import ipaddress
import os
import re
import socket
import subprocess
import tempfile
import tokenize
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path, PureWindowsPath
from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Iterator


@dataclass(frozen=True)
class HostChange:
    """One kind of host change LAW 0 forbids, with an example it must catch."""

    clause: str
    what: str
    pattern: re.Pattern[str]
    example: str
    #: False for patterns that only make sense in source code (`eval(`), not in a
    #: command line a test starts.
    runtime: bool = True
    #: False for changes LAW 0 permits Sletchy itself, but never a test run: rules in
    #: the `Sletchy` firewall group (§2), which `sletchy panic` removes.
    shipped: bool = True


def _p(text: str) -> re.Pattern[str]:
    return re.compile(text, re.IGNORECASE)


# Each clause's entries are the specific operations that make the change. Matching is
# case-insensitive, because Windows commands are: `-Verb RunAs` passed a check that
# only knew `runas`.
HOST_CHANGES: tuple[HostChange, ...] = (
    # §1 - no kernel-mode code, no Test Signing Mode, no services
    HostChange("§1", "boot configuration", _p(r"\bbcdedit\b"), "bcdedit /enum"),
    HostChange("§1", "Test Signing Mode", _p(r"testsigning"), "set testsigning on"),
    HostChange("§1", "a service or driver", _p(r"\bCreateServiceW?\b"), "CreateServiceW(scm)"),
    HostChange("§1", "a service or driver", _p(r"\bSC_MANAGER_"), "SC_MANAGER_ALL_ACCESS"),
    HostChange("§1", "a kernel driver", _p(r"SERVICE_KERNEL_DRIVER"), "SERVICE_KERNEL_DRIVER"),
    HostChange("§1", "a kernel driver", _p(r"\b[NZ][tw]LoadDriver\b"), "NtLoadDriver(name)"),
    HostChange("§1", "a filter driver", _p(r"FltRegisterFilter"), "FltRegisterFilter(drv)"),
    HostChange("§1", "a service", _p(r"\bNew-Service\b"), "New-Service -Name x"),
    HostChange(
        "§1", "a service", _p(r"\bsc(\.exe)?\b['\"]?\s*,?\s*['\"]?create\b"), "sc.exe create x"
    ),
    # §3 - Sletchy runs as a normal user and asks for no elevation at run time
    HostChange("§3", "elevation", _p(r"\brunas\b"), "Start-Process x -Verb RunAs"),
    HostChange("§3", "elevation", _p(r"requireAdministrator"), 'level="requireAdministrator"'),
    HostChange("§3", "elevation", _p(r"highestAvailable"), 'level="highestAvailable"'),
    HostChange("§3", "a privilege", _p(r"AdjustTokenPrivileges"), "AdjustTokenPrivileges(t)"),
    HostChange(
        "§3",
        "a privilege",
        _p(r"\bSe(Debug|LoadDriver|TakeOwnership|Backup|Restore|Tcb)Privilege\b"),
        "SeDebugPrivilege",
    ),
    # §2 - no registry values of its own
    HostChange(
        "§2", "a registry write", _p(r"\bimport\s+winreg\b|\bfrom\s+winreg\b"), "import winreg"
    ),
    HostChange("§2", "a registry write", _p(r"\bwinreg\s*="), 'winreg = "0.52"'),
    HostChange(
        "§2",
        "a registry write",
        _p(
            r"\bReg(SetValue|SetKeyValue|CreateKey|DeleteKey|DeleteValue|DeleteTree|RestoreKey|LoadKey)"
        ),
        "RegSetValueExW(key)",
    ),
    HostChange(
        "§2",
        "a registry write",
        _p(r"\breg(\.exe)?\b['\"]?\s*,?\s*['\"]?(add|delete|import|load|restore|copy)\b"),
        "reg add HKCU\\Software\\x",
    ),
    HostChange(
        "§2",
        "a registry write",
        _p(r"\b(Set|New|Remove|Rename)-ItemProperty\b"),
        "Set-ItemProperty x",
    ),
    # §2 and §4 - nothing starts at boot
    HostChange(
        "§4",
        "start at boot",
        _p(r"CurrentVersion\\+Run"),
        "Microsoft\\Windows\\CurrentVersion\\Run",
    ),
    HostChange("§4", "a scheduled task", _p(r"\bschtasks\b"), "schtasks /create /tn x"),
    HostChange(
        "§4", "a scheduled task", _p(r"\b(Register|New)-ScheduledTask"), "Register-ScheduledTask x"
    ),
    HostChange("§4", "start at boot", _p(r"shell:startup|Programs\\+Startup"), "shell:startup"),
    HostChange(
        "§4", "start at boot", _p(r"\bsystemctl\b[^\n]*\benable\b"), "systemctl --user enable x"
    ),
    HostChange("§4", "start at boot", _p(r"\bcrontab\b"), "crontab -e"),
    HostChange(
        "§4",
        "start at boot",
        _p(r"\.config/autostart|Launch(Agents|Daemons)"),
        "~/.config/autostart/x",
    ),
    HostChange("§4", "start at boot", _p(r"plugin-autostart"), "tauri-plugin-autostart"),
    # §2 - no system-wide network configuration
    HostChange(
        "§2",
        "the route table",
        _p(r"\broute(\.exe)?\b['\"]?\s*,?\s*['\"]?(add|delete|change)\b"),
        "route add 0.0.0.0",
    ),
    HostChange("§2", "the route table", _p(r"\b(New|Remove|Set)-NetRoute\b"), "New-NetRoute x"),
    HostChange(
        "§2",
        "system network settings",
        _p(r"\bnetsh\b[^\n]*\b(interface|winhttp|winsock)\b"),
        "netsh winhttp set proxy x",
    ),
    HostChange(
        "§2",
        "the hosts file",
        _p(r"etc[\\/]+hosts\b"),
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
    ),
    HostChange("§2", "DNS servers", _p(r"\bSet-DnsClient"), "Set-DnsClientServerAddress x"),
    HostChange(
        "§2",
        "a global proxy",
        _p(r"\bProxy(Enable|Server)\b|WinHttpSetDefaultProxy"),
        "ProxyEnable=1",
    ),
    HostChange(
        "§2",
        "the certificate store",
        _p(r"\bcertutil\b|\bImport-(Pfx)?Certificate\b|CertAddCertificate"),
        "certutil -addstore root x",
    ),
    HostChange(
        "§2", "the certificate store", _p(r"update-ca-certificates"), "update-ca-certificates"
    ),
    # §2 - no global environment variables, no PATH edits
    HostChange("§2", "a global environment variable", _p(r"\bsetx\b"), 'setx PATH "x"'),
    HostChange(
        "§2",
        "a global environment variable",
        _p(r"SetEnvironmentVariable"),
        "[Environment]::SetEnvironmentVariable('P','x','User')",
    ),
    HostChange(
        "§2",
        "a shell start-up file",
        _p(r"[~/\\]\.(bashrc|profile|zshrc|bash_profile)\b|/etc/(environment|profile)\b"),
        "echo x >> ~/.bashrc",
    ),
    # §6 - the host's own defences are never reconfigured
    HostChange(
        "§6", "Defender settings", _p(r"\b(Set|Add|Remove)-MpPreference\b"), "Set-MpPreference -x"
    ),
    HostChange(
        "§6",
        "firewall defaults",
        _p(r"\bSet-NetFirewall(Profile|Setting)\b"),
        "Set-NetFirewallProfile -Enabled False",
    ),
    HostChange(
        "§6",
        "firewall defaults",
        _p(r"\bnetsh\b[^\n]*\badvfirewall\b[^\n]*\bset\b"),
        "netsh advfirewall set allprofiles x",
    ),
    HostChange(
        "§6",
        "a firewall rule",
        _p(
            r"\b(New|Remove|Set|Enable|Disable|Copy)-NetFirewallRule\b"
            r"|\badvfirewall\s+firewall\s+(add|delete|set)\b"
        ),
        "Remove-NetFirewallRule -Group 'Sletchy'",
        shipped=False,
    ),
    # §7 - never mass-kill unrelated processes
    HostChange("§7", "killing by name", _p(r"\btaskkill\b"), "taskkill /im python.exe"),
    HostChange(
        "§7", "killing by name", _p(r"\bStop-Process\b[^\n]*-Name\b"), "Stop-Process -Name python"
    ),
    HostChange("§7", "killing by name", _p(r"\b(pkill|killall)\b"), "pkill python"),
    # LAW 4 - nothing fetches or evaluates code at run time
    HostChange("LAW 4", "running fetched code", _p(r"\bInvoke-Expression\b|\biex\b"), "iex (x)"),
    HostChange(
        "LAW 4",
        "fetching code",
        _p(r"\bInvoke-WebRequest\b|\bDownload(String|File)\b"),
        "Invoke-WebRequest x",
    ),
    HostChange("LAW 4", "running fetched code", _p(r"\|\s*(ba)?sh\b"), "curl x | sh"),
    HostChange(
        "LAW 4", "evaluating code", _p(r"(?<![\w.])(eval|exec)\("), "eval(text)", runtime=False
    ),
    HostChange(
        "LAW 4",
        "unpickling",
        _p(r"\bimport\s+pickle\b|\bpickle\.loads?\("),
        "pickle.loads(b)",
        runtime=False,
    ),
)

#: Ordinary lines that must trip nothing. Each one was a false alarm in a draft.
ORDINARY_CODE: tuple[str, ...] = (
    "self.profile = profile",
    "limit = self.profile.resources.wall_clock_seconds",
    "import sys; sys.platform",
    "registry = FlagRegistry()",
    "evaluate(actor, action, subject)",
    "message.format(value)",
    "routes = build_routes()",
    "PYTHONSTARTUP is stripped from the environment",
    "executor.run(command)",
    "self.recorder.launching(command)",
)


def host_changes_in(text: str, *, where: str) -> list[HostChange]:
    """Every host change named in `text` that LAW 0 forbids `where` ("shipped" or "runtime")."""
    if where not in ("shipped", "runtime"):
        raise ValueError(where)
    return [
        change
        for change in HOST_CHANGES
        if (change.shipped if where == "shipped" else change.runtime)
        and change.pattern.search(text)
    ]


# ── what the shipped code is, with comments removed ──────────────────────────
#
# Comments and docstrings are prose: "never call schtasks" is the rule, not a breach.
# String literals are kept, because that is exactly where a command lives.


def _python_code(text: str) -> str:
    lines = text.splitlines()
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(text).readline))
        tree = ast.parse(text)
    except (SyntaxError, tokenize.TokenError):
        return text
    for token in tokens:
        if token.type == tokenize.COMMENT:
            row, col = token.start
            lines[row - 1] = lines[row - 1][:col]
    docstrings: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef):
            first = node.body[0] if node.body else None
            if (
                isinstance(first, ast.Expr)
                and isinstance(first.value, ast.Constant)
                and isinstance(first.value.value, str)
                and first.end_lineno is not None
            ):
                docstrings.update(range(first.lineno, first.end_lineno + 1))
    return "\n".join("" if n in docstrings else line for n, line in enumerate(lines, 1))


def _c_like_code(text: str) -> str:
    """Rust and TypeScript: drop `//` and `/* */` comments, never a string's contents."""
    out: list[str] = []
    i, n, quote = 0, len(text), ""
    while i < n:
        ch = text[i]
        if quote:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = ""
            i += 1
        elif ch in '"`':
            quote = ch
            out.append(ch)
            i += 1
        elif text.startswith("//", i):
            end = text.find("\n", i)
            i = n if end < 0 else end
        elif text.startswith("/*", i):
            end = text.find("*/", i)
            stop = n if end < 0 else end + 2
            out.append("\n" * text.count("\n", i, stop))
            i = stop
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def _hash_comment_code(text: str) -> str:
    return "\n".join(re.sub(r"(^|\s)#.*$", "", line) for line in text.splitlines())


def _cmd_code(text: str) -> str:
    return "\n".join(
        "" if re.match(r"\s*(rem\b|::)", line, re.IGNORECASE) else line
        for line in text.splitlines()
    )


def _as_is(text: str) -> str:
    return text


SHIPPED_SUFFIXES: dict[str, Callable[[str], str]] = {
    ".py": _python_code,
    ".rs": _c_like_code,
    ".ts": _c_like_code,
    ".tsx": _c_like_code,
    ".js": _c_like_code,
    ".mjs": _c_like_code,
    ".cmd": _cmd_code,
    ".bat": _cmd_code,
    ".ps1": _hash_comment_code,
    ".sh": _hash_comment_code,
    ".toml": _hash_comment_code,
    ".json": _as_is,
    ".html": _as_is,
}


def code_of(path: Path, text: str) -> str:
    """`text` with its comments and docstrings blanked, line numbers kept."""
    if path.name == "pre-push":
        return _hash_comment_code(text)
    return SHIPPED_SUFFIXES.get(path.suffix.lower(), _as_is)(text)


def is_shipped_code(relative: str) -> bool:
    """Code Sletchy ships or runs on the host, as opposed to docs and tests."""
    path = Path(relative)
    if path.name.endswith(".lock") or path.name == "package-lock.json":
        return False  # versions of other people's packages, not code we wrote
    if path.parts[0] in {"src", "scripts", "apps", ".githooks"}:
        return path.suffix.lower() in SHIPPED_SUFFIXES or path.name == "pre-push"
    return len(path.parts) == 1 and path.suffix.lower() in {".cmd", ".bat", ".ps1", ".sh"}


# ── the run-time shield ──────────────────────────────────────────────────────


class HostShieldRefused(RuntimeError):
    """A test tried something LAW 0 forbids on this PC. Nothing was started or sent."""


#: Programs a test never starts, whatever their arguments: each one changes the host
#: in a way LAW 0 forbids, and a read-only use of them is not needed by any test.
REFUSED_PROGRAMS = frozenset(
    {
        "bcdedit", "certutil", "reg", "regedit", "regini", "runas", "sc", "schtasks",
        "setx", "shutdown", "taskkill", "msiexec", "netsh", "route", "wmic", "takeown",
    }
)  # fmt: skip

#: Programs that run other text as commands, so the text is checked as well.
SHELLS = frozenset({"cmd", "powershell", "pwsh", "bash", "sh", "wsl", "wscript", "cscript"})

_URL = re.compile(r"\b(?:https?|ftp)://(\[[^\]]*\]|[^/\s:'\"\[]+)", re.IGNORECASE)


def local_host(host: str | None) -> bool:
    """True only for this machine: loopback, the unspecified address, or none at all."""
    if host in (None, "", "localhost"):
        return True
    try:
        address = ipaddress.ip_address(str(host).strip("[]"))
    except ValueError:
        return False
    return address.is_loopback or address.is_unspecified


def _program(argv: list[str]) -> str:
    # PureWindowsPath splits on both `\` and `/`. A POSIX `Path` reads
    # `C:\Windows\System32\SC.EXE` as one name, which let it past the shield on
    # Linux CI (harmless there only because the file does not exist).
    name = PureWindowsPath(argv[0].strip("\"'")).name.lower()
    for suffix in (".exe", ".com", ".bat", ".cmd"):
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return name


def _inside(path: str, roots: Iterable[Path]) -> bool:
    try:
        target = Path(path.strip("\"'")).resolve()
    except (OSError, ValueError):
        return False
    return any(target == root or root in target.parents for root in roots)


def refusal_for_command(args: object, *, shell: bool, writable_roots: Iterable[Path]) -> str | None:
    """Why LAW 0 forbids starting this command in a test, or None if it may start."""
    if isinstance(args, str | bytes | os.PathLike):
        text = os.fsdecode(args)
        argv = text.split() if text.strip() else [""]
    else:
        argv = [os.fsdecode(a) for a in cast("Iterable[str | bytes | os.PathLike[str]]", args)]
        text = " ".join(argv)
    program = _program(argv)

    if program in REFUSED_PROGRAMS:
        return f"{program} changes the host (LAW 0)"
    if shell or program in SHELLS:
        for change in host_changes_in(text, where="runtime"):
            return f"{change.what} (LAW 0 {change.clause})"
        for word in re.findall(r"[\w.-]+", text.lower()):
            if word.removesuffix(".exe") in REFUSED_PROGRAMS:
                return f"{word} changes the host (LAW 0)"
    if program == "icacls":
        target = argv[1] if len(argv) > 1 else ""
        if not _inside(target, writable_roots):
            return f"icacls on {target!r}, outside the test's temp folders (LAW 0 §2)"
    for host in _URL.findall(text):
        if not local_host(host):
            return f"a request to {host}, off this machine (LAW 0 §6)"
    return None


def refusal_for_address(address: object) -> str | None:
    """Why a socket may not reach `address`, or None if it is on this machine."""
    if isinstance(address, tuple) and address:
        host = address[0]
        if isinstance(host, str) and not local_host(host):
            return f"a connection to {host}, off this machine (LAW 0 §6)"
    return None


@dataclass
class Shield:
    """Installed for the whole test session by `tests/conftest.py`.

    Every refusal is also kept in `refused`. A refusal nobody expected fails the run
    at the end, even if the code under test caught the exception: a broad `except`
    must not be able to hide a test that tried to change this PC.
    """

    writable_roots: tuple[Path, ...]
    refused: list[str] = field(default_factory=list)
    _undo: list[Callable[[], None]] = field(default_factory=list)

    def refuse(self, why: str) -> HostShieldRefused:
        self.refused.append(why)
        return HostShieldRefused(f"refused: {why}")

    @contextmanager
    def expecting_refusal(self) -> Iterator[list[str]]:
        """For the shield's own tests: refusals inside this block are the point."""
        start = len(self.refused)
        caught: list[str] = []
        try:
            yield caught
        finally:
            caught.extend(self.refused[start:])
            del self.refused[start:]

    def install(self) -> None:
        self._guard_processes()
        self._guard_sockets()
        self._guard_popups()

    def uninstall(self) -> None:
        while self._undo:
            self._undo.pop()()

    def _swap(self, owner: object, name: str, replacement: object) -> None:
        original = getattr(owner, name)
        setattr(owner, name, replacement)
        self._undo.append(lambda: setattr(owner, name, original))

    def _guard_processes(self) -> None:
        roots = self.writable_roots
        original_init = cast("Callable[..., None]", subprocess.Popen.__init__)

        def guarded_init(
            popen: subprocess.Popen[bytes], args: object, *rest: object, **kw: object
        ) -> None:
            why = refusal_for_command(args, shell=bool(kw.get("shell")), writable_roots=roots)
            if why:
                raise self.refuse(f"starting a command: {why}")
            original_init(popen, args, *rest, **kw)

        self._swap(subprocess.Popen, "__init__", guarded_init)

        def guarded_system(command: str) -> int:
            raise self.refuse(f"os.system({command[:60]!r}); tests use subprocess")

        self._swap(os, "system", guarded_system)

    def _guard_sockets(self) -> None:
        for name in ("connect", "connect_ex"):
            original = cast("Callable[..., object]", getattr(socket.socket, name))

            def guarded(
                sock: socket.socket,
                address: object,
                _original: Callable[..., object] = original,
            ) -> object:
                why = refusal_for_address(address)
                if why:
                    raise self.refuse(why)
                return _original(sock, address)

            self._swap(socket.socket, name, guarded)

        original_sendto = cast("Callable[..., int]", socket.socket.sendto)

        def guarded_sendto(sock: socket.socket, data: bytes, *args: object) -> int:
            why = refusal_for_address(args[-1] if args else None)
            if why:
                raise self.refuse(why)
            return original_sendto(sock, data, *args)

        self._swap(socket.socket, "sendto", guarded_sendto)

        original_lookup = cast("Callable[..., object]", socket.getaddrinfo)

        def guarded_lookup(host: object, *args: object, **kw: object) -> object:
            if isinstance(host, bytes):
                host = host.decode("ascii", "replace")
            if not (host is None or local_host(str(host))):
                raise self.refuse(f"a DNS lookup of {host}, off this machine (LAW 0 §6)")
            return original_lookup(host, *args, **kw)

        self._swap(socket, "getaddrinfo", guarded_lookup)

    def _guard_popups(self) -> None:
        """Nothing appears on the operator's screen from a test run."""

        def refused(*_: object, **__: object) -> None:
            raise self.refuse("opening a window or browser from a test")

        if hasattr(os, "startfile"):
            self._swap(os, "startfile", refused)
        import webbrowser

        self._swap(webbrowser, "open", refused)


def default_writable_roots(session_home: Path) -> tuple[Path, ...]:
    return (Path(tempfile.gettempdir()).resolve(), session_home.resolve())


# ── the processes a test starts ──────────────────────────────────────────────

#: Set by `tests/conftest.py` for the run: where a Python process a test started
#: writes its refusals, so the session can read them at the end (L016).
CHILD_LOG_ENV = "SLETCHY_TEST_SHIELD_LOG"
CHILD_LOG_NAME = "child-refusals.log"

#: The folder `tests/conftest.py` puts first on `PYTHONPATH`. Its `sitecustomize`
#: installs the shield in every Python a test starts, before the child's own code.
CHILD_SITE = Path(__file__).resolve().parent / "shield_site"


@dataclass
class ChildShield(Shield):
    """The shield in a Python process a test started, which the session cannot see into.

    Every refusal is also written to `log`. A refusal the child's own code caught would
    otherwise end with the child, and the run would pass.
    """

    log: Path | None = None

    def refuse(self, why: str) -> HostShieldRefused:
        if self.log is not None:
            with self.log.open("a", encoding="utf-8") as sink:
                sink.write(f"process {os.getpid()}: {why}\n")
        return super().refuse(why)


def install_in_child(log: Path) -> ChildShield:
    """Called by `shield_site/sitecustomize.py` as a child Python starts."""
    shield = ChildShield(writable_roots=default_writable_roots(log.parent), log=log)
    shield.install()
    return shield


def child_refusals(log: Path) -> list[str]:
    """The refusals the run's child processes wrote, one per line."""
    try:
        text = log.read_text(encoding="utf-8")
    except FileNotFoundError:
        return []
    return [line for line in text.splitlines() if line.strip()]


def elevation_refusal(*, elevated: bool, ci: bool) -> str | None:
    """Why the suite will not run, or None. CI is exempt: GitHub's Windows runner is
    always elevated, and that is a disposable machine, not the operator's."""
    if elevated and not ci:
        return (
            "refusing to run the tests as an administrator (LAW 0 §3). A test that goes "
            "wrong elevated can change this PC; run them from an ordinary terminal."
        )
    return None


Snapshot = dict[str, tuple[int, int]] | None


def snapshot(folder: Path) -> Snapshot:
    """Every file under `folder`, by size and modification time; None if it is absent."""
    if not folder.exists():
        return None
    return {
        str(p.relative_to(folder)): (p.stat().st_size, p.stat().st_mtime_ns)
        for p in sorted(folder.rglob("*"))
        if p.is_file()
    }


def session_problems(
    shield: Shield, real_var: Path, before: Snapshot, child_log: Path | None = None
) -> list[str]:
    """What makes a finished test run untrustworthy, in words for the operator."""
    problems: list[str] = []
    if shield.refused:
        problems.append(
            f"{len(shield.refused)} refusal(s) no test expected. Something tried to change "
            "this PC or leave it, and the error was caught and hidden: " + "; ".join(shield.refused)
        )
    children = child_refusals(child_log) if child_log is not None else []
    if children:
        problems.append(
            f"{len(children)} refusal(s) in a process a test started. Something it ran "
            "tried to change this PC or leave it: " + "; ".join(children)
        )
    if snapshot(real_var) != before:
        problems.append(
            f"{real_var} changed during the test run. A test wrote to the real Sletchy "
            "folder instead of a temp one (or Sletchy itself was in use while the tests "
            "ran). Find it before trusting this run."
        )
    return problems
