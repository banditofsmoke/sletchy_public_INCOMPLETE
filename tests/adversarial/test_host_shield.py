"""The host shield bites: each guard in `tests/conftest.py`, proven to refuse.

**Every probe here is harmless even if the guard it tests were missing.** That is the
rule this file is written to, because the test of a safety net must not need the net:

- the commands are help screens, read-only queries, or a PowerShell `-WhatIf`
- the network probes use a socket that is already closed, or an address given only
  as text to a program that ignores it, so nothing can be sent
- the keychain probes read an entry that does not exist

A guard that is not installed therefore shows up as a failed assertion here, never
as a change to this PC.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

import sletchy.cli.panic as panic_mod
from sletchy.cli.panic import REMOVE_RULES_SCRIPT
from sletchy.cli.panic import remove_firewall_rules as real_remove_firewall_rules
from tests.hostshield import (
    CHILD_LOG_NAME,
    HostShieldRefused,
    Shield,
    child_refusals,
    elevation_refusal,
    refusal_for_address,
    refusal_for_command,
    session_problems,
    snapshot,
)

if TYPE_CHECKING:
    from collections.abc import Callable

pytestmark = [pytest.mark.law_zero, pytest.mark.adversarial]

#: TEST-NET-1 (RFC 5737): reserved for documentation, never anyone's machine. Used
#: only as text and on closed sockets below, so it is never contacted.
OFF_MACHINE = "192.0.2.1"

windows_only = pytest.mark.skipif(sys.platform != "win32", reason="a Windows command")


# ── the shield is up for this whole run ─────────────────────────────────────


def test_the_shield_is_installed_for_the_whole_session(session_home: Path) -> None:
    import keyring
    from keyring.backends import fail

    assert subprocess.Popen.__init__.__name__ == "guarded_init"
    assert socket.socket.connect.__name__ == "guarded"
    assert socket.getaddrinfo.__name__ == "guarded_lookup"
    assert isinstance(keyring.get_keyring(), fail.Keyring)
    assert os.environ["PYTHON_KEYRING_BACKEND"] == "keyring.backends.fail.Keyring"

    home = Path(os.environ["SLETCHY_HOME"]).resolve()
    assert home == session_home.resolve()
    assert Path(tempfile.gettempdir()).resolve() in home.parents
    assert home != (Path.cwd() / "var").resolve()


def test_a_test_that_sets_no_home_writes_into_the_throwaway_one(session_home: Path) -> None:
    from sletchy.kernel import paths

    assert paths.home().resolve() == session_home.resolve()


# ── commands that change the host never start ───────────────────────────────

HARMLESS_IF_RUN = [
    pytest.param(["setx", "/?"], id="setx-help"),
    pytest.param(["schtasks", "/query", "/?"], id="schtasks-help"),
    pytest.param(["reg", "query", r"HKCU\Software\sletchy-shield-probe"], id="reg-query"),
    pytest.param(["netsh", "/?"], id="netsh-help"),
    pytest.param(["taskkill", "/?"], id="taskkill-help"),
    pytest.param(["bcdedit.exe", "/?"], id="bcdedit-help"),
    pytest.param(["C:\\Windows\\System32\\SC.EXE", "query", "x"], id="sc-full-path-upper-case"),
    pytest.param(
        ["powershell", "-NoProfile", "-Command", "Get-Date # Set-MpPreference"],
        id="defender-inside-a-shell",
    ),
    pytest.param(
        ["powershell", "-NoProfile", "-Command", REMOVE_RULES_SCRIPT + " -WhatIf"],
        id="panic-firewall-removal-unstubbed",
    ),
    pytest.param(["cmd", "/c", "echo", "schtasks"], id="refused-program-inside-cmd"),
    pytest.param("setx /?", id="as-one-string"),
]


@pytest.mark.parametrize("command", HARMLESS_IF_RUN)
def test_a_host_changing_command_is_refused_before_it_starts(
    host_shield: Shield, command: list[str] | str
) -> None:
    with host_shield.expecting_refusal() as caught, pytest.raises(HostShieldRefused):
        subprocess.run(command, capture_output=True, check=False, timeout=30)
    assert len(caught) == 1


def test_a_shell_command_string_is_checked_too(host_shield: Shield) -> None:
    with host_shield.expecting_refusal() as caught, pytest.raises(HostShieldRefused):
        subprocess.run("echo schtasks", shell=True, capture_output=True, check=False)  # noqa: S602
    assert caught


def test_a_refusal_caught_by_the_code_under_test_is_still_recorded(host_shield: Shield) -> None:
    """A broad `except` must not hide a test that tried to change this PC."""
    with host_shield.expecting_refusal() as caught:
        try:
            subprocess.run(["setx", "/?"], capture_output=True, check=False)
        except Exception:  # noqa: S110 - swallowing it is the scenario
            pass
    assert caught, "a swallowed refusal left no record"


def test_os_system_is_refused(host_shield: Shield) -> None:
    with host_shield.expecting_refusal() as caught, pytest.raises(HostShieldRefused):
        os.system("rem")  # noqa: S605
    assert caught


@windows_only
def test_icacls_outside_the_temp_folders_is_refused(host_shield: Shield) -> None:
    """Displaying the home folder's permissions changes nothing; granting would."""
    with host_shield.expecting_refusal() as caught, pytest.raises(HostShieldRefused):
        subprocess.run(["icacls", str(Path.home())], capture_output=True, check=False)
    assert caught


@windows_only
def test_icacls_inside_a_test_folder_still_runs(tmp_path: Path) -> None:
    """Positive control: the winjob tests grant on their own workspaces."""
    result = subprocess.run(["icacls", str(tmp_path)], capture_output=True, check=False)
    assert result.returncode == 0


def test_ordinary_commands_still_run() -> None:
    """Positive control: a shield that refuses everything proves nothing."""
    result = subprocess.run(
        [sys.executable, "-c", "print('ok')"], capture_output=True, text=True, check=True
    )
    assert result.stdout.strip() == "ok"


# ── nothing leaves this machine ──────────────────────────────────────────────


def test_a_url_off_this_machine_is_refused_in_any_command(host_shield: Shield) -> None:
    """The URL is an argument `python -c pass` ignores, so nothing could be sent."""
    with host_shield.expecting_refusal() as caught, pytest.raises(HostShieldRefused):
        subprocess.run([sys.executable, "-c", "pass", f"http://{OFF_MACHINE}/"], check=False)
    assert caught


@pytest.mark.parametrize(
    "address", [(OFF_MACHINE, 9), ("example.com", 443), ("10.0.0.1", 80), ("2001:db8::1", 80)]
)
def test_a_connection_off_this_machine_is_refused(
    host_shield: Shield, address: tuple[str, int]
) -> None:
    """On a closed socket: were the guard missing, this raises OSError and sends nothing."""
    family = socket.AF_INET6 if ":" in address[0] else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.close()
    with host_shield.expecting_refusal() as caught, pytest.raises(HostShieldRefused):
        sock.connect(address)
    assert caught


def test_a_datagram_off_this_machine_is_refused(host_shield: Shield) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.close()
    with host_shield.expecting_refusal() as caught, pytest.raises(HostShieldRefused):
        sock.sendto(b"x", (OFF_MACHINE, 9))
    assert caught


def test_a_lookup_of_an_address_off_this_machine_is_refused(host_shield: Shield) -> None:
    """A numeric address needs no DNS, so even unguarded this would send nothing."""
    with host_shield.expecting_refusal() as caught, pytest.raises(HostShieldRefused):
        socket.getaddrinfo(OFF_MACHINE, 80)
    assert caught


def test_loopback_still_works() -> None:
    """Positive control: the proxy design and the bridge tests need loopback."""
    with socket.create_server(("127.0.0.1", 0)) as server:
        port = server.getsockname()[1]
        with socket.create_connection(("127.0.0.1", port), timeout=5):
            pass
    assert socket.getaddrinfo("localhost", port)


# ── nothing appears on the screen ────────────────────────────────────────────


@pytest.mark.skipif(not hasattr(os, "startfile"), reason="os.startfile is Windows-only")
def test_opening_a_file_in_another_program_is_refused(host_shield: Shield, tmp_path: Path) -> None:
    """A path that does not exist: unguarded, this raises FileNotFoundError and opens nothing."""
    with host_shield.expecting_refusal() as caught, pytest.raises(HostShieldRefused):
        opener: Callable[[Path], None] = getattr(os, "startfile")  # noqa: B009 - Windows-only name
        opener(tmp_path / "does-not-exist.txt")
    assert caught


def test_a_browser_is_never_opened() -> None:
    """Checked by identity only: calling it unguarded would open a browser."""
    import webbrowser

    assert webbrowser.open.__name__ == "refused"


# ── the real keychain is out of reach ────────────────────────────────────────


def test_the_real_keychain_is_unreachable() -> None:
    """Reading an entry that does not exist: harmless even if this reached the keychain."""
    import keyring
    from keyring.errors import NoKeyringError

    with pytest.raises(NoKeyringError):
        keyring.get_password("sletchy-shield-probe", "never-written")


def test_a_child_process_cannot_reach_the_real_keychain_either() -> None:
    probe = (
        "import keyring\n"
        "try:\n"
        "    keyring.get_password('sletchy-shield-probe', 'never-written')\n"
        "except Exception as exc:\n"
        "    print(type(exc).__name__)\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", probe], capture_output=True, text=True, check=False
    )
    assert result.stdout.strip() == "NoKeyringError"


def test_a_python_process_a_test_starts_is_shielded_too(session_home: Path) -> None:
    """L016: the session's shield guarded the pytest process and nothing it started.

    `schtasks /?` is a help screen, so a child without the shield would only print it.
    The refusal is the point, so it is taken back out of the end-of-run check.
    """
    probe = (
        "import subprocess\n"
        "try:\n"
        "    subprocess.run(['schtasks', '/?'], capture_output=True)\n"
        "except Exception as exc:\n"
        "    print(type(exc).__name__)\n"
    )
    log = session_home / CHILD_LOG_NAME
    before = child_refusals(log)
    try:
        result = subprocess.run(
            [sys.executable, "-c", probe], capture_output=True, text=True, check=False
        )
        added = child_refusals(log)[len(before) :]
    finally:
        log.write_text("".join(f"{line}\n" for line in before), encoding="utf-8")
    assert result.stdout.strip() == "HostShieldRefused", result.stderr
    assert len(added) == 1
    assert "schtasks" in added[0]


def test_a_refusal_in_a_child_process_fails_the_run(tmp_path: Path) -> None:
    log = tmp_path / CHILD_LOG_NAME
    shield = Shield(writable_roots=(tmp_path,))
    assert session_problems(shield, tmp_path / "var", None, log) == []

    log.write_text("process 1: starting a command: schtasks changes the host\n", "utf-8")
    assert any(
        "in a process a test started" in p
        for p in session_problems(shield, tmp_path / "var", None, log)
    )


def test_no_test_can_reach_the_real_firewall_through_panic(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """L016: a test that forgets to stub panic's firewall step still never reaches it.

    The firewall here is a fake holding eight Sletchy rules, so nothing runs whether
    or not the default is in place. The control is the step the default replaces:
    given the same fake, it does reach for the rules.
    """
    ran: list[str] = []

    def eight_rules(script: str, timeout: float) -> subprocess.CompletedProcess[str]:
        ran.append(script)
        out = "8" if script == panic_mod.COUNT_RULES_SCRIPT else ""
        return subprocess.CompletedProcess([], 0, stdout=out, stderr="")

    monkeypatch.setattr(panic_mod, "_powershell", eight_rules)
    monkeypatch.setattr(panic_mod, "_is_windows", lambda: True)
    monkeypatch.setattr("sletchy.cli.panic.shutil.which", lambda _name: "powershell")
    monkeypatch.setattr(panic_mod, "_is_elevated", lambda: True)

    assert panic_mod.remove_firewall_rules() == (0, 0, None)
    assert ran == [], "the default asked the firewall"

    _removed, _kept, error = real_remove_firewall_rules()
    assert REMOVE_RULES_SCRIPT in ran
    assert error is not None
    assert "8 firewall rule(s)" in error


# ── the end-of-run checks ────────────────────────────────────────────────────


def test_a_changed_real_var_folder_fails_the_run(tmp_path: Path) -> None:
    real_var = tmp_path / "var"
    real_var.mkdir()
    (real_var / "flags.json").write_text("{}", encoding="utf-8")
    before = snapshot(real_var)
    shield = Shield(writable_roots=(tmp_path,))

    assert session_problems(shield, real_var, before) == []

    (real_var / "flags.json").write_text('{"x": 1}', encoding="utf-8")
    assert any(
        "changed during the test run" in p for p in session_problems(shield, real_var, before)
    )


def test_a_real_var_folder_created_by_the_run_fails_it(tmp_path: Path) -> None:
    real_var = tmp_path / "var"
    before = snapshot(real_var)
    (real_var / "ledger").mkdir(parents=True)
    (real_var / "ledger" / "segment-00000.ndjson").write_text("x", encoding="utf-8")

    problems = session_problems(Shield(writable_roots=(tmp_path,)), real_var, before)
    assert any("changed during the test run" in p for p in problems)


def test_an_unexpected_refusal_fails_the_run(tmp_path: Path) -> None:
    shield = Shield(writable_roots=(tmp_path,), refused=["starting a command: setx"])
    problems = session_problems(shield, tmp_path / "var", None)
    assert any("no test expected" in p and "setx" in p for p in problems)


def test_an_elevated_run_is_refused_except_on_ci() -> None:
    assert elevation_refusal(elevated=True, ci=False)
    assert elevation_refusal(elevated=True, ci=True) is None
    assert elevation_refusal(elevated=False, ci=False) is None


# ── the decisions, directly ──────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("command", "refused"),
    [
        (["curl", f"http://{OFF_MACHINE}/x"], True),
        (["curl", "http://127.0.0.1:8080/"], False),
        (["curl", "http://localhost/"], False),
        (["curl", "https://[::1]/"], False),
        (["git", "ls-files"], False),
        (["Route.EXE", "print"], True),
        ([r"C:\Windows\System32\SC.EXE", "query"], True),
        (["/usr/sbin/route", "add", "x"], True),
        (["icacls", "C:\\", "/grant", "x"], True),
    ],
)
def test_command_decisions(command: list[str], refused: bool, tmp_path: Path) -> None:
    why = refusal_for_command(command, shell=False, writable_roots=(tmp_path,))
    assert (why is not None) is refused, why


@pytest.mark.parametrize(
    ("address", "refused"),
    [
        (("127.0.0.1", 80), False),
        (("127.8.9.10", 80), False),
        (("::1", 80, 0, 0), False),
        (("localhost", 80), False),
        (("0.0.0.0", 80), False),  # noqa: S104
        ((OFF_MACHINE, 80), True),
        (("192.168.1.1", 80), True),
        (("example.com", 80), True),
    ],
)
def test_address_decisions(address: tuple[object, ...], refused: bool) -> None:
    assert (refusal_for_address(address) is not None) is refused
