"""`sletchy-soc startup`: what starts with the machine, read-only, in words (#146).

The planted cases are the two found on the operator's machine on 2026-10-04: an
automatic service, running as the most powerful account, whose program had been
removed with the product that installed it; and a scheduled task starting a
hardware-monitoring tool with administrator rights at every logon.

This sensor is the one file in shipped code allowed to name the registry's startup
keys (the operator's decision, 2026-10-04). The LAW 0 tests below are what that
permission rests on: it binds only reads, and its task query only reads.
"""

from __future__ import annotations

import argparse
import ast
import sys
from pathlib import Path

import pytest

from sletchy.kernel.ledger import InMemoryKeySource, Ledger
from sletchy.soc import cli as soc_cli
from sletchy.soc.sensors import startup as st
from sletchy.soc.sensors.startup import Autostart, StartupLook
from tests.unit.test_secret_scan import FAKE_KEYS

pytestmark = pytest.mark.adversarial

needs_windows = pytest.mark.skipif(sys.platform != "win32", reason="the sensor reads Windows")
SOURCE = Path(__file__).resolve().parents[2] / "src" / "sletchy" / "soc" / "sensors" / "_startup.py"
WINDOWS = "C:\\Windows"

LEFTOVER_SERVICE = Autostart(
    kind="service",
    where="LocalSystem",
    name="ProductFallbackUpdater",
    command='"C:\\Program Files (x86)\\Product\\Fallback Updater\\Updater.exe" FallbackUpdater=true',
)
MONITOR_TASK = Autostart(
    kind="task",
    where="administrator rights",
    name="\\GPU-Tool",
    command="C:\\Program Files (x86)\\GPU-Tool\\GPU-Tool.exe -restarted -minimized",
)


def look(*entries: Autostart) -> StartupLook:
    return StartupLook(entries=entries, unreadable=0, windows_folder=WINDOWS)


# ── which program a command starts ───────────────────────────────────────────


@pytest.mark.parametrize(
    ("command", "program"),
    [
        ('"C:\\Program Files\\App\\app.exe" --flag', "C:\\Program Files\\App\\app.exe"),
        ("C:\\Program Files\\App\\app.exe --flag", "C:\\Program Files\\App\\app.exe"),
        ("%SystemRoot%\\System32\\svchost.exe -k netsvcs", "C:\\Windows\\System32\\svchost.exe"),
        ("\\SystemRoot\\System32\\drivers\\x.sys", "C:\\Windows\\System32\\drivers\\x.sys"),
        ("system32\\x.exe", "C:\\Windows\\system32\\x.exe"),
        ("\\??\\C:\\Tools\\x.exe", "C:\\Tools\\x.exe"),
        ("", None),
    ],
)
def test_the_program_a_command_starts_is_found(command: str, program: str | None) -> None:
    assert st.program_of(command, WINDOWS) == program


# ── the patterns ─────────────────────────────────────────────────────────────


def test_a_service_whose_program_is_gone_is_a_finding() -> None:
    found = st.missing_program(look(LEFTOVER_SERVICE), exists=lambda _: False)
    assert [f.rule for f in found] == ["autostart_program_missing"]
    assert "Updater.exe" in found[0].summary


def test_a_program_that_is_there_is_not() -> None:
    assert st.missing_program(look(LEFTOVER_SERVICE), exists=lambda _: True) == []


def test_a_startup_folder_shortcut_or_a_bare_name_is_never_called_missing() -> None:
    """A shortcut is not a program path, and a bare name is found on PATH at start:
    neither can be checked by looking for a file, so neither is guessed about."""
    entries = (
        Autostart(kind="folder", where="this user", name="x.lnk", command="C:\\nowhere\\x.lnk"),
        Autostart(kind="registry", where="this user", name="tool", command="tool.exe --tray"),
    )
    assert st.missing_program(look(*entries), exists=lambda _: False) == []


def test_a_task_starting_a_program_with_administrator_rights_at_logon_is_a_finding() -> None:
    found = st.admin_at_logon(look(MONITOR_TASK))
    assert [f.rule for f in found] == ["autostart_admin_at_logon"]
    assert "administrator rights" in found[0].summary


@pytest.mark.parametrize(
    "entry",
    [
        Autostart(
            kind="task",
            where="administrator rights",
            name="\\Microsoft\\x",
            command="%windir%\\system32\\x.exe",
        ),
        Autostart(
            kind="task",
            where="ordinary rights",
            name="\\Updater",
            command="C:\\Program Files\\U\\u.exe",
        ),
    ],
)
def test_windows_own_tasks_and_ordinary_rights_are_not(entry: Autostart) -> None:
    assert st.admin_at_logon(look(entry)) == []


def test_a_program_set_to_start_from_a_user_writable_folder_is_a_finding() -> None:
    entry = Autostart(
        kind="registry",
        where="this user",
        name="updater",
        command="C:\\Users\\someone\\AppData\\Roaming\\upd\\upd.exe /silent",
    )
    found = st.from_user_folder(look(entry), signed=lambda _: False)
    assert [f.rule for f in found] == ["autostart_from_user_folder"]


def test_the_same_signed_by_a_trusted_publisher_is_not() -> None:
    """Chat, music and sync apps install into the user's own folders, signed. Naming each
    one every day would teach the operator to ignore the finding."""
    entry = Autostart(
        kind="registry",
        where="this user",
        name="chat",
        command="C:\\Users\\someone\\AppData\\Local\\Chat\\Update.exe",
    )
    assert st.from_user_folder(look(entry), signed=lambda _: True) == []


def test_the_same_from_program_files_is_not() -> None:
    entry = Autostart(
        kind="registry", where="every user", name="x", command='"C:\\Program Files\\X\\x.exe"'
    )
    assert st.from_user_folder(look(entry), signed=lambda _: False) == []


@pytest.mark.parametrize(("shape", "key"), FAKE_KEYS)
def test_a_secret_in_a_startup_command_is_masked(shape: str, key: str) -> None:
    """Secrets travel in arguments (ADR-0011). Masked before anything is shown or recorded."""
    cleaned = st.clean(f"C:\\Tools\\sync.exe --token {key}")
    assert key not in cleaned


def test_a_hostile_entry_name_cannot_write_to_the_terminal() -> None:
    entry = Autostart(
        kind="registry",
        where="this user",
        name="x\x1b[2J\nFAKE: all clear",
        command="C:\\Temp\\x.exe",
    )
    found = st.findings(look(entry), exists=lambda _: True, signed=lambda _: False)
    assert found and all(ch.isprintable() for f in found for ch in f.summary + f.identifier)


# ── only with the operator's say-so ──────────────────────────────────────────


def test_without_the_flag_nothing_is_read(tmp_path: Path) -> None:
    ledger = Ledger.open(tmp_path / "ledger", InMemoryKeySource(b"k" * 32))
    asked: list[bool] = []

    def read() -> StartupLook:
        asked.append(True)
        return look()

    lines: list[str] = []
    args = argparse.Namespace(view="startup", dry_run=True, top=25)
    assert soc_cli.run(args, ledger, read_startup=read, out=lines.append) == 0
    assert asked == []
    assert any(soc_cli.WATCH_FLAG in line for line in lines)


# ── LAW 0: it reads, and it can only read ────────────────────────────────────

READS = {
    "RegOpenKeyExW",
    "RegEnumValueW",
    "RegEnumKeyExW",
    "RegQueryValueExW",
    "RegCloseKey",
    "WinVerifyTrust",
}


@pytest.mark.law_zero
def test_every_call_the_startup_reader_binds_is_a_read() -> None:
    tree = ast.parse(SOURCE.read_text("utf-8"))
    bound = {
        call.args[1].value
        for call in ast.walk(tree)
        if isinstance(call, ast.Call)
        and isinstance(call.func, ast.Name)
        and call.func.id == "_bind"
        and isinstance(call.args[1], ast.Constant)
    }
    assert bound == READS
    direct = [
        node.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id in {"_advapi32", "_wintrust"}
    ]
    assert direct == [], "every binding goes through _bind, so the list above is complete"


@pytest.mark.law_zero
def test_every_key_it_opens_is_opened_to_read() -> None:
    """`KEY_READ` (0x20019) and the 64-bit view, nothing else: no right to set a value."""
    tree = ast.parse(SOURCE.read_text("utf-8"))
    opens = [
        call
        for call in ast.walk(tree)
        if isinstance(call, ast.Call)
        and isinstance(call.func, ast.Name)
        and call.func.id == "_RegOpenKeyExW"
    ]
    assert len(opens) == 1
    assert ast.unparse(opens[0].args[3]) == "KEY_READ | _KEY_WOW64_64KEY"
    assert "KEY_READ = 0x20019" in SOURCE.read_text("utf-8")


@pytest.mark.law_zero
def test_the_signature_check_never_goes_online() -> None:
    """No revocation lookup and cached data only: checking a signature must not be
    Sletchy reaching the internet unasked."""
    source = SOURCE.read_text("utf-8")
    assert "NO_NETWORK = 0x10 | 0x1000" in source
    assert source.count("dwProvFlags=NO_NETWORK") == 1
    assert "fdwRevocationChecks=_REVOKE_NONE" in source
    assert "_UI_NONE, _REVOKE_NONE, _CHOICE_FILE = 2, 0, 1" in source


@pytest.mark.law_zero
def test_the_task_query_only_reads() -> None:
    """The Task Scheduler is asked for tasks and their definitions, never told anything."""
    from sletchy.soc.sensors import startup  # noqa: F401 - the script lives beside the reader

    script = SOURCE.read_text("utf-8")
    start = script.index("TASKS_SCRIPT = (")
    text = script[start : script.index("\n)\n", start)].lower()
    for word in (
        "registertask",
        "deletetask",
        ".run(",
        ".enabled =",
        "highestavailable",
        "set-",
        "remove-",
        "disable-",
        "stop-",
        "start-",
        "new-scheduled",
    ):
        assert word not in text, word
    assert "gettasks" in text and "getfolders" in text, "positive control: the read calls are there"


# ── the sensor reads this machine ────────────────────────────────────────────


@needs_windows
def test_the_startup_keys_read_without_error() -> None:
    from sletchy.soc.sensors import _startup

    _, unreadable = _startup.run_keys()
    assert unreadable == 0, "an ordinary user can read every startup key"


@needs_windows
def test_the_service_list_reads_and_knows_a_service_every_windows_has() -> None:
    """Positive control: the event log service starts automatically on every Windows."""
    from sletchy.soc.sensors import _startup

    services, _ = _startup.services()
    assert any(s.name.lower() == "eventlog" and "svchost" in s.command.lower() for s in services)


@needs_windows
def test_the_task_reader_finds_tasks_that_run_at_boot_or_logon() -> None:
    """Positive control: every Windows has some. None found would mean the reader broke."""
    from sletchy.soc.sensors import _startup

    tasks, _ = _startup.tasks()
    assert tasks, "no boot or logon tasks read: the query failed silently"
    assert all(t.kind == "task" and t.name.startswith("\\") for t in tasks)


@needs_windows
def test_the_signature_check_tells_signed_from_unsigned(tmp_path: Path) -> None:
    """Positive and negative controls, offline. `explorer.exe` carries its own signature
    on every Windows; a file just written carries none."""
    from sletchy.soc.sensors import _startup

    assert _startup.signed(WINDOWS + "\\explorer.exe")
    unsigned = tmp_path / "tool.exe"
    unsigned.write_bytes(b"MZ not a real program")
    assert not _startup.signed(str(unsigned))
