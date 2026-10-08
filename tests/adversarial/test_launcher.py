"""`Open-Sletchy.cmd`, the file I double-click, tested before it is ever run for real.

Its first version was named `Start Sletchy.cmd` and had no test. The first time it was
run by hand, the command line was quoted wrongly, cmd read "Start" as its own START
built-in, and Windows put an error dialog on the screen of the only computer I
have. Nothing was harmed, but nothing should appear on that screen unannounced
(learnings/L010). So: the name is checked, the script is checked line by line, and the
Windows tests below run only its `--check` mode, which starts nothing and never waits.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

pytestmark = pytest.mark.adversarial

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER = ROOT / "Open-Sletchy.cmd"

#: cmd.exe built-ins. A launcher whose name begins with one of these runs the built-in
#: instead of the file when the name is typed without quotes.
CMD_BUILTINS = frozenset(
    "assoc break call cd chdir cls color copy date del dir echo endlocal erase exit for "
    "ftype goto if md mkdir mklink move path pause popd prompt pushd rd rem ren rename "
    "rmdir set setlocal shift start time title type ver verify vol".split()
)

#: Anything that would change the host. The launcher may only start what is already
#: here, or build it inside this folder.
FORBIDDEN = re.compile(
    r"\b(setx|reg(?:edit)?|msiexec|runas|schtasks|sc|icacls|netsh|powershell|pwsh|mklink"
    r"|del|erase|rd|rmdir|attrib|takeown|bcd\w+|wmic)\b"
    r"|set\s+\"?path=|%(?:appdata|localappdata|programfiles|systemroot|windir)%",
    re.IGNORECASE,
)


def name_problems(filename: str) -> list[str]:
    stem = Path(filename).stem
    problems = []
    if re.search(r"\s", filename):
        problems.append("has whitespace, so it must always be quoted")
    first = re.split(r"[-_.\s]", stem.lower(), maxsplit=1)[0]
    if first in CMD_BUILTINS:
        problems.append(f"begins with the cmd built-in {first!r}")
    if stem.lower() == "sletchy":
        problems.append("would shadow the sletchy CLI when typed in this folder")
    return problems


def code_lines(text: str) -> list[str]:
    """The lines cmd executes: not blank, not comments."""
    out = []
    for raw in text.splitlines():
        line = raw.strip()
        if line and not re.match(r"(?i)^(rem\b|::)", line):
            out.append(line)
    return out


def block_lines(text: str) -> list[str]:
    """Lines that open a ( ) block, which cmd parses whole before running any of it."""
    return [line for line in code_lines(text) if line.endswith("(") or line.startswith(")")]


def launcher_text() -> str:
    return LAUNCHER.read_bytes().decode("ascii")


# ── the name ────────────────────────────────────────────────────────────────


def test_the_launcher_name_cannot_be_misread_by_a_shell() -> None:
    assert name_problems(LAUNCHER.name) == []


def test_the_name_checker_catches_the_names_that_would_misfire() -> None:
    # Positive control, including the exact name that popped the dialog.
    assert name_problems("Start Sletchy.cmd")
    assert name_problems("sletchy.cmd")
    assert name_problems("call-sletchy.cmd")
    assert name_problems("Open Sletchy.cmd")
    assert name_problems("Open-Sletchy.cmd") == []


# ── the script ──────────────────────────────────────────────────────────────


def test_the_launcher_changes_nothing_on_the_host() -> None:
    hits = [line for line in code_lines(launcher_text()) if FORBIDDEN.search(line)]
    assert hits == []


def test_the_host_change_checker_can_say_no() -> None:
    for line in ('setx PATH "%PATH%;x"', 'set "PATH=x"', "reg add HKCU\\x", "del /q var\\x"):
        assert FORBIDDEN.search(line), line
    assert not FORBIDDEN.search('start "" "%EXE%"')


def test_the_launcher_has_no_parenthesised_blocks() -> None:
    # cmd parses a ( ) block whole, so a path with a bracket in it - "Program Files
    # (x86)" - expanded inside one ends the block early and runs the rest as commands.
    assert block_lines(launcher_text()) == []
    assert block_lines("if x (\r\n  echo %CD%\r\n)\r\n")  # positive control


def test_check_mode_never_waits_for_a_key() -> None:
    # Every `pause` and `choice` must be unreachable under --check: each is guarded on
    # the same line, or sits after the line that diverts --check elsewhere.
    lines = code_lines(launcher_text())
    divert = lines.index("if defined CHECK goto :check_build")
    for i, line in enumerate(lines):
        lowered = line.lower()
        if lowered.startswith(("pause", "choice")):
            in_build_branch = divert < i < lines.index(":check_build")
            in_failed_branch = lines.index(":failed") < i
            assert in_build_branch or in_failed_branch, line
        if "pause" in lowered and not lowered.startswith("pause"):
            assert lowered.startswith("if not defined check"), line


def test_every_path_the_launcher_names_is_the_real_one() -> None:
    text = launcher_text()
    cargo = tomllib.loads((ROOT / "apps/desktop/src-tauri/Cargo.toml").read_text("utf-8"))
    exe = f"apps\\desktop\\src-tauri\\target\\release\\{cargo['package']['name']}.exe"
    assert f'set "EXE={exe}"' in text
    scripts = tomllib.loads((ROOT / "pyproject.toml").read_text("utf-8"))["project"]["scripts"]
    assert "sletchy" in scripts
    assert 'set "KERNEL=.venv\\Scripts\\sletchy.exe"' in text
    assert (ROOT / "apps/desktop/WHAT-A-CLICK-CAN-DO.md").is_file()
    assert (ROOT / "apps/desktop/package.json").is_file()


def test_batch_files_are_checked_out_with_crlf() -> None:
    # cmd misreads labels and GOTO in a file with LF-only line endings.
    rules = (ROOT / ".gitattributes").read_text("utf-8").split()
    assert "*.cmd" in rules
    assert rules[rules.index("*.cmd") + 2] == "eol=crlf"


# ── on Windows, the real cmd.exe, --check only ──────────────────────────────

windows = pytest.mark.skipif(sys.platform != "win32", reason="cmd.exe is Windows-only")


def windows_launchers() -> int:
    out = subprocess.run(
        ["tasklist", "/FI", "IMAGENAME eq sletchy-desktop.exe", "/FO", "CSV", "/NH"],
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    ).stdout
    return out.lower().count("sletchy-desktop.exe")


def run_check(launcher: Path, cwd: Path) -> subprocess.CompletedProcess[str]:
    """Run the launcher exactly as Explorer does on a double-click, plus --check."""
    command = f'cmd.exe /d /s /c ""{launcher}" --check"'
    return subprocess.run(
        command,
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=60,  # a `pause` or `choice` reached under --check would hang until here
        check=False,
        env={**os.environ, "SLETCHY_HOME": str(cwd / "var")},
    )


@windows
def test_check_from_another_folder_finds_its_own_and_starts_nothing(tmp_path: Path) -> None:
    before = windows_launchers()
    result = run_check(LAUNCHER, tmp_path)
    assert windows_launchers() == before, "--check started a window"
    if (ROOT / ".venv/Scripts/sletchy.exe").exists():
        assert result.returncode in (0, 3), result.stdout + result.stderr
        assert "sletchy-desktop.exe" in result.stdout
    else:
        assert result.returncode == 2
    assert list(tmp_path.iterdir()) == [], "--check wrote into the folder it was run from"


@windows
def test_check_in_a_folder_with_spaces_and_brackets_says_what_is_missing(tmp_path: Path) -> None:
    # A copy with no Kernel beside it, in the kind of path that breaks careless cmd.
    folder = tmp_path / "Program Files (x86) & stuff"
    folder.mkdir()
    copy = folder / LAUNCHER.name
    shutil.copyfile(LAUNCHER, copy)
    result = run_check(copy, tmp_path)
    assert result.returncode == 2, result.stdout + result.stderr
    assert "uv sync" in result.stdout
    assert sorted(p.name for p in folder.iterdir()) == [LAUNCHER.name], "it created files"


@windows
def test_typed_without_quotes_it_runs_itself_not_a_built_in() -> None:
    # The exact mistake that popped the dialog: the name typed bare into cmd. A
    # person's own prompt finds files in its current folder; some automation turns
    # that off with NoDefaultCurrentDirectoryInExePath, so it is cleared here.
    env = {k: v for k, v in os.environ.items() if k.lower() != "nodefaultcurrentdirectoryinexepath"}
    result = subprocess.run(
        f"cmd.exe /d /c {LAUNCHER.name} --check",
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
        env=env,
    )
    assert result.returncode in (0, 2, 3), result.stdout + result.stderr
    assert "sletchy" in result.stdout.lower()
