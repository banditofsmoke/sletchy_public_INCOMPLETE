"""`sletchy sandbox run`: the Warden from a terminal, only through the supervisor (#52).

Most tests here use a spy backend that records what it was asked to run, and a
`subprocess.Popen` that fails the test if anything is constructed, so "refused" is
proven as "never started". Two tests run a real program, end to end.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from sletchy.cli import paths
from sletchy.cli.main import main
from sletchy.cli.sandbox import EXIT_KILLED, EXIT_REFUSED, EXIT_TIMED_OUT
from sletchy.kernel.contracts import IsolationBackend, IsolationProfile
from sletchy.kernel.ledger import InMemoryKeySource, Ledger
from sletchy.warden.isolation import Capabilities, LaunchResult, Sandbox
from sletchy.warden.isolation.recorder import COMPLETE_ACTION, LAUNCH_ACTION
from sletchy.warden.supervisor import ALLOWED_ACTION, DENIED_ACTION

pytestmark = [pytest.mark.adversarial, pytest.mark.law_zero]

KEY = InMemoryKeySource(b"k" * 32)


class Spy(Sandbox):
    """Records what it was asked to run, and with which profile; starts nothing."""

    backend = IsolationBackend.WINJOB
    runs: list[tuple[list[str], IsolationProfile]] = []  # noqa: RUF012 - reset per test
    result = LaunchResult(exit_code=0, stdout="", backend=IsolationBackend.WINJOB)
    minimums: list[IsolationBackend] = []  # noqa: RUF012 - reset per test

    @classmethod
    def available(cls) -> bool:
        return True

    @classmethod
    def capabilities(cls) -> Capabilities:
        return Capabilities()

    def run(self, command: list[str], *, timeout: float | None = None) -> LaunchResult:
        Spy.runs.append((command, self.profile))
        return Spy.result


@pytest.fixture(autouse=True)
def _home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(paths.ENV_HOME, str(tmp_path / "var"))
    monkeypatch.setattr("sletchy.cli.main.KeyringKeySource", lambda *a, **k: KEY)
    Ledger.open(paths.ledger_dir(), KEY).close()
    (tmp_path / "work").mkdir()


@pytest.fixture
def spy(monkeypatch: pytest.MonkeyPatch) -> type[Spy]:
    Spy.runs = []
    Spy.minimums = []
    Spy.result = LaunchResult(exit_code=0, stdout="", backend=IsolationBackend.WINJOB)

    def select(minimum: IsolationBackend, **_: object) -> type[Sandbox]:
        Spy.minimums.append(minimum)
        return Spy

    monkeypatch.setattr("sletchy.warden.supervisor.supervisor.registry.select", select)

    def no_process(*_: object, **__: object) -> None:
        pytest.fail("a process was constructed")

    monkeypatch.setattr(subprocess, "Popen", no_process)
    return Spy


def allow(**programs: str | Path) -> None:
    lines = ["[programs]", *(f'{name} = "{Path(p).as_posix()}"' for name, p in programs.items())]
    paths.allowlist_file().write_text("\n".join(lines) + "\n", encoding="utf-8")


def sandbox(tmp_path: Path, *argv: str, flags: tuple[str, ...] = ()) -> int:
    return main(["sandbox", "run", "--workspace", str(tmp_path / "work"), *flags, "--", *argv])


def entries() -> list[tuple[str, str | None]]:
    ledger = Ledger.open(paths.ledger_dir(), KEY)
    try:
        return [(e.action, e.verdict.rule_id) for e in ledger.entries()]
    finally:
        ledger.close()


# ── nothing runs that is not allowed, and every refusal is on the record ─────


def test_with_no_allowlist_nothing_runs(
    tmp_path: Path, spy: type[Spy], capsys: pytest.CaptureFixture[str]
) -> None:
    assert sandbox(tmp_path, sys.executable, "-c", "1") == EXIT_REFUSED
    assert "refused, nothing was run" in capsys.readouterr().err
    assert spy.runs == []
    assert entries() == [(DENIED_ACTION, "empty_allowlist")]


def test_an_unlisted_program_is_refused_and_recorded(tmp_path: Path, spy: type[Spy]) -> None:
    other = tmp_path / "tool.exe"
    other.write_bytes(b"x")
    allow(python=sys.executable)
    assert sandbox(tmp_path, str(other)) == EXIT_REFUSED
    assert spy.runs == []
    assert entries() == [(DENIED_ACTION, "not_allowlisted")]


@pytest.mark.parametrize(
    ("workspace", "rule"), [("missing", "workspace"), (r"\\.\pipe\x", "workspace")]
)
def test_a_bad_workspace_is_refused_and_recorded(
    tmp_path: Path, spy: type[Spy], workspace: str, rule: str
) -> None:
    allow(python=sys.executable)
    folder = workspace if workspace.startswith("\\") else str(tmp_path / workspace)
    code = main(["sandbox", "run", "--workspace", folder, "--", sys.executable, "-c", "1"])
    assert code == EXIT_REFUSED
    assert spy.runs == []
    assert entries() == [(DENIED_ACTION, rule)]


def test_an_allowlist_that_cannot_be_read_runs_nothing(
    tmp_path: Path, spy: type[Spy], capsys: pytest.CaptureFixture[str]
) -> None:
    paths.allowlist_file().write_text("[programs\npython = ", encoding="utf-8")
    assert sandbox(tmp_path, sys.executable) == EXIT_REFUSED
    assert "could not be read" in capsys.readouterr().err
    assert spy.runs == []


# ── what runs, and how its end is reported ───────────────────────────────────


def test_an_allowlisted_program_runs_and_its_exit_code_is_passed_through(
    tmp_path: Path, spy: type[Spy], capsys: pytest.CaptureFixture[str]
) -> None:
    allow(python=sys.executable)
    spy.result = LaunchResult(exit_code=7, stdout="hello\n", backend=IsolationBackend.WINJOB)
    assert sandbox(tmp_path, sys.executable, "-c", "x") == 7
    out = capsys.readouterr()
    assert out.out == "hello\n"
    assert "exited 7 (winjob)" in out.err
    assert [argv for argv, _ in spy.runs] == [[str(Path(sys.executable).resolve()), "-c", "x"]]
    assert entries() == [(ALLOWED_ACTION, "python")]


@pytest.mark.parametrize(
    ("result", "code", "said"),
    [
        (
            LaunchResult(exit_code=1, timed_out=True, backend=IsolationBackend.WINJOB),
            EXIT_TIMED_OUT,
            "wall-clock",
        ),
        (
            LaunchResult(exit_code=1, killed_by_limit=True, backend=IsolationBackend.WINJOB),
            EXIT_KILLED,
            "resource limit",
        ),
    ],
)
def test_a_stop_by_the_sandbox_is_told_apart_from_a_failure(
    tmp_path: Path,
    spy: type[Spy],
    capsys: pytest.CaptureFixture[str],
    result: LaunchResult,
    code: int,
    said: str,
) -> None:
    allow(python=sys.executable)
    spy.result = result
    assert sandbox(tmp_path, sys.executable) == code
    assert said in capsys.readouterr().err


# ── flags only tighten; nothing weakens ──────────────────────────────────────


@pytest.mark.parametrize(
    "flags",
    [
        ("--timeout", "301"),
        ("--timeout", "0"),
        ("--timeout", "ten"),
        ("--memory-mb", "4096"),
        ("--cpu-percent", "51"),
        ("--backend", "inproc"),
        ("--no-sandbox",),
        ("--allow-downgrade",),
    ],
)
def test_a_flag_that_would_widen_or_weaken_is_refused_before_anything_opens(
    tmp_path: Path, spy: type[Spy], flags: tuple[str, ...]
) -> None:
    allow(python=sys.executable)
    with pytest.raises(SystemExit) as exc:
        sandbox(tmp_path, sys.executable, flags=flags)
    assert exc.value.code == 2
    assert spy.runs == []
    assert entries() == []


def test_tightening_flags_reach_the_sandbox(tmp_path: Path, spy: type[Spy]) -> None:
    allow(python=sys.executable)
    flags = ("--timeout", "30", "--memory-mb", "256", "--cpu-percent", "10", "--backend", "subproc")
    sandbox(tmp_path, sys.executable, flags=flags)
    ((_, profile),) = spy.runs
    assert (profile.resources.wall_clock_seconds, profile.resources.memory_mb) == (30, 256)
    assert profile.resources.cpu_percent == 10
    assert spy.minimums == [IsolationBackend.SUBPROC]


def test_the_default_asks_for_the_strongest_sandbox(tmp_path: Path, spy: type[Spy]) -> None:
    allow(python=sys.executable)
    sandbox(tmp_path, sys.executable)
    assert spy.minimums == [IsolationBackend.WINJOB]


# ── the dry run ──────────────────────────────────────────────────────────────


def test_a_dry_run_says_what_would_run_and_starts_and_records_nothing(
    tmp_path: Path, spy: type[Spy], capsys: pytest.CaptureFixture[str]
) -> None:
    allow(python=sys.executable)
    assert sandbox(tmp_path, sys.executable, "-c", "1", flags=("--dry-run",)) == 0
    out = capsys.readouterr().out
    assert "would run" in out
    assert "allowed as  python" in out
    assert "nothing was started and nothing was recorded" in out
    assert spy.runs == []
    assert entries() == []


def test_a_dry_run_of_a_refused_command_records_nothing(tmp_path: Path, spy: type[Spy]) -> None:
    assert sandbox(tmp_path, sys.executable, flags=("--dry-run",)) == EXIT_REFUSED
    assert entries() == []


# ── a real program, end to end ───────────────────────────────────────────────

CURL = Path(r"C:\Windows\System32\curl.exe")


@pytest.mark.skipif(sys.platform != "win32" or not CURL.is_file(), reason="Windows, with curl.exe")
def test_a_real_program_runs_in_the_appcontainer_end_to_end(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """`curl --version` touches no network and runs inside an AppContainer (ADR-0006)."""
    allow(curl=CURL)
    assert sandbox(tmp_path, str(CURL), "--version") == 0
    out = capsys.readouterr()
    assert "curl" in out.out
    assert "(winjob)" in out.err
    assert [action for action, _ in entries()] == [ALLOWED_ACTION, LAUNCH_ACTION, COMPLETE_ACTION]


@pytest.mark.skipif(sys.platform == "win32", reason="the POSIX twin of the Windows test above")
def test_a_real_program_runs_end_to_end_off_windows(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    allow(python=sys.executable)
    code = sandbox(tmp_path, sys.executable, "-c", "print('ran')", flags=("--backend", "subproc"))
    assert code == 0
    assert "ran" in capsys.readouterr().out
    assert [action for action, _ in entries()] == [ALLOWED_ACTION, LAUNCH_ACTION, COMPLETE_ACTION]
