"""The supervisor: a denied command never becomes a process, not even briefly (#69).

The test for "denied" is never "the process exited non-zero". It is that the spawn path
was **never reached**: a spy sandbox records every `run()`, and `subprocess.Popen` is
replaced by one that fails the test if anything constructs it.
"""

from __future__ import annotations

import ast
import inspect
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from sletchy.kernel.contracts import Decision, IsolationBackend, IsolationProfile
from sletchy.kernel.ledger import InMemoryKeySource, Ledger
from sletchy.warden.isolation import (
    BackendUnavailable,
    Capabilities,
    LaunchResult,
    Sandbox,
    SandboxRecorder,
)
from sletchy.warden.isolation.recorder import COMPLETE_ACTION, LAUNCH_ACTION
from sletchy.warden.supervisor import (
    ALLOWED_ACTION,
    DENIED_ACTION,
    Allowlist,
    LaunchDenied,
    Supervisor,
)

pytestmark = [pytest.mark.adversarial, pytest.mark.law_zero]

REPO = Path(__file__).resolve().parents[2]
PROFILE = IsolationProfile.model_validate({"backend": IsolationBackend.INPROC})


class SpySandbox(Sandbox):
    """A backend that records every run instead of starting anything."""

    backend = IsolationBackend.INPROC
    runs: list[list[str]] = []  # noqa: RUF012 - a spy shared by every instance, reset per test

    @classmethod
    def available(cls) -> bool:
        return True

    @classmethod
    def capabilities(cls) -> Capabilities:
        return Capabilities()

    def run(self, command: list[str], *, timeout: float | None = None) -> LaunchResult:
        SpySandbox.runs.append(command)
        return LaunchResult(exit_code=0, backend=self.backend)


@pytest.fixture
def ledger(tmp_path: Path) -> Ledger:
    return Ledger.open(tmp_path / "ledger", InMemoryKeySource(b"k" * 32))


@pytest.fixture
def spy(monkeypatch: pytest.MonkeyPatch) -> list[list[str]]:
    SpySandbox.runs = []
    monkeypatch.setattr(
        "sletchy.warden.supervisor.supervisor.registry.select", lambda minimum, **_: SpySandbox
    )

    def no_process(*_: object, **__: object) -> None:
        pytest.fail("a process was constructed")

    monkeypatch.setattr(subprocess, "Popen", no_process)
    return SpySandbox.runs


def supervisor(ledger: Ledger, programs: dict[str, Any] | None = None) -> Supervisor:
    allow = Allowlist.of({"python": sys.executable} if programs is None else programs)
    return Supervisor(allow, recorder=SandboxRecorder(ledger=ledger, actor_id="supervisor_test"))


def denied(sup: Supervisor, command: object, tmp_path: Path) -> str:
    with pytest.raises(LaunchDenied) as caught:
        sup.launch(command, workspace=tmp_path, profile=PROFILE)  # type: ignore[arg-type]
    return caught.value.rule


def make(tmp_path: Path, name: str) -> Path:
    path = tmp_path / name
    path.write_bytes(b"not a real program")
    return path


# ── a denied command never spawns ────────────────────────────────────────────


@pytest.mark.parametrize(
    ("command", "rule"),
    [
        ("python -c print(1)", "command_string"),
        ([], "empty_command"),
        (["python"], "not_absolute"),
        (["python.exe", "-c", "1"], "not_absolute"),
        ([r"\\.\pipe\x"], "program_path"),
        ([r"\\server\share\tool.exe"], "program_path"),
        ([sys.executable, "a\x00b"], "bad_argument"),
        ([sys.executable, 3], "bad_argument"),
    ],
)
def test_a_malformed_or_unresolvable_command_never_spawns(
    ledger: Ledger, spy: list[list[str]], tmp_path: Path, command: object, rule: str
) -> None:
    assert denied(supervisor(ledger), command, tmp_path) == rule
    assert spy == []


def test_a_program_that_does_not_exist_never_spawns(
    ledger: Ledger, spy: list[list[str]], tmp_path: Path
) -> None:
    assert denied(supervisor(ledger), [str(tmp_path / "missing.exe")], tmp_path) == "not_found"
    assert spy == []


def test_a_stream_in_the_program_path_never_spawns(
    ledger: Ledger, spy: list[list[str]], tmp_path: Path
) -> None:
    assert (
        denied(supervisor(ledger), [str(make(tmp_path, "t.exe")) + ":s"], tmp_path)
        == "program_path"
    )
    assert spy == []


def test_an_unlisted_program_never_spawns(
    ledger: Ledger, spy: list[list[str]], tmp_path: Path
) -> None:
    """Allowlist, not blocklist: an ordinary, harmless, unknown program is refused."""
    assert (
        denied(supervisor(ledger), [str(make(tmp_path, "tool.exe"))], tmp_path) == "not_allowlisted"
    )
    assert spy == []


@pytest.mark.parametrize(
    "name", ["cmd.exe", "PowerShell.EXE", "pwsh", "wsl.exe", "bash", "wscript.exe"]
)
def test_a_shell_never_spawns(
    ledger: Ledger, spy: list[list[str]], tmp_path: Path, name: str
) -> None:
    assert denied(supervisor(ledger), [str(make(tmp_path, name)), "/c", "dir"], tmp_path) == "shell"
    assert spy == []


@pytest.mark.parametrize(
    "name", ["certutil.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "msbuild.exe"]
)
def test_a_tripwire_program_never_spawns(
    ledger: Ledger, spy: list[list[str]], tmp_path: Path, name: str
) -> None:
    assert (
        denied(supervisor(ledger), [str(make(tmp_path, name))], tmp_path) == "living_off_the_land"
    )
    assert spy == []


def test_with_nothing_allowlisted_nothing_runs(
    ledger: Ledger, spy: list[list[str]], tmp_path: Path
) -> None:
    """LAW 2: an empty list means nothing launches, not everything."""
    assert (
        denied(supervisor(ledger, {}), [sys.executable, "-c", "1"], tmp_path) == "empty_allowlist"
    )
    assert spy == []


def test_a_backend_that_cannot_be_had_is_a_recorded_refusal(
    ledger: Ledger, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The `select()` gap: it raises without writing; the supervisor writes for it."""

    def nothing_qualifies(minimum: object, **_: object) -> type[Sandbox]:
        msg = "no isolation backend at or above 'winjob' is available"
        raise BackendUnavailable(msg)

    monkeypatch.setattr("sletchy.warden.supervisor.supervisor.registry.select", nothing_qualifies)
    with pytest.raises(BackendUnavailable):
        supervisor(ledger).launch([sys.executable, "-c", "1"], workspace=tmp_path, profile=PROFILE)
    (entry,) = ledger.entries()
    assert entry.action == DENIED_ACTION
    assert entry.verdict.rule_id == "no_backend"


# ── every decision on the record, first ──────────────────────────────────────


def test_every_refusal_is_recorded_with_its_rule(
    ledger: Ledger, spy: list[list[str]], tmp_path: Path
) -> None:
    sup = supervisor(ledger)
    commands = {
        "empty_command": [],
        "not_absolute": ["python"],
        "shell": [str(make(tmp_path, "cmd.exe"))],
    }
    for command in commands.values():
        with pytest.raises(LaunchDenied):
            sup.launch(command, workspace=tmp_path, profile=PROFILE)
    entries = list(ledger.entries())
    assert [e.verdict.rule_id for e in entries] == list(commands)
    assert all(e.action == DENIED_ACTION and e.verdict.decision is Decision.DENY for e in entries)


def test_an_allowed_launch_is_recorded_before_it_runs(
    ledger: Ledger, spy: list[list[str]], tmp_path: Path
) -> None:
    supervisor(ledger).launch([sys.executable, "-c", "1"], workspace=tmp_path, profile=PROFILE)
    (entry,) = ledger.entries()
    assert entry.action == ALLOWED_ACTION
    assert entry.verdict.rule_id == "python"
    assert spy == [[str(Path(sys.executable).resolve()), "-c", "1"]]


def test_the_program_runs_by_its_resolved_path_whatever_spelling_was_given(
    ledger: Ledger, spy: list[list[str]], tmp_path: Path
) -> None:
    """The allowlisted path is canonical, and so is what is run: no PATH, no alias."""
    spelling = str(Path(sys.executable)).replace("\\", "/")
    if sys.platform == "win32":
        spelling = spelling.upper()
    supervisor(ledger).launch([spelling, "-V"], workspace=tmp_path, profile=PROFILE)
    assert spy[0][0] == str(Path(sys.executable).resolve())


def test_a_real_launch_goes_decision_then_launch_then_outcome(
    ledger: Ledger, tmp_path: Path
) -> None:
    """End to end, with a real process, in the strongest sandbox at or above `subproc`.

    On Windows that is `winjob`, whose AppContainer denies Python the files beside its own
    executable, so Python exits with an error: the containment working, not the test
    failing. What is asserted is the order on the record, and the rung that ran it.
    """
    profile = IsolationProfile.model_validate({"backend": IsolationBackend.SUBPROC})
    result = supervisor(ledger).launch(
        [sys.executable, "-c", "print('supervised')"], workspace=tmp_path, profile=profile
    )
    assert result.exit_code is not None, "a process ran and ended"
    assert result.backend.strength >= IsolationBackend.SUBPROC.strength
    assert [e.action for e in ledger.entries()] == [ALLOWED_ACTION, LAUNCH_ACTION, COMPLETE_ACTION]


# ── the list only shrinks, and nothing bypasses it ───────────────────────────


def test_the_allowlist_can_be_narrowed_and_never_widened(
    ledger: Ledger, spy: list[list[str]], tmp_path: Path
) -> None:
    sup = supervisor(ledger)
    for widening in ("add", "append", "extend", "insert", "update", "allow", "grant"):
        assert not hasattr(sup.allowlist, widening), widening
        assert not hasattr(sup, widening), widening
    sup.narrow("python")
    assert denied(sup, [sys.executable, "-c", "1"], tmp_path) == "empty_allowlist"


@pytest.mark.parametrize(
    "programs",
    [
        {"shell": "C:/Windows/System32/cmd.exe"},
        {"lolbin": "C:/Windows/System32/certutil.exe"},
        {"bare": "python"},
        {"Bad Name": sys.executable},
    ],
)
def test_the_allowlist_refuses_what_could_never_be_safe(programs: dict[str, str]) -> None:
    with pytest.raises(ValueError, match=r"\S"):
        Allowlist.of(programs)


def test_there_is_no_bypass_parameter() -> None:
    """No `force`, no `trusted`, no internal-caller exemption: every one becomes the default."""
    assert list(inspect.signature(Supervisor.launch).parameters) == [
        "self",
        "command",
        "workspace",
        "profile",
    ]
    assert list(inspect.signature(Supervisor.__init__).parameters) == [
        "self",
        "allowlist",
        "recorder",
    ]


# ── no command strings anywhere ──────────────────────────────────────────────


def _string_launches(source: str) -> list[int]:
    lines = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Call):
            continue
        if any(
            k.arg == "shell" and not (isinstance(k.value, ast.Constant) and k.value.value is False)
            for k in node.keywords
        ):
            lines.append(node.lineno)
        name = ast.unparse(node.func)
        if name in ("os.system", "os.popen", "os.startfile"):
            lines.append(node.lineno)
        launches = (
            "subprocess.run",
            "subprocess.Popen",
            "subprocess.call",
            "subprocess.check_output",
            "subprocess.check_call",
        )
        if (
            name in launches
            and node.args
            and isinstance(node.args[0], ast.Constant | ast.JoinedStr)
        ):
            lines.append(node.lineno)
    return lines


def test_nothing_in_src_launches_a_command_string_or_a_shell() -> None:
    files = sorted((REPO / "src").rglob("*.py"))
    assert len(files) > 50
    hits = [
        f"{f.relative_to(REPO)}:{n}" for f in files for n in _string_launches(f.read_text("utf-8"))
    ]
    assert hits == []


def test_the_command_string_check_can_fail() -> None:
    """Positive control."""
    assert _string_launches("import subprocess\nsubprocess.run('dir', shell=True)\n") == [2, 2]
    assert _string_launches("import os\nos.system('dir')\n") == [2]
    assert _string_launches("import subprocess\nsubprocess.run(['dir'])\n") == []
