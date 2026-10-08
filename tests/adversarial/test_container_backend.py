"""The `container` backend (#70, ADR-0014): what it refuses to do, and what it does.

The shared conformance suite holds its behaviour wherever it is available, which is
CI's Linux job with Podman and the pinned image. These tests hold what must be true
**everywhere**, including this Windows machine where it must never run: when it is
unavailable, that it installs and pulls nothing, and the exact restrictions on every
container it starts. The runtime is a fake here; nothing starts a container.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from sletchy.kernel.contracts import IsolationBackend, IsolationProfile
from sletchy.kernel.hostchanges import pending
from sletchy.kernel.ledger import InMemoryKeySource, Ledger, PayloadStore
from sletchy.kernel.paths import ENV_HOME, ledger_dir, payload_dir
from sletchy.kernel.secrets import child_env
from sletchy.warden.isolation import BackendUnavailable, SandboxRecorder
from sletchy.warden.isolation import container as container_mod
from sletchy.warden.isolation.container import IMAGE, ContainerSandbox

pytestmark = pytest.mark.adversarial

REPO = Path(__file__).resolve().parents[2]
FAKE_PODMAN = "/usr/bin/podman"


@pytest.fixture(autouse=True)
def _home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ENV_HOME, str(tmp_path / "home"))


@pytest.fixture
def recorder(_home: None) -> SandboxRecorder:
    return SandboxRecorder(
        ledger=Ledger.open(ledger_dir(), InMemoryKeySource(b"k" * 32)),
        actor_id="container_tests",
        payloads=PayloadStore.open(payload_dir()),
    )


@dataclass
class Podman:
    """Stands in for the runtime. Records every line; starts nothing."""

    image_present: bool = True
    run_exit: int = 0
    run_raises: bool = False
    rm_exit: int = 0
    calls: list[list[str]] = field(default_factory=list)
    journal_during_run: list[str] = field(default_factory=list)

    def __call__(self, argv: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        line = [str(a) for a in argv]
        self.calls.append(line)
        verb = line[1] if len(line) > 1 else ""
        if verb == "image":
            return subprocess.CompletedProcess(line, 0 if self.image_present else 1, "", "")
        if verb == "run":
            self.journal_during_run += [c.profile for c in pending()]
            if self.run_raises:
                raise subprocess.TimeoutExpired(line, 1)
            return subprocess.CompletedProcess(line, self.run_exit, "out\n", "")
        if verb == "rm":
            return subprocess.CompletedProcess(line, self.rm_exit, "", "")
        raise AssertionError(f"the backend ran something no test expected: {line}")

    def verbs(self) -> list[str]:
        return [c[1] for c in self.calls]


@pytest.fixture
def podman(monkeypatch: pytest.MonkeyPatch) -> Podman:
    fake = Podman()
    monkeypatch.setattr(container_mod, "_platform", lambda: "linux")
    monkeypatch.setattr(shutil, "which", lambda name: FAKE_PODMAN)
    monkeypatch.setattr(subprocess, "run", fake)
    return fake


def profile() -> IsolationProfile:
    return IsolationProfile(backend=IsolationBackend.CONTAINER)


def sandbox(tmp_path: Path, recorder: SandboxRecorder) -> ContainerSandbox:
    workspace = tmp_path / "workspace"
    workspace.mkdir(exist_ok=True)
    return ContainerSandbox(workspace, profile(), recorder=recorder)


# ── never here, never installed, never pulled ────────────────────────────────


def test_never_available_on_windows_whatever_is_installed(
    podman: Podman, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(container_mod, "_platform", lambda: "win32")

    assert not ContainerSandbox.available()
    assert podman.calls == [], "it asked the runtime anything on Windows"


def test_unavailable_without_podman(podman: Podman, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda name: None)

    assert not ContainerSandbox.available()


def test_unavailable_without_the_pinned_image(podman: Podman) -> None:
    podman.image_present = False

    assert not ContainerSandbox.available()
    assert podman.calls == [[FAKE_PODMAN, "image", "exists", IMAGE]]


def test_unavailable_means_the_run_does_not_happen_and_is_recorded(
    tmp_path: Path, recorder: SandboxRecorder, podman: Podman
) -> None:
    podman.image_present = False

    with pytest.raises(BackendUnavailable, match="installs and pulls nothing"):
        sandbox(tmp_path, recorder)
    assert "run" not in podman.verbs()
    assert [e.action for e in recorder.ledger.entries()] == ["warden.sandbox.refused"]


def test_the_backend_never_installs_pulls_or_starts_a_machine() -> None:
    source = Path(container_mod.__file__).read_text(encoding="utf-8")
    code = source.split('"""', 2)[2]  # the module docstring says what it never does
    # As argv words: the subcommands that fetch, install, or start a virtual machine.
    for never in ('"pull"', '"machine"', '"install"', '"apt-get"', '"wsl"', '"load"', '"import"'):
        assert never not in code, never
    assert '"--pull=never"' in code


def test_the_image_is_pinned_by_digest() -> None:
    assert re.fullmatch(r"[a-z0-9./-]+@sha256:[0-9a-f]{64}", IMAGE)


def test_ci_pulls_exactly_the_pinned_image_and_nothing_else() -> None:
    workflow = (REPO / ".github" / "workflows" / "ci.yml").read_text("utf-8")
    pulls = re.findall(r"podman pull (\S+)", workflow)
    assert pulls == [IMAGE]


# ── every container's restrictions ───────────────────────────────────────────


def test_every_restriction_is_on_the_line(
    tmp_path: Path, recorder: SandboxRecorder, podman: Podman
) -> None:
    box = sandbox(tmp_path, recorder)
    line = box.argv("sletchy-ctest", ["/bin/sh", "-c", "exit 0"])

    for flag in (
        "--rm",
        "--pull=never",
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
    ):
        assert flag in line, flag
    assert line[line.index("--pids-limit") + 1] == str(box.profile.resources.max_processes)
    assert line[line.index("--memory") + 1] == f"{box.profile.resources.memory_mb}m"
    assert line[-4:] == [IMAGE, "/bin/sh", "-c", "exit 0"]


def test_only_the_workspace_is_mounted_and_never_the_runtime_socket(
    tmp_path: Path, recorder: SandboxRecorder, podman: Podman
) -> None:
    box = sandbox(tmp_path, recorder)
    line = box.argv("sletchy-ctest", ["/bin/true"])

    mounts = [line[i + 1] for i, a in enumerate(line) if a in ("--volume", "-v", "--mount")]
    workspace = str(box.workspace)
    assert mounts == [f"{workspace}:{workspace}:rw"]
    assert not any("sock" in a for a in line)
    assert "--privileged" not in line


def test_only_the_kernels_allowlist_reaches_the_container(
    tmp_path: Path, recorder: SandboxRecorder, podman: Podman, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SLETCHY_CONTAINER_SECRET", "must-not-reach-the-container")
    box = sandbox(tmp_path, recorder)
    line = box.argv("sletchy-ctest", ["/bin/true"])

    passed = [line[i + 1] for i, a in enumerate(line) if a == "--env"]
    assert passed == [f"{k}={v}" for k, v in sorted(child_env().items())]
    assert not any("must-not-reach" in a for a in line)
    assert "--env-host" not in line


# ── journalled first, removed after ──────────────────────────────────────────


def test_a_run_is_journalled_before_it_starts_and_forgotten_once_removed(
    tmp_path: Path, recorder: SandboxRecorder, podman: Podman
) -> None:
    result = sandbox(tmp_path, recorder).run(["/bin/true"])

    assert result.exit_code == 0
    assert podman.verbs()[-2:] == ["run", "rm"]
    name = result.diagnostics["container"]
    assert podman.journal_during_run == [name], "the container was not journalled first"
    assert podman.calls[-1][-1] == name
    assert pending() == ()


def test_a_container_that_will_not_go_is_kept_for_panic(
    tmp_path: Path, recorder: SandboxRecorder, podman: Podman
) -> None:
    podman.rm_exit = 1

    result = sandbox(tmp_path, recorder).run(["/bin/true"])

    assert [c.profile for c in pending()] == [result.diagnostics["container"]]


def test_a_run_past_its_limit_is_stopped_and_removed(
    tmp_path: Path, recorder: SandboxRecorder, podman: Podman
) -> None:
    podman.run_raises = True

    result = sandbox(tmp_path, recorder).run(["/bin/sleep", "3600"], timeout=1)

    assert result.timed_out and result.killed_by_limit
    assert podman.verbs()[-1] == "rm"
    assert pending() == ()


def test_an_empty_command_is_refused(
    tmp_path: Path, recorder: SandboxRecorder, podman: Podman
) -> None:
    from sletchy.warden.isolation import LaunchRefused

    with pytest.raises(LaunchRefused, match="empty command"):
        sandbox(tmp_path, recorder).run([])
    assert "run" not in podman.verbs()
