"""The shared isolation conformance suite.

Every backend runs the same tests. They assert **behaviour** - this write is
refused, this environment variable is absent - never implementation, so a backend
can change substrate entirely and still be held to the same contract.

The design that makes this work: a backend **declares** what it enforces via
`capabilities()`, and the suite holds it to exactly that declaration.

- Claim a capability and fail to deliver → **the suite fails.** Overclaiming is the
  dangerous direction and is caught.
- Decline to claim one → the assertion is skipped for that backend, and
  `test_a_backend_that_declines_a_capability_is_recorded` prints what was skipped so
  a gap stays visible rather than looking like a pass.

`inproc` claims nothing and is the control: if a should-fail assertion passes for
`inproc`, the assertion is measuring something other than isolation. That is exactly
the confound the AppContainer spike hit - see ADR-0005 §4.

**The probe program is the platform shell, not Python.** Why, and what it cost to
find out, is in `probes.py`.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from sletchy.kernel.contracts import IsolationBackend, IsolationProfile, ResourceLimits
from sletchy.kernel.ledger import InMemoryKeySource, Ledger, PayloadStore
from sletchy.kernel.paths import ENV_HOME, ledger_dir, payload_dir, runtime_dir
from sletchy.warden.isolation import (
    BACKENDS,
    BackendUnavailable,
    Capabilities,
    ContainerSandbox,
    InProcSandbox,
    LaunchResult,
    Sandbox,
    SandboxRecorder,
    SubprocSandbox,
    WinJobSandbox,
    available_backends,
    select,
)
from tests.adversarial import probes

pytestmark = pytest.mark.adversarial

ALL_BACKENDS = [pytest.param(cls, id=cls.backend.value) for cls in BACKENDS.values()]


@pytest.fixture(autouse=True)
def _sandboxed_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep every backend's own bookkeeping inside the test's tmp_path.

    `winjob` writes a capture file and an undo journal under `SLETCHY_HOME`.
    Pointing it at a per-test directory means `test_a_sandbox_writes_nothing_
    outside_its_workspace` is a real residue check rather than a formality.
    """
    monkeypatch.setenv(ENV_HOME, str(tmp_path / "sletchy-home"))


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    ws = tmp_path / "workspace"
    ws.mkdir()
    return ws


@pytest.fixture
def recorder(_sandboxed_home: None) -> SandboxRecorder:
    """A real ledger, not a stub.

    Stubbing it would make every LAW 1 assertion in this suite a test of the stub.
    The chain is verified on open, so a backend that corrupted it would fail here.

    It lives under `SLETCHY_HOME` like the real thing, so the residue check below
    is testing the actual layout rather than a convenient one.
    """
    ledger = Ledger.open(ledger_dir(), InMemoryKeySource(b"k" * 32))
    return SandboxRecorder(
        ledger=ledger,
        actor_id="conformance",
        payloads=PayloadStore.open(payload_dir()),
    )


def profile(**kw: object) -> IsolationProfile:
    return IsolationProfile.model_validate({"backend": IsolationBackend.SUBPROC, **kw})


def make(cls: type[Sandbox], workspace: Path, recorder: SandboxRecorder, **kw: object) -> Sandbox:
    """Build a sandbox, skipping when this host cannot provide that backend.

    A backend that cannot run here is skipped by name rather than quietly passing:
    an assertion that never executed is not evidence.
    """
    if not cls.available():
        pytest.skip(f"{cls.backend.value} is not available on this host")
    return cls(workspace, profile(**kw), recorder=recorder)


# ── the positive control ─────────────────────────────────────────────────────


@pytest.mark.parametrize("cls", ALL_BACKENDS)
def test_the_sandbox_can_run_something_at_all(
    cls: type[Sandbox], workspace: Path, recorder: SandboxRecorder
) -> None:
    """The control every other assertion depends on.

    A suite of should-fail assertions passes trivially when nothing runs. ADR-0005
    §4 is the cautionary tale: three probe runs read as "denied everything" when the
    real answer was that the probe could not open its own output stream.
    """
    result = make(cls, workspace, recorder).run(probes.exit_with(42))

    assert result.exit_code == 42, (
        f"{cls.backend.value} could not run a trivial process; every other result "
        "in this suite is meaningless for it"
    )
    assert not result.timed_out


@pytest.mark.parametrize("cls", ALL_BACKENDS)
def test_stdout_comes_back(cls: type[Sandbox], workspace: Path, recorder: SandboxRecorder) -> None:
    result = make(cls, workspace, recorder).run(probes.print_text("hello"))
    assert "hello" in result.stdout


# ── declared capabilities are honest ─────────────────────────────────────────


@pytest.mark.parametrize("cls", ALL_BACKENDS)
def test_capabilities_are_declared(cls: type[Sandbox]) -> None:
    assert isinstance(cls.capabilities(), Capabilities)


def test_inproc_claims_nothing() -> None:
    """The control backend must not claim anything, or it stops being a control."""
    caps = InProcSandbox.capabilities()
    assert caps == Capabilities()


def test_subproc_claims_only_what_it_does() -> None:
    """`subproc` confines no filesystem and no network, and must not say it does."""
    caps = SubprocSandbox.capabilities()
    assert caps.strips_environment
    assert caps.enforces_resource_limits
    assert not caps.confines_filesystem
    assert not caps.confines_network
    assert not caps.kills_process_tree


def test_winjob_claims_the_filesystem_but_never_the_network() -> None:
    """The honesty rule, pinned to the one claim most tempting to overstate.

    Filesystem containment is measured (ADR-0005 §3, and this suite). Network
    denial is **not** - an AppContainer is expected to refuse a socket without the
    network capability, but expectation is not measurement. If this assertion is
    ever inverted, it must be because a probe proved it, not because it seemed
    obvious.
    """
    caps = WinJobSandbox.capabilities()
    assert caps.confines_filesystem
    assert caps.enforces_resource_limits
    assert caps.kills_process_tree
    assert caps.strips_environment
    assert not caps.confines_network, (
        "winjob must not claim network confinement until it has its own probe"
    )


def test_no_backend_claims_to_confine_the_network() -> None:
    """Nothing in Wave 2 has measured this yet, so nothing may claim it."""
    for cls in BACKENDS.values():
        assert not cls.capabilities().confines_network, f"{cls.backend.value} claims network"


@pytest.mark.parametrize("cls", ALL_BACKENDS)
def test_a_backend_that_declines_a_capability_is_recorded(
    cls: type[Sandbox], capsys: pytest.CaptureFixture[str]
) -> None:
    """Make the gaps visible instead of letting a skip look like a pass."""
    caps = cls.capabilities()
    declined = [name for name, value in vars(caps).items() if not value]
    with capsys.disabled():
        print(f"\n  {cls.backend.value}: does NOT enforce {declined or 'nothing - full coverage'}")


# ── environment stripping ────────────────────────────────────────────────────


@pytest.mark.parametrize("cls", ALL_BACKENDS)
def test_environment_stripping_matches_the_claim(
    cls: type[Sandbox], workspace: Path, monkeypatch: pytest.MonkeyPatch, recorder: SandboxRecorder
) -> None:
    """Claim it and it must hold; decline it and nothing is asserted."""
    monkeypatch.setenv(probes.SECRET_NAME, probes.SECRET_VALUE)

    result = make(cls, workspace, recorder).run(probes.print_env())

    if cls.capabilities().strips_environment:
        assert probes.SECRET_VALUE not in result.stdout, (
            f"{cls.backend.value} claims strips_environment but the child saw it"
        )
    else:
        # inproc: proves the assertion above is measuring something real.
        assert probes.SECRET_VALUE in result.stdout


# ── filesystem confinement ───────────────────────────────────────────────────


@pytest.mark.parametrize("cls", ALL_BACKENDS)
def test_filesystem_confinement_matches_the_claim(
    cls: type[Sandbox], workspace: Path, tmp_path: Path, recorder: SandboxRecorder
) -> None:
    outside = tmp_path / "outside.txt"
    outside.write_text("outside the workspace", encoding="utf-8")

    result = make(cls, workspace, recorder).run(probes.read_file(outside))

    if cls.capabilities().confines_filesystem:
        assert result.exit_code != 0, (
            f"{cls.backend.value} claims confines_filesystem but read outside its workspace"
        )
        assert "outside the workspace" not in result.stdout
    else:
        assert result.exit_code == 0, (
            "the probe itself is broken: an unconfined backend should read this file"
        )


@pytest.mark.parametrize("cls", ALL_BACKENDS)
def test_the_workspace_is_always_usable(
    cls: type[Sandbox], workspace: Path, recorder: SandboxRecorder
) -> None:
    """Confinement must not mean uselessness - an agent needs a scratch area.

    ADR-0005 measured this for AppContainer: a contained process keeps full use of
    its own folder, and a parent-placed workspace is readable.
    """
    (workspace / "given.txt").write_text("handed in by the parent", encoding="utf-8")

    result = make(cls, workspace, recorder).run(probes.read_file("given.txt"))

    assert result.exit_code == 0, f"{cls.backend.value} cannot read its own workspace"
    assert "handed in by the parent" in result.stdout


# ── resource limits ──────────────────────────────────────────────────────────


@pytest.mark.parametrize("cls", ALL_BACKENDS)
def test_a_wall_clock_limit_stops_a_hanging_process(
    cls: type[Sandbox], workspace: Path, recorder: SandboxRecorder
) -> None:
    sandbox = make(cls, workspace, recorder, resources=ResourceLimits(wall_clock_seconds=1))
    result = sandbox.run(probes.hang(), timeout=1)

    assert result.timed_out, f"{cls.backend.value} did not stop a hanging process"
    assert result.exit_code is None

    if cls.capabilities().enforces_resource_limits:
        assert result.killed_by_limit, (
            f"{cls.backend.value} claims enforces_resource_limits but did not say it "
            "was the one that killed the process"
        )


def test_a_timeout_is_distinguishable_from_a_failure(
    workspace: Path, recorder: SandboxRecorder
) -> None:
    """'The program failed' and 'we stopped the program' are different events."""
    sandbox = SubprocSandbox(workspace, profile(), recorder=recorder)

    failed = sandbox.run(probes.exit_with(1))
    stopped = sandbox.run(probes.hang(), timeout=1)

    assert failed.exit_code == 1 and not failed.timed_out and not failed.killed_by_limit
    assert stopped.timed_out and stopped.killed_by_limit
    assert not failed.succeeded and not stopped.succeeded


# ── selection never downgrades ───────────────────────────────────────────────


def test_select_returns_the_strongest_available() -> None:
    strongest: type[Sandbox] = SubprocSandbox
    if WinJobSandbox.available():
        strongest = WinJobSandbox
    if ContainerSandbox.available():
        strongest = ContainerSandbox
    assert select(IsolationBackend.INPROC) is strongest


def test_select_raises_when_the_minimum_is_unavailable() -> None:
    """The rule that keeps the ladder from being a loophole."""
    unreachable = (
        IsolationBackend.VM if ContainerSandbox.available() else IsolationBackend.CONTAINER
    )
    with pytest.raises(BackendUnavailable, match="does not run"):
        select(unreachable)


def test_the_container_backend_is_never_reachable_on_windows() -> None:
    """ADR-0014: on Windows a container needs a virtual machine Sletchy never starts."""
    if sys.platform == "win32":
        assert not ContainerSandbox.available()
        assert IsolationBackend.CONTAINER not in available_backends()


def test_select_never_silently_downgrades() -> None:
    """A weaker backend exists and is available; it must NOT be returned."""
    assert SubprocSandbox.available()
    with pytest.raises(BackendUnavailable):
        select(IsolationBackend.VM)


def test_select_has_no_downgrade_parameter() -> None:
    """If this fails, someone added the escape hatch that undoes ADR-0002."""
    import inspect

    params = set(inspect.signature(select).parameters)
    assert params == {"minimum", "required"}
    for forbidden in ("allow_downgrade", "fallback", "best_effort", "force"):
        assert forbidden not in params


def test_select_refuses_a_capability_nothing_provides() -> None:
    """No backend confines the network, so this must raise on every host."""
    with pytest.raises(BackendUnavailable, match="confines_network"):
        select(IsolationBackend.INPROC, required=Capabilities(confines_network=True))


def test_select_honours_a_capability_something_provides() -> None:
    assert select(IsolationBackend.INPROC, required=Capabilities(strips_environment=True))


@pytest.mark.skipif(not WinJobSandbox.available(), reason="winjob is Windows-only")
def test_a_filesystem_requirement_selects_winjob_and_nothing_weaker() -> None:
    """The ladder doing its job: only the backend that measured it qualifies."""
    chosen = select(IsolationBackend.INPROC, required=Capabilities(confines_filesystem=True))
    assert chosen is WinJobSandbox


def test_available_backends_are_ordered_weakest_first() -> None:
    order = [b.strength for b in available_backends()]
    assert order == sorted(order)


# ── inproc is test-only ──────────────────────────────────────────────────────


def test_inproc_refuses_to_load_outside_a_test_run(
    workspace: Path, monkeypatch: pytest.MonkeyPatch, recorder: SandboxRecorder
) -> None:
    """A convenience that bypasses a security boundary will be reached for."""
    monkeypatch.delitem(sys.modules, "pytest", raising=False)
    monkeypatch.delenv("SLETCHY_ALLOW_INPROC", raising=False)

    with pytest.raises(BackendUnavailable, match="NO isolation"):
        InProcSandbox(workspace, profile(), recorder=recorder)


def test_inproc_is_not_available_outside_a_test_run(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delitem(sys.modules, "pytest", raising=False)
    monkeypatch.delenv("SLETCHY_ALLOW_INPROC", raising=False)
    assert not InProcSandbox.available()


# ── honest reporting of what is NOT delivered ────────────────────────────────


@pytest.mark.law_zero
@pytest.mark.parametrize("cls", ALL_BACKENDS)
def test_a_sandbox_writes_nothing_outside_its_workspace(
    cls: type[Sandbox], workspace: Path, recorder: SandboxRecorder
) -> None:
    """The sandbox machinery itself must not litter the host.

    Two permitted destinations, and nothing else: the workspace, and the ledger and
    payload store under `SLETCHY_HOME` - which are not litter but the audit record
    LAW 1 requires. Both are named explicitly rather than allowing all of
    `SLETCHY_HOME`, because `var/run/` holds the capture file and the undo journal
    and those **must** be gone by the time a run returns.
    """
    permitted = (workspace, ledger_dir(), payload_dir())

    before = {p for p in workspace.parent.rglob("*") if p.is_file()}
    with make(cls, workspace, recorder) as sandbox:
        sandbox.run(probes.print_text("ok"))
    after = {p for p in workspace.parent.rglob("*") if p.is_file()}

    for path in after - before:
        assert any(root == path.parent or root in path.parents for root in permitted), (
            f"{cls.backend.value} left {path} outside its workspace and the ledger"
        )

    runtime = runtime_dir()
    leftover = [p for p in runtime.rglob("*") if p.is_file()] if runtime.is_dir() else []
    assert leftover == [], f"{cls.backend.value} left runtime residue: {leftover}"


@pytest.mark.parametrize("cls", ALL_BACKENDS)
def test_cleanup_is_idempotent(
    cls: type[Sandbox], workspace: Path, recorder: SandboxRecorder
) -> None:
    sandbox = make(cls, workspace, recorder)
    sandbox.cleanup()
    sandbox.cleanup()


@pytest.mark.parametrize("cls", ALL_BACKENDS)
def test_the_result_names_the_backend_that_produced_it(
    cls: type[Sandbox], workspace: Path, recorder: SandboxRecorder
) -> None:
    """So a ledger entry can record which rung actually ran the work."""
    result: LaunchResult = make(cls, workspace, recorder).run(probes.exit_with(0))
    assert result.backend is cls.backend


def test_every_probe_binary_resolves_to_an_absolute_path() -> None:
    """Guards every assertion above: if a probe cannot run, nothing is measured.

    Sandboxed children have no `PATH`, so an unresolved binary fails inside the
    sandbox and reads like confinement. Checking it here turns that into one
    legible failure instead of several misleading ones - which is exactly how this
    was found, four assertions at a time, on the POSIX CI lane.
    """
    binaries = [probes.SHELL]
    if not probes.WINDOWS:
        binaries += [probes.read_file("x")[2].split()[0], probes.hang()[2].split()[0]]

    for binary in binaries:
        assert Path(binary).is_absolute(), f"probe binary is not absolute: {binary}"
        assert Path(binary).is_file(), f"probe binary missing: {binary}"
