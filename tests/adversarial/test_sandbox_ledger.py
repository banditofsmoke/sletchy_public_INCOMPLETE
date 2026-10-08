"""LAW 1 for the Warden - no launch path escapes the ledger.

The isolation backends were LAW 1's one exception until now: they created
containers, applied limits, granted ACLs and killed process trees, and none of it
reached the chain. This file is what stops that being true again.

The question is not "does it log" - logging is easy to add and easy to skip. The
question is **can any path act without logging**, so the assertions here are about
paths and ordering rather than about the presence of an entry.
"""

from __future__ import annotations

import inspect
import json
from pathlib import Path
from typing import Any

import pytest

from sletchy.kernel.contracts import Decision, IsolationBackend, IsolationProfile, Plane
from sletchy.kernel.ledger import InMemoryKeySource, Ledger, PayloadStore
from sletchy.kernel.paths import ENV_HOME, ledger_dir, payload_dir
from sletchy.warden.isolation import (
    BACKENDS,
    InProcSandbox,
    LaunchRefused,
    Sandbox,
    SandboxRecorder,
    SubprocSandbox,
    WinJobSandbox,
)
from sletchy.warden.isolation.recorder import (
    COMPLETE_ACTION,
    KILLED_ACTION,
    LAUNCH_ACTION,
    REFUSED_ACTION,
)
from tests.adversarial import probes

pytestmark = pytest.mark.adversarial

ALL_BACKENDS = [pytest.param(cls, id=cls.backend.value) for cls in BACKENDS.values()]


@pytest.fixture(autouse=True)
def _sandboxed_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ENV_HOME, str(tmp_path / "sletchy-home"))


@pytest.fixture
def ledger(_sandboxed_home: None) -> Ledger:
    return Ledger.open(ledger_dir(), InMemoryKeySource(b"k" * 32))


@pytest.fixture
def recorder(ledger: Ledger) -> SandboxRecorder:
    return SandboxRecorder(
        ledger=ledger, actor_id="test_actor", payloads=PayloadStore.open(payload_dir())
    )


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    ws = tmp_path / "workspace"
    ws.mkdir()
    return ws


def profile(**kw: object) -> IsolationProfile:
    return IsolationProfile.model_validate({"backend": IsolationBackend.SUBPROC, **kw})


def make(cls: type[Sandbox], workspace: Path, recorder: SandboxRecorder, **kw: object) -> Sandbox:
    if not cls.available():
        pytest.skip(f"{cls.backend.value} is not available on this host")
    return cls(workspace, profile(**kw), recorder=recorder)


def actions(ledger: Ledger) -> list[str]:
    return [e.action for e in ledger.entries()]


# ── the structural half: a sandbox cannot exist without a ledger ─────────────


@pytest.mark.parametrize("cls", ALL_BACKENDS)
def test_a_backend_cannot_be_constructed_without_a_recorder(
    cls: type[Sandbox], workspace: Path
) -> None:
    """The control that makes every other assertion here redundant if it holds.

    A recorder with a default would be a launch path that skips the ledger, and it
    would be reached - every "just for this one case" bypass eventually ships.
    """
    with pytest.raises(TypeError):
        cls(workspace, profile())  # type: ignore[call-arg]


def test_the_recorder_is_a_required_keyword_on_the_interface() -> None:
    """Asserted on the signature, so a default cannot be added quietly."""
    parameter = inspect.signature(Sandbox.__init__).parameters["recorder"]
    assert parameter.default is inspect.Parameter.empty, (
        "recorder gained a default; that is a launch path that can skip the ledger"
    )
    assert parameter.kind is inspect.Parameter.KEYWORD_ONLY


def test_the_recorder_cannot_be_repointed_after_construction(
    workspace: Path, recorder: SandboxRecorder
) -> None:
    """Frozen, so one half of an execution cannot be recorded somewhere else."""
    with pytest.raises((AttributeError, TypeError)):
        recorder.actor_id = "someone_else"  # type: ignore[misc]


# ── the behavioural half: every path actually records ───────────────────────


@pytest.mark.parametrize("cls", ALL_BACKENDS)
def test_a_successful_run_records_a_launch_and_a_completion(
    cls: type[Sandbox], workspace: Path, recorder: SandboxRecorder, ledger: Ledger
) -> None:
    make(cls, workspace, recorder).run(probes.exit_with(0))

    assert actions(ledger) == [LAUNCH_ACTION, COMPLETE_ACTION]


@pytest.mark.parametrize("cls", ALL_BACKENDS)
def test_a_failing_program_is_recorded_as_complete_not_killed(
    cls: type[Sandbox], workspace: Path, recorder: SandboxRecorder, ledger: Ledger
) -> None:
    """A non-zero exit is the program's failure, not the sandbox intervening."""
    make(cls, workspace, recorder).run(probes.exit_with(3))

    recorded = actions(ledger)
    assert recorded == [LAUNCH_ACTION, COMPLETE_ACTION]
    assert KILLED_ACTION not in recorded
    assert "exited 3" in list(ledger.entries())[-1].verdict.reason


@pytest.mark.parametrize("cls", ALL_BACKENDS)
def test_a_run_we_stopped_is_recorded_as_killed(
    cls: type[Sandbox], workspace: Path, recorder: SandboxRecorder, ledger: Ledger
) -> None:
    """The distinction the issue asked for: stopped-by-us is not exited-non-zero."""
    make(cls, workspace, recorder, resources={"wall_clock_seconds": 1}).run(
        probes.hang(), timeout=1
    )

    assert actions(ledger) == [LAUNCH_ACTION, KILLED_ACTION]


@pytest.mark.parametrize("cls", ALL_BACKENDS)
def test_an_empty_command_is_refused_and_recorded(
    cls: type[Sandbox], workspace: Path, recorder: SandboxRecorder, ledger: Ledger
) -> None:
    """A refusal is the entry that matters most, and it must not be the silent one."""
    with pytest.raises(LaunchRefused):
        make(cls, workspace, recorder).run([])

    entries = list(ledger.entries())
    assert [e.action for e in entries] == [REFUSED_ACTION]
    assert entries[0].verdict.decision is Decision.DENY
    assert LAUNCH_ACTION not in actions(ledger), "a refused command still recorded a launch"


@pytest.mark.parametrize("cls", ALL_BACKENDS)
def test_every_entry_names_the_warden_and_the_actor(
    cls: type[Sandbox], workspace: Path, recorder: SandboxRecorder, ledger: Ledger
) -> None:
    make(cls, workspace, recorder).run(probes.exit_with(0))

    for entry in ledger.entries():
        assert entry.plane is Plane.WARDEN
        assert entry.actor_id == "test_actor"


# ── ordering: the record precedes the action ────────────────────────────────


@pytest.mark.law_zero
def test_the_launch_entry_is_durable_before_the_process_starts(
    workspace: Path, recorder: SandboxRecorder, ledger: Ledger, monkeypatch: pytest.MonkeyPatch
) -> None:
    """LAW 1's actual requirement, asserted as an ordering.

    Reads the ledger **from disk** at the moment the process would be created. An
    entry that exists only in memory at that point is not a record - a crash during
    the launch would take it with it.
    """
    import subprocess

    seen: list[list[str]] = []
    real_run = subprocess.run

    def spy(*args: Any, **kwargs: Any) -> Any:
        # Re-open the ledger from disk. Nothing held in memory counts as a record,
        # and reading through the live object would not tell them apart.
        on_disk = Ledger.open(ledger_dir(), InMemoryKeySource(b"k" * 32))
        seen.append([e.action for e in on_disk.entries()])
        return real_run(*args, **kwargs)

    # String target: monkeypatch does not type-check the replacement against
    # `subprocess.run`'s overload set, which a spy cannot satisfy.
    monkeypatch.setattr("sletchy.warden.isolation.subproc.subprocess.run", spy)
    SubprocSandbox(workspace, profile(), recorder=recorder).run(probes.exit_with(0))

    assert seen, "the process was never started, so the ordering was not observed"
    assert seen[0] == [LAUNCH_ACTION], (
        f"at CreateProcess time the durable ledger held {seen[0]}, not a launch entry"
    )


@pytest.mark.law_zero
@pytest.mark.skipif(not WinJobSandbox.available(), reason="winjob requires Windows")
def test_winjob_records_before_it_spawns(
    workspace: Path, recorder: SandboxRecorder, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Same rule, on the backend that actually contains something."""
    from sletchy.warden.isolation import _win32

    order: list[str] = []
    real_spawn = _win32.spawn
    real_append = type(recorder.ledger).append

    def watched_append(self: Ledger, **kwargs: object) -> object:
        order.append(f"ledger:{kwargs['action']}")
        return real_append(self, **kwargs)  # type: ignore[arg-type]

    def watched_spawn(*args: object, **kwargs: object) -> object:
        order.append("spawn")
        return real_spawn(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(type(recorder.ledger), "append", watched_append)
    monkeypatch.setattr(_win32, "spawn", watched_spawn)

    WinJobSandbox(workspace, profile(), recorder=recorder).run(probes.exit_with(0))

    assert order[0] == f"ledger:{LAUNCH_ACTION}", (
        f"spawn was not preceded by a launch entry: {order}"
    )
    assert order[1] == "spawn"


# ── the payload carries what the entry cannot ───────────────────────────────


def test_the_full_command_is_stored_in_the_payload_not_the_entry(
    workspace: Path, recorder: SandboxRecorder, ledger: Ledger
) -> None:
    """The subject stays short so a chain is readable; argv goes to the store.

    This is also what keeps the chain small - the design reason payloads are
    content-addressed into a side store in the first place.
    """
    command = probes.exit_with(0)
    SubprocSandbox(workspace, profile(), recorder=recorder).run(command)

    launch = next(e for e in ledger.entries() if e.action == LAUNCH_ACTION)
    assert launch.payload_hash is not None
    assert launch.subject.identifier == command[0]

    assert recorder.payloads is not None
    body = json.loads(recorder.payloads.get(launch.payload_hash))
    assert body["command"] == command


def test_a_recorder_without_a_payload_store_still_records(workspace: Path, ledger: Ledger) -> None:
    """The payload store is an optimisation; the entry is the control.

    A missing store must not become a missing record - that would make the audit
    trail depend on a component that is allowed to be absent.
    """
    recorder = SandboxRecorder(ledger=ledger, actor_id="no_payloads")
    SubprocSandbox(workspace, profile(), recorder=recorder).run(probes.exit_with(0))

    entries = list(ledger.entries())
    assert [e.action for e in entries] == [LAUNCH_ACTION, COMPLETE_ACTION]
    assert all(e.payload_hash is None for e in entries)


def test_the_chain_still_verifies_after_a_run(
    workspace: Path, recorder: SandboxRecorder, ledger: Ledger
) -> None:
    """Sandbox entries are ordinary entries. Nothing about them is special-cased."""
    SubprocSandbox(workspace, profile(), recorder=recorder).run(probes.exit_with(0))

    reopened = Ledger.open(ledger_dir(), InMemoryKeySource(b"k" * 32))
    assert reopened.verify() == 2


def test_inproc_records_too_despite_confining_nothing(
    workspace: Path, recorder: SandboxRecorder, ledger: Ledger
) -> None:
    """LAW 1 is not conditional on the isolation being any good.

    `inproc` is the weakest thing here and the most likely to be treated as "not
    worth recording". It is recorded.
    """
    InProcSandbox(workspace, profile(), recorder=recorder).run(probes.exit_with(0))

    assert actions(ledger) == [LAUNCH_ACTION, COMPLETE_ACTION]
