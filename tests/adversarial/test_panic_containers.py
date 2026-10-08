"""`sletchy panic` and the containers a hard kill left behind (#70).

A `container` run journals its container before starting it and removes it in a
`finally`. When the process dies between the two, panic removes it. The runtime is a
fake that records what it was asked; nothing here starts or removes a real container.
A record names a container panic will remove, so it is held to exactly what the
backend writes, as #94 holds a sandbox record.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from sletchy.cli import panic as panic_mod
from sletchy.cli.panic import revert_host_changes
from sletchy.kernel.hostchanges import HostChange, pending, record
from sletchy.kernel.paths import ENV_HOME

pytestmark = [pytest.mark.adversarial, pytest.mark.law_zero]


@dataclass
class Runtime:
    exit_code: int = 0
    removed: list[str] = field(default_factory=list)

    def run(self, argv: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        line = [str(a) for a in argv]
        if Path(line[0]).name != "podman" or line[1:4] != ["rm", "--force", "--ignore"]:
            raise AssertionError(f"panic ran something no test expected: {line}")
        self.removed.append(line[4])
        return subprocess.CompletedProcess(
            line, self.exit_code, "", "boom" if self.exit_code else ""
        )


@pytest.fixture(autouse=True)
def runtime(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Runtime:
    monkeypatch.setenv(ENV_HOME, str(tmp_path / "var"))
    fake = Runtime()
    monkeypatch.setattr(shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(subprocess, "run", fake.run)
    # Nothing here reaches panic's firewall step; stubbed so nothing ever could.
    monkeypatch.setattr(panic_mod, "remove_firewall_rules", lambda *, dry_run=False: (0, 0, None))
    return fake


def container(context_id: str, **kw: object) -> HostChange:
    return HostChange.model_validate(
        {"context_id": context_id, "kind": "container", "profile": f"sletchy-{context_id}", **kw}
    )


def test_a_container_a_dead_run_left_is_removed_and_forgotten(runtime: Runtime) -> None:
    record(container("cdead0001"))

    assert revert_host_changes() == (1, ())
    assert runtime.removed == ["sletchy-cdead0001"]
    assert pending() == ()


def test_a_container_that_will_not_go_is_kept_and_named(runtime: Runtime) -> None:
    runtime.exit_code = 1
    record(container("cstuck001"))

    reverted, errors = revert_host_changes()

    assert reverted == 0
    assert "cstuck001" in errors[0]
    assert len(pending()) == 1


def test_no_runtime_means_could_not_look_never_nothing_there(
    runtime: Runtime, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(shutil, "which", lambda name: None)
    record(container("cnolook01"))

    reverted, errors = revert_host_changes()

    assert reverted == 0
    assert "could not be checked" in errors[0]
    assert len(pending()) == 1


@pytest.mark.parametrize(
    "forged",
    [
        {"profile": "someone-elses-container"},
        {"profile": "sletchy-cother0001"},
        {"sid": "S-1-15-2-1"},
        {"granted_paths": ("/home",)},
    ],
)
def test_a_container_record_the_backend_could_not_have_written_is_refused(
    runtime: Runtime, forged: dict[str, object]
) -> None:
    record(container("cforged01", **forged))

    reverted, errors = revert_host_changes()

    assert reverted == 0
    assert runtime.removed == [], "panic removed a container it does not own"
    assert "refused" in errors[0]
    assert len(pending()) == 1


def test_a_plan_counts_the_container_and_touches_nothing(runtime: Runtime) -> None:
    record(container("cplan0001"))

    assert revert_host_changes(dry_run=True) == (1, ())
    assert runtime.removed == []
    assert len(pending()) == 1


def test_panic_and_the_warden_agree_on_the_container_name() -> None:
    """Two copies of one prefix, because `cli` may not import `warden`. This keeps them one."""
    from sletchy.warden.isolation import container as container_mod

    assert panic_mod.CONTAINER_PREFIX == container_mod.NAME_PREFIX
    assert panic_mod.CONTAINER_RUNTIME == container_mod.RUNTIME
