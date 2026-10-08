"""The host shield: LAW 0 around every test run, not just inside the tests that remember it.

The suite runs on the operator's only computer. Before this file, a test that forgot
to redirect `SLETCHY_HOME` would write to the real `var/` beside the repo, and a
test that forgot to stub panic's firewall step would really try it. Each test file
guarded itself, and nothing guarded the gap between them.

For the whole session, before the first test is even collected:

- **an elevated run is refused** on a developer machine. A test bug run as an
  administrator can do far more harm, and the suite's privilege claims mean nothing
  there anyway. GitHub's Windows runner is always elevated, so CI is exempt, exactly
  as `test_the_test_suite_itself_is_not_running_elevated` already is
- **`SLETCHY_HOME` defaults to a throwaway folder**, so a test that sets nothing
  writes nothing real. Tests that set their own still win
- **the real keychain is unreachable**: `keyring` gets its failing backend, here and
  in every child process through `PYTHON_KEYRING_BACKEND`
- **`tests/hostshield.py` refuses**, before anything starts or is sent: a command
  that changes the host, `icacls` outside the temp folders, a connection or DNS
  lookup off this machine, and a window or browser opening. A refusal no test
  expected fails the run, even if the code under test caught it
- **every Python a test starts is shielded too**: `shield_site/` goes first on
  `PYTHONPATH`, and its `sitecustomize` installs the shield in the child. The child's
  refusals are written to the session folder and fail the run the same way (L016)
- **panic's firewall step answers as a host with no Sletchy rules**, in every test.
  The operator's real rules are never counted for removal, let alone removed (L016)
- **the real `var/` is checked at the end**: if anything in it changed during the
  run, the run fails and says so

Proven by `tests/adversarial/test_host_shield.py`.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

import pytest

from tests.hostshield import (
    CHILD_LOG_ENV,
    CHILD_LOG_NAME,
    CHILD_SITE,
    Shield,
    Snapshot,
    default_writable_roots,
    elevation_refusal,
    session_problems,
    snapshot,
)


@dataclass
class _Session:
    shield: Shield
    home: Path
    real_var: Path
    before: Snapshot


_STATE: list[_Session] = []


def _running_elevated() -> bool:
    if sys.platform == "win32":
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    return hasattr(os, "geteuid") and os.geteuid() == 0


def pytest_configure(config: pytest.Config) -> None:
    why = elevation_refusal(elevated=_running_elevated(), ci=bool(os.environ.get("CI")))
    if why:
        pytest.exit(why, returncode=3)

    home = Path(tempfile.mkdtemp(prefix="sletchy-test-home-"))
    os.environ["SLETCHY_HOME"] = str(home)
    os.environ["PYTHON_KEYRING_BACKEND"] = "keyring.backends.fail.Keyring"

    import keyring
    from keyring.backends import fail

    keyring.set_keyring(fail.Keyring())  # type: ignore[no-untyped-call]

    os.environ[CHILD_LOG_ENV] = str(home / CHILD_LOG_NAME)
    os.environ["PYTHONPATH"] = os.pathsep.join(
        p for p in (str(CHILD_SITE), os.environ.get("PYTHONPATH", "")) if p
    )

    real_var = Path(config.rootpath) / "var"
    shield = Shield(writable_roots=default_writable_roots(home))
    shield.install()
    _STATE.append(_Session(shield=shield, home=home, real_var=real_var, before=snapshot(real_var)))


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    if not _STATE:
        return
    state = _STATE.pop()
    state.shield.uninstall()
    problems = session_problems(
        state.shield, state.real_var, state.before, state.home / CHILD_LOG_NAME
    )
    if problems:
        session.exitstatus = pytest.ExitCode.TESTS_FAILED
        for problem in problems:
            print(f"\nHOST SHIELD: {problem}")
    shutil.rmtree(state.home, ignore_errors=True)


@pytest.fixture(autouse=True)
def _no_real_firewall_removal(monkeypatch: pytest.MonkeyPatch) -> None:
    """LAW 0 §6: no test's panic reaches for this PC's firewall rules (L016).

    Panic removes the `Sletchy` group's rules when it counts any. While the host had
    none, a test that forgot to stub that step was safe by luck. Once the operator
    installed them (#33), two such tests reached for them. The read-only count stays
    real, for its positive control. A test of the removal itself sets its own fake,
    or calls the function it imported.
    """
    monkeypatch.setattr(
        "sletchy.cli.panic.remove_firewall_rules", lambda *, dry_run=False: (0, 0, None)
    )


def _tests_never_read_the_firewall() -> list[str]:
    raise OSError("tests never read this machine's firewall rules")


@pytest.fixture(autouse=True)
def _no_real_firewall_read(monkeypatch: pytest.MonkeyPatch) -> None:
    """The self-check reads the real `Sletchy` rules (#33); no test does.

    Read-only, but what it reads is this machine, so a test would pass or fail by what
    is installed here. A test of the reading itself passes its own fake, or calls the
    function it imported.
    """
    monkeypatch.setattr("sletchy.cli.selfcheck._read_firewall", _tests_never_read_the_firewall)


@pytest.fixture
def host_shield() -> Shield:
    """The session's shield, for the tests that prove it bites."""
    assert _STATE, "the host shield is not installed"
    return _STATE[-1].shield


@pytest.fixture
def session_home() -> Path:
    assert _STATE, "the host shield is not installed"
    return _STATE[-1].home
