"""`sletchy panic` - LAW 0 §2 made executable.

A panic button that has never been pressed is a rumour, so these tests press it:
from a clean state, from a dirty state, twice in a row, and from a state where the
ledger itself is broken.

Nothing here touches the real host. `SLETCHY_HOME` is redirected to `tmp_path`, and
the firewall step is stubbed - LAW 0 §6 forbids tests that reconfigure the host's
real firewall.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from sletchy.cli import paths
from sletchy.cli.main import main
from sletchy.cli.panic import PanicReport, clear_runtime, panic
from sletchy.kernel.flags import RESET_ACTION, WRITE_FAILED_ACTION, FlagStore
from sletchy.kernel.ledger import InMemoryKeySource, Ledger

pytestmark = [pytest.mark.adversarial, pytest.mark.law_zero]


@pytest.fixture(autouse=True)
def _sandboxed_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Every test runs against a throwaway home, never the operator's."""
    monkeypatch.setenv(paths.ENV_HOME, str(tmp_path / "var"))


@pytest.fixture(autouse=True)
def _no_real_firewall(monkeypatch: pytest.MonkeyPatch) -> None:
    """LAW 0 §6: never touch the host's real firewall from a test."""
    monkeypatch.setattr(
        "sletchy.cli.panic.remove_firewall_rules",
        lambda *, dry_run=False: (0, 0, None),
    )


def flags(tmp_path: Path) -> FlagStore:
    ledger = Ledger.open(paths.ledger_dir(), InMemoryKeySource(b"k" * 32))
    return FlagStore.open(ledger, paths.flags_file())


# ── it reverts ───────────────────────────────────────────────────────────────


def test_panic_resets_every_flag(tmp_path: Path) -> None:
    store = flags(tmp_path)
    store.set("egress_enabled", True, reason="a")
    store.set("senses_microphone", True, reason="b")

    report = panic(store)

    assert report.flags_reset == 2
    assert store.snapshot() == store.registry.defaults()
    assert not any(store.is_on(f.name) for f in store.registry.dangerous())


def test_panic_clears_runtime_files(tmp_path: Path) -> None:
    run = paths.runtime_dir()
    run.mkdir(parents=True)
    (run / "daemon.pid").write_text("1234", encoding="utf-8")
    (run / "agent.lock").write_text("", encoding="utf-8")

    assert panic(flags(tmp_path)).runtime_files_cleared == 2
    assert list(run.iterdir()) == []


def test_panic_is_idempotent(tmp_path: Path) -> None:
    """Running it twice is harmless, and the second run says so."""
    store = flags(tmp_path)
    store.set("egress_enabled", True, reason="a")

    first = panic(store)
    second = panic(store)

    assert first.flags_reset == 1
    assert second.flags_reset == 0
    assert second.clean


def test_panic_on_a_clean_state_reports_zero(tmp_path: Path) -> None:
    """Honest reporting: it must not claim a reset that was a no-op."""
    report = panic(flags(tmp_path))
    assert report.flags_reset == 0
    assert report.runtime_files_cleared == 0
    assert report.clean


# ── it is not destructive ────────────────────────────────────────────────────


def test_panic_does_not_delete_the_ledger(tmp_path: Path) -> None:
    """The ledger is evidence. An emergency stop that destroys it is worse
    than the emergency."""
    store = flags(tmp_path)
    store.set("egress_enabled", True, reason="a")
    before = sorted(p.name for p in paths.ledger_dir().iterdir())

    panic(store)

    assert sorted(p.name for p in paths.ledger_dir().iterdir()) == before
    assert Ledger.open(paths.ledger_dir(), InMemoryKeySource(b"k" * 32)).verify() > 0


def test_panic_does_not_delete_payloads(tmp_path: Path) -> None:
    from sletchy.kernel.ledger import PayloadStore

    payloads = PayloadStore.open(paths.payload_dir())
    digest = payloads.put(b"evidence")

    panic(flags(tmp_path))

    assert payloads.has(digest)


def test_panic_only_clears_the_runtime_directory(tmp_path: Path) -> None:
    """It must not wander outside var/run/."""
    run = paths.runtime_dir()
    run.mkdir(parents=True)
    (run / "daemon.pid").write_text("1", encoding="utf-8")
    keep = paths.home() / "keep-me.txt"
    keep.write_text("not runtime state", encoding="utf-8")

    panic(flags(tmp_path))

    assert keep.exists()
    assert not (run / "daemon.pid").exists()


def test_clear_runtime_on_a_missing_directory_is_not_an_error() -> None:
    assert clear_runtime() == 0


# ── it works when things are broken ──────────────────────────────────────────


def test_panic_works_with_no_flag_store_at_all(tmp_path: Path) -> None:
    """The wedged case: the ledger is unreadable, so there is no store to pass.

    Panic must still remove firewall rules and clear runtime files, because a
    broken ledger is precisely when stopping matters most.
    """
    run = paths.runtime_dir()
    run.mkdir(parents=True)
    (run / "daemon.pid").write_text("1", encoding="utf-8")

    report = panic(None)

    assert report.clean
    assert report.runtime_files_cleared == 1
    assert report.flags_reset == 0


def test_panic_survives_a_corrupt_ledger_via_the_cli(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """End to end, from a genuinely broken state."""
    store = flags(tmp_path)
    store.set("egress_enabled", True, reason="a")

    segment = paths.ledger_dir() / "segment-00000.ndjson"
    rows = segment.read_text(encoding="utf-8").splitlines()
    rows[0] = rows[0].replace("egress_enabled", "tampered_flag")
    segment.write_text("\n".join(rows) + "\n", encoding="utf-8")

    code = main(["stop"])

    assert code == 0
    out = capsys.readouterr()
    assert "STOP EVERYTHING" in out.out
    assert "ledger unavailable" in out.err


def test_one_failing_step_does_not_stop_the_others(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A firewall that will not answer must not prevent flags being reset."""
    monkeypatch.setattr(
        "sletchy.cli.panic.remove_firewall_rules",
        lambda *, dry_run=False: (0, 0, "netsh refused"),
    )
    store = flags(tmp_path)
    store.set("egress_enabled", True, reason="a")

    report = panic(store)

    assert report.flags_reset == 1
    assert not report.clean
    assert "netsh refused" in report.errors[0]


# ── it never prompts, and dry-run changes nothing ────────────────────────────


def test_panic_takes_no_confirmation_argument() -> None:
    """A prompt is a failure mode in the command you run when things are wrong."""
    import inspect

    params = set(inspect.signature(panic).parameters)
    assert params == {"flags", "reason", "dry_run"}
    for forbidden in ("confirm", "yes", "force", "interactive"):
        assert forbidden not in params


def test_dry_run_changes_nothing(tmp_path: Path) -> None:
    store = flags(tmp_path)
    store.set("egress_enabled", True, reason="a")
    run = paths.runtime_dir()
    run.mkdir(parents=True)
    (run / "daemon.pid").write_text("1", encoding="utf-8")

    report = panic(store, dry_run=True)

    assert report.flags_reset == 0
    assert store.is_on("egress_enabled")
    assert (run / "daemon.pid").exists()
    assert report.runtime_files_cleared == 1  # reports what it would clear


# ── the reset is recorded ────────────────────────────────────────────────────


def test_panic_writes_a_final_ledger_entry(tmp_path: Path) -> None:
    store = flags(tmp_path)
    store.set("egress_enabled", True, reason="a")

    report = panic(store, reason="host misbehaving")

    assert report.ledger_sealed
    ledger = Ledger.open(paths.ledger_dir(), InMemoryKeySource(b"k" * 32))
    entry = next(e for e in ledger.entries() if e.action == "kernel.flag.reset")
    assert "host misbehaving" in entry.verdict.reason
    assert ledger.verify() > 0


def test_the_report_renders_without_claiming_more_than_it_did(tmp_path: Path) -> None:
    rendered = PanicReport().render()
    assert "flags reset            0" in rendered
    assert "not written" in rendered


def test_panic_survives_a_host_with_no_keychain_backend(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Regression: CI caught this on a headless runner.

    `keyring` raises its own `NoKeyringError` when no backend exists. That escaped
    our error hierarchy, so `sletchy panic` crashed on exactly the kind of broken
    host it exists for. `KeyringKeySource.get()` now translates any backend failure
    into `SigningKeyBackendUnavailable`, and `cmd_panic` catches broadly.
    """
    import keyring

    def explode(service: str, name: str) -> str | None:
        msg = "No recommended backend was available"
        raise keyring.errors.NoKeyringError(msg)

    monkeypatch.setattr(keyring, "get_password", explode)

    assert main(["stop"]) == 0
    assert "ledger unavailable" in capsys.readouterr().err


def test_a_missing_keychain_backend_raises_our_error_type(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Callers must never have to know about keyring's exception hierarchy."""
    import keyring

    from sletchy.kernel.ledger import SigningKeyBackendUnavailable, SigningKeyMissing
    from sletchy.kernel.ledger.keys import KeyringKeySource

    def explode(service: str, name: str) -> str | None:
        msg = "No recommended backend was available"
        raise keyring.errors.NoKeyringError(msg)

    monkeypatch.setattr(keyring, "get_password", explode)

    with pytest.raises(SigningKeyBackendUnavailable) as exc:
        KeyringKeySource().get()

    # A subclass, so everything that fails closed on a missing key also fails
    # closed on an unreachable one.
    assert isinstance(exc.value, SigningKeyMissing)


def test_panic_reports_what_the_ledger_holds_when_the_flag_file_cannot_be_written(
    tmp_path: Path,
) -> None:
    """The reset entry is written, the file is not: the report must say both (#104).

    Before, panic said "final ledger entry not written" over an entry that had been.
    """
    store = flags(tmp_path)
    store.set("senses_camera", True, reason="video call")
    paths.flags_file().unlink()
    paths.flags_file().mkdir()

    report = panic(store)

    assert not report.clean
    assert report.ledger_sealed, "the reset entry is in the ledger, so the report must say so"
    assert report.flags_reset == 0
    assert any("no flag was reset" in e for e in report.errors)
    ledger = Ledger.open(paths.ledger_dir(), InMemoryKeySource(b"k" * 32))
    assert [e.action for e in ledger.entries()][-2:] == [RESET_ACTION, WRITE_FAILED_ACTION]
