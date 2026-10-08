"""The `sletchy` command surface."""

from __future__ import annotations

from pathlib import Path

import pytest

from sletchy.cli import paths
from sletchy.cli.main import EXIT_CORRUPT, EXIT_FAILED, EXIT_OK, _new_name, build_parser, main
from sletchy.kernel.flags import FlagStore
from sletchy.kernel.ledger import InMemoryKeySource, Ledger


@pytest.fixture(autouse=True)
def _sandboxed_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(paths.ENV_HOME, str(tmp_path / "var"))


@pytest.fixture
def _key(monkeypatch: pytest.MonkeyPatch) -> None:
    """Point the CLI at a throwaway in-memory key, never the real keychain."""
    monkeypatch.setenv("SLETCHY_ALLOW_INMEMORY_KEY", "1")
    monkeypatch.setattr(
        "sletchy.cli.main.KeyringKeySource", lambda *a, **k: InMemoryKeySource(b"k" * 32)
    )


def seed(tmp_path: Path) -> FlagStore:
    ledger = Ledger.open(paths.ledger_dir(), InMemoryKeySource(b"k" * 32))
    return FlagStore.open(ledger, paths.flags_file())


# ── parser ───────────────────────────────────────────────────────────────────


def test_every_command_is_reachable() -> None:
    parser = build_parser()
    for argv in (
        ["init"],
        ["status"],
        ["ledger", "verify"],
        ["flags", "list"],
        ["flags", "set", "cli_verbose", "on"],
        ["stop"],
        ["stop", "--dry-run"],
    ):
        assert hasattr(parser.parse_args(argv), "func"), argv


def test_the_old_name_still_works_and_is_listed_nowhere(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """`panic` became `stop`. Old notes keep working; no help line shows the old word."""
    assert _new_name(["panic", "--dry-run"]) == ["stop", "--dry-run"]
    assert _new_name(["status"]) == ["status"]
    assert _new_name(["flags", "set", "panic"]) == ["flags", "set", "panic"], "only the command"
    with pytest.raises(SystemExit):
        build_parser().parse_args(["--help"])
    listed = capsys.readouterr().out
    assert "stop" in listed
    assert "panic" not in listed


def test_a_bare_invocation_is_an_error() -> None:
    """No default command - `sletchy` alone must not do something."""
    with pytest.raises(SystemExit):
        build_parser().parse_args([])


def test_flags_set_rejects_a_value_that_is_not_on_or_off() -> None:
    with pytest.raises(SystemExit):
        build_parser().parse_args(["flags", "set", "cli_verbose", "maybe"])


@pytest.mark.usefixtures("_key")
@pytest.mark.parametrize("tail", ["-1", "0", "-500", "abc", "1.5", ""])
def test_ledger_show_refuses_a_tail_that_is_not_a_positive_number(tail: str) -> None:
    """`--tail -1` crashed with a ValueError; `--tail 0` said "no entries match" (#96)."""
    with pytest.raises(SystemExit) as refused:
        main(["ledger", "show", "--tail", tail])
    assert refused.value.code == 2
    assert not paths.ledger_dir().exists(), "the ledger was opened before --tail was checked"


@pytest.mark.usefixtures("_key")
def test_ledger_show_takes_a_positive_tail(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The control for the refusals above."""
    seed(tmp_path).set("cli_verbose", True)
    assert main(["ledger", "show", "--tail", "1"]) == EXIT_OK
    assert "cli_verbose -> on" in capsys.readouterr().out


# ── status and verify ────────────────────────────────────────────────────────


@pytest.mark.usefixtures("_key")
def test_status_reports_a_verified_chain(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    seed(tmp_path)
    assert main(["status"]) == EXIT_OK

    out = capsys.readouterr().out
    assert "chain verified" in out
    assert "no dangerous flags enabled" in out


@pytest.mark.usefixtures("_key")
def test_status_names_any_dangerous_flag_that_is_on(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    seed(tmp_path).set("egress_enabled", True, reason="testing")
    main(["status"])
    assert "DANGEROUS ON: egress_enabled" in capsys.readouterr().out


@pytest.mark.usefixtures("_key")
def test_verify_reports_the_entry_count(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    seed(tmp_path).set("cli_verbose", True)
    assert main(["ledger", "verify"]) == EXIT_OK
    assert "chain verified: 1 entries" in capsys.readouterr().out


@pytest.mark.usefixtures("_key")
def test_verify_exits_two_on_a_corrupt_chain(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A distinct exit code, so a script can tell corruption from a plain failure."""
    seed(tmp_path).set("cli_verbose", True)
    segment = paths.ledger_dir() / "segment-00000.ndjson"
    segment.write_text(segment.read_text(encoding="utf-8").replace("cli_verbose", "x"), "utf-8")

    assert main(["ledger", "verify"]) == EXIT_CORRUPT
    err = capsys.readouterr().err
    assert "LEDGER CORRUPT" in err
    assert "does not repair" in err


@pytest.mark.usefixtures("_key")
def test_status_exits_two_on_a_corrupt_chain(tmp_path: Path) -> None:
    """`status` must not print a reassuring summary over a broken chain."""
    seed(tmp_path).set("cli_verbose", True)
    segment = paths.ledger_dir() / "segment-00000.ndjson"
    segment.write_text(segment.read_text(encoding="utf-8").replace("cli_verbose", "x"), "utf-8")

    assert main(["status"]) == EXIT_CORRUPT


# ── flags ────────────────────────────────────────────────────────────────────


@pytest.mark.usefixtures("_key")
def test_flags_list_marks_dangerous_ones(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    seed(tmp_path)
    assert main(["flags", "list"]) == EXIT_OK

    out = capsys.readouterr().out
    assert "! off  egress_enabled" in out
    assert "  ON   cli_colour" in out


@pytest.mark.usefixtures("_key")
def test_flags_set_requires_a_reason_for_a_dangerous_flag(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    seed(tmp_path)
    assert main(["flags", "set", "egress_enabled", "on"]) == EXIT_FAILED

    err = capsys.readouterr().err
    assert "DANGEROUS" in err
    assert "--reason" in err


@pytest.mark.usefixtures("_key")
def test_flags_set_works_with_a_reason(tmp_path: Path) -> None:
    seed(tmp_path)
    assert main(["flags", "set", "egress_enabled", "on", "--reason", "hosted model"]) == EXIT_OK
    assert seed(tmp_path).is_on("egress_enabled")


@pytest.mark.usefixtures("_key")
def test_an_unknown_flag_exits_non_zero(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    seed(tmp_path)
    assert main(["flags", "set", "egres_enabled", "on", "--reason", "typo"]) == EXIT_FAILED
    assert "unknown flag" in capsys.readouterr().err


# ── init ─────────────────────────────────────────────────────────────────────


def test_init_reports_the_fresh_install_posture(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The first thing a new user sees should say what is off."""
    monkeypatch.setenv("SLETCHY_ALLOW_INMEMORY_KEY", "1")

    class FakeSource(InMemoryKeySource):
        def provision(self, *, overwrite: bool = False) -> None:
            return

    monkeypatch.setattr("sletchy.cli.main.KeyringKeySource", lambda *a, **k: FakeSource(b"k" * 32))

    assert main(["init"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "every dangerous flag is off" in out
    assert paths.ledger_dir().is_dir()
    assert paths.payload_dir().is_dir()


# ── LAW 0 ────────────────────────────────────────────────────────────────────


@pytest.mark.law_zero
@pytest.mark.usefixtures("_key")
def test_the_cli_writes_nothing_outside_sletchy_home(tmp_path: Path) -> None:
    seed(tmp_path).set("cli_verbose", True)
    main(["status"])
    main(["flags", "list"])
    main(["ledger", "verify"])

    home = paths.home()
    for path in tmp_path.rglob("*"):
        if path.is_file():
            assert home in path.parents, f"{path} was written outside SLETCHY_HOME"


@pytest.mark.law_zero
def test_home_is_overridable_so_nothing_assumes_a_fixed_location(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(paths.ENV_HOME, str(tmp_path / "elsewhere"))
    assert paths.home() == tmp_path / "elsewhere"
    assert paths.ledger_dir().parent == tmp_path / "elsewhere"
    assert paths.payload_dir().parent == tmp_path / "elsewhere"
    assert paths.runtime_dir().parent == tmp_path / "elsewhere"


@pytest.mark.law_zero
def test_every_path_lives_under_home(tmp_path: Path) -> None:
    """LAW 0 §2: one directory, so uninstall is one delete."""
    home = paths.home()
    for path in (
        paths.ledger_dir(),
        paths.payload_dir(),
        paths.flags_file(),
        paths.runtime_dir(),
    ):
        assert home in path.parents
