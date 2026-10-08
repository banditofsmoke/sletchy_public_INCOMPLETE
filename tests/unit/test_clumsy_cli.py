"""The Clumsy story at the terminal: a damaged `var/` gets a sentence, not a traceback (#97).

Each test does to `var/` what a careless person does - leaves a file where a folder
goes, makes a file read-only, runs `init` over a broken record - and asserts that
`main()` answers with an exit code and one line saying what failed, and that no
exception escapes. Every one of these printed a Python traceback before #97.

The key is always in memory. Nothing here touches the real keychain.
"""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

import pytest

from sletchy.cli import main as cli_main
from sletchy.cli import paths
from sletchy.cli.main import EXIT_CORRUPT, EXIT_FAILED, EXIT_OK, main
from sletchy.kernel.flags import FlagStore
from sletchy.kernel.ledger import InMemoryKeySource, Ledger

KEY = b"k" * 32


class FakeKeychain(InMemoryKeySource):
    """`init`'s view of the keychain: provisioning once, then "already exists"."""

    provisioned: int = 0

    def provision(self, *, overwrite: bool = False) -> None:
        if FakeKeychain.provisioned and not overwrite:
            msg = "a ledger signing key already exists"
            raise ValueError(msg)
        FakeKeychain.provisioned += 1


@pytest.fixture(autouse=True)
def _home_and_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(paths.ENV_HOME, str(tmp_path / "var"))
    monkeypatch.setenv("SLETCHY_ALLOW_INMEMORY_KEY", "1")
    FakeKeychain.provisioned = 0
    monkeypatch.setattr(cli_main, "KeyringKeySource", lambda *a, **k: FakeKeychain(KEY))


def seed() -> FlagStore:
    ledger = Ledger.open(paths.ledger_dir(), InMemoryKeySource(KEY))
    store = FlagStore.open(ledger, paths.flags_file())
    store.set("senses_camera", True, reason="video call")
    return store


def segment() -> Path:
    return paths.ledger_dir() / "segment-00000.ndjson"


def one_line(err: str) -> str:
    lines = [ln for ln in err.splitlines() if ln.strip()]
    assert lines, "nothing was said"
    assert "Traceback" not in err
    return lines[-1]


# ── a file where the ledger folder goes ──────────────────────────────────────


@pytest.mark.parametrize(
    "argv",
    [
        ["status"],
        ["ledger", "verify"],
        ["ledger", "show"],
        ["flags", "list"],
        ["flags", "set", "senses_camera", "off"],
        ["init"],
    ],
    ids=lambda argv: " ".join(argv),
)
def test_a_file_where_the_ledger_folder_goes_is_a_sentence_and_exit_one(
    argv: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    paths.home().mkdir(parents=True)
    paths.ledger_dir().write_text("not a folder", encoding="utf-8")

    assert main(argv) == EXIT_FAILED
    line = one_line(capsys.readouterr().err)
    assert line.startswith("sletchy "), line
    assert str(paths.ledger_dir()) in line, f"the sentence does not say where: {line}"
    assert paths.ledger_dir().read_text(encoding="utf-8") == "not a folder"


# ── a flags file that cannot be replaced ─────────────────────────────────────


def test_a_folder_where_flags_json_goes_is_a_sentence_and_exit_one(
    capsys: pytest.CaptureFixture[str],
) -> None:
    seed()
    paths.flags_file().unlink()
    paths.flags_file().mkdir()

    assert main(["flags", "set", "cli_verbose", "on"]) == EXIT_FAILED
    line = one_line(capsys.readouterr().err)
    assert line.startswith("sletchy flags set: could not use "), line
    assert "flags" in line


@pytest.mark.skipif(
    sys.platform != "win32", reason="a read-only file blocks a rename on Windows only"
)
def test_a_read_only_flags_json_is_a_sentence_and_exit_one(
    capsys: pytest.CaptureFixture[str],
) -> None:
    seed()
    os.chmod(paths.flags_file(), stat.S_IREAD)
    try:
        assert main(["flags", "set", "senses_camera", "off"]) == EXIT_FAILED
    finally:
        os.chmod(paths.flags_file(), stat.S_IREAD | stat.S_IWRITE)
    line = one_line(capsys.readouterr().err)
    assert "flags.json" in line, line


# ── init over a broken record ────────────────────────────────────────────────


def test_init_over_a_corrupt_record_exits_two_and_changes_nothing(
    capsys: pytest.CaptureFixture[str],
) -> None:
    seed()
    data = segment().read_bytes()
    segment().write_bytes(data.replace(b"video call", b"video cell"))
    before = segment().read_bytes()

    assert main(["init"]) == EXIT_CORRUPT
    err = capsys.readouterr().err
    assert "LEDGER CORRUPT" in err
    assert "Traceback" not in err
    assert segment().read_bytes() == before, "init touched a record that does not verify"


def test_init_after_a_torn_last_line_exits_two(capsys: pytest.CaptureFixture[str]) -> None:
    seed()
    seed().set("cli_verbose", True)
    data = segment().read_bytes()
    segment().write_bytes(data[:-20])

    assert main(["init"]) == EXIT_CORRUPT
    err = capsys.readouterr().err
    assert "LEDGER CORRUPT" in err
    assert "Traceback" not in err


def test_init_run_twice_leaves_the_key_alone_and_says_so(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["init"]) == EXIT_OK
    assert "provisioned" in capsys.readouterr().out
    assert main(["init"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "already exists - left untouched" in out
    assert FakeKeychain.provisioned == 1, "a second init provisioned a second key"
    assert Ledger.open(paths.ledger_dir(), InMemoryKeySource(KEY)).verify() == 0


def test_init_keeps_the_exit_code_contract(capsys: pytest.CaptureFixture[str]) -> None:
    """0 set up, 1 failed, 2 corrupt - each from `init` itself."""
    assert main(["init"]) == EXIT_OK

    segment().write_text("{ not an entry\n", encoding="utf-8")
    assert main(["init"]) == EXIT_CORRUPT

    segment().unlink()
    paths.ledger_dir().rmdir()
    paths.ledger_dir().write_text("not a folder", encoding="utf-8")
    assert main(["init"]) == EXIT_FAILED
    assert "Traceback" not in capsys.readouterr().err


# ── the net is not a blanket ─────────────────────────────────────────────────


def test_a_programming_error_still_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    """Only ledger and filesystem failures become sentences; a bug stays a bug."""

    def broken(_: object) -> int:
        msg = "a bug, not an operational failure"
        raise TypeError(msg)

    monkeypatch.setattr(cli_main, "cmd_status", broken)
    with pytest.raises(TypeError, match="a bug"):
        main(["status"])


def test_a_switch_that_could_not_be_written_says_it_did_not_change(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """One sentence that says the switch stayed as it was, and that the record agrees."""
    seed()
    paths.flags_file().unlink()
    paths.flags_file().mkdir()

    assert main(["flags", "set", "cli_verbose", "on"]) == EXIT_FAILED
    line = one_line(capsys.readouterr().err)
    assert "cli_verbose stayed off, and the ledger says so" in line, line


# ── a folder with no Sletchy in it (#102) ────────────────────────────────────

READ_COMMANDS = [
    ["status"],
    ["ledger", "verify"],
    ["ledger", "show"],
    ["flags", "list"],
    ["flags", "set", "senses_camera", "off"],
]


@pytest.mark.parametrize("argv", READ_COMMANDS, ids=lambda argv: " ".join(argv))
def test_before_init_every_command_says_not_set_up_and_creates_nothing(
    argv: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(argv) == EXIT_FAILED
    said = capsys.readouterr()
    assert "not set up" in (said.out + said.err).lower(), said
    assert "Traceback" not in said.err
    assert not paths.home().exists(), f"{' '.join(argv)} created {paths.home()}"


@pytest.mark.parametrize("argv", READ_COMMANDS, ids=lambda argv: " ".join(argv))
def test_a_command_run_from_another_folder_creates_nothing_there(
    argv: list[str],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """With no SLETCHY_HOME the home is `var/` under the current folder."""
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.delenv(paths.ENV_HOME)
    monkeypatch.chdir(elsewhere)

    assert main(argv) == EXIT_FAILED
    said = capsys.readouterr()
    assert list(elsewhere.iterdir()) == [], "a second, empty Sletchy was started here"
    assert "verified" not in said.out + said.err, "an absent record was called verified"
    assert str(elsewhere) in said.out + said.err, "it does not say which folder it looked in"


def test_after_init_status_reads_the_record_it_set_up(capsys: pytest.CaptureFixture[str]) -> None:
    """The control: refusing an absent home must not refuse a real one."""
    assert main(["init"]) == EXIT_OK
    capsys.readouterr()
    assert main(["status"]) == EXIT_OK
    assert "0 entries, chain verified" in capsys.readouterr().out


# ── the same thing twice, a missing argument, a very long reason (#105) ──────


def test_the_same_flip_twice_leaves_one_state_records_both_and_verifies(
    capsys: pytest.CaptureFixture[str],
) -> None:
    seed()
    assert main(["flags", "set", "cli_verbose", "on"]) == EXIT_OK
    assert main(["flags", "set", "cli_verbose", "on"]) == EXIT_OK

    ledger = Ledger.open(paths.ledger_dir(), InMemoryKeySource(KEY))
    flips = [e for e in ledger.entries() if e.subject.identifier == "cli_verbose"]
    assert len(flips) == 2, "a repeated flip must still be recorded"
    assert FlagStore.open(ledger, paths.flags_file()).is_on("cli_verbose")
    assert ledger.verify() == 3


def test_flags_set_with_no_value_is_refused_and_writes_nothing() -> None:
    seed()
    before = segment().read_bytes()

    with pytest.raises(SystemExit) as refused:
        main(["flags", "set", "senses_camera"])

    assert refused.value.code == 2, "argparse refuses it before anything is opened"
    assert segment().read_bytes() == before


def test_a_reason_longer_than_the_record_holds_is_cut_and_still_verifies() -> None:
    seed()
    assert main(["flags", "set", "senses_microphone", "on", "--reason", "why " * 600]) == EXIT_OK

    ledger = Ledger.open(paths.ledger_dir(), InMemoryKeySource(KEY))
    last = list(ledger.entries())[-1]
    assert last.subject.identifier == "senses_microphone"
    assert len(last.verdict.reason) == 512
    assert ledger.verify() == 2
