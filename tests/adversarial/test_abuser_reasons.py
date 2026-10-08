"""A reason is the one free-text field in the record. What can someone do with it?

`--reason` on the command line and `reason` on the bridge go into the signed entry as
typed: the ledger stores what was said, and nothing rewrites it before it is signed.
`sletchy ledger show` is how a person reads it back. Until #96 a reason could print a
second, fake entry; send escape sequences straight to the terminal; crash the reader
when its output went to a file; or be one invisible character and still count as a
reason for turning a dangerous switch on.

Every test runs against a throwaway `SLETCHY_HOME` and an in-memory key.
"""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path

import pytest

from sletchy.cli import paths
from sletchy.cli.bridge import Bridge, handle_line
from sletchy.cli.main import EXIT_FAILED, EXIT_OK, main
from sletchy.kernel.flags import FlagStore
from sletchy.kernel.ledger import InMemoryKeySource, Ledger

pytestmark = pytest.mark.adversarial

KEY = InMemoryKeySource(b"k" * 32)


@pytest.fixture(autouse=True)
def _home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(paths.ENV_HOME, str(tmp_path / "var"))
    monkeypatch.setattr("sletchy.cli.main.KeyringKeySource", lambda *a, **k: KEY)
    Ledger.open(paths.ledger_dir(), KEY).close()


def last_reason() -> str:
    ledger = Ledger.open(paths.ledger_dir(), KEY)
    try:
        return list(ledger.entries())[-1].verdict.reason
    finally:
        ledger.close()


def flag_on(name: str) -> bool:
    ledger = Ledger.open(paths.ledger_dir(), KEY)
    try:
        return FlagStore.open(ledger, paths.flags_file()).is_on(name)
    finally:
        ledger.close()


# ── reading it back ──────────────────────────────────────────────────────────

FAKE_ENTRY = (
    "\n     9  2026-01-01T00:00:00+00:00  kernel  operator  kernel.flag.flip  deny  "
    "egress_enabled -> off: all clear"
)


def test_a_reason_cannot_print_a_second_entry(capsys: pytest.CaptureFixture[str]) -> None:
    """Found 2026-10-03: this reason printed a line indistinguishable from a real entry."""
    assert main(["flags", "set", "egress_enabled", "on", "--reason", "testing" + FAKE_ENTRY]) == 0
    capsys.readouterr()

    assert main(["ledger", "show"]) == EXIT_OK
    lines = capsys.readouterr().out.splitlines()

    assert len(lines) == 1, f"one entry printed as {len(lines)} lines: {lines}"
    assert "\\n" in lines[0], "the newline must be shown, escaped, not dropped"
    assert "\n" in last_reason(), "the record keeps what was typed; only the display escapes"


@pytest.mark.parametrize(
    "hostile",
    [
        "\x1b[2K\x1b[1A",  # erase the line, move up: rewrites what was printed before
        "\x1b]0;owned\x07",  # set the terminal title
        "\r",  # return to column 0 and overprint
        "\x08\x08\x08",  # backspaces
        "‮",  # right-to-left override: reorders what follows
        "\x9b",  # the one-byte C1 form of ESC [
        "\x00",
    ],
    ids=["erase-line", "title", "carriage-return", "backspace", "rtl-override", "c1-csi", "nul"],
)
def test_no_control_character_reaches_the_terminal_raw(
    capsys: pytest.CaptureFixture[str], hostile: str
) -> None:
    assert main(["flags", "set", "cli_verbose", "on", "--reason", f"before{hostile}after"]) == 0
    capsys.readouterr()

    assert main(["ledger", "show"]) == EXIT_OK
    out = capsys.readouterr().out

    assert hostile not in out
    assert "before" in out and "after" in out


def test_printable_text_in_any_script_is_stored_and_shown_as_typed(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The control for the two above: escaping is for what cannot be shown, not what is foreign."""
    reason = "café für Ωmega, 日本語, عربى, and a fire \U0001f525"
    assert main(["flags", "set", "cli_verbose", "on", "--reason", reason]) == EXIT_OK
    capsys.readouterr()

    assert main(["ledger", "verify"]) == EXIT_OK
    assert main(["ledger", "show"]) == EXIT_OK
    assert reason in capsys.readouterr().out
    assert reason in last_reason()


def test_a_reason_the_output_encoding_cannot_hold_does_not_crash_the_reader(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`sletchy ledger show > audit.txt` on Windows writes cp1252. One emoji crashed it."""
    assert main(["flags", "set", "cli_verbose", "on", "--reason", "fire \U0001f525 done"]) == 0

    raw = io.BytesIO()
    piped = io.TextIOWrapper(raw, encoding="cp1252", newline="\n")
    monkeypatch.setattr(sys, "stdout", piped)

    assert main(["ledger", "show"]) == EXIT_OK
    piped.flush()
    text = raw.getvalue().decode("cp1252")

    assert "fire" in text and "done" in text
    assert "\\U0001f525" in text, "the character is escaped, not silently dropped"


# ── turning a switch on ──────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "reason",
    ["​", "​‌‍", "⁠", "‮", "\x00", "\t \n", "　"],
    ids=[
        "zwsp",
        "zero-width-run",
        "word-joiner",
        "rtl-override",
        "nul",
        "whitespace",
        "ideo-space",
    ],
)
def test_an_invisible_reason_does_not_turn_a_dangerous_switch_on(
    capsys: pytest.CaptureFixture[str], reason: str
) -> None:
    assert main(["flags", "set", "egress_enabled", "on", "--reason", reason]) == EXIT_FAILED
    assert "requires a reason" in capsys.readouterr().err
    assert not flag_on("egress_enabled")


def test_an_invisible_reason_is_refused_from_the_window_too() -> None:
    request = {
        "id": 1,
        "method": "flags.set",
        "params": {
            "name": "egress_enabled",
            "enabled": True,
            "reason": "​",
            "confirm": "egress_enabled",
        },
    }
    answer = json.loads(handle_line(Bridge(KEY), json.dumps(request).encode()))
    assert answer["error"]["code"] == "reason_required"
    assert not flag_on("egress_enabled")


def test_a_visible_reason_in_any_script_is_enough() -> None:
    """The control: a reason in Japanese, or one emoji, is a reason a person can see."""
    assert main(["flags", "set", "egress_enabled", "on", "--reason", "日本"]) == EXIT_OK
    assert flag_on("egress_enabled")
    assert main(["flags", "set", "senses_camera", "on", "--reason", "\U0001f4f7"]) == EXIT_OK
    assert flag_on("senses_camera")
