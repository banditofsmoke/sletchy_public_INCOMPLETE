"""`sletchy ledger show` and the read path the desktop shares with it (#50)."""

from __future__ import annotations

from pathlib import Path

import pytest

from sletchy.cli import paths
from sletchy.cli.ledger_view import MAX_TAIL, EntryView, matches_action, read_entries, render
from sletchy.cli.main import EXIT_CORRUPT, EXIT_OK, main
from sletchy.kernel.contracts import Decision, Plane, Subject, SubjectKind, Verdict
from sletchy.kernel.ledger import InMemoryKeySource, Ledger

KEY = InMemoryKeySource(b"k" * 32)


@pytest.fixture(autouse=True)
def _sandboxed_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(paths.ENV_HOME, str(tmp_path / "var"))
    monkeypatch.setattr("sletchy.cli.main.KeyringKeySource", lambda *a, **k: KEY)


def ledger_with(*actions: tuple[str, Decision]) -> Ledger:
    ledger = Ledger.open(paths.ledger_dir(), KEY)
    for action, decision in actions:
        ledger.append(
            plane=Plane.WARDEN,
            actor_id="tester",
            action=action,
            subject=Subject(kind=SubjectKind.FLAG, identifier="x"),
            verdict=Verdict(decision=decision, reason=f"{action} {decision.value}", rule_id=None),
        )
    return ledger


@pytest.mark.parametrize(
    ("action", "prefix", "expected"),
    [
        ("warden.sandbox.launch", "warden.sandbox", True),
        ("warden.sandbox", "warden.sandbox", True),
        ("warden.sandboxes.launch", "warden.sandbox", False),
        ("kernel.flag.flip", "warden", False),
    ],
)
def test_action_filtering_is_segment_aware(action: str, prefix: str, expected: bool) -> None:
    assert matches_action(action, prefix) is expected


def test_entries_come_back_oldest_first_and_tail_keeps_the_newest() -> None:
    ledger = ledger_with(*[(f"kernel.test.n{i}", Decision.ALLOW) for i in range(5)])
    assert [e.seq for e in read_entries(ledger)] == [0, 1, 2, 3, 4]
    assert [e.seq for e in read_entries(ledger, tail=2)] == [3, 4]


def test_filters_compose() -> None:
    ledger = ledger_with(
        ("warden.sandbox.launch", Decision.ALLOW),
        ("warden.sandbox.refuse", Decision.DENY),
        ("kernel.flag.flip", Decision.DENY),
    )
    denied = read_entries(ledger, denied_only=True)
    assert [e.action for e in denied] == ["warden.sandbox.refuse", "kernel.flag.flip"]
    both = read_entries(ledger, denied_only=True, action_prefix="warden")
    assert [e.action for e in both] == ["warden.sandbox.refuse"]


def test_tail_is_capped() -> None:
    ledger = ledger_with(*[("kernel.test.many", Decision.ALLOW)] * 3)
    assert len(read_entries(ledger, tail=MAX_TAIL * 10)) == 3  # cap applies; no error


def test_render_prints_one_inert_line_per_entry_whatever_a_field_holds() -> None:
    """Every text field is escaped, not only the reason: the class, not the one instance."""
    nasty = "a\nb\rc\x1bd‮e\x00f"
    entry = EntryView(
        seq=1,
        ts="2026-10-03T00:00:00+00:00",
        plane="kernel",
        actor=nasty,
        action=nasty,
        subject=nasty,
        decision="allow",
        reason=nasty,
        has_payload=False,
    )
    text = render([entry, entry])
    assert len(text.splitlines()) == 2
    assert all(ch.isprintable() for ch in text.replace("\n", ""))
    assert "a\\nb\\rc\\x1bd\\u202ee\\x00f" in text


def test_a_view_never_carries_hashes_or_signatures() -> None:
    """What a screen shows is for reading, not for forging from."""
    fields = set(EntryView.model_fields)
    assert not fields & {"signature", "prev_hash", "payload_hash", "ts_mono"}


def test_reading_writes_nothing() -> None:
    ledger = ledger_with(("kernel.test.one", Decision.ALLOW))
    segment = paths.ledger_dir() / "segment-00000.ndjson"
    before = segment.read_bytes()
    read_entries(ledger, tail=10, denied_only=True, action_prefix="kernel")
    assert segment.read_bytes() == before


def test_cli_show_prints_entries(capsys: pytest.CaptureFixture[str]) -> None:
    ledger_with(("kernel.test.shown", Decision.ALLOW)).close()
    assert main(["ledger", "show"]) == EXIT_OK
    assert "kernel.test.shown" in capsys.readouterr().out


def test_cli_show_prints_nothing_from_a_corrupt_chain(capsys: pytest.CaptureFixture[str]) -> None:
    ledger_with(("kernel.test.real", Decision.ALLOW)).close()
    segment = paths.ledger_dir() / "segment-00000.ndjson"
    segment.write_text(segment.read_text("utf-8").replace("real", "fake"), "utf-8")

    assert main(["ledger", "show"]) == EXIT_CORRUPT
    captured = capsys.readouterr()
    assert captured.out == "", "a forged history was shown"
    assert "CORRUPT" in captured.err
