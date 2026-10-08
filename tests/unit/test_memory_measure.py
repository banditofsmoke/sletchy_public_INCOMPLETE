"""Measuring a judge (#195): the set's shape, the counting, and the command.

A fake Ollama answers as the judge; nothing here reaches a real model server or the real
keychain.
"""

from __future__ import annotations

import io
import json
from collections.abc import Iterator, Sequence
from pathlib import Path

import pytest

from sletchy.cli import paths
from sletchy.cli.main import EXIT_FAILED, EXIT_OK, main
from sletchy.kernel.flags import FlagStore
from sletchy.kernel.ledger import InMemoryKeySource, Ledger
from sletchy.mind.memory.gate import Scores
from sletchy.mind.memory.measure import MAX_PASSAGES, Item, measure, read_set
from sletchy.mind.memory.store import Passage
from tests.fake_ollama import FakeOllama, chat_answer, fake_ollama

ROOT = Path(__file__).resolve().parents[2]
SEED = ROOT / "docs" / "measure" / "judge-seed.jsonl"


def row(**overrides: object) -> str:
    base: dict[str, object] = {
        "question": "Where are the keys?",
        "passages": ["By the back door.", "The door is blue."],
        "helps": [0],
        "answerable": True,
    }
    return json.dumps({**base, **overrides})


class Oracle:
    """A judge that knows the answers, or one told to say the same thing every time."""

    name = "oracle:test"

    def __init__(self, items: Sequence[Item] | None = None, always: Scores | None = None) -> None:
        self.by_question = {i.question: i for i in items or ()}
        self.always = always

    def judge(self, question: str, passages: Sequence[Passage]) -> Scores:
        if self.always is not None:  # its first number, for every passage
            said = self.always
            return Scores((said.each[0],) * len(passages), said.answerable, said.readable)
        item = self.by_question[question]
        each = tuple(1.0 if i in item.helps else 0.0 for i in range(len(passages)))
        return Scores(each, 1.0 if item.answerable else 0.0, True)


def test_the_seed_set_is_a_well_formed_set_of_fourteen() -> None:
    items = read_set(SEED.read_text(encoding="utf-8").splitlines())

    assert len(items) == 14
    assert sum(i.answerable for i in items) == 8
    assert all(i.answerable == bool(i.helps) for i in items)


@pytest.mark.parametrize(
    ("line", "reason"),
    [
        ("not json", "line 1"),
        (row(helps=[2]), "positions"),
        (row(helps=[True]), "positions"),
        (row(passages=[]), "passages"),
        (row(passages=["x"] * (MAX_PASSAGES + 1)), "passages"),
        (row(answerable="yes"), "true or false"),
        (row(extra=1), "an object of"),
        (row(question=" "), "question"),
    ],
)
def test_a_malformed_row_is_refused_by_its_line(line: str, reason: str) -> None:
    with pytest.raises(ValueError, match=reason):
        read_set([line])


def test_a_judge_that_knows_the_answers_scores_full_marks() -> None:
    items = read_set(SEED.read_text(encoding="utf-8").splitlines())

    report = measure(Oracle(items), items)

    assert (report.precision, report.recall, report.answerable_accuracy) == (1.0, 1.0, 1.0)
    assert report.unreadable == 0


def test_a_judge_that_keeps_everything_is_caught_by_precision() -> None:
    items = read_set(SEED.read_text(encoding="utf-8").splitlines())

    report = measure(Oracle(always=Scores((1.0,), 1.0, True)), items)

    assert report.recall == 1.0
    assert report.precision == pytest.approx(8 / 29)
    assert report.answerable_accuracy == pytest.approx(8 / 14)


def test_a_judge_that_fails_keeps_nothing_and_is_counted() -> None:
    class Broken:
        name = "broken:test"

        def judge(self, question: str, passages: Sequence[Passage]) -> Scores:
            raise OSError("no model server")

    items = read_set([row()])

    report = measure(Broken(), items)

    assert (report.kept_right, report.missed, report.unreadable) == (0, 1, 1)


# ── from a terminal ─────────────────────────────────────────────────────────


@pytest.fixture
def ollama() -> Iterator[FakeOllama]:
    yield from fake_ollama()


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[FlagStore]:
    monkeypatch.setenv(paths.ENV_HOME, str(tmp_path / "var"))
    monkeypatch.setenv("SLETCHY_ALLOW_INMEMORY_KEY", "1")
    monkeypatch.setattr(
        "sletchy.cli.main.KeyringKeySource", lambda *a, **k: InMemoryKeySource(b"k" * 32)
    )
    opened = Ledger.open(paths.ledger_dir(), InMemoryKeySource(b"k" * 32))
    flags = FlagStore.open(opened, paths.flags_file())
    yield flags
    opened.close()


def test_measure_from_a_terminal(
    home: FlagStore,
    ollama: FakeOllama,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home.set("mind_local_models", True, reason="testing")
    monkeypatch.setattr("sys.stdin", io.StringIO(row() + "\n" + row(helps=[], answerable=False)))
    ollama.answers = [
        chat_answer(json.dumps({"p1": 0.9, "p2": 0.1, "answerable": 0.8})),
        chat_answer(json.dumps({"p1": 0.7, "p2": 0.1, "answerable": 0.6})),
    ]

    assert (
        main(["memory", "measure", "--port", str(ollama.server_address[1]), "gemma3:1b"]) == EXIT_OK
    )

    out = capsys.readouterr().out
    assert "questions    2" in out
    assert "precision    0.50" in out
    assert "answerable   0.50" in out


def test_measure_with_local_models_off_asks_nothing(
    home: FlagStore,
    ollama: FakeOllama,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO(row()))

    assert (
        main(["memory", "measure", "--port", str(ollama.server_address[1]), "gemma3:1b"])
        == EXIT_FAILED
    )

    assert "Local AI models are switched off" in capsys.readouterr().err
    assert ollama.seen == []
