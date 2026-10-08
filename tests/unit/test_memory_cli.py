"""`sletchy memory` from a terminal (ADR-0019, #194).

The ledger is in memory and the home is a temporary folder; a fake Ollama answers the
embedding requests. Nothing here touches the real keychain or a real model server.
"""

from __future__ import annotations

import io
from collections.abc import Iterator
from pathlib import Path

import pytest

from sletchy.cli import paths
from sletchy.cli.main import EXIT_FAILED, EXIT_OK, main
from sletchy.kernel.flags import FlagStore
from sletchy.kernel.ledger import InMemoryKeySource, Ledger
from sletchy.mind.memory.store import FILENAME
from tests.fake_ollama import FakeOllama, fake_ollama

NOTES = "# Garage\n\nMy automobile is red.\n\n# Garden\n\nThe roses want water.\n"


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


def stdin(monkeypatch: pytest.MonkeyPatch, text: str) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO(text))


def test_add_search_list_and_forget_from_a_terminal(
    home: FlagStore, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    home.set("mind_memory", True, reason="testing")
    stdin(monkeypatch, NOTES)

    assert main(["memory", "add", "notes.md"]) == EXIT_OK
    assert "notes.md: 4 new chunks, 0 already held" in capsys.readouterr().out

    assert main(["memory", "search", "roses", "water"]) == EXIT_OK
    out = capsys.readouterr()
    assert "[1] notes.md > Garden  (words, " in out.out
    assert "  > The roses want water." in out.out
    assert "searched by words only" in out.err

    assert main(["memory", "list"]) == EXIT_OK
    assert "notes.md" in capsys.readouterr().out

    assert main(["memory", "forget", "notes.md"]) == EXIT_OK
    assert "Forgot 4 chunks of notes.md" in capsys.readouterr().out
    assert main(["memory", "list"]) == EXIT_OK
    assert "Memory is empty." in capsys.readouterr().out
    assert (paths.memory_dir() / FILENAME).exists()


def test_memory_switched_off_says_how_to_turn_it_on(
    home: FlagStore, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    stdin(monkeypatch, NOTES)

    assert main(["memory", "add", "notes.md"]) == EXIT_FAILED
    assert "sletchy flags set mind_memory on" in capsys.readouterr().err
    assert main(["memory", "search", "roses"]) == EXIT_FAILED
    assert not paths.memory_dir().exists()


def test_search_by_meaning_through_the_door(
    home: FlagStore,
    ollama: FakeOllama,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home.set("mind_memory", True, reason="testing")
    home.set("mind_local_models", True, reason="testing")
    port = str(ollama.server_address[1])
    stdin(monkeypatch, NOTES)

    assert main(["memory", "add", "--port", port, "--embed", "gemma3:1b", "notes.md"]) == EXIT_OK
    assert "with vectors" in capsys.readouterr().out
    assert main(["memory", "search", "--port", port, "--embed", "gemma3:1b", "car"]) == EXIT_OK

    out = capsys.readouterr()
    assert "[1] notes.md > Garage  (meaning, " in out.out
    assert "searched by words and meaning" in out.err


def test_adding_by_meaning_with_local_models_off_says_so_and_stores_nothing(
    home: FlagStore,
    ollama: FakeOllama,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home.set("mind_memory", True, reason="testing")
    stdin(monkeypatch, NOTES)
    port = str(ollama.server_address[1])

    assert (
        main(["memory", "add", "--port", port, "--embed", "gemma3:1b", "notes.md"]) == EXIT_FAILED
    )
    assert "Local AI models are switched off" in capsys.readouterr().err
    assert ollama.seen == []
    assert main(["memory", "list"]) == EXIT_OK
    assert "Memory is empty." in capsys.readouterr().out


def test_a_passage_is_shown_inert(
    home: FlagStore, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    home.set("mind_memory", True, reason="testing")
    stdin(monkeypatch, "Clear the screen \x1b[2J now.")
    assert main(["memory", "add", "evil.md"]) == EXIT_OK
    capsys.readouterr()

    assert main(["memory", "search", "clear", "screen"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "\x1b" not in out
    assert "?[2J" in out


def test_an_empty_document_is_not_added(
    home: FlagStore, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    home.set("mind_memory", True, reason="testing")
    stdin(monkeypatch, "\n\n  \n")

    assert main(["memory", "add", "blank.md"]) == EXIT_FAILED
    assert "no text" in capsys.readouterr().err
