"""Chunking (ADR-0019, #194): structure first, three sizes linked by parent, named by content."""

from __future__ import annotations

from sletchy.mind.memory.chunk import (
    MAX_PARAGRAPH_CHARS,
    SEP,
    Chunk,
    Kind,
    Level,
    chunk_id,
    document,
    paragraphs,
    sentences,
    turn,
)

NOTES = """Intro line before any heading.

# Install

Run the installer. Then open the window. It asks nothing.

## Windows

Double-click the file.

# Use

Ask a question.
"""


def at(chunks: list[Chunk], level: Level) -> list[Chunk]:
    return [c for c in chunks if c.level is level]


def test_a_document_is_cut_by_headings_then_paragraphs_then_sentences() -> None:
    chunks = document("notes.md", NOTES)

    headers = [c.header for c in at(chunks, Level.SECTION)]
    assert headers == [
        "notes.md",
        f"notes.md{SEP}Install",
        f"notes.md{SEP}Install{SEP}Windows",
        f"notes.md{SEP}Use",
    ]
    assert [c.text for c in at(chunks, Level.PARAGRAPH)] == [
        "Intro line before any heading.",
        "Run the installer. Then open the window. It asks nothing.",
        "Double-click the file.",
        "Ask a question.",
    ]


def test_a_heading_closes_every_heading_at_its_depth_or_deeper() -> None:
    chunks = document("n", "# A\n\na\n\n### C\n\nc\n\n## B\n\nb\n")

    assert [c.header for c in at(chunks, Level.SECTION)] == [
        f"n{SEP}A",
        f"n{SEP}A{SEP}C",
        f"n{SEP}A{SEP}B",
    ]


def test_windows_move_one_sentence_at_a_time_inside_their_paragraph() -> None:
    chunks = document("notes.md", NOTES)
    windows = at(chunks, Level.SENTENCES)
    install = next(c for c in at(chunks, Level.PARAGRAPH) if c.text.startswith("Run"))

    assert [w.text for w in windows] == [
        "Run the installer. Then open the window.",
        "Then open the window. It asks nothing.",
    ]
    assert all(w.parent == install.id for w in windows)


def test_a_paragraph_no_longer_than_a_window_has_no_windows() -> None:
    chunks = document("n", "One sentence. Two sentences.")

    assert at(chunks, Level.SENTENCES) == []
    assert len(at(chunks, Level.PARAGRAPH)) == 1


def test_every_paragraph_sits_in_its_section() -> None:
    chunks = document("notes.md", NOTES)
    sections = {c.id: c for c in at(chunks, Level.SECTION)}

    for paragraph in at(chunks, Level.PARAGRAPH):
        assert paragraph.parent in sections
        assert sections[paragraph.parent].header == paragraph.header


def test_a_long_paragraph_is_cut_at_sentence_ends() -> None:
    sentence = "This sentence is about forty characters. "
    long = sentence * (MAX_PARAGRAPH_CHARS // len(sentence) * 3)

    pieces = paragraphs(long)

    assert len(pieces) == 3
    assert all(len(p) <= MAX_PARAGRAPH_CHARS for p in pieces)
    assert all(p.endswith("characters.") for p in pieces)


def test_one_enormous_sentence_is_still_cut_to_size() -> None:
    pieces = paragraphs("x" * (MAX_PARAGRAPH_CHARS * 2 + 5))

    assert [len(p) for p in pieces] == [MAX_PARAGRAPH_CHARS, MAX_PARAGRAPH_CHARS, 5]


def test_a_list_item_is_a_sentence() -> None:
    assert sentences("- milk\n- eggs\n- bread") == ["- milk", "- eggs", "- bread"]


def test_the_same_text_in_the_same_place_has_the_same_id() -> None:
    first = document("notes.md", NOTES)
    again = document("notes.md", NOTES)
    elsewhere = document("other.md", NOTES)

    assert [c.id for c in first] == [c.id for c in again]
    assert not {c.id for c in first} & {c.id for c in elsewhere}
    assert chunk_id(Level.SECTION, "h", "t") != chunk_id(Level.PARAGRAPH, "h", "t")


def test_ids_are_unique_within_a_document() -> None:
    chunks = document("n", "Same.\n\nSame.\n\nSame.")

    assert len({c.id for c in chunks}) == len(chunks)


def test_a_turn_keeps_question_and_answer_together_and_cites_its_answer() -> None:
    chunks = turn("c-1234abcd", 2, "What is my name?", "Your name is Ada.", cites=17)

    paragraph = at(chunks, Level.PARAGRAPH)[0]
    assert paragraph.text == "Question: What is my name?\nAnswer: Your name is Ada."
    assert paragraph.header == f"conversation c-1234abcd{SEP}turn 2"
    assert {c.kind for c in chunks} == {Kind.CONVERSATION}
    assert {c.cites for c in chunks} == {17}
    assert {c.source for c in chunks} == {"c-1234abcd"}


def test_an_answer_of_several_paragraphs_keeps_its_paragraphs() -> None:
    chunks = turn("c-1", 1, "Plan?", "First, rest.\n\nThen, work.", cites=3)

    assert [c.text for c in at(chunks, Level.PARAGRAPH)] == [
        "Question: Plan?\nAnswer: First, rest.",
        "Then, work.",
    ]


def test_an_empty_document_has_no_chunks() -> None:
    assert document("n", "\n\n   \n") == []
