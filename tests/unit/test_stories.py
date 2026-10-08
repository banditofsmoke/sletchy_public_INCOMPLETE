"""Every user story cites tests that exist, or names the issue that will hold it.

`docs/stories/` describes what Sletchy does for five kinds of person. Each acceptance
criterion names the pytest node that proves it, or says `GAP #N` when nothing does yet.
This file keeps those citations honest:

- a cited test that does not exist, **by that name, in that file**, fails the build.
  This repo has already shipped one invented test name (the desktop help registry), and
  a story citing a test nobody wrote converts an unknown into a false certainty;
- a `GAP` that names no issue fails, because a gap with no number is a note nobody
  will reread (L005);
- a story file that yields no criteria fails, because a checker that parses nothing
  passes everything (L001). The positive controls at the bottom prove the checker
  catches what it claims to catch.

The checker reads test files with `ast`, never by importing them, so citing a test
cannot run it and a story cannot be satisfied by a name that only appears in a string.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from functools import cache
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
STORIES = REPO / "docs" / "stories"
PERSONAS = ("simple", "custom", "raw", "clumsy", "abuser")

#: `| S1.2 | the criterion | held by |` - the only row shape that counts as a criterion.
CRITERION = re.compile(r"^\|\s*(?P<id>[A-Z]\d+\.\d+)\s*\|(?P<text>[^|]+)\|(?P<held>[^|]+)\|\s*$")
#: A full pytest node id: a path under tests/, then a function or Class::method.
NODE = re.compile(r"^(?P<file>tests/[\w/]+\.py)::(?P<name>\w+(?:::\w+)?)$")
GAP = re.compile(r"\bGAP\b(?P<rest>\s*#\d+)?")
STORY_HEADING = re.compile(r"^## (?P<id>[A-Z]\d+)\. \S")
STORY_LINE = re.compile(r"^As an? .+, I want .+, so that .+\.$")


@dataclass(frozen=True)
class Criterion:
    source: str
    id: str
    tests: tuple[str, ...]
    gaps: tuple[int, ...]


@dataclass(frozen=True)
class Story:
    source: str
    id: str
    says_who_what_why: bool


@cache
def _collectable(path: Path) -> frozenset[str]:
    """Every test node id pytest could collect from one file, read without importing it."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    names: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.name.startswith(
            "test"
        ):
            names.add(node.name)
        elif isinstance(node, ast.ClassDef) and node.name.startswith("Test"):
            for item in node.body:
                if isinstance(item, ast.FunctionDef | ast.AsyncFunctionDef) and (
                    item.name.startswith("test")
                ):
                    names.add(f"{node.name}::{item.name}")
    return frozenset(names)


def node_exists(node: str, root: Path = REPO) -> bool:
    match = NODE.match(node)
    if match is None:
        return False
    path = root / match["file"]
    return path.is_file() and match["name"] in _collectable(path)


def parse(text: str, source: str) -> tuple[list[Story], list[Criterion], list[str]]:
    """Stories, criteria, and every structural error, from one story file."""
    stories: list[Story] = []
    criteria: list[Criterion] = []
    errors: list[str] = []
    lines = text.splitlines()

    for i, line in enumerate(lines):
        heading = STORY_HEADING.match(line)
        if heading:
            body = next((ln for ln in lines[i + 1 :] if ln.strip()), "")
            stories.append(Story(source, heading["id"], bool(STORY_LINE.match(body.strip()))))
            continue

        row = CRITERION.match(line)
        if row is None:
            continue
        cid, held = row["id"], row["held"]

        spans = re.findall(r"`([^`]*)`", held)
        tests = tuple(spans)
        for span in spans:
            if not NODE.match(span):
                errors.append(
                    f"{source} {cid}: `{span}` is not a full test id (tests/<path>.py::<name>)"
                )

        gaps: list[int] = []
        outside = re.sub(r"`[^`]*`", "", held)
        for gap in GAP.finditer(outside):
            if gap["rest"] is None:
                errors.append(f"{source} {cid}: a GAP must name the issue that will close it")
            else:
                gaps.append(int(gap["rest"].strip().lstrip("#")))

        if not tests and not gaps:
            errors.append(f"{source} {cid}: held by nothing - cite a test or a GAP #N")
        criteria.append(Criterion(source, cid, tests, tuple(gaps)))

    return stories, criteria, errors


def check(text: str, source: str, root: Path = REPO) -> list[str]:
    """Every reason a story file is not honest about what holds it."""
    stories, criteria, errors = parse(text, source)
    if not criteria:
        errors.append(f"{source}: no acceptance criteria found - the checker read nothing")
    for story in stories:
        if not story.says_who_what_why:
            errors.append(f"{source} {story.id}: needs 'As a ..., I want ..., so that ...'")
        if not any(c.id.startswith(story.id + ".") for c in criteria):
            errors.append(f"{source} {story.id}: a story with no acceptance criteria")
    for criterion in criteria:
        errors.extend(
            f"{source} {criterion.id}: cites {test}, which does not exist by that name in that file"
            for test in criterion.tests
            if NODE.match(test) and not node_exists(test, root)
        )
    return errors


def story_files() -> list[Path]:
    return [STORIES / f"{persona}.md" for persona in PERSONAS]


def all_criteria() -> list[Criterion]:
    found: list[Criterion] = []
    for path in story_files():
        _, criteria, _ = parse(path.read_text(encoding="utf-8"), path.name)
        found.extend(criteria)
    return found


# ── the stories ──────────────────────────────────────────────────────────────


def test_every_persona_has_a_story_file_and_the_index_links_it() -> None:
    index = (STORIES / "README.md").read_text(encoding="utf-8")
    for path in story_files():
        assert path.is_file(), f"missing {path.relative_to(REPO)}"
        assert f"]({path.name})" in index, f"README.md does not link {path.name}"


def test_every_story_is_honest_about_what_holds_it() -> None:
    errors = [
        error
        for path in story_files()
        for error in check(path.read_text(encoding="utf-8"), path.name)
    ]
    assert errors == []


def test_criterion_ids_are_unique_across_every_story() -> None:
    ids = [c.id for c in all_criteria()]
    assert len(ids) == len(set(ids)), sorted({i for i in ids if ids.count(i) > 1})


def test_the_stories_are_not_empty() -> None:
    """L001's control: if parsing silently broke, every check above would pass on nothing."""
    for path in story_files():
        stories, criteria, _ = parse(path.read_text(encoding="utf-8"), path.name)
        assert len(stories) >= 3, f"{path.name}: {len(stories)} stories"
        assert len(criteria) >= 6, f"{path.name}: {len(criteria)} criteria"
    assert sum(len(c.tests) for c in all_criteria()) >= 60


# ── positive controls: the checker catches what it claims to ─────────────────

STORY = (
    "## X1. A story\n\n"
    "As a tester, I want a control, so that the checker is proven.\n\n"
    "| # | Criterion | Held by |\n"
    "|---|---|---|\n"
)
REAL = "tests/unit/test_stories.py::test_the_checker_catches_an_invented_test_name"


def test_the_checker_accepts_a_real_citation() -> None:
    """Without this, a checker that refused everything would look strict."""
    assert check(STORY + f"| X1.1 | real | `{REAL}` |\n", "control.md") == []


def test_the_checker_catches_an_invented_test_name() -> None:
    errors = check(
        STORY + "| X1.1 | invented | `tests/unit/test_cli.py::test_this_was_never_written` |\n",
        "control.md",
    )
    assert any("test_this_was_never_written" in e and "does not exist" in e for e in errors)


def test_the_checker_catches_a_real_name_in_the_wrong_file() -> None:
    wrong = "tests/unit/test_cli.py::test_the_checker_catches_an_invented_test_name"
    errors = check(STORY + f"| X1.1 | moved | `{wrong}` |\n", "control.md")
    assert any("does not exist" in e for e in errors)


def test_the_checker_catches_a_gap_with_no_issue() -> None:
    errors = check(STORY + "| X1.1 | unheld | GAP |\n", "control.md")
    assert any("must name the issue" in e for e in errors)
    assert check(STORY + "| X1.1 | unheld | GAP #105 |\n", "control.md") == []


def test_the_checker_catches_an_abbreviated_or_unheld_criterion() -> None:
    abbreviated = check(STORY + "| X1.1 | short | `...::test_x` |\n", "control.md")
    assert any("not a full test id" in e for e in abbreviated)
    unheld = check(STORY + "| X1.1 | nothing | probably fine |\n", "control.md")
    assert any("held by nothing" in e for e in unheld)


def test_the_checker_catches_a_story_without_its_why_or_its_criteria() -> None:
    no_why = check(
        STORY.replace(", so that the checker is proven", "") + f"| X1.1 | r | `{REAL}` |\n", "c.md"
    )
    assert any("so that" in e for e in no_why)
    no_criteria = check(
        STORY + f"## X2. Another\n\nAs a b, I want c, so that d.\n\n| X1.1 | r | `{REAL}` |\n",
        "c.md",
    )
    assert any("X2: a story with no acceptance criteria" in e for e in no_criteria)


def test_the_checker_reads_nothing_as_a_failure() -> None:
    assert check("# A heading and no table\n", "empty.md") != []


def test_a_name_that_only_appears_in_a_string_is_not_a_test(tmp_path: Path) -> None:
    """The file is parsed, not grepped: a name in a docstring is not a test."""
    fake = tmp_path / "tests" / "unit" / "test_fake.py"
    fake.parent.mkdir(parents=True)
    fake.write_text(
        '"""test_only_in_a_docstring"""\n\ndef test_real() -> None:\n    pass\n', "utf-8"
    )
    assert node_exists("tests/unit/test_fake.py::test_real", tmp_path)
    assert not node_exists("tests/unit/test_fake.py::test_only_in_a_docstring", tmp_path)
