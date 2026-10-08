"""The PR shape check is a control, so it gets positive and negative controls.

`scripts/pr_check.py` holds every PR's title and body to the shape in
docs/LAW/writing-conventions.md, section 2. A check that cannot fire is a hypothesis
(L001), and one that fires on a correct PR gets bypassed, so both directions are tested.
The template, the conventions and the check describe one shape, and the last tests here
hold them to each other, so the three cannot drift apart again.
"""

from __future__ import annotations

import importlib.util
import re
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "pr_check.py"
TEMPLATE = ROOT / ".github" / "pull_request_template.md"
FORMS = ROOT / ".github" / "ISSUE_TEMPLATE"
CONVENTIONS = ROOT / "docs" / "LAW" / "writing-conventions.md"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("pr_check", SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["pr_check"] = module
    spec.loader.exec_module(module)
    return module


pr = _load()


def _template() -> str:
    return TEMPLATE.read_text("utf-8").replace("\r\n", "\n")


GOOD_BODY = """Closes #12

## Summary
The ledger could be forked by two writers. One writer at a time now.

## Changes
- `kernel/ledger/lock.py`: a lock file held for each append

## Tests
| Test | What it proves | Fails without the change |
|---|---|---|
| `test_two_writers_never_fork` | appends from two processes stay one chain | yes |

```text
pytest           1475 passed, 24 skipped
-m law_zero      532 passed
```

## Risk
Docs only: no code, test or workflow changes.

## Not in scope
- Locks across machines, #58
"""


# --- titles -------------------------------------------------------------------------


@pytest.mark.parametrize(
    "title",
    [
        "fix(kernel/ledger): refuse a second writer",
        "feat(warden/egress): add the egress gate, sandbox proxy and client",
        "fix(kernel,cli): show every reason as one inert line",
        "docs(adr): record that lane rules bind for TCP over IPv4",
        "spike(warden/isolation): measure whether a sandbox can see the GPU",
        "ci(deps): pin every action to a commit",
    ],
)
def test_a_title_in_the_agreed_shape_passes(title: str) -> None:
    assert pr.title_problems(title) == []


@pytest.mark.parametrize(
    ("title", "fragment"),
    [
        ("fix(kernel/ledger): refuse " + "x" * 60, "at most 72"),
        ("Project setup: uv, ruff, mypy", "not `type(scope): subject`"),
        ("docs: refresh the build state", "not `type(scope): subject`"),
        ("feature(kernel): add a ledger", "type 'feature'"),
        ("feat(egress): add the gate", "'egress' is not one of"),
        ("feat(warden/Egress): add the gate", "one lower-case word"),
        ("feat(warden): the supervisor never spawns a denied command", "starts with 'the'"),
        ("feat(warden): Add the supervisor", "starts with 'Add'"),
        ("feat(warden): sandbox lanes and rules", "starts with 'sandbox'"),
        ("fix(cli): refuse a forged journal line.", "full stop"),
        ("fix(cli): refuse a  forged line", "stray spaces"),
        ("fix(cli): refuse a forged line " + chr(0x2014) + " by name", "em dash"),
    ],
)
def test_each_way_a_title_can_be_wrong_is_named(title: str, fragment: str) -> None:
    problems = pr.title_problems(title)
    assert any(fragment in problem for problem in problems), problems


# --- bodies -------------------------------------------------------------------------


def test_a_body_in_the_agreed_shape_passes() -> None:
    assert pr.body_problems(GOOD_BODY) == []


def test_crlf_line_endings_change_nothing() -> None:
    assert pr.body_problems(GOOD_BODY.replace("\n", "\r\n")) == []


@pytest.mark.parametrize(
    "first",
    ["Refs #33, #71: the UDP round is left", "Fixes #9", "No issue: a typo in a comment"],
)
def test_every_way_of_naming_the_issue_is_accepted(first: str) -> None:
    assert pr.body_problems(GOOD_BODY.replace("Closes #12", first)) == []


@pytest.mark.parametrize(
    ("change", "fragment"),
    [
        (lambda b: b.replace("Closes #12", "Closes #"), "names no issue"),
        (lambda b: b.replace("Closes #12\n", ""), "names no issue"),
        (lambda b: b.replace("## Risk", "## Risks"), "missing heading(s): ## Risk"),
        (
            lambda b: b.replace("## Summary", "## TEMP").replace("## Changes", "## Summary")
            .replace("## TEMP", "## Changes"),
            "out of order",
        ),
        (lambda b: b.replace("## Tests", "## Why\nx\n## Notes\ny\n## Tests"), "at most one"),
        (lambda b: b.replace("## Not in scope", "## Notes\nx\n## Not in scope"), "between"),
        (lambda b: b.replace("## Changes", "## How to check by hand\n1. run\n## Changes"),
         "goes last"),
        (lambda b: b + "\n## Summary\nagain\n", "appears twice"),
        (lambda b: b.replace("pytest           1475", "pytest           ___"), "a blank left"),
        (lambda b: b.replace("1475 passed", "all passed"), "no gate numbers"),
        (lambda b: b.replace("| `test_two", "|  |  |  |\n| `test_two"), "every cell empty"),
        (lambda b: b.replace("- Locks", "-\n- Locks"), "empty list item"),
    ],
)  # fmt: skip
def test_each_way_a_body_can_be_wrong_is_named(change: Callable[[str], str], fragment: str) -> None:
    problems = pr.body_problems(change(GOOD_BODY))
    assert any(fragment in problem for problem in problems), problems


def test_a_heading_inside_a_code_block_or_a_comment_is_not_a_heading() -> None:
    body = GOOD_BODY.replace("## Risk", "```\n## Risk\n```\n<!--\n## Risk\n-->")
    assert any("missing heading(s): ## Risk" in p for p in pr.body_problems(body))


def test_the_template_unfilled_is_refused() -> None:
    problems = pr.body_problems(_template())
    assert any("names no issue" in p for p in problems)
    assert any("a blank left" in p for p in problems)
    assert any("every cell empty" in p for p in problems)


def test_the_template_filled_in_passes() -> None:
    """The template can be satisfied: fill every blank and it has the agreed shape."""
    text = _template().replace("Closes #\n", "Closes #1\n")
    text = re.sub(r"___", "7", text)
    text = re.sub(r"^\|(?:\s*\|)+\s*$\n", "", text, flags=re.MULTILINE)
    text = re.sub(r"^(?:-|1\.)\s*$\n", "", text, flags=re.MULTILINE)
    text = re.sub(r"^\| (\w[\w ]*) \|  \|$", r"| \1 | answered |", text, flags=re.MULTILINE)
    assert pr.body_problems(text) == []


def test_the_template_has_the_headings_the_check_requires_in_order() -> None:
    names = re.findall(r"^## (.+)$", _template(), flags=re.MULTILINE)
    assert names == [*pr.REQUIRED, pr.HAND]


def test_the_word_one_letter_from_the_name_is_refused_anywhere() -> None:
    word = "Sk" + "etchy"
    title = "fix(kernel/ledger): refuse a second writer"
    problems = pr.check_text(f"{title}\n\n{GOOD_BODY}\nA {word} edge.\n")
    assert any("one letter from the project's name" in p for p in problems)
    assert pr.check_text(f"{title}\n\n{GOOD_BODY}") == []


def test_a_whole_pr_is_checked_title_first() -> None:
    problems = pr.check_text("feat(kernel): The ledger\n\n" + GOOD_BODY)
    assert problems and all(p.startswith("title: ") for p in problems)
    assert pr.check_text("fix(kernel/ledger): refuse a second writer\n\n" + GOOD_BODY) == []


# --- the command --------------------------------------------------------------------


def _run(*args: str, stdin: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        input=stdin,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )


def test_from_stdin_a_right_pr_exits_0_and_a_wrong_one_exits_1() -> None:
    good = _run("-", stdin="fix(kernel/ledger): refuse a second writer\n\n" + GOOD_BODY)
    bad = _run("-", stdin="the ledger\n\n" + GOOD_BODY)
    assert (good.returncode, bad.returncode) == (0, 1), (good.stdout, bad.stdout)
    assert "not `type(scope): subject`" in bad.stdout


def test_github_that_cannot_be_read_is_never_called_right(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def broken(*_args: object, **_kwargs: object) -> object:
        raise OSError("no gh here")

    monkeypatch.setattr(pr.subprocess, "run", broken)
    assert pr.main(["--github"]) == 2


# --- one shape, written in three places ---------------------------------------------


def _backticked_after(label: str) -> tuple[str, ...]:
    text = CONVENTIONS.read_text("utf-8")
    start = text.index(label)
    paragraph = text[start : text.index("\n\n", start)]
    return tuple(re.findall(r"`([a-z]+)`", paragraph))


def test_the_conventions_list_the_types_the_check_accepts() -> None:
    assert _backticked_after("**Types:**") == pr.TYPES


def test_the_conventions_list_the_areas_the_check_accepts() -> None:
    assert _backticked_after("**Areas:**") == pr.AREAS


def test_ci_runs_the_check_on_every_pr() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text("utf-8")
    assert "python scripts/pr_check.py -" in workflow


def test_no_issue_starts_blank() -> None:
    config = (FORMS / "config.yml").read_text("utf-8")
    assert re.search(r"^blank_issues_enabled: false$", config, flags=re.MULTILINE)


@pytest.mark.parametrize("form", ["build_task.yml", "bug.yml", "spike.yml"])
def test_every_issue_form_requires_its_abuse_cases(form: str) -> None:
    blocks = (FORMS / form).read_text("utf-8").split("  - type: ")
    abuse = [block for block in blocks if "id: abuse_cases" in block]
    assert len(abuse) == 1
    assert "required: true" in abuse[0]
