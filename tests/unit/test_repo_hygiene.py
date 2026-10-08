"""Repo-wide rules that only hold if something checks them.

A rule written in a conventions doc and checked by nobody is the L005 failure: it
reads as enforced and is not. Each rule here was a written convention first.

Every check walks `git ls-files`, so it sees exactly what would be published, and
every check asserts it actually scanned something. A hygiene test that passes
because it read zero files is a positive-control failure (L001), not a pass.
"""

from __future__ import annotations

import importlib.util
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]

# Built from code points so this file never contains the character it bans.
EM_DASH = chr(0x2014)
EN_DASH = chr(0x2013)


def tracked_files() -> list[Path]:
    out = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files", "-z"],
        capture_output=True,
        check=True,
    ).stdout.decode("utf-8")
    return [ROOT / p for p in out.split("\0") if p]


def tracked_text() -> dict[Path, str]:
    texts: dict[Path, str] = {}
    for path in tracked_files():
        try:
            texts[path] = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, FileNotFoundError):
            continue  # binary, or deleted in the working tree
    return texts


def em_dash_lines(text: str) -> list[int]:
    return [n for n, line in enumerate(text.splitlines(), 1) if EM_DASH in line]


# --- no em dashes ------------------------------------------------------------


def test_detector_finds_an_em_dash() -> None:
    """Positive control: the detector must be able to fail."""
    assert em_dash_lines(f"clean\nnot {EM_DASH} clean\n") == [2]
    assert em_dash_lines(f"a - b, a -- b, a {EN_DASH} b") == []


def test_no_em_dashes_in_tracked_files() -> None:
    texts = tracked_text()
    assert len(texts) > 100, f"scanned only {len(texts)} files; the walk is broken"
    offenders = [
        f"{path.relative_to(ROOT)}:{n}" for path, text in texts.items() for n in em_dash_lines(text)
    ]
    assert not offenders, "em dash found; write ' - ' instead:\n" + "\n".join(offenders)


# --- one word, never ---------------------------------------------------------

#: The English word one letter from the project's name. The operator asked never to see
#: it (2026-10-05). Built from pieces, so this file never contains it.
LOOKALIKE = re.compile("sk" + "etch" + "y", re.IGNORECASE)


def test_detector_finds_the_lookalike() -> None:
    """Positive control, and the near miss that must pass."""
    assert LOOKALIKE.search("a " + "SK" + "ETCHY" + " plan")
    assert not LOOKALIKE.search("a sketch of the plan")


def test_the_lookalike_is_in_no_tracked_file() -> None:
    offenders = [
        str(path.relative_to(ROOT))
        for path, text in tracked_text().items()
        if LOOKALIKE.search(text)
    ]
    assert not offenders, "the word one letter from the project's name: " + ", ".join(offenders)


# --- in my own voice ---------------------------------------------------------

#: My first name. The repository reads in my own voice, so it never names me in the
#: third person (2026-10-07, writing-conventions section 0.2); "the operator" is the
#: role. Built from pieces, so this file never contains it. A copyright notice is the
#: one place a name belongs.
MY_NAME = re.compile(r"\b" + "Way" + r"ne\b")
NAMED_FOR_COPYRIGHT = frozenset({"LICENSE", "NOTICE"})


def test_detector_finds_my_name() -> None:
    """Positive control, and the near miss that must pass."""
    assert MY_NAME.search("Way" + "ne decided this.")
    assert not MY_NAME.search("I decided this, by the " + "way" + "; next week.")


def test_my_name_is_in_no_tracked_file() -> None:
    offenders = [
        str(path.relative_to(ROOT))
        for path, text in tracked_text().items()
        if path.name not in NAMED_FOR_COPYRIGHT and MY_NAME.search(text)
    ]
    assert not offenders, "write it in my own voice (section 0.2): " + ", ".join(offenders)


# --- every internal markdown link resolves -----------------------------------

LINK = re.compile(r"\[[^\]]*\]\(([^)\s]+)\)")
HEADING = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$")
EXPLICIT_ANCHOR = re.compile(r"<a\s+(?:id|name)=\"([^\"]+)\"")
FENCE = re.compile(r"^\s*(```|~~~)")


def github_slug(heading: str) -> str:
    """The anchor GitHub generates for a heading.

    Link syntax collapses to its text, then everything that is not a word
    character, a space, or a hyphen is dropped, and spaces become hyphens.
    """
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", heading).strip().lower()
    text = re.sub(r"[^\w\- ]", "", text)
    return text.replace(" ", "-")


def outside_fences(text: str) -> list[str]:
    lines, fenced = [], False
    for line in text.splitlines():
        if FENCE.match(line):
            fenced = not fenced
            continue
        if not fenced:
            lines.append(line)
    return lines


def anchors_in(text: str) -> set[str]:
    anchors: set[str] = set()
    seen: dict[str, int] = {}
    for line in outside_fences(text):
        anchors.update(EXPLICIT_ANCHOR.findall(line))
        m = HEADING.match(line)
        if not m:
            continue
        slug = github_slug(m.group(2))
        count = seen.get(slug, 0)
        anchors.add(slug if count == 0 else f"{slug}-{count}")
        seen[slug] = count + 1
    return anchors


def broken_links(md: Path, text: str) -> list[str]:
    broken = []
    for line in outside_fences(text):
        for target in LINK.findall(line):
            if re.match(r"^[a-z]+:", target):  # http:, https:, mailto:
                continue
            path_part, _, anchor = target.partition("#")
            dest = (md.parent / path_part).resolve() if path_part else md
            if not dest.exists():
                broken.append(f"{target} (no such path)")
                continue
            if anchor and dest.suffix == ".md":
                if anchor not in anchors_in(dest.read_text(encoding="utf-8")):
                    broken.append(f"{target} (no such anchor)")
    return broken


def test_slug_matches_github() -> None:
    assert github_slug("13. Under the hood - the engineering") == (
        "13-under-the-hood---the-engineering"
    )
    assert github_slug("LAW 0 - Do no harm to the host machine") == (
        "law-0---do-no-harm-to-the-host-machine"
    )
    assert github_slug("`sletchy panic`") == "sletchy-panic"


def test_link_checker_catches_a_dead_anchor(tmp_path: Path) -> None:
    """Positive control: a dead anchor and a dead path must both be reported."""
    md = tmp_path / "a.md"
    md.write_text("# Real heading\n[ok](#real-heading) [bad](#nope) [gone](missing.md)\n")
    assert broken_links(md, md.read_text()) == [
        "#nope (no such anchor)",
        "missing.md (no such path)",
    ]


@pytest.mark.parametrize("ignored", ["```", "~~~"])
def test_link_checker_ignores_code_fences(tmp_path: Path, ignored: str) -> None:
    md = tmp_path / "a.md"
    md.write_text(f"{ignored}\n[x](#not-a-real-link)\n{ignored}\n")
    assert broken_links(md, md.read_text()) == []


def test_every_internal_markdown_link_resolves() -> None:
    mds = {p: t for p, t in tracked_text().items() if p.suffix == ".md"}
    assert len(mds) > 20, f"scanned only {len(mds)} markdown files; the walk is broken"
    offenders = [
        f"{path.relative_to(ROOT)}: {b}"
        for path, text in mds.items()
        for b in broken_links(path, text)
    ]
    assert not offenders, "broken internal links:\n" + "\n".join(offenders)


# --- Sletchy stands on its own -----------------------------------------------
#
# My rule, 2026-10-02: no reference to the outside design docs Sletchy was first measured
# against, or to their author, anywhere in this repo, ever. Sletchy's laws are its own
# (ADR-0007). The list lives in `scripts/public_check.py`, which holds issue and PR
# text to the same rule (LAW 6: one list), assembled from pieces so neither file
# contains the terms.


def _outside_references() -> tuple[re.Pattern[str], ...]:
    spec = importlib.util.spec_from_file_location(
        "public_check_for_hygiene", ROOT / "scripts" / "public_check.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses look their module up while loading
    spec.loader.exec_module(module)
    patterns = module.OUTSIDE_REFERENCES
    assert isinstance(patterns, tuple)
    return patterns


OUTSIDE_REFERENCES = _outside_references()


def outside_reference_lines(text: str) -> list[int]:
    return [
        n
        for n, line in enumerate(text.splitlines(), 1)
        if any(p.search(line) for p in OUTSIDE_REFERENCES)
    ]


def test_detector_finds_an_outside_reference() -> None:
    """Positive control: every pattern must be able to fire, and ordinary words must not."""
    planted = ["E" + "VT", "S" + "eb", "S" + "eb" + "astien", "Gre" + "ef", "men" + "tor"]
    for word in planted:
        assert outside_reference_lines(f"clean\nsee {word} here\n") == [2], word
    assert outside_reference_lines("event, debugging, sebum-free, mentioned") == []


def test_no_outside_references_in_tracked_files() -> None:
    texts = tracked_text()
    assert len(texts) > 100, f"scanned only {len(texts)} files; the walk is broken"
    offenders = [
        f"{path.relative_to(ROOT)}:{n}"
        for path, text in texts.items()
        for n in outside_reference_lines(text)
    ]
    assert not offenders, "outside design-doc reference found:\n" + "\n".join(offenders)
