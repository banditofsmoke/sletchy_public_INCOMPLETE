#!/usr/bin/env python3
"""Check that a PR's title and body have the agreed shape.

The title becomes the subject of the commit on `main`, and the body is what a reviewer
reads to decide. Both have a written shape (docs/LAW/writing-conventions.md, section 2),
and a shape that is only written down drifts: titles had grown into sentences past the
length limit, and docs-only PRs carried empty tables. This checks what can be checked.

    python scripts/pr_check.py pr.md        # the title, a blank line, then the body
    python scripts/pr_check.py -            # the same, on stdin (what CI sends)
    python scripts/pr_check.py --github     # every PR title already posted

A title is `type(scope): subject`:

- `type` is one of TYPES
- `scope` is one or more comma-joined areas, each one of AREAS or `area/module`
- `subject` starts with an imperative verb from VERBS, in lower case, and does not end
  in a full stop
- the whole title is at most MAX_TITLE characters

A body names its issue on its first line, has the REQUIRED headings in order, and keeps
no unfilled part of the template. `--github` checks titles only: bodies posted before
this check had other headings, and one is reshaped when it is next touched.

Exit 0 = the shape is right, 1 = it is not, 2 = could not look (never read as right, L009).

Standard library only, like `public_check.py`, so CI runs it with a bare Python.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

TYPES = ("feat", "fix", "perf", "refactor", "test", "docs", "ci", "chore", "spike")

#: The planes, then the parts of the repository that are not a plane.
AREAS = (
    "kernel",
    "warden",
    "soc",
    "mind",
    "senses",
    "forge",
    "vault",
    "cli",
    "desktop",
    "docs",
    "adr",
    "deps",
    "ci",
    "tests",
)

MAX_TITLE = 72

#: Imperative verbs a subject may start with. A missing verb is added here, in the same
#: change that first needs it; a noun or a sentence ("the gate ...") never is.
VERBS = frozenset(
    {
        "add", "allow", "anchor", "apply", "ask", "bind", "block", "build", "bump", "cache",
        "cap", "catch", "check", "clarify", "clean", "close", "collect", "confine", "correct",
        "count", "cover", "cut", "decide", "delete", "deny", "describe", "detect",
        "document", "drop", "enforce", "explain", "expose", "extract", "file", "fix", "flag",
        "gate", "grant", "guard", "handle", "harden", "hide", "hold", "import", "install",
        "keep", "label", "launch", "license", "limit", "list", "load", "lock", "log",
        "lower", "make", "mark", "mask", "measure", "merge", "move", "name", "note", "open",
        "pin", "point", "probe", "prove", "publish", "pull", "raise", "read", "rebuild",
        "record", "reduce", "refresh", "refuse", "reject", "remove", "rename", "render",
        "replace", "report", "require", "reset", "reshape", "restore", "restrict", "retry",
        "return", "revert", "rewrite", "rotate", "route", "run", "scan", "seal", "separate",
        "shield", "show", "sign", "simplify", "skip", "speed", "split", "start", "stop",
        "support", "sweep", "switch", "test", "tighten", "track", "trim", "turn", "undo",
        "unify", "update", "upgrade", "use", "validate", "verify", "wire", "write",
    }
)  # fmt: skip

#: The body's headings, in this order. HAND may follow them; one other may sit between
#: Changes and Tests, for the decision a reviewer should challenge.
REQUIRED = ("Summary", "Changes", "Tests", "Risk", "Not in scope")
HAND = "How to check by hand"

TITLE = re.compile(r"^(?P<type>[^(:\s]+)\((?P<scope>[^()]*)\): (?P<subject>.*)$")
MODULE = re.compile(r"^[a-z][a-z0-9-]*$")
ISSUE_LINE = re.compile(r"^(?:(?:Closes|Fixes|Resolves|Refs) #\d+|No issue: \S)")
GATE_LINE = re.compile(r"^pytest\s+\d+ passed", re.MULTILINE)
COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)
FENCE = re.compile(r"^(```|~~~)")
EMPTY_ROW = re.compile(r"^\|(?:\s*\|)+\s*$")
EMPTY_ITEM = re.compile(r"^(?:[-*]|\d+\.)\s*$")
#: Built from its code point, so this file never contains the character it bans.
EM_DASH = chr(0x2014)
#: The word one letter from the project's name, which the operator asked never to see.
LOOKALIKE = re.compile("sk" + "etch" + "y", re.IGNORECASE)


class CouldNotLook(Exception):
    """GitHub could not be read, so nothing can be called the right shape."""


def title_problems(title: str) -> list[str]:
    """Everything wrong with one title; empty means it has the shape."""
    found: list[str] = []
    if len(title) > MAX_TITLE:
        found.append(f"{len(title)} characters; at most {MAX_TITLE}")
    if EM_DASH in title:
        found.append("an em dash; write ' - '")
    match = TITLE.match(title)
    if match is None:
        found.append("not `type(scope): subject`")
        return found
    if match["type"] not in TYPES:
        found.append(f"type {match['type']!r} is not one of {', '.join(TYPES)}")
    for part in match["scope"].split(","):
        area, slash, module = part.partition("/")
        if area not in AREAS:
            found.append(f"scope {part!r}: {area!r} is not one of {', '.join(AREAS)}")
        elif slash and not MODULE.match(module):
            found.append(f"scope {part!r}: the module must be one lower-case word")
    subject = match["subject"]
    first = subject.split(" ", 1)[0]
    if first not in VERBS:
        found.append(
            f"the subject starts with {first!r}, not an imperative verb in lower case"
            " (VERBS in scripts/pr_check.py; add a verb there if one is missing)"
        )
    if subject.endswith("."):
        found.append("the subject ends in a full stop")
    if subject != subject.strip() or "  " in subject:
        found.append("stray spaces in the subject")
    return found


def _visible(body: str) -> list[str]:
    """The body's lines as GitHub shows them: comments removed, line endings normalised."""
    return COMMENT.sub("", body.replace("\r\n", "\n")).split("\n")


def body_problems(body: str) -> list[str]:
    """Everything wrong with one body; empty means it has the shape."""
    lines = _visible(body)
    found: list[str] = []

    first = next((line.strip() for line in lines if line.strip()), "")
    if not ISSUE_LINE.match(first):
        found.append(
            "the first line names no issue: 'Closes #N', 'Refs #N', or 'No issue: <reason>'"
        )

    headings: list[tuple[str, int]] = []
    sections: dict[str, list[str]] = {}
    current: list[str] = []
    fenced = False
    for line in lines:
        if FENCE.match(line.strip()):
            fenced = not fenced
        elif not fenced and line.startswith("## "):
            name = line[3:].strip()
            headings.append((name, len(headings)))
            current = sections.setdefault(name, [])
            continue
        current.append(line)
        if not fenced and EMPTY_ROW.match(line.strip()):
            found.append("a table row with every cell empty: fill it or delete it")
        if not fenced and EMPTY_ITEM.match(line.strip()):
            found.append("an empty list item: fill it or delete it")
        if "___" in line:
            found.append(f"a blank left in the template: {line.strip()[:60]!r}")

    names = [name for name, _ in headings]
    missing = [name for name in REQUIRED if name not in names]
    if missing:
        found.append(f"missing heading(s): {', '.join('## ' + name for name in missing)}")
    else:
        positions = [names.index(name) for name in REQUIRED]
        if positions != sorted(positions):
            found.append(f"headings out of order; the order is {', '.join(REQUIRED)}")
    extra = [name for name in names if name not in REQUIRED and name != HAND]
    if len(extra) > 1:
        found.append(f"{len(extra)} extra sections ({', '.join(extra)}); at most one")
    elif extra and not missing:
        at = names.index(extra[0])
        if not names.index("Changes") < at < names.index("Tests"):
            found.append(f"the extra section {extra[0]!r} goes between Changes and Tests")
    if HAND in names and not missing and names.index(HAND) < names.index("Not in scope"):
        found.append(f"'{HAND}' goes last")
    if len(names) != len(set(names)):
        found.append("a heading appears twice")

    if "Tests" in sections and not GATE_LINE.search("\n".join(sections["Tests"])):
        found.append("## Tests has no gate numbers: a line 'pytest  N passed, M skipped'")
    return found


def check_text(text: str) -> list[str]:
    """A PR as CI sends it: the title, a blank line, then the body."""
    title, _, body = text.replace("\r\n", "\n").partition("\n")
    found = [f"title: {problem}" for problem in title_problems(title.strip())]
    found += [f"body: {problem}" for problem in body_problems(body)]
    if LOOKALIKE.search(text):
        found.append("the word one letter from the project's name; use another")
    return found


def fetch_titles() -> list[tuple[int, str]]:
    """Every PR's number and title, open, closed and merged."""
    try:
        result = subprocess.run(
            ["gh", "pr", "list", "--state", "all", "--limit", "1000",  # noqa: S607
             "--json", "number,title"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=False,
        )  # fmt: skip
    except OSError as exc:
        raise CouldNotLook(f"gh could not run: {exc}") from exc
    if result.returncode != 0:
        raise CouldNotLook(f"gh pr list failed: {result.stderr.strip()[:200]}")
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise CouldNotLook(f"gh pr list returned something that is not JSON: {exc}") from exc
    if not isinstance(data, list):
        raise CouldNotLook(f"gh pr list returned {type(data).__name__}, not a list")
    return [(int(item["number"]), str(item["title"])) for item in data]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check a PR's title and body shape.")
    parser.add_argument("path", nargs="?", help="title, blank line, body; or - for stdin")
    parser.add_argument("--github", action="store_true", help="every PR title on GitHub")
    args = parser.parse_args(argv)
    if args.path is None and not args.github:
        parser.error("give a file, -, or --github")

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    found: list[str] = []
    if args.path is not None:
        if args.path == "-":
            text = sys.stdin.buffer.read().decode("utf-8", errors="replace")
        else:
            text = Path(args.path).read_text("utf-8")
        found += check_text(text)
    if args.github:
        try:
            titles = fetch_titles()
        except CouldNotLook as exc:
            print(f"pr check: could not look: {exc}", file=sys.stderr)
            return 2
        for number, title in sorted(titles):
            found += [f"#{number} {title!r}: {problem}" for problem in title_problems(title)]

    for problem in found:
        print(problem)
    if found:
        print(f"\npr check: {len(found)} problem(s).", file=sys.stderr)
        return 1
    print("pr check: the shape is right")
    return 0


if __name__ == "__main__":
    sys.exit(main())
