#!/usr/bin/env python3
"""Keep private material out of issues, PRs, commits and comments.

Everything posted to the tracker is written for a public reader, even while the
repository is private (docs/LAW/writing-conventions.md, "Written for a public reader").
A tracker is the first thing anyone studying a project reads, so it is also
reconnaissance: a home-folder path names an account, a remark about the machine says
how much an outage would cost its owner, and a pointer to an old archive says where
keys once leaked. GitHub keeps the earlier text of every edited body and comment.

Run it before posting, and over everything already posted:

    python scripts/public_check.py body.md            # a file you are about to post
    python scripts/public_check.py -                  # stdin
    python scripts/public_check.py --github           # every issue, PR and comment

Exit 0 = clean, 1 = findings, 2 = could not look (never read as clean, L009).

Standard library only, like `secret_scan.py`, so CI runs it with a bare Python. On a
developer machine it also looks for this machine's own account name and the folder
the checkout lives in, both read at run time so neither is ever written in this file.
"""

from __future__ import annotations

import argparse
import getpass
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from secret_scan import PATTERNS as SECRET_PATTERNS
from secret_scan import mask

ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class Marker:
    """One kind of private material, with an example it must catch."""

    name: str
    why: str
    pattern: re.Pattern[str]
    example: str


def _p(text: str) -> re.Pattern[str]:
    return re.compile(text, re.IGNORECASE)


#: Words assembled from pieces, so this file does not contain what it bans.
_OUTSIDE = [
    re.compile(r"\b" + "E" + "VT" + r"\b"),
    re.compile(r"\b" + "S" + "eb" + r"\b"),
    re.compile("S" + "eb" + "astien", re.IGNORECASE),
    re.compile("Gre" + "ef", re.IGNORECASE),
    re.compile("men" + "tor", re.IGNORECASE),
    re.compile("agentic" + "_platform", re.IGNORECASE),
    re.compile("treat as " + "LAW", re.IGNORECASE),
    re.compile("SOURCES" + r"\.md"),
]

#: The outside design docs Sletchy was first measured against, and their author.
#: Sletchy's laws are its own (ADR-0007); `tests/unit/test_repo_hygiene.py` holds the
#: tracked files to the same list.
OUTSIDE_REFERENCES: tuple[re.Pattern[str], ...] = tuple(_OUTSIDE)
_OUTSIDE_EXAMPLES = (
    "E" + "VT",
    "S" + "eb",
    "S" + "eb" + "astien",
    "Gre" + "ef",
    "men" + "tor",
    "agentic" + "_platform",
    "treat as " + "LAW",
    "SOURCES" + ".md",
)

MARKERS: tuple[Marker, ...] = (
    Marker(
        "a home folder",
        "names an account on a real machine, and where its files are",
        _p(r"\b[A-Z]:[\\/]+Users[\\/]+(?!<|Public\b|Default\b|All Users\b)[^\\/\s`'\"<>]+"),
        "C:\\Users\\someone\\Desktop",
    ),
    Marker(
        "a home folder",
        "names an account on a real machine, and where its files are",
        _p(r"(?<![\w.~])/(?:home|Users)/(?!<|runner\b)[A-Za-z0-9_.-]+"),
        "/home/someone/projects",
    ),
    Marker(
        "an email address",
        "reaches a person directly",
        _p(
            r"\b(?!no-?reply@)[\w.+-]+@(?!(?:users\.)?noreply\.github\.com\b|example\.(?:com|org|net)\b)"
            r"[\w-]+(?:\.[\w-]+)+"
        ),
        "someone@mail.test",
    ),
    Marker(
        "personal circumstances",
        "about the maintainer's life, not the code; tells an attacker what an outage costs",
        _p(r"\bincome\b|\bonly (?:computer|pc|machine|laptop)\b|\bsecond[- ]hand\b"),
        "this is the operator's only computer",
    ),
    Marker(
        "my name in the third person",
        "the repository reads in my own voice: write I or my, or the operator for the role",
        re.compile(r"\b" + "Way" + r"ne\b"),
        "Way" + "ne decided this",
    ),
    Marker(
        "the private archive",
        "points at where credentials once leaked",
        _p(r"Scraps and Parts|CREDENTIALS-TO-ROTATE|\blive (?:api )?keys?\b"),
        "the archive holds live API keys",
    ),
    Marker(
        "internal session talk",
        "process notes a public reader cannot use",
        _p(r"\bsecond thread\b|\bthird thread\b|\bagency[- ]site session\b|SECOND-THREAD-PROMPT"),
        "the second thread fixed it",
    ),
    Marker(
        "words written in heat",
        "read forever by people who were not there",
        _p(r"\b" + "fu" + r"ck\w*|\b" + "sh" + r"it\b|\b" + "wt" + r"f\b"),
        "what the " + "fu" + "ck",
    ),
    *(
        Marker("an outside reference", "Sletchy's laws are its own (ADR-0007)", p, example)
        for p, example in zip(OUTSIDE_REFERENCES, _OUTSIDE_EXAMPLES, strict=True)
    ),
)

#: Account names too generic to mean anyone: CI runners and containers use these.
_GENERIC_ACCOUNTS = frozenset(
    {"runner", "runneradmin", "root", "user", "admin", "administrator", "vscode", "codespace"}
)


def _public_identity() -> str:
    """The repository's own address: a name in it is already public."""
    try:
        result = subprocess.run(  # noqa: S603 - a fixed git command, no outside input
            ["git", "-C", str(ROOT), "remote", "get-url", "origin"],  # noqa: S607
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return ""
    return result.stdout.strip().lower()


def machine_markers() -> tuple[Marker, ...]:
    """This machine's account names and the checkout's folder, read now, never stored."""
    public = _public_identity()
    names = {Path.home().name}
    try:
        names.add(getpass.getuser())
    except (OSError, KeyError):
        pass  # no account name to read, so none to look for
    markers = [
        Marker(
            "this machine's account name",
            "names the account on the machine this was written on",
            re.compile(r"(?<![\w-])" + re.escape(name) + r"(?![\w-])"),
            name,
        )
        for name in sorted(names)
        if name and name.lower() not in _GENERIC_ACCOUNTS and name.lower() not in public
    ]
    # On Windows, the drive and the first folder of the checkout. A POSIX home folder
    # is already covered by the home-folder marker above.
    if ROOT.drive and len(ROOT.parts) > 1:
        folder = str(Path(*ROOT.parts[:2]))
        loose = re.escape(ROOT.drive) + r"[\\/]+" + re.escape(ROOT.parts[1])
        markers.append(
            Marker(
                "this machine's folders",
                "maps the maintainer's disk",
                re.compile(loose, re.IGNORECASE),
                folder,
            )
        )
    return tuple(markers)


@dataclass(frozen=True)
class Finding:
    where: str
    line: int
    marker: str
    why: str
    shown: str

    def __str__(self) -> str:
        return f"{self.where}:{self.line}: {self.marker} - {self.why}: {self.shown}"


def check_text(text: str, where: str, *, extra: tuple[Marker, ...] = ()) -> list[Finding]:
    """Every private thing in `text`, with secrets masked and machine names withheld."""
    findings: list[Finding] = []
    for number, line in enumerate(text.splitlines(), 1):
        for marker in (*MARKERS, *extra):
            for match in marker.pattern.finditer(line):
                shown = "[withheld]" if marker in extra else match.group(0)[:60]
                findings.append(Finding(where, number, marker.name, marker.why, shown))
        for name, pattern in SECRET_PATTERNS:
            for match in pattern.finditer(line):
                findings.append(
                    Finding(
                        where, number, f"a {name} credential", "never posted", mask(match.group(0))
                    )
                )
    return findings


def check_items(
    items: list[dict[str, object]], kind: str, *, extra: tuple[Marker, ...] = ()
) -> list[Finding]:
    """An issue or PR list as `gh ... --json number,title,body,comments` returns it."""
    findings: list[Finding] = []
    for item in items:
        number = item.get("number")
        findings += check_text(str(item.get("title") or ""), f"{kind} #{number} title", extra=extra)
        findings += check_text(str(item.get("body") or ""), f"{kind} #{number} body", extra=extra)
        comments = item.get("comments") or []
        if not isinstance(comments, list):
            comments = []
        for index, comment in enumerate(comments, 1):
            body = comment.get("body", "") if isinstance(comment, dict) else ""
            findings += check_text(str(body), f"{kind} #{number} comment {index}", extra=extra)
    return findings


class CouldNotLook(RuntimeError):
    """The tracker could not be read. Never reported as clean."""


def fetch(kind: str) -> list[dict[str, object]]:
    try:
        result = subprocess.run(  # noqa: S603 - kind is "issue" or "pr", set below
            ["gh", kind, "list", "--state", "all", "--limit", "1000",  # noqa: S607
             "--json", "number,title,body,comments"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            cwd=ROOT,
        )  # fmt: skip
    except OSError as exc:
        raise CouldNotLook(f"gh could not run: {exc}") from exc
    if result.returncode != 0:
        raise CouldNotLook(f"gh {kind} list failed: {result.stderr.strip()[:200]}")
    try:
        data = json.loads(result.stdout or "")
    except json.JSONDecodeError as exc:
        raise CouldNotLook(f"gh {kind} list returned something that is not JSON: {exc}") from exc
    if not isinstance(data, list):
        raise CouldNotLook(f"gh {kind} list returned {type(data).__name__}, not a list")
    return data


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Find private material before it is posted.")
    parser.add_argument("paths", nargs="*", help="files to check, or - for stdin")
    parser.add_argument("--github", action="store_true", help="every issue, PR and comment")
    args = parser.parse_args(argv)
    if not args.paths and not args.github:
        parser.error("give a file, -, or --github")

    # Tracker text is UTF-8 whatever the console's code page is.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    extra = machine_markers()
    findings: list[Finding] = []
    for path in args.paths:
        if path == "-":
            text = sys.stdin.buffer.read().decode("utf-8", errors="replace")
        else:
            text = Path(path).read_text("utf-8")
        findings += check_text(text, "stdin" if path == "-" else path, extra=extra)
    if args.github:
        try:
            for kind in ("issue", "pr"):
                findings += check_items(fetch(kind), kind, extra=extra)
        except CouldNotLook as exc:
            print(f"public check: could not look: {exc}", file=sys.stderr)
            return 2

    for finding in findings:
        print(finding)
    if findings:
        print(
            f"\npublic check: {len(findings)} finding(s). Rewrite them before posting.",
            file=sys.stderr,
        )
        return 1
    print("public check: clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
