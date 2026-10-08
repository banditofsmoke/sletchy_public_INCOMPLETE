"""The public check is itself a control, so it gets positive and negative controls.

`scripts/public_check.py` reads issue, PR and comment text for private material
before it is posted. A checker that cannot fire is a hypothesis (L001), and one that
fires on ordinary writing gets ignored, so both directions are tested here.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "public_check.py"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("public_check", SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["public_check"] = module
    spec.loader.exec_module(module)
    return module


pc = _load()


def run(*args: str, stdin: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        input=stdin,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )


# ── every marker can fire ────────────────────────────────────────────────────


@pytest.mark.parametrize("marker", pc.MARKERS, ids=lambda m: f"{m.name}:{m.example[:20]}")
def test_every_marker_catches_its_own_example(marker: object) -> None:
    assert marker.example, f"{marker.name} has no example to prove it"  # type: ignore[attr-defined]
    found = pc.check_text(f"before\n{marker.example}\nafter", "t")  # type: ignore[attr-defined]
    assert [f.line for f in found] == [2], marker.example  # type: ignore[attr-defined]


def test_a_credential_is_caught_and_never_printed_whole() -> None:
    key = "gsk_" + "0" * 40 + "A"
    found = pc.check_text(f"token {key}", "t")
    assert len(found) == 1
    assert key not in str(found[0])
    assert "credential" in found[0].marker


# ── ordinary writing trips nothing ───────────────────────────────────────────


@pytest.mark.parametrize(
    "line",
    [
        "I decided this on 2026-10-03.",
        "The operator runs it from the repo folder.",
        r"A path like C:\Users\<name>\AppData is fine as a placeholder.",
        r"C:\var\sletchy-evil must not be accepted as inside C:\var\sletchy",
        "Commits come from 123+Sletch@users.noreply.github.com, or noreply@github.com.",
        "See github.com/Sletch/sletchy/pull/136 for the change.",
        "The UI runs on the main thread.",
        "Uttu Connect: tribes and friends, opt-in.",
        "event, debugging, sebum-free, mentioned",
        "/home/runner/work is the CI checkout",
        "a reason someone@example.com would not reach anyone",
    ],
)
def test_ordinary_writing_trips_no_marker(line: str) -> None:
    assert pc.check_text(line, "t") == []


# ── this machine, read at run time ───────────────────────────────────────────


def test_this_machines_account_name_is_found_and_withheld(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(pc.Path, "home", classmethod(lambda cls: Path("/somewhere/Quillon")))
    monkeypatch.setattr(pc.getpass, "getuser", lambda: "runner")
    monkeypatch.setattr(
        pc, "_public_identity", lambda: "https://git.example.invalid/someorg/repo.git"
    )

    extra = pc.machine_markers()
    found = pc.check_text("logged in as Quillon on the box", "t", extra=extra)

    assert [f.marker for f in found] == ["this machine's account name"]
    assert "Quillon" not in str(found[0]), "the name it found must not be printed"


def test_a_generic_or_public_account_name_is_not_a_finding(monkeypatch: pytest.MonkeyPatch) -> None:
    """`runner` is every CI machine; a name in the repo's own address is already public."""
    monkeypatch.setattr(pc.Path, "home", classmethod(lambda cls: Path("/somewhere/runner")))
    monkeypatch.setattr(pc.getpass, "getuser", lambda: "Someorg")
    monkeypatch.setattr(
        pc, "_public_identity", lambda: "https://git.example.invalid/someorg/repo.git"
    )

    names = [m for m in pc.machine_markers() if m.name == "this machine's account name"]
    assert names == []


def test_the_markers_are_built_from_this_machine_not_stored() -> None:
    """Positive control on the real machine: the folder marker exists on Windows."""
    folders = [m for m in pc.machine_markers() if m.name == "this machine's folders"]
    if pc.ROOT.drive:
        assert len(folders) == 1
        assert folders[0].pattern.search(str(pc.ROOT))
    else:
        assert folders == []


# ── the tracker sweep ────────────────────────────────────────────────────────


def test_titles_bodies_and_comments_are_all_read() -> None:
    items = [
        {
            "number": 7,
            "title": "fine",
            "body": "fine\nthis is my only computer",
            "comments": [{"body": "ok"}, {"body": "the second thread did it"}],
        }
    ]
    found = pc.check_items(items, "issue")
    assert [(f.where, f.line) for f in found] == [("issue #7 body", 2), ("issue #7 comment 2", 1)]


def test_a_tracker_that_cannot_be_read_is_never_reported_clean(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Could not look is an error, never a zero (L009)."""

    def broken(*_: object, **__: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="auth failed")

    monkeypatch.setattr(pc.subprocess, "run", broken)
    monkeypatch.setattr(pc, "machine_markers", lambda: ())
    assert pc.main(["--github"]) == 2


@pytest.mark.parametrize("stdout", ["", "<html>rate limited</html>", '{"not": "a list"}'])
def test_an_answer_that_is_not_a_list_is_never_reported_clean(
    monkeypatch: pytest.MonkeyPatch, stdout: str
) -> None:
    def odd(*_: object, **__: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(args=[], returncode=0, stdout=stdout, stderr="")

    monkeypatch.setattr(pc.subprocess, "run", odd)
    monkeypatch.setattr(pc, "machine_markers", lambda: ())
    assert pc.main(["--github"]) == 2


def test_text_that_is_not_ascii_is_read_as_utf8() -> None:
    result = run("-", stdin="section § 5 and an arrow →, all fine\n")
    assert result.returncode == 0, result.stdout + result.stderr


# ── the command line ─────────────────────────────────────────────────────────


def test_clean_text_exits_zero() -> None:
    result = run("-", stdin="I decided this.\n")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "clean" in result.stdout


def test_private_text_exits_one_and_names_the_line() -> None:
    result = run("-", stdin="fine\nthe archive holds live API keys\n")
    assert result.returncode == 1
    assert "stdin:2: the private archive" in result.stdout


def test_nothing_to_check_is_a_usage_error() -> None:
    assert run().returncode == 2
