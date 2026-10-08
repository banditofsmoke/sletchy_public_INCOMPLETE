"""LAW 4 for imports: everything third-party is pinned, hashed, licensed to ship (#34, phase 1).

LAW 4 says nothing is trusted, imports included, and #34 calls it the least-honoured law
in the repository. The locks already pinned versions and hashes; nothing checked that they
still did, that CI installed only what they pinned, that a licence allows Uttu to ship it
(ADR-0010), or that the code CI itself runs could not be swapped under a moved tag.

What this does not do yet, and #34 still holds: a vetting record per dependency, known
vulnerabilities, and the quarantine run that watches what a new dependency actually does.
"""

from __future__ import annotations

import importlib.metadata
import json
import re
import shutil
import subprocess
import tomllib
from pathlib import Path

import pytest

pytestmark = [pytest.mark.adversarial, pytest.mark.law_zero]

REPO = Path(__file__).resolve().parents[2]
WORKFLOWS = sorted((REPO / ".github" / "workflows").glob("*.yml"))
UV_LOCK = tomllib.loads((REPO / "uv.lock").read_text("utf-8"))
NPM_LOCK = json.loads((REPO / "apps" / "desktop" / "package-lock.json").read_text("utf-8"))

COMMIT = re.compile(r"^[0-9a-f]{40}$")
USES = re.compile(r"^\s*-?\s*uses:\s*([^\s#]+)", re.MULTILINE)


# ── what CI runs is pinned to a commit, not a tag ────────────────────────────


def pinned(reference: str) -> bool:
    """`owner/repo@<40 hex>`, or a local action. A tag or a branch can be moved."""
    if reference.startswith("./"):
        return True
    _, _, ref = reference.partition("@")
    return bool(COMMIT.match(ref))


def test_every_github_action_is_pinned_to_a_commit() -> None:
    """A moved tag runs someone else's code with this repository's token."""
    assert WORKFLOWS, "no workflows found; the check read nothing"
    uses = [ref for wf in WORKFLOWS for ref in USES.findall(wf.read_text("utf-8"))]
    assert len(uses) >= 5
    assert [ref for ref in uses if not pinned(ref)] == []


def test_the_pin_check_can_fail() -> None:
    """Positive control."""
    assert not pinned("actions/checkout@v4")
    assert not pinned("actions/checkout@main")
    assert not pinned("actions/checkout@11d5960")
    assert pinned("actions/checkout@11d5960a326750d5838078e36cf38b85af677262")


RELEASE_COMMENT = re.compile(r"^\s*-?\s*uses:\s*[^\s#]+@[0-9a-f]{40}\s+#\s*v\d+\.\d+\.\d+\s*$")


def test_every_pin_names_the_exact_release_it_was_taken_from() -> None:
    """A bare hash tells a reviewer nothing. `# v4` names a moving major; `# v4.2.1` names
    the release, which is what the next update is compared against."""
    lines = [
        line for wf in WORKFLOWS for line in wf.read_text("utf-8").splitlines() if USES.match(line)
    ]
    assert len(lines) >= 5
    assert [line.strip() for line in lines if not RELEASE_COMMENT.match(line)] == []
    assert not RELEASE_COMMENT.match("- uses: a/b@" + "0" * 40 + "  # v4"), "positive control"


def test_every_pre_commit_hook_is_pinned_to_a_commit() -> None:
    config = (REPO / ".pre-commit-config.yaml").read_text("utf-8")
    revs = re.findall(r"^\s*rev:\s*([^\s#]+)", config, re.MULTILINE)
    assert revs, "no remote hooks found"
    assert [rev for rev in revs if not COMMIT.match(rev)] == []


# ── CI installs only what the locks pin ──────────────────────────────────────


def test_every_install_in_ci_is_from_the_lock() -> None:
    """`uv sync --locked` refuses a lock that is out of date; `npm ci` refuses one that differs."""
    text = "\n".join(wf.read_text("utf-8") for wf in WORKFLOWS)
    syncs = re.findall(r"uv sync[^\n]*", text)
    assert syncs
    assert [s for s in syncs if "--locked" not in s] == []
    assert "npm install" not in text
    assert "npm ci" in text
    assert not re.search(r"pip install(?![^\n]*--require-hashes)", text)


@pytest.mark.skipif(shutil.which("uv") is None, reason="needs uv on PATH")
def test_a_dependency_added_without_the_lock_is_refused(tmp_path: Path) -> None:
    """The behaviour `--locked` relies on, measured offline in a copy: nothing is fetched."""
    for name in ("pyproject.toml", "uv.lock", "README.md"):
        shutil.copy(REPO / name, tmp_path / name)
    (tmp_path / "src" / "sletchy").mkdir(parents=True)
    shutil.copy(REPO / "src" / "sletchy" / "__init__.py", tmp_path / "src" / "sletchy")

    def check() -> int:
        return subprocess.run(
            ["uv", "lock", "--check", "--offline"],
            cwd=tmp_path,
            capture_output=True,
            check=False,
        ).returncode

    assert check() == 0, "positive control: the copied lock is current"
    project = tmp_path / "pyproject.toml"
    project.write_text(
        project.read_text("utf-8").replace(
            "dependencies = [", 'dependencies = [\n    "six>=1.16",', 1
        ),
        encoding="utf-8",
    )
    assert check() != 0


# ── every package pinned by hash ─────────────────────────────────────────────


def test_every_python_package_is_pinned_by_version_and_hash() -> None:
    packages = [p for p in UV_LOCK["package"] if "editable" not in p.get("source", {})]
    assert len(packages) > 20
    unhashed = []
    for package in packages:
        artifacts = [
            *package.get("wheels", []),
            *([package["sdist"]] if "sdist" in package else []),
        ]
        if not artifacts or not all(a.get("hash", "").startswith("sha256:") for a in artifacts):
            unhashed.append(package["name"])
        assert package.get("version"), package["name"]
    assert unhashed == []


def test_every_crate_is_pinned_by_checksum() -> None:
    lock = tomllib.loads(
        (REPO / "apps" / "desktop" / "src-tauri" / "Cargo.lock").read_text("utf-8")
    )
    from_registry = [p for p in lock["package"] if str(p.get("source", "")).startswith("registry+")]
    assert len(from_registry) > 100
    assert [p["name"] for p in from_registry if not p.get("checksum")] == []


# ── every shipped licence lets Uttu ship it (ADR-0010) ───────────────────────

#: Licences that let Uttu, Apache-2.0, ship a dependency unmodified. Copyleft licences
#: (the GPL family) are not here: they need a decision, never a default.
PERMISSIVE = re.compile(
    r"\b(MIT|BSD|Apache|ISC|PSF|Python Software Foundation|MPL-2\.0|Mozilla Public License 2\.0"
    r"|Unlicense|0BSD|Zlib|CC0)\b",
    re.IGNORECASE,
)
COPYLEFT = re.compile(r"\b(A?GPL|LGPL|General Public License)\b", re.IGNORECASE)


def acceptable(licence: str) -> bool:
    """True when some alternative in the expression is permissive and none forces copyleft."""
    alternatives = re.split(r"\s+OR\s+|\s*\|\s*", licence)
    return any(PERMISSIVE.search(a) and not COPYLEFT.search(a) for a in alternatives)


def python_licence(name: str) -> str | None:
    """What an installed distribution declares, or None if it is not installed here."""
    try:
        metadata = importlib.metadata.metadata(name)
    except importlib.metadata.PackageNotFoundError:
        return None
    if metadata.get("License-Expression"):
        return str(metadata["License-Expression"])
    classifiers = [
        c.split(" :: ")[-1]
        for c in metadata.get_all("Classifier") or []
        if c.startswith("License ::")
    ]
    if classifiers:
        return " | ".join(classifiers)
    declared = (metadata.get("License") or "").strip()
    return declared.splitlines()[0][:80] if declared else "UNKNOWN"


def shipped_python() -> set[str]:
    """The runtime closure of Sletchy's own dependencies; dev tools are not shipped."""
    by_name = {p["name"]: p for p in UV_LOCK["package"]}
    todo = [d["name"] for d in by_name["sletchy"].get("dependencies", [])]
    seen: set[str] = set()
    while todo:
        name = todo.pop()
        if name not in seen:
            seen.add(name)
            todo.extend(d["name"] for d in by_name[name].get("dependencies", []))
    return seen


def test_every_shipped_python_dependency_is_licensed_to_ship() -> None:
    """Checked from installed metadata; packages for another platform are checked on it."""
    shipped = shipped_python()
    assert {"keyring", "pydantic"} <= shipped
    licences = {name: python_licence(name) for name in sorted(shipped)}
    installed = {name: lic for name, lic in licences.items() if lic is not None}
    assert len(installed) >= 8, f"only {len(installed)} checked; the walk is broken"
    assert {name: lic for name, lic in installed.items() if not acceptable(lic)} == {}


def test_every_shipped_npm_dependency_is_licensed_to_ship() -> None:
    shipped = {k: v for k, v in NPM_LOCK["packages"].items() if k and not v.get("dev")}
    assert shipped, "no shipped npm packages found"
    assert {
        k: v.get("license") for k, v in shipped.items() if not acceptable(str(v.get("license")))
    } == {}


# ── every shipped dependency has a written reason (#34 phase 2) ──────────────

RECORD = REPO / "docs" / "supply" / "DEPENDENCIES.md"
RECORD_ROW = re.compile(r"^\|\s*`([^`]+)`\s*\|\s*([^|\s]+)\s*\|", re.MULTILINE)


def recorded(text: str) -> dict[str, str]:
    """Package name to version, from the record's table."""
    rows = RECORD_ROW.findall(text.split("## The record", 1)[-1].split("\n## ", 1)[0])
    return dict(rows)


def unrecorded(record: dict[str, str], shipped: dict[str, str]) -> list[str]:
    """Every way the record and the lock disagree, in words."""
    problems = [
        f"{name} {version} has no row" for name, version in shipped.items() if name not in record
    ]
    problems += [
        f"{name} is recorded at {record[name]}, locked at {version}"
        for name, version in shipped.items()
        if name in record and record[name] != version
    ]
    problems += [f"{name} has a row but does not ship" for name in record if name not in shipped]
    return sorted(problems)


def test_every_shipped_dependency_has_a_vetting_record_at_its_locked_version() -> None:
    """Adding, removing or upgrading a dependency fails until its row says why."""
    by_name = {p["name"]: p["version"] for p in UV_LOCK["package"]}
    shipped = {name: by_name[name] for name in shipped_python()}
    record = recorded(RECORD.read_text("utf-8"))
    assert len(record) >= 10, f"read only {len(record)} rows; the parser is broken"
    assert unrecorded(record, shipped) == []


def test_the_record_check_can_fail() -> None:
    """Positive control: each kind of drift is caught."""
    shipped = {"keyring": "25.7.0", "pydantic": "2.13.4"}
    assert unrecorded({"keyring": "25.7.0", "pydantic": "2.13.4"}, shipped) == []
    assert unrecorded({"keyring": "25.7.0"}, shipped) == ["pydantic 2.13.4 has no row"]
    assert unrecorded({"keyring": "25.6.0", "pydantic": "2.13.4"}, shipped) == [
        "keyring is recorded at 25.6.0, locked at 25.7.0"
    ]
    assert unrecorded({**shipped, "six": "1.16"}, shipped) == ["six has a row but does not ship"]
    table = "## The record\n\n| Package | Version |\n|---|---|\n| `keyring` | 25.7.0 | x |\n\n## Next\n| `six` | 1 |"
    assert recorded(table) == {"keyring": "25.7.0"}, "only the record's own table counts"


@pytest.mark.parametrize(
    ("licence", "ok"),
    [
        ("MIT", True),
        ("Apache-2.0 OR BSD-3-Clause", True),
        ("BSD-3-Clause", True),
        ("PSF-2.0", True),
        ("Apache-2.0 OR MIT", True),
        ("MIT License | Apache Software License", True),
        ("GPL-3.0-only", False),
        ("LGPL-2.1-or-later", False),
        ("AGPL-3.0", False),
        ("GPL-2.0 OR MIT", True),
        ("UNKNOWN", False),
        ("Proprietary", False),
    ],
)
def test_the_licence_check_can_tell_them_apart(licence: str, ok: bool) -> None:
    """Positive and negative controls: a check that passes everything checks nothing."""
    assert acceptable(licence) is ok
