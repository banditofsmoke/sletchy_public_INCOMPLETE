"""Plane dependency enforcement.

`import-linter` runs in CI and checks the real package. These tests do something it
cannot: they prove the *rules themselves bite*, by running the same analysis against
deliberately-violating fixtures.

That distinction matters. import-linter currently passes partly because the planes
are still small - an analysis over a few dozen modules proves little on its own. A
contract that has never been seen to fail is a hypothesis.
"""

from __future__ import annotations

import ast
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
FIXTURES = REPO / "tests" / "fixtures" / "violations"

#: mind/senses/forge/vault may import kernel + warden. warden/soc may import only
#: kernel. kernel may import nothing from sletchy. apps never touches warden.
FORBIDDEN: dict[str, frozenset[str]] = {
    "kernel": frozenset({"warden", "soc", "mind", "senses", "forge", "vault", "cli"}),
    "warden": frozenset({"soc", "mind", "senses", "forge", "vault", "cli"}),
    "soc": frozenset({"warden", "mind", "senses", "forge", "vault", "cli"}),
    "mind": frozenset({"soc", "senses", "forge", "vault", "cli"}),
    "senses": frozenset({"soc", "mind", "forge", "vault", "cli"}),
    "forge": frozenset({"soc", "mind", "senses", "vault", "cli"}),
    "vault": frozenset({"soc", "mind", "senses", "forge", "cli"}),
    "cli": frozenset({"warden", "soc", "senses", "forge", "vault"}),
}

#: The one door through a forbidden plane: the Shell may reach the Warden only through
#: its supervisor, which decides and records every launch (ADR-0011, #52). Nothing else
#: in the Warden - the sandboxes, fsguard - is reachable from the Shell.
ALLOWED_INTO: dict[str, tuple[str, ...]] = {"cli": ("sletchy.warden.supervisor",)}

#: Only `warden/egress/` may hold a network client. Everywhere else gets a
#: Kernel-provided client pointed at the Warden proxy.
NETWORK_MODULES = frozenset(
    {"socket", "ssl", "http", "urllib", "httpx", "requests", "aiohttp", "websockets", "ftplib"}
)


def imported_names(source: str) -> set[str]:
    """Every module a file imports, as dotted names."""
    names: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names.add(node.module)
    return names


def plane_violations(path: Path, source: str) -> list[str]:
    """Cross-plane imports this file makes that its own plane may not."""
    parts = path.relative_to(REPO / "src" / "sletchy").parts
    if len(parts) < 2:
        return []
    plane = parts[0]
    forbidden = FORBIDDEN.get(plane, frozenset())

    doors = ALLOWED_INTO.get(plane, ())
    found = []
    for name in imported_names(source):
        if not name.startswith("sletchy."):
            continue
        if any(name == door or name.startswith(door + ".") for door in doors):
            continue
        target = name.split(".")[1]
        if target in forbidden:
            found.append(f"{plane} imports {target} ({name})")
    return found


def network_violations(path: Path, source: str) -> list[str]:
    relative = path.relative_to(REPO / "src")
    if relative.parts[:3] == ("sletchy", "warden", "egress"):
        return []
    return [
        f"{relative} imports {name}"
        for name in imported_names(source)
        if name.split(".")[0] in NETWORK_MODULES
    ]


def package_files() -> list[Path]:
    return sorted((REPO / "src" / "sletchy").rglob("*.py"))


# ── the real package obeys the rules ─────────────────────────────────────────


def test_no_plane_imports_upward_or_sideways() -> None:
    found = [v for p in package_files() for v in plane_violations(p, p.read_text("utf-8"))]
    assert found == [], f"plane dependency violations: {found}"


def test_the_kernel_imports_nothing_from_sletchy() -> None:
    """The trust root is the only thing everything else may assume."""
    for path in package_files():
        if path.relative_to(REPO / "src" / "sletchy").parts[0] != "kernel":
            continue
        for name in imported_names(path.read_text("utf-8")):
            if name.startswith("sletchy.") and not name.startswith("sletchy.kernel"):
                pytest.fail(f"{path.name} imports {name}; the kernel imports nothing from sletchy")


def test_only_the_warden_egress_module_may_hold_a_network_client() -> None:
    """Nothing reaches the outside world except through the Warden."""
    found = [v for p in package_files() for v in network_violations(p, p.read_text("utf-8"))]
    assert found == [], f"direct network clients outside warden/egress: {found}"


# ── and the rules are proven to fail ─────────────────────────────────────────


def test_the_plane_check_catches_a_kernel_importing_warden() -> None:
    fixture = FIXTURES / "kernel_imports_warden.py"
    fake = REPO / "src" / "sletchy" / "kernel" / "violation.py"

    found = plane_violations(fake, fixture.read_text("utf-8"))

    assert found, "the plane check did not catch kernel -> warden"
    assert "kernel imports warden" in found[0]


def test_the_plane_check_catches_sibling_imports() -> None:
    fixture = FIXTURES / "soc_imports_warden.py"
    fake = REPO / "src" / "sletchy" / "soc" / "violation.py"

    found = plane_violations(fake, fixture.read_text("utf-8"))

    assert found, "the plane check did not catch soc -> warden"


def test_the_network_check_catches_a_direct_client() -> None:
    fixture = FIXTURES / "mind_direct_network.py"
    fake = REPO / "src" / "sletchy" / "mind" / "violation.py"

    found = network_violations(fake, fixture.read_text("utf-8"))

    assert len(found) == 2, f"expected socket and httpx to be caught, got {found}"


def test_the_network_check_permits_warden_egress() -> None:
    """The one place a client belongs must not be flagged."""
    fixture = FIXTURES / "mind_direct_network.py"
    allowed = REPO / "src" / "sletchy" / "warden" / "egress" / "proxy.py"

    assert network_violations(allowed, fixture.read_text("utf-8")) == []


def test_the_plane_check_catches_the_shell_importing_the_soc() -> None:
    """ADR-0011: the window reads the SOC's findings from the ledger, never its code."""
    fixture = FIXTURES / "cli_imports_soc.py"
    fake = REPO / "src" / "sletchy" / "cli" / "violation.py"

    found = plane_violations(fake, fixture.read_text("utf-8"))

    assert found == ["cli imports soc (sletchy.soc)"]


def test_nothing_imports_the_soc() -> None:
    """ADR-0011: the SOC is a bolt-on, so every other plane is forbidden to import it."""
    for plane, forbidden in FORBIDDEN.items():
        if plane != "soc":
            assert "soc" in forbidden, f"{plane} may import the SOC"


def test_every_fixture_is_a_real_violation() -> None:
    """Guards against a fixture that has quietly stopped violating anything."""
    fixtures = sorted(FIXTURES.glob("*.py"))
    assert len(fixtures) == 4
    for fixture in fixtures:
        assert imported_names(fixture.read_text("utf-8")), f"{fixture.name} imports nothing"


def test_fixtures_are_not_importable_by_the_package() -> None:
    """They must never be reachable from `src/`."""
    assert FIXTURES.is_relative_to(REPO / "tests")
    assert not (REPO / "src").joinpath("tests").exists()


# ── the configured contracts match the ones enforced here ────────────────────


def test_import_linter_is_configured_and_agrees() -> None:
    """A drift check.

    Two mechanisms enforce the same rule - the contracts in pyproject.toml and the
    checks above. If someone loosens one, this notices.
    """
    config = tomllib.loads((REPO / "pyproject.toml").read_text("utf-8"))
    contracts = config["tool"]["importlinter"]["contracts"]

    layered = next(c for c in contracts if c["type"] == "layers")
    assert layered["layers"][-1] == "sletchy.kernel", "the kernel must be the bottom layer"

    forbidden = {c["source_modules"][0]: c for c in contracts if c["type"] == "forbidden"}
    kernel = forbidden["sletchy.kernel"]
    for plane in ("warden", "soc", "mind", "senses", "forge", "vault"):
        assert f"sletchy.{plane}" in kernel["forbidden_modules"]

    # ADR-0011: the Shell's rule is stated once in each mechanism, and they must agree.
    # The Warden is forbidden to the Shell package by package, every one except the door,
    # so a new Warden package (egress, supply) fails this until it is forbidden too.
    shell = forbidden["sletchy.cli"]
    warden = REPO / "src" / "sletchy" / "warden"
    packages = {p.name for p in warden.iterdir() if (p / "__init__.py").is_file()}
    expected = {f"sletchy.{plane}" for plane in FORBIDDEN["cli"] - {"warden"}} | {
        f"sletchy.warden.{name}"
        for name in packages
        if f"sletchy.warden.{name}" not in ALLOWED_INTO["cli"]
    }
    assert set(shell["forbidden_modules"]) == expected
    assert shell.get("allow_indirect_imports") is True, "the door's own imports are its business"


def test_the_shell_may_use_the_supervisor_and_nothing_else_in_the_warden() -> None:
    """ADR-0011 and #52: one door, and it is the one that decides and records."""
    fake = REPO / "src" / "sletchy" / "cli" / "violation.py"
    assert plane_violations(fake, "from sletchy.warden.supervisor import Supervisor\n") == []
    assert plane_violations(fake, "import sletchy.warden.supervisor.supervisor\n") == []
    for other in ("sletchy.warden.isolation", "sletchy.warden.fsguard", "sletchy.warden"):
        assert plane_violations(fake, f"import {other}\n"), other
    assert plane_violations(fake, "from sletchy.warden.supervisorx import y\n")


@pytest.mark.slow
def test_import_linter_passes_on_the_real_package() -> None:
    """Runs the actual tool, so this suite cannot pass while CI fails."""
    result = subprocess.run(
        [sys.executable, "-m", "importlinter.cli", "lint-imports"],
        cwd=REPO,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
