#!/usr/bin/env python3
"""Block API keys from entering the repo.

Runs as a pre-commit hook (staged files) and in CI (whole tree). The patterns are
drawn from what actually leaked across the archived projects - see
docs/salvage/CREDENTIALS-TO-ROTATE.md. Six keys across three providers, live when
found, one of them spread to eight files including a packaged Electron build. All six
have been dead since 2026-10-08.

Exit 0 = clean, exit 1 = findings. Findings are printed with the value masked; this
script never writes a secret to stdout in full.
"""

from __future__ import annotations

import argparse
import importlib.util
import subprocess
import sys
from pathlib import Path
from types import ModuleType

#: The one list of secret shapes (LAW 6), which Sletchy also masks with before it prints
#: anything (#86). Loaded by its path: CI runs this script with a bare Python and no
#: installed package, and that file imports nothing from Sletchy so it can be.
SHAPES_FILE = (
    Path(__file__).resolve().parents[1] / "src" / "sletchy" / "kernel" / "secrets" / "shapes.py"
)


def _load_shapes() -> ModuleType:
    spec = importlib.util.spec_from_file_location("sletchy_secret_shapes", SHAPES_FILE)
    if spec is None or spec.loader is None:
        sys.exit(f"secret scan: cannot load the secret shapes from {SHAPES_FILE}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


_SHAPES = _load_shapes()
PATTERNS = _SHAPES.PATTERNS
FALLBACK_DEFAULT = _SHAPES.FALLBACK_DEFAULT
mask = _SHAPES.mask

SKIP_DIRS = {
    ".git",
    "Scraps and Parts",
    "var",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    ".ruff_cache",
    ".mypy_cache",
    ".pytest_cache",
    "dist",
    "build",
}
SCAN_SUFFIXES = {
    ".py",
    ".js",
    ".ts",
    ".tsx",
    ".jsx",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".md",
    ".txt",
    ".env",
    ".cfg",
    ".ini",
    ".sh",
    ".ps1",
    ".html",
    ".ipynb",
}

# Lines carrying this marker are test fixtures asserting the scanner works.
ALLOW_MARKER = "secret-scan: allow"


def scan_text(text: str, path: Path) -> list[str]:
    findings: list[str] = []
    for lineno, line in enumerate(text.splitlines(), 1):
        if ALLOW_MARKER in line:
            continue
        for name, pattern in PATTERNS:
            for m in pattern.finditer(line):
                findings.append(f"{path}:{lineno}  {name}  {mask(m.group(0))}")
        if FALLBACK_DEFAULT.search(line):
            findings.append(
                f"{path}:{lineno}  secret as env-lookup fallback default "
                f"- fail closed instead (LAW: kernel/secrets)"
            )
    return findings


def iter_paths(explicit: list[str]) -> list[Path]:
    if explicit:
        return [Path(p) for p in explicit if Path(p).is_file()]
    out: list[Path] = []
    for p in Path().rglob("*"):
        if not p.is_file() or p.suffix.lower() not in SCAN_SUFFIXES:
            continue
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        out.append(p)
    return out


def staged_paths() -> list[str]:
    # S607: git is resolved from PATH on purpose - this hook runs inside a git
    # invocation, so git is by definition present and is the one the user is using.
    r = subprocess.run(
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],  # noqa: S607
        capture_output=True,
        text=True,
        check=False,
    )
    return [p for p in r.stdout.splitlines() if p.strip()]


def main() -> int:
    ap = argparse.ArgumentParser(description="Scan for committed secrets.")
    ap.add_argument("paths", nargs="*", help="files to scan (default: whole tree)")
    ap.add_argument("--staged", action="store_true", help="scan git-staged files only")
    args = ap.parse_args()

    targets = iter_paths(staged_paths() if args.staged else args.paths)

    findings: list[str] = []
    for path in targets:
        if path.suffix.lower() not in SCAN_SUFFIXES:
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        try:
            findings.extend(scan_text(path.read_text(encoding="utf-8", errors="ignore"), path))
        except OSError:
            continue

    if findings:
        print("\nSECRET SCAN FAILED - do not commit these:\n", file=sys.stderr)
        for f in findings:
            print(f"  {f}", file=sys.stderr)
        print(
            "\nSecrets belong in the OS keychain, referenced by SecretRef.\n"
            "See docs/salvage/CREDENTIALS-TO-ROTATE.md for why this hook exists.\n",
            file=sys.stderr,
        )
        return 1

    print(f"secret scan: clean ({len(targets)} files)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
