#!/usr/bin/env python3
"""Ask OSV about every locked package; fail on a known vulnerability nobody accepted (#34).

Reads the three lockfiles - `uv.lock` (PyPI), `apps/desktop/package-lock.json` (npm)
and `apps/desktop/src-tauri/Cargo.lock` (crates.io) - and sends each name and version
to the OSV database (osv.dev), the public aggregate of the advisories each ecosystem
publishes. Nothing else is sent.

**It runs in CI, never in the test suite**: it needs the network, which the suite
refuses (LAW 0 §6). The parsing and the verdict are tested without it.

A vulnerability fails the run unless `docs/supply/VULNERABILITIES.md` accepts it, with
a reason and a date after which the acceptance runs out. An answer that cannot be had
- the service down, a page of results it did not finish - fails too: "could not ask" is
never "nothing found" (L009).

    python scripts/known_vulnerabilities.py            ask OSV, exit 1 on anything unaccepted
    python scripts/known_vulnerabilities.py --list     print what would be asked; send nothing
"""

from __future__ import annotations

import json
import re
import sys
import tomllib
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from datetime import date
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
QUERY_URL = "https://api.osv.dev/v1/querybatch"
ACCEPTED = REPO / "docs" / "supply" / "VULNERABILITIES.md"
BATCH = 500


@dataclass(frozen=True)
class Package:
    ecosystem: str
    name: str
    version: str


def python_packages(lock: dict[str, object]) -> list[Package]:
    found = []
    for item in lock.get("package", []):  # type: ignore[union-attr]
        source = item.get("source", {})
        if "registry" in source and item.get("version"):
            found.append(Package("PyPI", item["name"], item["version"]))
    return found


def npm_packages(lock: dict[str, object]) -> list[Package]:
    found = []
    for path, item in lock.get("packages", {}).items():  # type: ignore[union-attr]
        if not path or item.get("link") or not item.get("version"):
            continue
        name = item.get("name") or path.rsplit("node_modules/", 1)[-1]
        found.append(Package("npm", name, item["version"]))
    return found


def crates(lock: dict[str, object]) -> list[Package]:
    return [
        Package("crates.io", item["name"], item["version"])
        for item in lock.get("package", [])  # type: ignore[union-attr]
        if str(item.get("source", "")).startswith("registry+")
    ]


def locked() -> list[Package]:
    desktop = REPO / "apps" / "desktop"
    packages = python_packages(tomllib.loads((REPO / "uv.lock").read_text("utf-8")))
    packages += npm_packages(json.loads((desktop / "package-lock.json").read_text("utf-8")))
    packages += crates(tomllib.loads((desktop / "src-tauri" / "Cargo.lock").read_text("utf-8")))
    return sorted(set(packages), key=lambda p: (p.ecosystem, p.name, p.version))


def accepted(text: str, today: date) -> tuple[dict[str, date], list[str]]:
    """The accepted ids and their end dates, and the ids whose acceptance has run out.

    A row is `| ID | package | why | YYYY-MM-DD |`. A row without a reason or a date
    accepts nothing.
    """
    ok: dict[str, date] = {}
    expired: list[str] = []
    for line in text.splitlines():
        cells = [c.strip().strip("`") for c in line.strip().strip("|").split("|")]
        if len(cells) != 4 or not re.fullmatch(r"[A-Z][A-Z0-9]*-[\w-]+", cells[0]):
            continue
        ident, _package, why, until = cells
        try:
            end = date.fromisoformat(until)
        except ValueError:
            continue
        if not why:
            continue
        if end < today:
            expired.append(ident)
        else:
            ok[ident] = end
    return ok, expired


Post = Callable[[str, bytes], bytes]


def _post(url: str, body: bytes) -> bytes:
    request = urllib.request.Request(  # noqa: S310 - a constant https URL
        url, data=body, headers={"Content-Type": "application/json"}, method="POST"
    )
    with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310
        return bytes(response.read())


def ask(packages: list[Package], post: Post = _post) -> dict[Package, list[str]]:
    """The OSV ids each package is affected by. Raises `OSError` if an answer is partial."""
    found: dict[Package, list[str]] = {}
    for start in range(0, len(packages), BATCH):
        chunk = packages[start : start + BATCH]
        body = json.dumps(
            {
                "queries": [
                    {"package": {"ecosystem": p.ecosystem, "name": p.name}, "version": p.version}
                    for p in chunk
                ]
            }
        ).encode()
        answer = json.loads(post(QUERY_URL, body))
        results = answer.get("results")
        if not isinstance(results, list) or len(results) != len(chunk):
            raise OSError("OSV's answer did not have one result per package")
        for package, result in zip(chunk, results, strict=True):
            if result.get("next_page_token"):
                raise OSError(f"OSV had more results for {package.name} than one page")
            ids = sorted(v["id"] for v in result.get("vulns", []))
            if ids:
                found[package] = ids
    return found


def verdict(found: dict[Package, list[str]], ok: dict[str, date], expired: list[str]) -> list[str]:
    """One line per vulnerability nobody accepted, or whose acceptance ran out."""
    lines = []
    for package, ids in sorted(found.items(), key=lambda kv: (kv[0].ecosystem, kv[0].name)):
        for ident in ids:
            if ident in ok:
                continue
            why = "its acceptance has run out" if ident in expired else "not accepted"
            lines.append(
                f"{ident}  {package.ecosystem} {package.name} {package.version}  ({why})"
                f"  https://osv.dev/vulnerability/{ident}"
            )
    return lines


def main(argv: list[str] | None = None, *, post: Post = _post, today: date | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    packages = locked()
    if "--list" in args:
        for p in packages:
            print(f"{p.ecosystem:<10} {p.name} {p.version}")
        print(f"{len(packages)} packages; nothing was sent")
        return 0
    ok, expired = accepted(ACCEPTED.read_text("utf-8"), today or date.today())
    try:
        found = ask(packages, post)
    except (OSError, ValueError) as exc:
        print(f"known vulnerabilities: could not ask OSV, so nothing is known clean: {exc}")
        return 1
    problems = verdict(found, ok, expired)
    for line in problems:
        print(line)
    accepted_here = sum(1 for ids in found.values() for i in ids if i in ok)
    print(
        f"known vulnerabilities: {len(packages)} packages asked; {len(problems)} not accepted, "
        f"{accepted_here} accepted in {ACCEPTED.relative_to(REPO).as_posix()}"
    )
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
