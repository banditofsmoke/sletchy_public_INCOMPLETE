"""Where Sletchy keeps its state.

**One directory. That is the whole of [LAW 0 §2](../../../docs/LAW/00-do-no-harm.md)'s
storage promise.** Uninstall is: stop the process, run `sletchy panic`, delete this
directory. Nothing else on the host has been touched.

Overridable by `SLETCHY_HOME` so tests and a portable install can point elsewhere -
and so `panic` can be pointed at the right tree when more than one exists.

**Why this lives in the Kernel.** It began in `cli/`, which was fine while the CLI
was the only writer. The Warden now needs the same root, to journal the host
changes it makes so that `panic` can revert them - and `warden` may not import
`cli`, nor `cli` import `warden`. A state root that two planes disagree about is
not a promise, so the one definition belongs at the bottom of the stack where both
can depend on it.
"""

from __future__ import annotations

import os
from pathlib import Path

ENV_HOME = "SLETCHY_HOME"


def home() -> Path:
    """The root of everything Sletchy writes."""
    override = os.environ.get(ENV_HOME)
    if override:
        return Path(override)
    return Path.cwd() / "var"


def ledger_dir() -> Path:
    return home() / "ledger"


def payload_dir() -> Path:
    return home() / "payloads"


def allowlist_file() -> Path:
    """The programs `sletchy sandbox run` may start. Absent: none (LAW 2)."""
    return home() / "allowlist.toml"


def flags_file() -> Path:
    return home() / "flags.json"


def memory_dir() -> Path:
    """The recall store (ADR-0019). Derived from the record and my documents, so deleting
    it loses nothing the ledger does not hold."""
    return home() / "memory"


def runtime_dir() -> Path:
    """Locks, pid files, socket paths - everything `panic` may safely delete.

    Kept separate from the ledger and payloads precisely so panic has somewhere it
    is allowed to clear without touching anything that constitutes evidence.
    """
    return home() / "run"
