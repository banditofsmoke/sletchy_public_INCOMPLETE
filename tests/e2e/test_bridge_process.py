"""The bridge as the window meets it: a separate process, on real pipes, end to end.

Every other bridge test calls `handle_line` in-process. This one starts the Kernel as
its own process, writes requests to its stdin and reads its stdout, and walks every
button the window has - status, the self-check, the switches, a dangerous switch's
two proofs, the ledger, Stop everything's plan and run, garbage on the wire - then
closes stdin and checks the process exits cleanly.

**Two things are not real: the key and the firewall.** The bridge is started on an
in-memory signing key, so the test never writes to the operator's Windows Credential
Manager. Panic's firewall step answers as a host with no Sletchy rules: real, it is
the operator's own firewall, and on 2026-10-04 this test reached for the rules he had
just installed (L016). Everything else - the ledger on disk, flags.json, the
self-check, the rest of panic - is the real code, under a throwaway `SLETCHY_HOME`,
and the host shield is in the Kernel's process too (`tests/shield_site`).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from sletchy.kernel.ledger import InMemoryKeySource, Ledger

KERNEL = (
    "import sys\n"
    "import sletchy.cli.panic\n"
    "sletchy.cli.panic.remove_firewall_rules = lambda *, dry_run=False: (0, 0, None)\n"
    "import sletchy.cli.selfcheck\n"
    "def _no_firewall():\n"
    "    raise OSError('tests never read the real firewall rules')\n"
    "sletchy.cli.selfcheck._read_firewall = _no_firewall\n"
    "from sletchy.cli.bridge import Bridge, serve\n"
    "from sletchy.kernel.ledger import InMemoryKeySource\n"
    "sys.stdout = sys.stderr\n"
    "raise SystemExit(serve(Bridge(InMemoryKeySource(b'k' * 32)), sys.stdin.buffer, sys.__stdout__.buffer))\n"
)


class Kernel:
    def __init__(self, home: Path) -> None:
        env = {**os.environ, "SLETCHY_HOME": str(home), "SLETCHY_ALLOW_INMEMORY_KEY": "1"}
        self.proc = subprocess.Popen(
            [sys.executable, "-c", KERNEL],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )
        self.next_id = 1

    def raw(self, line: bytes) -> dict[str, Any]:
        assert self.proc.stdin is not None and self.proc.stdout is not None
        self.proc.stdin.write(line + b"\n")
        self.proc.stdin.flush()
        answer: dict[str, Any] = json.loads(self.proc.stdout.readline())
        return answer

    def ask(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        rid = self.next_id
        self.next_id += 1
        answer = self.raw(
            json.dumps({"id": rid, "method": method, "params": params or {}}).encode()
        )
        assert answer["id"] == rid, "an answer arrived for a different request"
        return answer

    def close(self) -> int:
        assert self.proc.stdin is not None
        self.proc.stdin.close()
        return self.proc.wait(timeout=30)


@pytest.fixture
def kernel(tmp_path: Path) -> Iterator[Kernel]:
    k = Kernel(tmp_path / "var")
    yield k
    if k.proc.poll() is None:
        k.proc.kill()
        k.proc.wait(timeout=10)


def test_every_button_in_the_window_end_to_end(kernel: Kernel, tmp_path: Path) -> None:
    # Set up and status.
    assert kernel.ask("init")["ok"]
    status = kernel.ask("status")["result"]
    assert status["ledger_state"] == "ok"
    assert status["dangerous_on"] == []

    # The meter.
    check = kernel.ask("selfcheck")["result"]
    assert 0 <= check["score"] <= check["ceiling"] < 100

    # Switches: all present, dangerous ones off, one wired (#146).
    flags = kernel.ask("flags.list")["result"]["flags"]
    assert not [f for f in flags if f["risk"] == "dangerous" and f["enabled"]]
    assert [f["name"] for f in flags if f["wired"]] == [
        "mind_local_models",
        "mind_memory",
        "soc_watch_machine",
    ]

    # A dangerous switch: refused without its name, then without a reason, then allowed.
    on = {"name": "senses_camera", "enabled": True}
    assert kernel.ask("flags.set", on)["error"]["code"] == "confirmation_required"
    assert (
        kernel.ask("flags.set", {**on, "confirm": "senses_camera"})["error"]["code"]
        == "reason_required"
    )
    view = kernel.ask("flags.set", {**on, "confirm": "senses_camera", "reason": "e2e"})["result"]
    assert view["enabled"] is True
    assert kernel.ask("status")["result"]["dangerous_on"] == ["senses_camera"]
    assert kernel.ask("selfcheck")["result"]["score"] < check["score"], "the meter did not notice"

    # The record says who, and verifies.
    tail = kernel.ask("ledger.tail", {"limit": 5})["result"]
    assert tail["verified"] >= 1
    assert tail["entries"][-1]["actor"] == "operator-desktop"

    # Talk to a model, switched off as on a fresh install: refused and recorded, and
    # nothing is sent. This Kernel is on Ollama's own port, so it is never switched on.
    assert kernel.ask("models.list")["error"]["code"] == "switched_off"
    question = {"model": "gemma3:1b", "question": "Hi"}
    ticket = kernel.ask("model.ask", question)["result"]["ticket"]
    # The refusal comes from a worker thread that opens its own ledger handle, so it is
    # waited for by time, not by a count of checks: on a busy machine 200 quick checks
    # ran out first (2026-10-07).
    deadline = time.monotonic() + 20
    state = kernel.ask("model.answer", {"ticket": ticket})["result"]
    while state["state"] == "thinking":
        assert time.monotonic() < deadline, "the refused question never finished"
        time.sleep(0.02)
        state = kernel.ask("model.answer", {"ticket": ticket})["result"]
    assert (state["state"], state["error_code"]) == ("failed", "switched_off")
    denied = kernel.ask("ledger.tail", {"limit": 2, "action_prefix": "warden.egress.local"})
    assert [e["decision"] for e in denied["result"]["entries"]] == ["deny", "deny"]

    # Garbage on the wire does not kill it.
    assert kernel.raw(b"\xff not json")["error"]["code"] == "bad_request"
    assert kernel.ask("evil.exec")["error"]["code"] == "method_not_allowed"

    # Stop everything: the plan changes nothing; the run resets; both honest.
    plan = kernel.ask("stop.plan")["result"]
    assert plan["dry_run"] is True
    assert kernel.ask("status")["result"]["dangerous_on"] == ["senses_camera"]
    run = kernel.ask("stop.run")["result"]
    assert run["clean"] is True, run["errors"]
    assert run["flags_reset"] == 1
    assert kernel.ask("status")["result"]["dangerous_on"] == []

    # Everything it wrote is under SLETCHY_HOME.
    written = {p.relative_to(tmp_path).parts[0] for p in tmp_path.rglob("*")}
    assert written == {"var"}

    # Closing the pipe ends it, cleanly.
    assert kernel.close() == 0


def test_a_kernel_killed_between_requests_leaves_a_record_that_verifies(
    kernel: Kernel, tmp_path: Path
) -> None:
    assert kernel.ask("init")["ok"]
    for name in ("cli_verbose", "cli_colour"):
        assert kernel.ask("flags.set", {"name": name, "enabled": True})["ok"]

    kernel.proc.kill()
    kernel.proc.wait(timeout=30)

    ledger = Ledger.open(tmp_path / "var" / "ledger", InMemoryKeySource(b"k" * 32))
    assert ledger.verify() == 2
    assert [e.subject.identifier for e in ledger.entries()] == ["cli_verbose", "cli_colour"]


HOSTILE = [
    b"{",
    b"null",
    b"[]",
    b"42",
    b'"status"',
    b"\xff\xfe not utf-8",
    b"\x1b[2J\x1b[H",
    b'{"id": 1}',
    b'{"id": -1, "method": "status", "params": {}}',
    b'{"id": 1, "method": "rm -rf /", "params": {}}',
    b'{"id": 1, "method": "ledger.repair", "params": {}}',
    b'{"id": 1, "method": "flags.set", "params": {"name": "egress_enabled", "enabled": true}}',
    b'{"id": 1, "method": "flags.set", "params": {"name": "x", "enabled": "yes"}}',
    b"[" * 5000 + b"]" * 5000,
    b"x" * 70_000,
]


def test_a_flood_of_hostile_lines_is_answered_line_for_line_and_the_kernel_survives(
    kernel: Kernel,
) -> None:
    """Every hostile line gets exactly one answer, an error, and the Kernel still works."""
    assert kernel.ask("init")["ok"]
    answered = 0
    for _ in range(20):
        for line in HOSTILE:
            answer = kernel.raw(line)
            assert answer["ok"] is False, f"a hostile line was obeyed: {line[:60]!r}"
            answered += 1

    assert answered == 20 * len(HOSTILE)
    status = kernel.ask("status")
    assert status["ok"] and status["result"]["ledger_state"] == "ok"
    assert status["result"]["dangerous_on"] == [], "a hostile line turned something on"
    assert kernel.close() == 0
