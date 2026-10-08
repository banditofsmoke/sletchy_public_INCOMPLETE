"""A contained program and its one door out (#32), on Windows, end to end.

`winjob` starts a proxy for a run whose profile allows any host and hands the child
its address. These tests run real contained `curl` through it. Every request names
this machine's own address, which the gate refuses as an address rather than a name,
so nothing is ever sent anywhere: what is measured is that the child **reaches the
proxy**, that the proxy **decides and records**, and that a run without a door gets
none.
"""

from __future__ import annotations

import os
import socket
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest

from sletchy.kernel.contracts import IsolationBackend, IsolationProfile, NetworkPolicy
from sletchy.kernel.ledger import InMemoryKeySource, Ledger, PayloadStore
from sletchy.kernel.paths import ENV_HOME, ledger_dir, payload_dir
from sletchy.warden.egress import EgressGate
from sletchy.warden.egress import gate as gate_mod
from sletchy.warden.isolation import SandboxRecorder, WinJobSandbox

pytestmark = [
    pytest.mark.adversarial,
    pytest.mark.skipif(not WinJobSandbox.available(), reason="winjob requires Windows"),
]

CURL = Path(os.environ.get("SystemRoot", "C:\\Windows")) / "System32" / "curl.exe"


@pytest.fixture(autouse=True)
def _home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ENV_HOME, str(tmp_path / "home"))


@pytest.fixture
def ledger(_home: None) -> Ledger:
    return Ledger.open(ledger_dir(), InMemoryKeySource(b"k" * 32))


@pytest.fixture
def recorder(ledger: Ledger) -> SandboxRecorder:
    return SandboxRecorder(
        ledger=ledger, actor_id="egress_e2e", payloads=PayloadStore.open(payload_dir())
    )


@pytest.fixture
def listener() -> Iterator[tuple[int, list[bytes]]]:
    """A loopback port that records anything that reaches it directly."""
    seen: list[bytes] = []
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(4)
    server.settimeout(0.2)
    stop = threading.Event()

    def accept() -> None:
        while not stop.is_set():
            try:
                conn, _ = server.accept()
            except OSError:
                continue
            with conn:
                conn.settimeout(2)
                try:
                    seen.append(conn.recv(4096))
                    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\ndirect")
                except OSError:
                    pass

    thread = threading.Thread(target=accept, daemon=True)
    thread.start()
    yield server.getsockname()[1], seen
    stop.set()
    thread.join(2)
    server.close()


def _gate(ledger: Ledger) -> EgressGate:
    def no_dns(host: str, port: int) -> list[object]:
        raise AssertionError(f"the gate looked up {host}; nothing in this test may")

    def no_connect(*_: object) -> object:
        raise AssertionError("the gate connected; nothing in this test may")

    return EgressGate(
        ledger=ledger,
        network=NetworkPolicy(allow_egress=("allowed.example",), allow_ports=(80, 443)),
        actor_id="egress_e2e",
        switched_on=lambda: True,
        resolve=no_dns,  # type: ignore[arg-type]
        connect=no_connect,  # type: ignore[arg-type]
    )


def _profile(*hosts: str) -> IsolationProfile:
    return IsolationProfile(
        backend=IsolationBackend.WINJOB,
        network=NetworkPolicy(allow_egress=hosts, allow_ports=(80, 443)),
    )


def test_a_contained_program_reaches_the_proxy_and_the_proxy_decides(
    tmp_path: Path, ledger: Ledger, recorder: SandboxRecorder, listener: tuple[int, list[bytes]]
) -> None:
    port, direct = listener
    workspace = tmp_path / "ws"
    workspace.mkdir()
    request = [str(CURL), "-sS", "--max-time", "10", f"http://127.0.0.1:{port}/"]

    # The control: with no door, does a contained program reach loopback at all? It did
    # on 10.0.19045 (ADR-0006 finding 1) and did not on GitHub's Windows Server 2025
    # runner (finding 6). Where it cannot, there is no proxy to reach either.
    control = WinJobSandbox(workspace, _profile("allowed.example"), recorder=recorder).run(request)
    if not direct:
        pytest.skip(
            "a contained program cannot reach loopback on this Windows "
            f"({control.stdout.strip()[:60]}), so it has no way out at all (ADR-0006 finding 6)"
        )
    direct.clear()

    result = WinJobSandbox(
        workspace, _profile("allowed.example"), recorder=recorder, egress=_gate(ledger)
    ).run(request)

    assert "Sletchy refused this" in result.stdout, result.stdout
    assert direct == [], "the request went around the proxy"
    refusals = [
        e
        for e in ledger.entries()
        if e.action == gate_mod.REQUEST_ACTION and e.verdict.decision == "deny"
    ]
    assert len(refusals) == 1
    assert "an address, not a name" in refusals[0].verdict.reason


def test_a_run_whose_profile_allows_no_host_gets_no_door(
    tmp_path: Path, ledger: Ledger, recorder: SandboxRecorder
) -> None:
    workspace = tmp_path / "ws"
    workspace.mkdir()

    result = WinJobSandbox(workspace, _profile(), recorder=recorder, egress=_gate(ledger)).run(
        [os.environ["COMSPEC"], "/c", "set"]
    )

    assert "HTTP_PROXY" not in result.stdout.upper()
    assert "HTTPS_PROXY" not in result.stdout.upper()


def test_a_run_given_no_gate_gets_no_door(
    tmp_path: Path, ledger: Ledger, recorder: SandboxRecorder
) -> None:
    workspace = tmp_path / "ws"
    workspace.mkdir()

    result = WinJobSandbox(workspace, _profile("allowed.example"), recorder=recorder).run(
        [os.environ["COMSPEC"], "/c", "set"]
    )

    assert "HTTP_PROXY" not in result.stdout.upper()


def test_the_door_closes_when_the_run_ends(
    tmp_path: Path, ledger: Ledger, recorder: SandboxRecorder
) -> None:
    workspace = tmp_path / "ws"
    workspace.mkdir()

    result = WinJobSandbox(
        workspace, _profile("allowed.example"), recorder=recorder, egress=_gate(ledger)
    ).run([os.environ["COMSPEC"], "/c", "set HTTP_PROXY"])

    line = next(ln for ln in result.stdout.splitlines() if ln.upper().startswith("HTTP_PROXY="))
    port = int(line.rsplit(":", 1)[1].strip().rstrip("/"))
    with pytest.raises(OSError):
        socket.create_connection(("127.0.0.1", port), timeout=2).close()
