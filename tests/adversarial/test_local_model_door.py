"""The door to a local model server (ADR-0017): one port, a few questions, the switch.

A fake model server runs on loopback and records every request it is sent, so each
test can say what reached it, not only what the door returned. Nothing here starts
or talks to a real model server.

The questions, from the abuse cases:

- with the switch off, nothing is sent, and the refusal is on the record
- a request that makes a model server fetch, write or delete is refused before it is
  sent, however it is spelled
- the door reaches 127.0.0.1 and the one port, and has no way to be pointed anywhere else
- every request is recorded before it connects; an answer past its limit is cut
"""

from __future__ import annotations

import inspect
import json
import socket
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from sletchy.kernel.contracts import Decision
from sletchy.kernel.ledger import InMemoryKeySource, Ledger
from sletchy.warden.egress import EgressDenied, LocalLimits, LocalModelDoor
from sletchy.warden.egress import local as local_mod

pytestmark = pytest.mark.adversarial


class FakeServer(ThreadingHTTPServer):
    seen: list[tuple[str, str]]
    answer: bytes


class _Handler(BaseHTTPRequestHandler):
    server: FakeServer

    def _reply(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        self.server.seen.append((self.command, self.path))
        body = self.server.answer
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = _reply
    do_POST = _reply
    do_DELETE = _reply

    def log_message(self, *_: object) -> None:
        pass


@pytest.fixture
def server() -> Iterator[FakeServer]:
    srv = FakeServer(("127.0.0.1", 0), _Handler)
    srv.seen = []
    srv.answer = json.dumps({"models": []}).encode()
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv
    srv.shutdown()
    srv.server_close()


@pytest.fixture
def ledger(tmp_path: Path) -> Ledger:
    return Ledger.open(tmp_path / "ledger", InMemoryKeySource(b"k" * 32))


def door(ledger: Ledger, server: FakeServer, *, on: bool = True, **kw: object) -> LocalModelDoor:
    return LocalModelDoor(
        ledger=ledger,
        actor_id="test",
        switched_on=lambda: on,
        engine="ollama",
        port=server.server_address[1],
        **kw,  # type: ignore[arg-type]
    )


def recorded(ledger: Ledger) -> list[tuple[str, Decision, str]]:
    return [
        (e.action, e.verdict.decision, e.verdict.reason)
        for e in ledger.entries()
        if e.action.startswith(local_mod.LOCAL_ACTION)
    ]


def test_a_question_reaches_the_server_and_is_recorded(ledger: Ledger, server: FakeServer) -> None:
    reply = door(ledger, server).request("GET", "/api/tags")
    assert reply.status == 200
    assert server.seen == [("GET", "/api/tags")]
    [(action, decision, _)] = recorded(ledger)
    assert (action, decision) == (local_mod.LOCAL_ACTION, Decision.ALLOW)


def test_switched_off_nothing_is_sent_and_the_refusal_is_recorded(
    ledger: Ledger, server: FakeServer
) -> None:
    with pytest.raises(EgressDenied, match="switched off"):
        door(ledger, server, on=False).request("GET", "/api/tags")
    assert server.seen == []
    assert [d for _, d, _ in recorded(ledger)] == [Decision.DENY]


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("POST", "/api/pull"),  # would download a model from the internet
        ("POST", "/api/push"),
        ("POST", "/api/create"),
        ("POST", "/api/copy"),
        ("DELETE", "/api/delete"),
        ("POST", "/api/generate"),  # not on the list, though harmless
        ("GET", "/api/chat"),  # the right path, the wrong method
        ("POST", "/api/chat/"),
        ("POST", "/API/CHAT"),
        ("POST", "/api/chat?stream=true"),
        ("POST", "//api/chat"),
        ("POST", "/api/chat/../pull"),
        ("POST", "/api/chat HTTP/1.1\r\nX: y\r\n\r\nPOST /api/pull"),
        ("POST", "http://127.0.0.1:11434/api/chat"),
    ],
)
def test_anything_but_a_listed_question_is_refused_before_it_is_sent(
    ledger: Ledger, server: FakeServer, method: str, path: str
) -> None:
    with pytest.raises(EgressDenied, match="not a question this door asks"):
        door(ledger, server).request(method, path, b"{}")
    assert server.seen == []
    assert [d for _, d, _ in recorded(ledger)] == [Decision.DENY]


def test_a_request_over_its_limit_is_refused_before_connecting(
    ledger: Ledger, server: FakeServer
) -> None:
    small = door(ledger, server, limits=LocalLimits(max_request_bytes=10))
    with pytest.raises(EgressDenied, match="over the limit"):
        small.request("POST", "/api/chat", b"x" * 11)
    assert server.seen == []


def test_an_answer_past_its_limit_is_cut_and_recorded(ledger: Ledger, server: FakeServer) -> None:
    server.answer = b"x" * 5000
    small = door(ledger, server, limits=LocalLimits(max_response_bytes=1000))
    with pytest.raises(EgressDenied, match="passed 1000 bytes"):
        small.request("GET", "/api/tags")
    assert recorded(ledger)[-1][:2] == (local_mod.LOCAL_CUT_ACTION, Decision.DENY)


def test_the_record_comes_before_the_connection(ledger: Ledger) -> None:
    """Nobody is listening on this port: the allow entry is written anyway, first."""
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        free = probe.getsockname()[1]
    closed = LocalModelDoor(
        ledger=ledger, actor_id="test", switched_on=lambda: True, engine="ollama", port=free
    )
    with pytest.raises(OSError):
        closed.request("GET", "/api/version")
    assert [d for _, d, _ in recorded(ledger)] == [Decision.ALLOW]


def test_the_door_connects_to_this_machine_and_nowhere_else(
    ledger: Ledger, server: FakeServer
) -> None:
    calls: list[tuple[str, int]] = []
    real = local_mod.system_connector

    def watch(address: str, port: int, timeout: float):  # type: ignore[no-untyped-def]
        calls.append((address, port))
        return real(address, port, timeout)

    door(ledger, server, connect=watch).request("GET", "/api/tags")
    assert calls == [("127.0.0.1", server.server_address[1])]


def test_nothing_points_the_door_at_another_host() -> None:
    """No host, address or URL parameter, at construction or per request."""
    built = set(inspect.signature(LocalModelDoor).parameters)
    asked = set(inspect.signature(LocalModelDoor.request).parameters)
    assert built == {"ledger", "actor_id", "switched_on", "engine", "port", "limits", "connect"}
    assert asked == {"self", "method", "path", "body"}


@pytest.mark.parametrize("port", [0, 80, 443, 1023, 65536, -1])
def test_a_privileged_or_impossible_port_is_refused(ledger: Ledger, port: int) -> None:
    with pytest.raises(ValueError, match="port"):
        LocalModelDoor(
            ledger=ledger, actor_id="t", switched_on=lambda: True, engine="ollama", port=port
        )


def test_an_unknown_engine_is_refused(ledger: Ledger) -> None:
    with pytest.raises(ValueError, match="no such engine"):
        LocalModelDoor(
            ledger=ledger, actor_id="t", switched_on=lambda: True, engine="vllm", port=8000
        )


def test_no_engine_lists_a_request_that_writes_fetches_or_deletes() -> None:
    risky = ("pull", "push", "create", "copy", "delete", "upload", "download", "slots", "props")
    for engine, questions in local_mod.ENGINES.items():
        for method, path in questions:
            assert method in ("GET", "POST"), (engine, method)
            assert not any(word in path for word in risky), (engine, path)
