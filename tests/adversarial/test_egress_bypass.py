"""The egress gate, the sandbox proxy and the client (#32): what gets out, and what is refused.

**Nothing here leaves this machine (LAW 0 §6).** Names are resolved by a fake DNS that
answers with documentation addresses (RFC 5737), and the connector carries a
connection to one of those to a server this test runs on loopback. The host shield
refuses any real lookup or any connection off the machine, so a fake that failed to
install would fail the run rather than reach anyone.

The questions, from the issue's abuse cases:

- a host, port, method or size the policy does not allow is refused, on the ledger
  first, and nothing connects
- a destination dressed up (an address, `user@host`, a lookalike, a number, a name
  that resolves to this machine or a private network) is refused
- a redirect is never followed; a response or an upload past its limit is cut
- a sandbox's proxy serves only that run, and only on loopback
- nothing offers a way around any of it
"""

from __future__ import annotations

import base64
import inspect
import ipaddress
import socket
import socketserver
import threading
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from sletchy.kernel.contracts import NetworkPolicy
from sletchy.kernel.ledger import InMemoryKeySource, Ledger, LedgerBusy
from sletchy.warden.egress import (
    EgressClient,
    EgressDenied,
    EgressGate,
    EgressProxy,
    Limits,
)
from sletchy.warden.egress import gate as gate_mod
from sletchy.warden.egress import policy as policy_mod

pytestmark = pytest.mark.adversarial

ALLOWED = "allowed.example"
BASE = "http://allowed.example"
#: Where the fake DNS sends the allowed name: documentation space, nobody's.
ALLOWED_AT = ipaddress.IPv4Address("203.0.113.10")
LIMITS = Limits(max_request_bytes=4096, max_response_bytes=64 * 1024, idle_seconds=5.0)


# ── a world on loopback ──────────────────────────────────────────────────────


@dataclass
class Seen:
    requests: list[bytes] = field(default_factory=list)


class _Upstream(socketserver.BaseRequestHandler):
    """An HTTP server for the allowed name, or an echo for a tunnel."""

    server: _World

    def handle(self) -> None:
        sock: socket.socket = self.request
        sock.settimeout(5)
        if self.server.echo:
            while data := sock.recv(65536):
                sock.sendall(data)
            return
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = sock.recv(4096)
            if not chunk:
                return
            data += chunk
        self.server.seen.requests.append(data)
        path = data.split(b" ", 2)[1]
        if path == b"/redirect":
            sock.sendall(
                b"HTTP/1.1 302 Found\r\nLocation: http://elsewhere.example/\r\n"
                b"Content-Length: 0\r\nConnection: close\r\n\r\n"
            )
        elif path == b"/huge":
            sock.sendall(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n")
            try:
                for _ in range(1000):
                    sock.sendall(b"x" * 8192)
            except OSError:
                return
        else:
            sock.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello")


class _World(socketserver.ThreadingTCPServer):
    daemon_threads = True

    def __init__(self, *, echo: bool) -> None:
        self.seen = Seen()
        self.echo = echo
        super().__init__(("127.0.0.1", 0), _Upstream)


@pytest.fixture
def world() -> Iterator[dict[int, _World]]:
    """Port 80 is the HTTP server, port 443 the echo a tunnel reaches."""
    servers = {80: _World(echo=False), 443: _World(echo=True)}
    for server in servers.values():
        threading.Thread(
            target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
        ).start()
    yield servers
    for server in servers.values():
        server.shutdown()
        server.server_close()


@dataclass
class Net:
    """The fake DNS and the connector, recording every question put to them."""

    world: dict[int, _World]
    answers: dict[str, list[ipaddress.IPv4Address | ipaddress.IPv6Address]] = field(
        default_factory=dict
    )
    lookups: list[str] = field(default_factory=list)
    connects: list[tuple[str, int, int]] = field(default_factory=list)
    ledger: Ledger | None = None

    def resolve(self, host: str, port: int) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
        self.lookups.append(host)
        if host not in self.answers:
            raise OSError(f"no such name: {host}")
        return self.answers[host]

    def connect(
        self, address: ipaddress.IPv4Address | ipaddress.IPv6Address, port: int, timeout: float
    ) -> socket.socket:
        self.connects.append((str(address), port, self.ledger.length if self.ledger else -1))
        if address != ALLOWED_AT or port not in self.world:
            raise OSError("this test's world has nothing there")
        host, there = self.world[port].server_address[:2]
        return socket.create_connection((str(host), int(there)), timeout=timeout)


@pytest.fixture
def ledger(tmp_path: Path) -> Ledger:
    return Ledger.open(tmp_path / "ledger", InMemoryKeySource(b"k" * 32))


@pytest.fixture
def net(world: dict[int, _World], ledger: Ledger) -> Net:
    return Net(
        world=world, answers={ALLOWED: [ALLOWED_AT], "a.wild.example": [ALLOWED_AT]}, ledger=ledger
    )


def make_gate(
    ledger: Ledger,
    net: Net,
    *,
    hosts: tuple[str, ...] = (ALLOWED, "*.wild.example"),
    ports: tuple[int, ...] = (80, 443),
    on: bool = True,
) -> EgressGate:
    return EgressGate(
        ledger=ledger,
        network=NetworkPolicy(allow_egress=hosts, allow_ports=ports),
        actor_id="test_agent",
        switched_on=lambda: on,
        limits=LIMITS,
        resolve=net.resolve,
        connect=net.connect,
    )


@pytest.fixture
def gate(ledger: Ledger, net: Net) -> EgressGate:
    return make_gate(ledger, net)


def entries(ledger: Ledger, action: str = gate_mod.REQUEST_ACTION) -> list[tuple[str, str]]:
    return [(e.verdict.decision, e.verdict.reason) for e in ledger.entries() if e.action == action]


def refused(gate: EgressGate, method: str, host: str, port: int = 80, **kw: int) -> EgressDenied:
    with pytest.raises(EgressDenied) as caught:
        gate.open(method, host, port, **kw)
    return caught.value


# ── the gate: what is allowed, and in what order ─────────────────────────────


def test_an_allowed_request_is_recorded_before_it_connects(
    gate: EgressGate, ledger: Ledger, net: Net
) -> None:
    with gate.open("GET", ALLOWED, 80):
        pass

    assert entries(ledger) == [("allow", f"GET {ALLOWED}:80, connecting to {ALLOWED_AT}")]
    assert net.connects == [(str(ALLOWED_AT), 80, 1)], "it connected before the record"


@pytest.mark.parametrize(
    ("method", "host", "port", "declared", "why"),
    [
        ("GET", "other.example", 80, 0, "not on the allowlist"),
        ("GET", ALLOWED, 8080, 0, "port 8080 is not allowed"),
        ("DELETE", ALLOWED, 80, 0, "method DELETE is not allowed"),
        ("POST", ALLOWED, 80, LIMITS.max_request_bytes + 1, "over the limit"),
    ],
)
def test_each_policy_refusal_is_recorded_and_nothing_connects(
    gate: EgressGate,
    ledger: Ledger,
    net: Net,
    method: str,
    host: str,
    port: int,
    declared: int,
    why: str,
) -> None:
    denied = refused(gate, method, host, port, declared_bytes=declared)

    assert why in denied.reason
    assert net.connects == []
    recorded = list(ledger.entries())
    assert denied.seq == recorded[-1].seq, "the exception names an entry that is not the denial"
    assert recorded[-1].verdict.decision == "deny"
    assert why in recorded[-1].verdict.reason


def test_switched_off_nothing_leaves_even_an_allowed_host(ledger: Ledger, net: Net) -> None:
    gate = make_gate(ledger, net, on=False)

    denied = refused(gate, "GET", ALLOWED)

    assert "switched off" in denied.reason
    assert net.lookups == [] and net.connects == []


def test_an_empty_allowlist_denies_everything(ledger: Ledger, net: Net) -> None:
    gate = make_gate(ledger, net, hosts=())

    assert "allowlist is empty" in refused(gate, "GET", ALLOWED).reason


@pytest.mark.parametrize(
    ("host", "why"),
    [
        ("192.0.2.1", "an address, not a name"),
        ("[2001:db8::1]", "an address, not a name"),
        (f"user@{ALLOWED}", "more than a name"),
        (f"{ALLOWED}/path", "more than a name"),
        ("2130706433", "a number written as a name"),
        ("0x7f000001", "a number written as a name"),
        ("127.1", "a number written as a name"),
        ("localhost", "always means this machine"),
        ("sub.localhost", "always means this machine"),
        ("", "no host"),
        ("bad_name.example", "not a valid name"),
        ("-dash.example", "not a valid name"),
    ],
)
def test_a_destination_that_is_not_plainly_a_name_is_refused_unresolved(
    gate: EgressGate, net: Net, host: str, why: str
) -> None:
    denied = refused(gate, "GET", host)

    assert why in denied.reason
    assert net.lookups == [], "a disguised destination was looked up"
    assert net.connects == []


def test_a_lookalike_in_another_script_matches_nothing(gate: EgressGate, net: Net) -> None:
    lookalike = "\N{CYRILLIC SMALL LETTER A}llowed.example"

    denied = refused(gate, "GET", lookalike)

    assert "not on the allowlist" in denied.reason
    assert net.connects == []


@pytest.mark.parametrize("spelling", [ALLOWED.upper(), ALLOWED + ".", " " + ALLOWED])
def test_one_name_spelled_differently_is_the_same_name(gate: EgressGate, spelling: str) -> None:
    with gate.open("GET", spelling, 80):
        pass


def test_a_wildcard_covers_names_under_it_and_not_the_name_itself(
    gate: EgressGate, net: Net
) -> None:
    with gate.open("GET", "a.wild.example", 80):
        pass
    assert "not on the allowlist" in refused(gate, "GET", "wild.example").reason
    assert "not on the allowlist" in refused(gate, "GET", "evilwild.example").reason


def _floor_samples() -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """One address from every block under the floor, taken from the floor itself."""
    samples = []
    for net, _why in (*policy_mod.FLOOR_V4, *policy_mod.FLOOR_V6):
        block = ipaddress.ip_network(net)
        samples.append(block[-1] if block.num_addresses > 1 else block[0])
    loopback = ipaddress.ip_network("127.0.0.0/8")[1]
    samples += [
        ipaddress.IPv6Address(int(ipaddress.IPv6Address("::ffff:0:0")) + int(loopback)),
        ipaddress.IPv6Address(int(ipaddress.IPv6Address("64:ff9b::")) + int(loopback)),
        ipaddress.IPv6Address(int(ipaddress.IPv6Address("2002::")) + (int(loopback) << 80)),
    ]
    return samples


@pytest.mark.parametrize("address", _floor_samples(), ids=str)
def test_a_name_that_resolves_under_the_floor_is_refused_whatever_the_allowlist(
    gate: EgressGate, net: Net, address: ipaddress.IPv4Address | ipaddress.IPv6Address
) -> None:
    """Loopback, private networks, cloud metadata: never, even for an allowed name."""
    net.answers[ALLOWED] = [address]

    denied = refused(gate, "GET", ALLOWED)

    assert "never allowed" in denied.reason
    assert net.connects == []


def test_one_bad_address_among_good_ones_refuses_the_name(gate: EgressGate, net: Net) -> None:
    """Rebinding by round robin: the second answer is this machine."""
    net.answers[ALLOWED] = [ALLOWED_AT, ipaddress.ip_network("127.0.0.0/8")[1]]

    assert "never allowed" in refused(gate, "GET", ALLOWED).reason
    assert net.connects == []


def test_the_name_is_looked_up_once_and_the_checked_address_is_connected(
    gate: EgressGate, net: Net
) -> None:
    with gate.open("GET", ALLOWED, 80):
        pass

    assert net.lookups == [ALLOWED]
    assert [c[0] for c in net.connects] == [str(ALLOWED_AT)]


def test_a_name_that_does_not_resolve_is_refused(gate: EgressGate) -> None:
    assert "did not resolve" in refused(gate, "GET", "missing.wild.example").reason


def test_a_ledger_that_cannot_record_means_nothing_connects(
    gate: EgressGate, ledger: Ledger, net: Net, monkeypatch: pytest.MonkeyPatch
) -> None:
    def busy(**_: object) -> object:
        raise LedgerBusy("held by another writer")

    monkeypatch.setattr(ledger, "append", busy)

    with pytest.raises(LedgerBusy):
        gate.open("GET", ALLOWED, 80)
    assert net.connects == []


def test_many_refusals_raise_one_signal_for_the_soc(gate: EgressGate, ledger: Ledger) -> None:
    for n in range(gate_mod.FLOOD_COUNT * 2):
        refused(gate, "GET", f"probe{n}.example")

    floods = entries(ledger, gate_mod.FLOOD_ACTION)
    assert len(floods) == 1
    assert "refused" in floods[0][1]


def test_a_narrowed_gate_is_never_wider(gate: EgressGate, net: Net) -> None:
    narrow = gate.narrowed(
        NetworkPolicy(allow_egress=(ALLOWED, "extra.example"), allow_ports=(80,))
    )

    assert narrow.network.allow_egress == (ALLOWED,)
    assert narrow.network.allow_ports == (80,)
    assert "port 443 is not allowed" in refused(narrow, "CONNECT", ALLOWED, 443).reason


# ── nothing offers a way around ──────────────────────────────────────────────


def test_no_door_has_a_parameter_that_skips_a_check() -> None:
    expected: dict[Callable[..., object], set[str]] = {
        EgressGate.__init__: {
            "self",
            "ledger",
            "network",
            "actor_id",
            "switched_on",
            "limits",
            "resolve",
            "connect",
            "clock",
        },
        EgressGate.open: {"self", "method", "host", "port", "declared_bytes"},
        EgressClient.__init__: {"self", "gate"},
        EgressClient.request: {"self", "method", "url", "body", "headers"},
        EgressProxy.__init__: {"self", "gate", "password"},
    }
    for function, names in expected.items():
        assert set(inspect.signature(function).parameters) == names, function.__qualname__


# ── the client ───────────────────────────────────────────────────────────────


def test_the_client_fetches_through_the_gate(
    gate: EgressGate, ledger: Ledger, world: dict[int, _World]
) -> None:
    answer = EgressClient(gate).request(
        "GET", f"{BASE}/ok", headers={"Host": "evil.example", "X-Trace": "1"}
    )

    assert (answer.status, answer.body) == (200, b"hello")
    sent = world[80].seen.requests[0].decode()
    assert f"Host: {ALLOWED}\r\n" in sent
    assert "evil.example" not in sent, "the caller's Host went out"
    assert "X-Trace: 1" in sent
    assert [d for d, _ in entries(ledger)] == ["allow"]


def test_a_redirect_comes_back_and_is_never_followed(
    gate: EgressGate, ledger: Ledger, world: dict[int, _World], net: Net
) -> None:
    answer = EgressClient(gate).request("GET", f"{BASE}/redirect")

    assert answer.status == 302
    assert answer.header("location") == "http://elsewhere.example/"
    assert len(world[80].seen.requests) == 1
    assert net.lookups == [ALLOWED], "the client went looking for the redirect's host"
    assert len(entries(ledger)) == 1


def test_an_answer_past_its_limit_is_cut_and_recorded(gate: EgressGate, ledger: Ledger) -> None:
    with pytest.raises(EgressDenied, match="passed"):
        EgressClient(gate).request("GET", f"{BASE}/huge")

    assert entries(ledger, gate_mod.CUT_ACTION), "the cut was not on the ledger"


def test_the_client_refuses_a_disguised_url_before_anything_connects(
    gate: EgressGate, net: Net
) -> None:
    with pytest.raises(EgressDenied, match="more than a name"):
        EgressClient(gate).request("GET", "http://user@allowed.example/ok")
    assert net.connects == []


# ── the proxy a sandbox is handed ────────────────────────────────────────────


def _ask(proxy: EgressProxy, raw: bytes) -> bytes:
    with socket.create_connection(("127.0.0.1", proxy.port), timeout=5) as sock:
        sock.sendall(raw)
        answer = b""
        while chunk := sock.recv(65536):
            answer += chunk
        return answer


def _auth(proxy: EgressProxy) -> bytes:
    token = base64.b64encode(f"sletchy:{proxy.password}".encode()).decode()
    return f"Proxy-Authorization: Basic {token}\r\n".encode()


@pytest.fixture
def proxy(gate: EgressGate) -> Iterator[EgressProxy]:
    with EgressProxy(gate) as running:
        yield running


def test_the_proxy_listens_on_loopback_only(proxy: EgressProxy) -> None:
    parts = urlsplit(proxy.url)
    assert (parts.username, parts.hostname) == ("sletchy", "127.0.0.1")
    assert proxy._server is not None
    assert proxy._server.server_address[0] == "127.0.0.1"


@pytest.mark.parametrize("auth", [b"", b"Proxy-Authorization: Basic c2xldGNoeTp3cm9uZw==\r\n"])
def test_without_this_runs_password_the_proxy_refuses_and_records(
    proxy: EgressProxy, ledger: Ledger, world: dict[int, _World], auth: bytes
) -> None:
    answer = _ask(proxy, b"GET http://allowed.example/ok HTTP/1.1\r\n" + auth + b"\r\n")

    assert answer.startswith(b"HTTP/1.1 407")
    assert world[80].seen.requests == []
    assert entries(ledger) == [
        ("deny", "a request to the sandbox proxy without this run's password")
    ]


def test_plain_http_goes_out_with_the_checked_host_and_without_the_proxys_headers(
    proxy: EgressProxy, world: dict[int, _World]
) -> None:
    answer = _ask(
        proxy,
        b"GET http://allowed.example/ok?q=1 HTTP/1.1\r\nHost: evil.example\r\n"
        + _auth(proxy)
        + b"Proxy-Connection: keep-alive\r\n\r\n",
    )

    assert answer.startswith(b"HTTP/1.1 200") and answer.endswith(b"hello")
    sent = world[80].seen.requests[0].decode()
    assert sent.startswith("GET /ok?q=1 HTTP/1.1\r\n")
    assert f"Host: {ALLOWED}\r\n" in sent
    for leaked in ("evil.example", "Proxy-Authorization", "Proxy-Connection"):
        assert leaked not in sent


def test_a_refused_request_tells_the_sandbox_why_and_where_it_is_recorded(
    proxy: EgressProxy, ledger: Ledger, world: dict[int, _World]
) -> None:
    answer = _ask(proxy, b"GET http://other.example/ HTTP/1.1\r\n" + _auth(proxy) + b"\r\n")

    assert answer.startswith(b"HTTP/1.1 403")
    seq = list(ledger.entries())[-1].seq
    assert f"(ledger {seq})".encode() in answer
    assert world[80].seen.requests == []


def test_a_body_of_unknown_length_is_refused(proxy: EgressProxy, ledger: Ledger) -> None:
    answer = _ask(
        proxy,
        b"POST http://allowed.example/ HTTP/1.1\r\n"
        + _auth(proxy)
        + b"Transfer-Encoding: chunked\r\n\r\n",
    )

    assert answer.startswith(b"HTTP/1.1 403")
    assert "unknown length" in entries(ledger)[-1][1]


def test_a_tunnel_carries_bytes_both_ways(proxy: EgressProxy) -> None:
    with socket.create_connection(("127.0.0.1", proxy.port), timeout=5) as sock:
        sock.sendall(b"CONNECT allowed.example:443 HTTP/1.1\r\n" + _auth(proxy) + b"\r\n")
        assert sock.recv(4096).startswith(b"HTTP/1.1 200")
        sock.sendall(b"ping")
        assert sock.recv(4096) == b"ping"


def test_a_tunnel_to_a_refused_host_is_never_opened(proxy: EgressProxy, net: Net) -> None:
    answer = _ask(proxy, b"CONNECT other.example:443 HTTP/1.1\r\n" + _auth(proxy) + b"\r\n")

    assert answer.startswith(b"HTTP/1.1 403")
    assert net.connects == []


def test_a_tunnel_that_sends_past_its_limit_is_cut(proxy: EgressProxy, ledger: Ledger) -> None:
    with socket.create_connection(("127.0.0.1", proxy.port), timeout=5) as sock:
        sock.sendall(b"CONNECT allowed.example:443 HTTP/1.1\r\n" + _auth(proxy) + b"\r\n")
        assert sock.recv(4096).startswith(b"HTTP/1.1 200")
        try:
            for _ in range(LIMITS.max_request_bytes // 512 + 4):
                sock.sendall(b"y" * 512)
        except OSError:
            pass
        sock.settimeout(5)
        try:
            while sock.recv(65536):
                pass
        except OSError:
            pass

    assert any("sent over" in reason for _, reason in entries(ledger, gate_mod.CUT_ACTION))


def test_an_answer_through_the_proxy_stops_at_its_limit(proxy: EgressProxy, ledger: Ledger) -> None:
    answer = _ask(proxy, b"GET http://allowed.example/huge HTTP/1.1\r\n" + _auth(proxy) + b"\r\n")

    assert len(answer) <= LIMITS.max_response_bytes
    assert entries(ledger, gate_mod.CUT_ACTION)


def test_a_request_that_is_not_for_a_proxy_is_refused(proxy: EgressProxy) -> None:
    assert _ask(proxy, b"GET / HTTP/1.1\r\n" + _auth(proxy) + b"\r\n").startswith(b"HTTP/1.1 400")


def test_a_stopped_proxy_is_gone(gate: EgressGate) -> None:
    proxy = EgressProxy(gate).start()
    port = proxy.port
    proxy.stop()

    with pytest.raises(OSError):
        socket.create_connection(("127.0.0.1", port), timeout=2).close()
