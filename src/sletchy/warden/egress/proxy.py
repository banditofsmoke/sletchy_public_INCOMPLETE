"""A sandbox's one door out: an HTTP proxy on loopback, for one run (#32).

`winjob` starts one for a run whose profile allows any host, hands the child its
address through `HTTP_PROXY` and `HTTPS_PROXY`, and stops it when the run ends. A
contained program reaches it on loopback (ADR-0006 finding 1) and nothing else:
the container refuses other machines (finding 5), and the firewall rules are the
second lock (#33).

Two kinds of request, both decided by the gate before anything connects:

- `CONNECT host:port`, for HTTPS. The proxy sees the name and the port, never the
  content; the bytes each way are counted against the limits as they pass
- `GET http://host/path` and the other allowed methods, for plain HTTP. The request
  goes on with the `Host` the gate checked, never the one the sandbox sent, and with
  the proxy's own headers removed

Every request carries a password made for this run, so another program on the
machine that finds the port cannot use this run's allowlist. Redirects are passed
back as they are: following one is a new request, and a new decision.
"""

from __future__ import annotations

import base64
import hmac
import secrets
import select
import socket
import socketserver
import threading
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from sletchy.kernel.ledger import LedgerError
from sletchy.warden.egress.gate import EgressDenied
from sletchy.warden.egress.policy import canonical_host

if TYPE_CHECKING:
    from sletchy.warden.egress.gate import EgressGate

#: The longest request head accepted, request line and headers together.
MAX_HEAD_BYTES = 16 * 1024
#: Connections one run may hold open through the proxy at once.
MAX_CONNECTIONS = 16
USER = "sletchy"
#: Headers that are the proxy's business, or that would let the sandbox speak for it.
_HOP = frozenset(
    {
        "connection",
        "host",
        "keep-alive",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailer",
        "upgrade",
    }
)


class EgressProxy:
    """One run's proxy. `with EgressProxy(gate) as proxy:` and hand `proxy.url` on."""

    def __init__(self, gate: EgressGate, *, password: str | None = None) -> None:
        self.gate = gate
        self.password = password or secrets.token_urlsafe(24)
        self._server: _Server | None = None
        self._thread: threading.Thread | None = None

    @property
    def port(self) -> int:
        if self._server is None:
            raise RuntimeError("the proxy is not running")
        return int(self._server.server_address[1])

    @property
    def url(self) -> str:
        """The address a child is given, password included."""
        return f"http://{USER}:{self.password}@127.0.0.1:{self.port}"

    def start(self) -> EgressProxy:
        self._server = _Server(self)
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            # How often the loop looks for stop(): a run ending waits this long, at most.
            kwargs={"poll_interval": 0.05},
            name="sletchy-egress-proxy",
            daemon=True,
        )
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._server is None:
            return
        server, self._server = self._server, None
        server.shutdown()
        server.server_close()
        if self._thread is not None:
            self._thread.join(5)

    def __enter__(self) -> EgressProxy:
        return self.start()

    def __exit__(self, *_exc: object) -> None:
        self.stop()

    def authorised(self, value: str) -> bool:
        expected = "Basic " + base64.b64encode(f"{USER}:{self.password}".encode()).decode()
        return hmac.compare_digest(value.strip().encode(), expected.encode())


class _Server(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, proxy: EgressProxy) -> None:
        self.proxy = proxy
        self.slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
        # Loopback, always: the honeypot rule (LAW 0 §4) holds for the door out too.
        super().__init__(("127.0.0.1", 0), _Handler)


class _Handler(socketserver.BaseRequestHandler):
    server: _Server

    def handle(self) -> None:
        client: socket.socket = self.request
        proxy = self.server.proxy
        client.settimeout(proxy.gate.limits.idle_seconds)
        if not self.server.slots.acquire(blocking=False):
            _reply(client, 503, "Service Unavailable", "too many connections at once")
            return
        try:
            self._serve(client, proxy)
        except (OSError, ValueError):
            return
        finally:
            self.server.slots.release()

    def _serve(self, client: socket.socket, proxy: EgressProxy) -> None:
        head, rest = _read_head(client)
        if head is None:
            _reply(client, 431, "Request Header Fields Too Large", "the request head is too long")
            return
        lines = head.decode("latin-1").split("\r\n")
        try:
            method, target, _version = lines[0].split(" ", 2)
        except ValueError:
            _reply(client, 400, "Bad Request", "not an HTTP request")
            return
        headers = _headers(lines[1:])
        if headers is None:
            _reply(client, 400, "Bad Request", "a header line Sletchy could not read")
            return
        if not proxy.authorised(_first(headers, "proxy-authorization")):
            seq = proxy.gate.refuse_unknown_caller(
                "a request to the sandbox proxy without this run's password"
            )
            _reply(
                client,
                407,
                "Proxy Authentication Required",
                f"Sletchy refused this: no password for this proxy (ledger {seq})",
                extra='Proxy-Authenticate: Basic realm="sletchy"\r\n',
            )
            return
        if method.upper() == "CONNECT":
            self._tunnel(client, proxy, target, rest)
        else:
            self._forward(client, proxy, method, target, headers, rest)

    # ── HTTPS ────────────────────────────────────────────────────────────────

    def _tunnel(self, client: socket.socket, proxy: EgressProxy, target: str, rest: bytes) -> None:
        host, _, port_text = target.rpartition(":")
        port = _port(port_text)
        if not host or port is None:
            _reply(client, 400, "Bad Request", "CONNECT needs host:port")
            return
        upstream = _open(client, proxy, "CONNECT", host, port, 0)
        if upstream is None:
            return
        with upstream:
            client.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            _pump(proxy, client, upstream, host, port, already_up=rest)

    # ── plain HTTP ───────────────────────────────────────────────────────────

    def _forward(
        self,
        client: socket.socket,
        proxy: EgressProxy,
        method: str,
        target: str,
        headers: list[tuple[str, str]],
        rest: bytes,
    ) -> None:
        parts = urlsplit(target)
        if parts.scheme.lower() != "http" or not parts.netloc:
            _reply(
                client,
                400,
                "Bad Request",
                "a proxy request names http://host/...; HTTPS uses CONNECT",
            )
            return
        if _first(headers, "transfer-encoding"):
            reason = "a request body of unknown length (Transfer-Encoding)"
            _refuse(client, proxy, method, parts.hostname or parts.netloc, 80, reason)
            return
        length_text = _first(headers, "content-length") or "0"
        if not length_text.isdigit():
            _reply(client, 400, "Bad Request", "a Content-Length that is not a number")
            return
        length = int(length_text)
        netloc = parts.netloc
        host = netloc if "@" in netloc else (parts.hostname or "")
        try:
            port = parts.port or 80
        except ValueError:
            _reply(client, 400, "Bad Request", "a port that is not a number")
            return
        upstream = _open(client, proxy, method, host, port, length)
        if upstream is None:
            return
        with upstream:
            checked = canonical_host(host)  # the gate accepted it, so this cannot fail
            path = parts.path or "/"
            if parts.query:
                path += "?" + parts.query
            lines = [
                f"{method} {path} HTTP/1.1",
                f"Host: {checked}" + (f":{port}" if port != 80 else ""),
            ]
            lines += [f"{k}: {v}" for k, v in headers if k.lower() not in _HOP]
            lines += ["Connection: close", "", ""]
            upstream.sendall("\r\n".join(lines).encode("latin-1"))
            body = rest[:length]
            remaining = length - len(body)
            upstream.sendall(body)
            while remaining > 0:
                chunk = client.recv(min(65536, remaining))
                if not chunk:
                    return
                upstream.sendall(chunk)
                remaining -= len(chunk)
            _pump(proxy, client, upstream, checked, port, upload_done=True)


# ── helpers ──────────────────────────────────────────────────────────────────


def _open(
    client: socket.socket, proxy: EgressProxy, method: str, host: str, port: int, length: int
) -> socket.socket | None:
    """The gate's answer as a socket, or a reply to the sandbox saying why not."""
    try:
        return proxy.gate.open(method, host, port, declared_bytes=length)
    except EgressDenied as denied:
        _reply(
            client, 403, "Forbidden", f"Sletchy refused this: {denied.reason} (ledger {denied.seq})"
        )
    except LedgerError:
        _reply(
            client,
            503,
            "Service Unavailable",
            "Sletchy could not record this, so it did not send it",
        )
    except OSError:
        _reply(client, 502, "Bad Gateway", "the allowed host could not be reached")
    return None


def _refuse(
    client: socket.socket, proxy: EgressProxy, method: str, host: str, port: int, reason: str
) -> None:
    try:
        proxy.gate.refuse(method, host, port, reason)
    except EgressDenied as denied:
        _reply(client, 403, "Forbidden", f"Sletchy refused this: {reason} (ledger {denied.seq})")


def _pump(
    proxy: EgressProxy,
    client: socket.socket,
    upstream: socket.socket,
    host: str,
    port: int,
    *,
    already_up: bytes = b"",
    upload_done: bool = False,
) -> None:
    """Copy both ways until either side ends, counting each against its limit.

    A chunk that would cross a limit is not sent: the transfer stops at the limit,
    and the cut is recorded.
    """
    limits = proxy.gate.limits
    up = down = 0
    if already_up:
        up = len(already_up)
        if up > limits.max_request_bytes:
            proxy.gate.cut(host, port, f"the sandbox sent over {limits.max_request_bytes} bytes")
            return
        upstream.sendall(already_up)
    watched = [upstream] if upload_done else [client, upstream]
    while True:
        readable, _, _ = select.select(watched, [], [], limits.idle_seconds)
        if not readable:
            return
        for side in readable:
            data = side.recv(65536)
            if not data:
                return
            if side is client:
                up += len(data)
                if up > limits.max_request_bytes:
                    proxy.gate.cut(
                        host,
                        port,
                        f"the sandbox sent over {limits.max_request_bytes} bytes; stopped",
                    )
                    return
                upstream.sendall(data)
            else:
                down += len(data)
                if down > limits.max_response_bytes:
                    proxy.gate.cut(
                        host,
                        port,
                        f"the answer passed {limits.max_response_bytes} bytes; stopped there",
                    )
                    return
                client.sendall(data)


def _read_head(sock: socket.socket) -> tuple[bytes | None, bytes]:
    """The request head, and whatever arrived after it. None if it never ended."""
    buffer = b""
    while b"\r\n\r\n" not in buffer:
        if len(buffer) > MAX_HEAD_BYTES:
            return None, b""
        chunk = sock.recv(4096)
        if not chunk:
            raise ValueError("the connection closed before the request ended")
        buffer += chunk
    head, _, rest = buffer.partition(b"\r\n\r\n")
    if len(head) > MAX_HEAD_BYTES:
        return None, b""
    return head, rest


def _headers(lines: list[str]) -> list[tuple[str, str]] | None:
    parsed: list[tuple[str, str]] = []
    for line in lines:
        if not line:
            continue
        name, sep, value = line.partition(":")
        if not sep or not name or name != name.strip() or any(c in name for c in " \t"):
            return None
        parsed.append((name, value.strip()))
    return parsed


def _first(headers: list[tuple[str, str]], name: str) -> str:
    return next((v for k, v in headers if k.lower() == name), "")


def _port(text: str) -> int | None:
    if not text.isdigit():
        return None
    port = int(text)
    return port if 1 <= port <= 65535 else None


def _reply(sock: socket.socket, status: int, reason: str, text: str, *, extra: str = "") -> None:
    body = (text + "\n").encode("utf-8")
    head = (
        f"HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain; charset=utf-8\r\n"
        f"Content-Length: {len(body)}\r\n{extra}Connection: close\r\n\r\n"
    )
    try:
        sock.sendall(head.encode("latin-1") + body)
    except OSError:
        return
