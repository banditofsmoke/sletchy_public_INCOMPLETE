"""The client Sletchy's own planes use to reach the outside world (#32).

The only sanctioned one: the import check refuses a network client anywhere outside
`warden/egress/`, and this one gets its sockets from the gate, so every request it
makes is decided and recorded before it connects.

What it deliberately lacks, and must keep lacking:

- **No redirect following.** A `3xx` comes back as a response. Following it is a new
  request to a new host, and so a new policy question
- **No way around the gate**: no `direct=`, no `verify=False`, no proxy setting, no
  host to trust. A test holds the signature to exactly what is here
- **No reading past the limit.** The answer is read up to the response limit and no
  further; one byte more and the transfer is cut, and the cut recorded
"""

from __future__ import annotations

import http.client
import ssl
from dataclasses import dataclass
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from sletchy.warden.egress.gate import EgressDenied
from sletchy.warden.egress.policy import canonical_host

if TYPE_CHECKING:
    from sletchy.warden.egress.gate import EgressGate

#: Headers the client writes itself. A caller's copy of one is dropped, not merged.
_OWN = frozenset({"host", "connection", "content-length", "transfer-encoding"})


@dataclass(frozen=True)
class Response:
    status: int
    reason: str
    headers: tuple[tuple[str, str], ...]
    body: bytes

    def header(self, name: str) -> str | None:
        return next((v for k, v in self.headers if k.lower() == name.lower()), None)


class EgressClient:
    """HTTP and HTTPS through the gate, one request per connection."""

    def __init__(self, gate: EgressGate) -> None:
        self._gate = gate

    def request(
        self,
        method: str,
        url: str,
        *,
        body: bytes = b"",
        headers: dict[str, str] | None = None,
    ) -> Response:
        """One request. Raises `EgressDenied` if refused or cut, `OSError` if unreachable."""
        parts = urlsplit(url)
        scheme = parts.scheme.lower()
        if scheme not in ("http", "https"):
            raise ValueError(f"only http and https: {scheme or 'no scheme'}")
        netloc = parts.netloc
        host = netloc if "@" in netloc else (parts.hostname or "")
        port = parts.port or (443 if scheme == "https" else 80)
        sock = self._gate.open(method, host, port, declared_bytes=len(body))
        name = canonical_host(host)  # the gate accepted it, so this cannot fail
        try:
            if scheme == "https":
                sock = ssl.create_default_context().wrap_socket(sock, server_hostname=name)
            path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
            lines = [
                f"{method.upper()} {path} HTTP/1.1",
                f"Host: {name}" + ("" if port in (80, 443) else f":{port}"),
                "Connection: close",
                f"Content-Length: {len(body)}",
            ]
            lines += [f"{k}: {v}" for k, v in (headers or {}).items() if k.lower() not in _OWN]
            sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + body)
            answer = http.client.HTTPResponse(sock, method=method.upper())
            answer.begin()
            limit = self._gate.limits.max_response_bytes
            data = answer.read(limit + 1)
            if len(data) > limit:
                reason = f"the answer passed {limit} bytes; stopped there"
                raise EgressDenied(reason, self._gate.cut(name, port, reason))
            return Response(
                status=answer.status,
                reason=answer.reason,
                headers=tuple(answer.getheaders()),
                body=data,
            )
        finally:
            sock.close()
