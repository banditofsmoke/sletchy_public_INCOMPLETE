"""The door to a model server on this machine (ADR-0017).

The gate (`gate.py`) refuses this machine by a floor no allowlist lowers, and that stays
true: a service on this machine is the first thing a confused deputy is aimed at. A model
server running here is reached through this door instead. It is the gate's opposite in
where it may go, and its twin in everything else:

- **One address and one port.** `127.0.0.1` and the port the operator names, never a
  name, so there is no lookup to rebind and no other machine to reach
- **A short list of requests, each a question for a model**: list the models, ask one,
  turn text into vectors (ADR-0019), say which models are loaded (#202), and say what
  one model can do (#204).
  Never a request that makes the server fetch, write or delete anything (Ollama's
  `pull`, `push`, `create`, `copy`, `delete`). A local server that downloads on request
  would be a way round the gate
- **The switch**, `mind_local_models`, off on a fresh install and read on every request
- **Recorded before it connects**, allowed or refused (LAW 1)
- **Limits while the bytes pass**: the request's size before connecting, the answer's
  size while reading, and how long it may take

**Nothing here starts a model server.** If none is answering, the request fails and says
so. Whichever server answers is outside Sletchy, unmodified and unimported: Ollama today,
the operator's own build of llama.cpp later. Changing it is an engine name and a port.
"""

from __future__ import annotations

import http.client
import socket
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, NoReturn

from sletchy.kernel.contracts import Decision, Plane, Subject, SubjectKind, Verdict
from sletchy.warden.egress.client import Response
from sletchy.warden.egress.gate import EgressDenied

if TYPE_CHECKING:
    from sletchy.kernel.ledger import Ledger

LOCAL_ACTION = "warden.egress.local"
LOCAL_CUT_ACTION = "warden.egress.local.cut"

#: The only address this door connects to.
THIS_MACHINE = "127.0.0.1"

#: Each engine's questions, exactly: a method and a path, matched whole. Anything else,
#: a query string or a trailing slash included, is refused.
ENGINES: dict[str, frozenset[tuple[str, str]]] = {
    "ollama": frozenset(
        {
            ("GET", "/api/version"),
            ("GET", "/api/tags"),
            ("GET", "/api/ps"),
            ("POST", "/api/show"),
            ("POST", "/api/chat"),
            ("POST", "/api/embed"),
        }
    ),
    "llama.cpp": frozenset(
        {
            ("GET", "/health"),
            ("GET", "/v1/models"),
            ("POST", "/v1/chat/completions"),
        }
    ),
}

#: Ports an unprivileged server can listen on. The operator names one of them.
PORTS = range(1024, 65536)

Connector = Callable[[str, int, float], socket.socket]


def system_connector(address: str, port: int, timeout: float) -> socket.socket:
    return socket.create_connection((address, port), timeout=timeout)


@dataclass(frozen=True)
class LocalLimits:
    """A local model is slow, not far: long to answer, small to ask."""

    max_request_bytes: int = 256 * 1024
    max_response_bytes: int = 8 * 1024 * 1024
    connect_seconds: float = 3.0
    #: The longest wait for the next bytes. A model that spills onto the processor
    #: can take minutes over one answer.
    idle_seconds: float = 300.0


class LocalModelDoor:
    """One port on this machine, a few requests, the switch, and the record."""

    def __init__(
        self,
        *,
        ledger: Ledger,
        actor_id: str,
        switched_on: Callable[[], bool],
        engine: str,
        port: int,
        limits: LocalLimits | None = None,
        connect: Connector = system_connector,
    ) -> None:
        if engine not in ENGINES:
            raise ValueError(f"no such engine: {engine!r}; known: {', '.join(sorted(ENGINES))}")
        if port not in PORTS:
            raise ValueError(f"port {port} is not one an unprivileged server can use")
        self._ledger = ledger
        self.actor_id = actor_id
        self._switched_on = switched_on
        self.engine = engine
        self.port = port
        self.limits = limits or LocalLimits()
        self._connect = connect

    @property
    def where(self) -> str:
        return f"{THIS_MACHINE}:{self.port}"

    def request(self, method: str, path: str, body: bytes = b"") -> Response:
        """One request. Raises `EgressDenied` if refused or cut, `OSError` if nobody answers."""
        verb = method.upper()
        self._decide(verb, path, len(body))
        self._ledger.append(
            plane=Plane.WARDEN,
            actor_id=self.actor_id,
            action=LOCAL_ACTION,
            subject=Subject(kind=SubjectKind.HOST, identifier=f"{self.where}{path}"),
            verdict=Verdict(
                decision=Decision.ALLOW, reason=f"{verb} {path} to {self.engine} on {self.where}"
            ),
        )
        sock = self._connect(THIS_MACHINE, self.port, self.limits.connect_seconds)
        try:
            sock.settimeout(self.limits.idle_seconds)
            lines = [
                f"{verb} {path} HTTP/1.1",
                f"Host: {self.where}",
                "Connection: close",
                "Content-Type: application/json",
                f"Content-Length: {len(body)}",
            ]
            sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("ascii") + body)
            answer = http.client.HTTPResponse(sock, method=verb)
            answer.begin()
            limit = self.limits.max_response_bytes
            data = answer.read(limit + 1)
            if len(data) > limit:
                self._cut(path, f"the answer passed {limit} bytes; stopped there")
            return Response(
                status=answer.status,
                reason=answer.reason,
                headers=tuple(answer.getheaders()),
                body=data,
            )
        finally:
            sock.close()

    def _decide(self, verb: str, path: str, size: int) -> None:
        if not self._switched_on():
            self._refuse(verb, path, "local models are switched off")
        if (verb, path) not in ENGINES[self.engine]:
            self._refuse(verb, path, f"not a question this door asks {self.engine}")
        if size > self.limits.max_request_bytes:
            self._refuse(
                verb,
                path,
                f"a request of {size} bytes, over the limit of {self.limits.max_request_bytes}",
            )

    def _refuse(self, verb: str, path: str, reason: str) -> NoReturn:
        shown = "".join(ch if ch.isprintable() else "?" for ch in path)[:120]
        entry = self._ledger.append(
            plane=Plane.WARDEN,
            actor_id=self.actor_id,
            action=LOCAL_ACTION,
            subject=Subject(kind=SubjectKind.HOST, identifier=f"{self.where}{shown or '/'}"),
            verdict=Verdict(decision=Decision.DENY, reason=f"{verb[:20]}: {reason}"[:512]),
        )
        raise EgressDenied(reason, entry.seq)

    def _cut(self, path: str, reason: str) -> NoReturn:
        entry = self._ledger.append(
            plane=Plane.WARDEN,
            actor_id=self.actor_id,
            action=LOCAL_CUT_ACTION,
            subject=Subject(kind=SubjectKind.HOST, identifier=f"{self.where}{path}"),
            verdict=Verdict(decision=Decision.DENY, reason=reason[:512]),
        )
        raise EgressDenied(reason, entry.seq)
