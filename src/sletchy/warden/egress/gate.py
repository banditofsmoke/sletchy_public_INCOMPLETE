"""The gate: one decision per connection, on the ledger before the connection opens (#32).

Everything that leaves goes through `EgressGate.open`: the proxy a sandbox is handed
(`proxy.py`) and the client Sletchy's own planes use (`client.py`). There is no other
way to get a socket out of this package, and no parameter that skips a step.

The order is the contract:

1. **Switched on?** Off denies everything, whatever the allowlist. The gate is handed
   the switch by whoever builds it; nothing in the product builds one yet, so the
   `egress_enabled` flag is still read by nothing, and the registry says so
2. **Name, port, method, declared size**, each against policy (`policy.py`)
3. **Resolve once**, and refuse if any address is under the floor
4. **Record** the verdict: allowed or denied, with the reason (LAW 1)
5. Only then, and only if allowed, **connect** to the address that was checked

A denial raises `EgressDenied` carrying the reason and the ledger sequence number of
the entry that records it. Repeated denials from one actor in a short window add one
more entry, a signal the SOC can read.
"""

from __future__ import annotations

import ipaddress
import socket
import time
from collections import deque
from collections.abc import Callable
from typing import TYPE_CHECKING, NoReturn

from sletchy.kernel.contracts import Decision, NetworkPolicy, Plane, Subject, SubjectKind, Verdict
from sletchy.warden.egress.policy import (
    IPAddress,
    Limits,
    NotAName,
    allowed_by,
    canonical_host,
    under_floor,
)

if TYPE_CHECKING:
    from sletchy.kernel.ledger import Ledger

REQUEST_ACTION = "warden.egress.request"
CUT_ACTION = "warden.egress.cut"
FLOOD_ACTION = "warden.egress.flood"

#: This many denials for one actor inside the window raise one flood entry.
FLOOD_COUNT = 5
FLOOD_WINDOW_SECONDS = 60.0

Resolver = Callable[[str, int], list[IPAddress]]
Connector = Callable[[IPAddress, int, float], socket.socket]


class EgressDenied(PermissionError):
    """A request the Warden refused. Already on the ledger as entry `seq`."""

    def __init__(self, reason: str, seq: int | None) -> None:
        super().__init__(
            f"egress refused: {reason}" + (f" (ledger {seq})" if seq is not None else "")
        )
        self.reason = reason
        self.seq = seq


def system_resolver(host: str, port: int) -> list[IPAddress]:
    """Every address the name resolves to, for TCP. Raises `OSError` if none."""
    found = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    addresses: list[IPAddress] = []
    for *_, sockaddr in found:
        address = ipaddress.ip_address(str(sockaddr[0]).split("%", 1)[0])
        if address not in addresses:
            addresses.append(address)
    if not addresses:
        raise OSError(f"{host} resolved to nothing")
    return addresses


def system_connector(address: IPAddress, port: int, timeout: float) -> socket.socket:
    return socket.create_connection((str(address), port), timeout=timeout)


def _shown(text: str, limit: int = 200) -> str:
    """Printable and bounded, for a ledger reason: the host may be hostile text."""
    safe = text.encode("ascii", "backslashreplace").decode("ascii")
    safe = "".join(ch if ch.isprintable() else "?" for ch in safe)
    return safe if len(safe) <= limit else safe[: limit - 3] + "..."


class EgressGate:
    """The one door out. Built with a ledger, a policy and the switch; nothing else."""

    def __init__(
        self,
        *,
        ledger: Ledger,
        network: NetworkPolicy,
        actor_id: str,
        switched_on: Callable[[], bool],
        limits: Limits | None = None,
        resolve: Resolver = system_resolver,
        connect: Connector = system_connector,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._ledger = ledger
        self.network = network
        self.actor_id = actor_id
        self._switched_on = switched_on
        self.limits = limits or Limits()
        self._resolve = resolve
        self._connect = connect
        self._clock = clock
        self._denials: deque[float] = deque()
        self._flood_at: float | None = None

    def narrowed(self, network: NetworkPolicy) -> EgressGate:
        """The same gate, for a sandbox whose profile allows less. Only ever narrower."""
        return EgressGate(
            ledger=self._ledger,
            network=self.network.tighten(network),
            actor_id=self.actor_id,
            switched_on=self._switched_on,
            limits=self.limits,
            resolve=self._resolve,
            connect=self._connect,
            clock=self._clock,
        )

    # ── the decision ─────────────────────────────────────────────────────────

    def open(self, method: str, host: str, port: int, *, declared_bytes: int = 0) -> socket.socket:
        """Decide, record, then connect to the checked address. Raises `EgressDenied`."""
        verb = method.upper()
        try:
            name = canonical_host(host)
        except NotAName as exc:
            self.refuse(verb, host, port, str(exc))
        address = self._decide(verb, name, port, declared_bytes)
        self._ledger.append(
            plane=Plane.WARDEN,
            actor_id=self.actor_id,
            action=REQUEST_ACTION,
            subject=Subject(kind=SubjectKind.HOST, identifier=f"{name}:{port}"),
            verdict=Verdict(
                decision=Decision.ALLOW, reason=f"{verb} {name}:{port}, connecting to {address}"
            ),
        )
        return self._connect(address, port, self.limits.connect_seconds)

    def _decide(self, verb: str, name: str, port: int, declared_bytes: int) -> IPAddress:
        if not self._switched_on():
            self.refuse(verb, name, port, "internet access is switched off")
        if not self.network.allow_egress:
            self.refuse(verb, name, port, "nothing may leave: the allowlist is empty")
        if port not in self.network.allow_ports:
            self.refuse(verb, name, port, f"port {port} is not allowed")
        if verb != "CONNECT" and verb not in self.limits.methods:
            self.refuse(verb, name, port, f"the method {_shown(verb, 20)} is not allowed")
        if declared_bytes > self.limits.max_request_bytes:
            self.refuse(
                verb,
                name,
                port,
                f"a request of {declared_bytes} bytes, over the limit of "
                f"{self.limits.max_request_bytes}",
            )
        if not allowed_by(name, self.network.allow_egress):
            self.refuse(verb, name, port, "the host is not on the allowlist")
        try:
            addresses = self._resolve(name, port)
        except OSError as exc:
            self.refuse(verb, name, port, f"the name did not resolve ({_shown(str(exc), 80)})")
        for address in addresses:
            why = under_floor(address)
            if why:
                self.refuse(
                    verb,
                    name,
                    port,
                    f"the name resolves to {address}, {why}, which is never allowed",
                )
        return addresses[0]

    def refuse(self, verb: str, host: str, port: int, reason: str) -> NoReturn:
        """Record a refusal, raise a flood signal if due, then raise `EgressDenied`."""
        shown = _shown(host)
        entry = self._ledger.append(
            plane=Plane.WARDEN,
            actor_id=self.actor_id,
            action=REQUEST_ACTION,
            subject=Subject(kind=SubjectKind.HOST, identifier=f"{shown or '?'}:{port}"),
            verdict=Verdict(decision=Decision.DENY, reason=f"{_shown(verb, 20)}: {reason}"[:512]),
        )
        self._count_denial()
        raise EgressDenied(reason, entry.seq)

    def _count_denial(self) -> None:
        now = self._clock()
        self._denials.append(now)
        while self._denials and now - self._denials[0] > FLOOD_WINDOW_SECONDS:
            self._denials.popleft()
        quiet = self._flood_at is None or now - self._flood_at > FLOOD_WINDOW_SECONDS
        if len(self._denials) >= FLOOD_COUNT and quiet:
            self._flood_at = now
            self._ledger.append(
                plane=Plane.WARDEN,
                actor_id=self.actor_id,
                action=FLOOD_ACTION,
                subject=Subject(kind=SubjectKind.HOST, identifier=f"denials by {self.actor_id}"),
                verdict=Verdict(
                    decision=Decision.ALLOW,
                    reason=(
                        f"{len(self._denials)} requests refused in {FLOOD_WINDOW_SECONDS:.0f} s: "
                        "something is trying many destinations"
                    ),
                ),
            )

    # ── during the transfer ──────────────────────────────────────────────────

    def cut(self, host: str, port: int, reason: str) -> int:
        """Record a transfer stopped part-way, after the bytes it was allowed. Returns its seq."""
        entry = self._ledger.append(
            plane=Plane.WARDEN,
            actor_id=self.actor_id,
            action=CUT_ACTION,
            subject=Subject(kind=SubjectKind.HOST, identifier=f"{_shown(host)}:{port}"),
            verdict=Verdict(decision=Decision.DENY, reason=reason[:512]),
        )
        return entry.seq

    def refuse_unknown_caller(self, reason: str) -> int:
        """Record a request that never reached the policy question. Returns its seq."""
        entry = self._ledger.append(
            plane=Plane.WARDEN,
            actor_id=self.actor_id,
            action=REQUEST_ACTION,
            subject=Subject(kind=SubjectKind.HOST, identifier="the sandbox proxy"),
            verdict=Verdict(decision=Decision.DENY, reason=reason[:512]),
        )
        self._count_denial()
        return entry.seq
