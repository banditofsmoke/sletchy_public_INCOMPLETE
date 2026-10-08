"""What the sensors read, as data (#146).

Everything here comes from the operating system and is described by whatever is
running: a process names itself, and a hostile one names itself to mislead. Nothing
in these models is trusted, and every string is made safe before it is shown
(`shown`) or recorded.
"""

from __future__ import annotations

from datetime import datetime
from enum import IntEnum
from typing import Annotated, Literal

from pydantic import Field

from sletchy.kernel.contracts.base import Contract, Name

Port = Annotated[int, Field(ge=0, le=65535)]

#: The addresses a socket listens on to be reachable from every network. Compared
#: against, never bound to.
EVERY_INTERFACE = ("0.0.0.0", "::")  # noqa: S104


class TcpState(IntEnum):
    """`MIB_TCP_STATE`, plus NONE for UDP and UNKNOWN for a value Windows adds later."""

    NONE = 0
    CLOSED = 1
    LISTEN = 2
    SYN_SENT = 3
    SYN_RECEIVED = 4
    ESTABLISHED = 5
    FIN_WAIT_1 = 6
    FIN_WAIT_2 = 7
    CLOSE_WAIT = 8
    CLOSING = 9
    LAST_ACK = 10
    TIME_WAIT = 11
    DELETE_TCB = 12
    UNKNOWN = 99

    @classmethod
    def of(cls, value: int) -> TcpState:
        try:
            return cls(value)
        except ValueError:
            return cls.UNKNOWN


class Proc(Contract):
    """One running process. `path` is None where Windows would not let us look (L009)."""

    pid: Annotated[int, Field(ge=0)]
    parent: Annotated[int, Field(ge=0)]
    name: Annotated[str, Field(max_length=520)]
    path: Annotated[str, Field(max_length=32768)] | None
    memory_bytes: Annotated[int, Field(ge=0)]
    cpu_seconds: Annotated[float, Field(ge=0)]
    threads: Annotated[int, Field(ge=0)]
    handles: Annotated[int, Field(ge=0)]
    started: datetime | None


class Sock(Contract):
    """One socket and the process that owns it. A listener has no remote end."""

    protocol: Literal["tcp", "udp"]
    local_address: Annotated[str, Field(max_length=64)]
    local_port: Port
    remote_address: Annotated[str, Field(max_length=64)] | None
    remote_port: Port | None
    state: TcpState
    pid: Annotated[int, Field(ge=0)]

    @property
    def listening(self) -> bool:
        return self.protocol == "tcp" and self.state is TcpState.LISTEN

    @property
    def on_every_interface(self) -> bool:
        """Reachable from the network, not only from this machine."""
        return self.local_address in EVERY_INTERFACE

    @property
    def loopback_only(self) -> bool:
        return self.local_address.startswith("127.") or self.local_address == "::1"


class Snapshot(Contract):
    """One look at the machine, already narrowed to what the operator allowed."""

    taken_at: datetime
    processes: tuple[Proc, ...]
    sockets: tuple[Sock, ...]
    whole_machine: bool
    windows_folder: str


class Finding(Contract):
    """Something wrong, in words, with the rule that found it. Only these reach the
    ledger; a snapshot never does (ADR-0011 decision 4)."""

    rule: Name
    identifier: Annotated[str, Field(min_length=1, max_length=1024)]
    summary: Annotated[str, Field(min_length=1, max_length=480)]


def shown(text: str, limit: int = 200) -> str:
    """Safe to print or record: control characters escaped, length bounded (#96)."""
    safe = "".join(
        ch if ch.isprintable() else ch.encode("unicode_escape").decode("ascii") for ch in text
    )
    return safe if len(safe) <= limit else safe[: limit - 3] + "..."
