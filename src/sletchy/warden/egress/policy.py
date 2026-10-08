"""What may leave, decided from the name and the address before anything connects (#32).

Two questions, in this order, and both must say yes:

1. **Is the name allowed?** The name is made canonical first (lowercase, no trailing
   dot, IDNA), then matched against the capability's allowlist, tightened by policy.
   Anything that is not plainly a name is refused before matching: an address
   literal, `user@host`, a number dressed as a name, a name that is always this
   machine. A lookalike in another script becomes `xn--...` and matches nothing.
2. **Is every address it resolves to allowed?** A floor no allowlist can lower: this
   machine, private networks, link-local (where cloud metadata lives), multicast and
   the reserved blocks. If **any** address the name resolves to is under the floor,
   the request is refused, and the connection goes to the address that was checked,
   never to a second lookup. That is what closes DNS rebinding.

Addresses reserved for documentation (RFC 5737, RFC 3849) are not under the floor:
nothing routes them, so reaching one reaches nothing, and the tests use them.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

#: Never reachable through the Warden, whatever the allowlist says.
FLOOR_V4: tuple[tuple[str, str], ...] = (
    ("0.0.0.0/8", "this network"),
    ("10.0.0.0/8", "a private network"),
    ("100.64.0.0/10", "a carrier's shared network"),
    ("127.0.0.0/8", "this machine"),
    ("169.254.0.0/16", "link-local, where cloud metadata services answer"),
    ("172.16.0.0/12", "a private network"),
    ("192.0.0.0/24", "reserved for protocol assignments"),
    ("192.168.0.0/16", "a private network"),
    ("198.18.0.0/15", "reserved for benchmarking"),
    ("224.0.0.0/4", "multicast"),
    ("240.0.0.0/4", "reserved, and broadcast"),
)
FLOOR_V6: tuple[tuple[str, str], ...] = (
    ("::/128", "the unspecified address"),
    ("::1/128", "this machine"),
    ("fc00::/7", "a private network"),
    ("fe80::/10", "link-local"),
    ("ff00::/8", "multicast"),
)
_FLOOR = tuple((ipaddress.ip_network(net), why) for net, why in (*FLOOR_V4, *FLOOR_V6))
#: IPv6 forms that carry an IPv4 address inside, which is checked in its own right.
_V4_INSIDE = (
    ipaddress.ip_network("::ffff:0:0/96"),  # IPv4-mapped
    ipaddress.ip_network("64:ff9b::/96"),  # NAT64
)
_SIX_TO_FOUR = ipaddress.ip_network("2002::/16")

_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_NUMERIC_LABEL = re.compile(r"^(0x[0-9a-f]*|[0-9]+)$")


class NotAName(ValueError):
    """The host is not something the allowlist could be asked about. Says why."""


def canonical_host(raw: str) -> str:
    """The one spelling of a host the allowlist is matched against, or `NotAName`."""
    text = raw.strip()
    if not text:
        raise NotAName("no host")
    if any(ch in text for ch in "@/\\?#%") or any(ord(ch) < 0x21 or ord(ch) == 0x7F for ch in text):
        raise NotAName("a host carrying more than a name (user@host, a path, a space)")
    bare = text.strip("[]")
    try:
        ipaddress.ip_address(bare)
    except ValueError:
        pass
    else:
        raise NotAName("an address, not a name: the allowlist holds names")
    name = text.lower().removesuffix(".")
    try:
        name = name.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise NotAName(f"not a valid name ({exc.__class__.__name__})") from exc
    if len(name) > 253:
        raise NotAName("longer than any name")
    labels = name.split(".")
    if not all(_LABEL.match(label) for label in labels):
        raise NotAName("not a valid name")
    if all(_NUMERIC_LABEL.match(label) for label in labels):
        raise NotAName("a number written as a name, which resolves as an address")
    if labels[-1] == "localhost":
        raise NotAName("a name that always means this machine")
    return name


def allowed_by(host: str, patterns: tuple[str, ...]) -> bool:
    """Exact names, and `*.suffix` for anything under a suffix (never the suffix itself)."""
    for pattern in patterns:
        entry = pattern.strip().lower().removesuffix(".")
        if entry.startswith("*."):
            if host.endswith(entry[1:]) and host != entry[2:]:
                return True
        elif host == entry:
            return True
    return False


def under_floor(address: IPAddress) -> str | None:
    """Why this address may never be reached, or None."""
    for net in _V4_INSIDE:
        if address in net:
            return under_floor(ipaddress.IPv4Address(int(address) & 0xFFFFFFFF))
    if address in _SIX_TO_FOUR:
        inner = ipaddress.IPv4Address((int(address) >> 80) & 0xFFFFFFFF)
        return under_floor(inner)
    for net, why in _FLOOR:
        if address.version == net.version and address in net:
            return why
    return None


@dataclass(frozen=True)
class Limits:
    """How much a request may carry and how long it may take. Enforced while streaming."""

    methods: frozenset[str] = field(default_factory=lambda: frozenset({"GET", "HEAD", "POST"}))
    max_request_bytes: int = 1024 * 1024
    max_response_bytes: int = 32 * 1024 * 1024
    connect_seconds: float = 10.0
    idle_seconds: float = 30.0
