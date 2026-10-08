"""`warden/egress/` - the only way out (#32).

Nothing reaches the outside world except through here. The import check refuses a
network client anywhere else in Sletchy (`tests/unit/test_import_layers.py`), and
everything here gets its connections from one place, `EgressGate.open`, which decides
and records before it connects.

- `policy.py`: canonical names, the allowlist match, and the address floor no
  allowlist lowers
- `gate.py`: the decision, the record, the connection to the checked address
- `proxy.py`: a sandbox's door, on loopback, for one run
- `client.py`: the door for Sletchy's own planes
- `local.py`: the door to a model server on this machine, one port, a few requests (ADR-0017)

Under it all, for a sandbox: the container refuses other machines by itself
(ADR-0006 finding 5) and the firewall rules are the second lock (#33, ADR-0013).
"""

from sletchy.warden.egress.client import EgressClient, Response
from sletchy.warden.egress.gate import EgressDenied, EgressGate
from sletchy.warden.egress.local import LocalLimits, LocalModelDoor
from sletchy.warden.egress.policy import Limits, NotAName
from sletchy.warden.egress.proxy import EgressProxy

__all__ = [
    "EgressClient",
    "EgressDenied",
    "EgressGate",
    "EgressProxy",
    "Limits",
    "LocalLimits",
    "LocalModelDoor",
    "NotAName",
    "Response",
]
