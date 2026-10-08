"""The CLI's view of Sletchy's state root.

The paths themselves moved to [`kernel/paths.py`](../kernel/paths.py) when the
Warden started needing them too: `warden` may not import `cli`, so a root both
planes must agree on cannot live here. They are re-exported rather than
re-derived, so there is still exactly one definition of where state lives.

What remains here is the one path-shaped constant that is genuinely a CLI concern:
the firewall group `panic` deletes by name.
"""

from __future__ import annotations

from sletchy.kernel.paths import (
    ENV_HOME,
    allowlist_file,
    flags_file,
    home,
    ledger_dir,
    memory_dir,
    payload_dir,
    runtime_dir,
)

#: The single named group every firewall rule Sletchy creates belongs to, so they
#: can be removed wholesale without enumerating them. Nothing creates a rule
#: outside this group; `panic` removes the group.
FIREWALL_GROUP = "Sletchy"

__all__ = [
    "ENV_HOME",
    "FIREWALL_GROUP",
    "allowlist_file",
    "flags_file",
    "home",
    "ledger_dir",
    "memory_dir",
    "payload_dir",
    "runtime_dir",
]
