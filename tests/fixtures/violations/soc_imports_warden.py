"""VIOLATION: sibling planes importing each other.

`soc` and `warden` are siblings, not a stack. The SOC reads the ledger; it does not
reach into the enforcer, and the enforcer does not call the watcher.
"""

from sletchy.warden.egress import proxy  # noqa: F401  - fixture, never executed
