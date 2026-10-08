"""VIOLATION: the Shell importing the SOC.

ADR-0011: the SOC reads hostile input, so its code never runs inside the window. The
Shell reads what the SOC found from the ledger instead.
"""

from sletchy.soc import detect  # noqa: F401  - fixture, never executed
