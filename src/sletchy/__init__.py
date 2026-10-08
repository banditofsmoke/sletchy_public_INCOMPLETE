"""Sletchy - a sealed personal enclave.

Seven planes, depending downward only:

    mind | senses | forge | vault     the capabilities
    warden | soc                      enforcement and observation
    kernel                            the trust root

Two structural rules, enforced by import-linter in CI:

1. Nothing reaches the outside world except through ``warden``.
2. Everything writes to ``kernel``'s ledger.

Read ``docs/LAW/00-do-no-harm.md`` before changing anything in ``warden``.
"""

__version__ = "0.0.1"
