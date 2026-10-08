"""VIOLATION: the trust root importing a plane above it.

If `kernel` may import `warden`, then "kernel imports nothing from sletchy" is a
diagram rather than a property, and a cycle can hide a bypass.
"""

from sletchy.warden import something  # noqa: F401  - fixture, never executed
