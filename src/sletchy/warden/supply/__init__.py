"""`warden/supply/` - what a dependency does, measured rather than assumed (#34).

`quarantine.py` imports a package in a fresh Python with an audit hook watching, and
refuses and records any connection, program start or write outside its own folder.
Why each package is here is written in `docs/supply/DEPENDENCIES.md`; whether any has a
known vulnerability is asked of OSV by `scripts/known_vulnerabilities.py`, in CI.
"""

from sletchy.warden.supply.quarantine import Event, Profile, profile

__all__ = ["Event", "Profile", "profile"]
