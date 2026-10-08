"""VIOLATION: a plane opening its own socket.

Nothing reaches the outside world except through the Warden. A raw client anywhere
outside `warden/egress/` is a hole in the membrane, whatever the intent.
"""

import socket  # noqa: F401  - fixture, never executed

import httpx  # noqa: F401  - fixture, never executed
