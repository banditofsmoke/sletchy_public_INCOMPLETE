"""Windows' AppContainer SID derivation in plain Python, for tests that must not call Windows.

Measured on 10.0.19045 (2026-10-03) against `DeriveAppContainerSidFromAppContainerName`
for three names, one of them a real Microsoft package: the SID is `S-1-15-2-` and seven
sub-authorities, each a little-endian 32-bit slice of SHA-256 over the lowercased name
in UTF-16LE. `test_abuser_panic.py::test_the_derivation_is_the_one_windows_uses` holds
this equal to the real call on every Windows run, so a fake that drifted from Windows
would fail there rather than quietly pass the panic tests that use it.
"""

from __future__ import annotations

import hashlib


def derive_sid(name: str) -> str:
    digest = hashlib.sha256(name.lower().encode("utf-16-le")).digest()
    parts = (int.from_bytes(digest[i : i + 4], "little") for i in range(0, 28, 4))
    return "S-1-15-2-" + "-".join(str(part) for part in parts)
