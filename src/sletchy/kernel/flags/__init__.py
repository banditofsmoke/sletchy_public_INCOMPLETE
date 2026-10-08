"""Flags - one switchboard, dangerous things off by default.

This is what makes Sletchy handable to someone non-technical: they receive a copy
where everything touching the network, the filesystem outside `var/`, the
microphone, the camera, the screen, a wallet, or a training run is already off, and
the system is useful before anything is turned on.

LAW 8, enforced in three places: `Flag`'s validator refuses a dangerous default,
`FlagRegistry` re-checks the whole set, and a test enumerates the entire registry on
a fresh install.
"""

from sletchy.kernel.flags.errors import (
    FlagError,
    FlagRegistryInvalid,
    FlagWriteFailed,
    ReasonRequired,
    UnknownFlag,
)
from sletchy.kernel.flags.registry import DEFAULT_FLAGS, FlagRegistry
from sletchy.kernel.flags.store import (
    FLIP_ACTION,
    RESET_ACTION,
    WRITE_FAILED_ACTION,
    FlagStore,
)

__all__ = [
    "DEFAULT_FLAGS",
    "FLIP_ACTION",
    "RESET_ACTION",
    "WRITE_FAILED_ACTION",
    "FlagError",
    "FlagRegistry",
    "FlagRegistryInvalid",
    "FlagStore",
    "FlagWriteFailed",
    "ReasonRequired",
    "UnknownFlag",
]
