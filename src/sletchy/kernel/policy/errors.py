"""Policy failures.

Every one of these is fatal at startup rather than a warning. A policy nobody can
read is not a policy, and continuing with a partial one is worse than not starting:
it produces a system that looks configured and is not.
"""

from __future__ import annotations


class PolicyError(Exception):
    """Base for every policy failure."""


class PolicyUnreadable(PolicyError):
    """The policy file is missing, unopenable, or not valid TOML."""


class PolicyInvalid(PolicyError):
    """The policy parsed as TOML but is not a valid rule set."""


class WideningRejected(PolicyError):
    """A merge would have produced a bound wider than what was declared.

    LAW 3. This is not recoverable and there is no flag that permits it - the
    component whose profile would have been widened refuses to start.
    """
