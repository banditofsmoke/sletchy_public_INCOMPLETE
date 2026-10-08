"""Flag failures."""

from __future__ import annotations


class FlagError(Exception):
    """Base for every flag failure."""


class UnknownFlag(FlagError):
    """No such flag is declared.

    Raised on both read and write. An unknown flag is never created on demand and
    never silently reads as `False`: a typo would otherwise leave a capability
    permanently and invisibly disabled, which looks identical to it being off on
    purpose.
    """


class FlagRegistryInvalid(FlagError):
    """The declared flag set violates LAW 8 or contains a duplicate."""


class FlagWriteFailed(FlagError, OSError):
    """A flip or a reset went into the ledger, then `flags.json` could not be replaced.

    The ledger also holds a second entry saying the change did not take effect, so the
    chain says what happened, and every flag is as it was before (#104). An `OSError`,
    carrying the file and the reason, so the CLI answers it with a sentence (#97).
    """


class ReasonRequired(FlagError):
    """Turning on a DANGEROUS flag without saying why.

    The ledger records who, when, and why. Two of those are automatic; the third
    has to be supplied, and a blank one is not an answer.
    """
