"""Secret failures.

Every message in this module is written on the assumption it will end up in a log,
a traceback, or a ledger reason. None of them may contain a secret value - which is
why they name the *ref* and never interpolate what was resolved.
"""

from __future__ import annotations


class SecretError(Exception):
    """Base for every secret failure."""


class SecretMissing(SecretError):
    """No such secret in the keychain.

    Fatal, always. There is no fallback default and no environment-variable
    substitute, because that exact pattern is how one live key reached eight files
    across three projects: an env lookup with a real key as its second argument
    *works* when the variable is absent, so nothing ever surfaces that a baked-in
    credential is in use.
    """


class SecretBackendUnavailable(SecretError):
    """The OS keychain cannot be reached.

    Distinct from `SecretMissing` on purpose: "the vault is locked" and "the vault
    does not contain this" call for different operator responses, and collapsing
    them would send someone hunting for a missing secret when the real problem is a
    broken keyring service.
    """
