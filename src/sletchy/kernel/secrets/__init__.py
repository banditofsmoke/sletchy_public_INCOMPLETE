"""Secrets - keychain refs, resolved late, failing closed.

Six live API keys leaked across the archived projects. One reached eight files in
three separate projects, including a packaged Electron build. The mechanism was a
single line that read a key from the environment *with a real key as the fallback* -
so it worked when the variable was absent, and nothing ever surfaced that a
baked-in credential was in use.

Everything here is shaped to make that impossible:

- `SecretRef` (from #1) has no `value`, `default`, or `fallback` field.
- `SecretResolver.resolve()` has no `default` parameter and exactly one successful
  return path.
- `Secret` shows its ref from `__repr__`, `__str__`, and `__format__`, so the value
  only escapes through an explicit, greppable `.reveal()`.
- `child_env()` is an allowlist, so a sandboxed child never inherits a credential
  it was not handed.
"""

from sletchy.kernel.secrets.env import child_env, stripped_from
from sletchy.kernel.secrets.errors import (
    SecretBackendUnavailable,
    SecretError,
    SecretMissing,
)
from sletchy.kernel.secrets.resolver import (
    RESOLVE_ACTION,
    KeyringBackend,
    Secret,
    SecretResolver,
)

__all__ = [
    "RESOLVE_ACTION",
    "KeyringBackend",
    "Secret",
    "SecretBackendUnavailable",
    "SecretError",
    "SecretMissing",
    "SecretResolver",
    "child_env",
    "stripped_from",
]
