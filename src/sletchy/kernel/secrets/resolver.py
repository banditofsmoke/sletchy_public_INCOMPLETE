"""Resolving a `SecretRef` into a value, at the moment of use.

Three properties, each enforced by shape rather than by care:

**Fail closed.** `resolve()` has exactly one successful return path: a keychain read
that found something. Every other outcome raises. There is no `default=` parameter
and no environment-variable fallback, and adding either would reintroduce the exact
bug that leaked six keys across the archived projects.

**The value never lands anywhere durable.** `Secret` wraps it, and its `__repr__`,
`__str__`, and Pydantic serialisation all show the ref. You have to call `.reveal()`
to get the string, which makes every disclosure point greppable.

**Every resolution is recorded - the ref, never the value.** So "which secret was
used, when, by whom" is answerable after the fact without the ledger becoming a
place secrets accumulate.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

from sletchy.kernel.contracts import Decision, Plane, Subject, SubjectKind, Verdict
from sletchy.kernel.ledger.canonical import content_hash
from sletchy.kernel.secrets.errors import SecretBackendUnavailable, SecretMissing

if TYPE_CHECKING:
    from sletchy.kernel.contracts import SecretRef
    from sletchy.kernel.ledger import Ledger

RESOLVE_ACTION = "kernel.secret.resolve"


@runtime_checkable
class KeyringBackend(Protocol):
    """The slice of the `keyring` API this module uses.

    Declared as a Protocol rather than importing `keyring` directly so tests can
    substitute a fake without a real credential store ever being touched - and so
    mypy checks the substitution instead of trusting it.
    """

    def get_password(self, service: str, name: str) -> str | None: ...

    def set_password(self, service: str, name: str, value: str) -> None: ...

    def delete_password(self, service: str, name: str) -> None: ...


class Secret:
    """A resolved secret value that resists being written down by accident.

    Not a security boundary - anything holding this can call `.reveal()`. It is a
    *legibility* boundary: it makes an accidental `print(secret)` or an f-string in
    a log message harmless, and makes every deliberate disclosure grep-able as
    `.reveal()`.
    """

    __slots__ = ("_ref", "_value")

    def __init__(self, ref: SecretRef, value: str) -> None:
        self._ref = ref
        self._value = value

    @property
    def ref(self) -> SecretRef:
        return self._ref

    def reveal(self) -> str:
        """Return the raw value. Every call site is a disclosure point."""
        return self._value

    def fingerprint(self) -> str:
        """A hash of the value, safe to log.

        Lets an operator confirm two systems hold the *same* secret, or that a
        rotation actually changed something, without either fact requiring the
        value to be printed.
        """
        return content_hash(self._value.encode("utf-8"))[:16]

    def __repr__(self) -> str:
        return f"Secret({self._ref.service}/{self._ref.name})"

    __str__ = __repr__

    def __format__(self, spec: str) -> str:
        """Defeats `f"{secret}"` and `"{}".format(secret)` alike."""
        return repr(self)

    def __eq__(self, other: object) -> bool:
        """Constant-time comparison against another `Secret`.

        Comparing against a bare `str` returns NotImplemented rather than doing the
        obvious thing - an accidental `secret == "hunter2"` should be a type error
        in review, not a timing oracle.
        """
        if not isinstance(other, Secret):
            return NotImplemented
        import hmac

        return hmac.compare_digest(self._value, other._value)

    def __hash__(self) -> int:
        """Hashes the ref, not the value - a secret must not key a dict by content."""
        return hash((self._ref.service, self._ref.name))


class SecretResolver:
    """Reads secrets from the OS keychain. Fails closed."""

    __slots__ = ("_backend", "_ledger")

    def __init__(self, ledger: Ledger, backend: KeyringBackend | None = None) -> None:
        self._ledger = ledger
        self._backend = backend

    def resolve(self, ref: SecretRef, *, actor_id: str = "kernel") -> Secret:
        """Read `ref` from the keychain, or raise.

        There is deliberately no `default` parameter. If you find yourself wanting
        one, the call site wants a *flag* (is this capability configured?) rather
        than a secret with a fallback.
        """
        keyring = self._keyring()
        try:
            stored = keyring.get_password(ref.service, ref.name)
        except Exception as exc:
            self._record(ref, actor_id, Decision.DENY, "keychain unavailable")
            msg = f"cannot read the OS keychain for {ref}: {type(exc).__name__}"
            raise SecretBackendUnavailable(msg) from exc

        if stored is None:
            self._record(ref, actor_id, Decision.DENY, "not present in the keychain")
            msg = (
                f"no secret for {ref}. Add it with `sletchy secrets add {ref.name}`. "
                "There is no fallback default: a secret that can carry one is a "
                "secret that will eventually ship one."
            )
            raise SecretMissing(msg)

        secret = Secret(ref, stored)
        self._record(ref, actor_id, Decision.ALLOW, f"resolved (fp {secret.fingerprint()})")
        return secret

    def exists(self, ref: SecretRef) -> bool:
        """Whether a secret is present, without resolving it.

        For `sletchy status` and first-run checks - reporting what is configured
        should not require reading, and does not write a resolution to the ledger.
        """
        try:
            return self._keyring().get_password(ref.service, ref.name) is not None
        except Exception:
            return False

    def add(self, ref: SecretRef, value: str, *, overwrite: bool = False) -> None:
        """Store a secret. Operator-initiated only; never called on a read path."""
        keyring = self._keyring()
        if not overwrite and keyring.get_password(ref.service, ref.name) is not None:
            msg = f"a secret already exists for {ref}; pass overwrite=True to replace it"
            raise ValueError(msg)
        keyring.set_password(ref.service, ref.name, value)
        self._record(ref, "operator", Decision.ALLOW, "stored")

    def remove(self, ref: SecretRef) -> None:
        """Delete a secret from the keychain."""
        try:
            self._keyring().delete_password(ref.service, ref.name)
        except Exception as exc:
            msg = f"cannot remove {ref}: {type(exc).__name__}"
            raise SecretBackendUnavailable(msg) from exc
        self._record(ref, "operator", Decision.DENY, "removed")

    def _keyring(self) -> KeyringBackend:
        if self._backend is not None:
            return self._backend
        try:
            import keyring
        except ImportError as exc:  # pragma: no cover - dependency is declared
            msg = "keyring is not installed"
            raise SecretBackendUnavailable(msg) from exc
        return keyring

    def _record(self, ref: SecretRef, actor_id: str, decision: Decision, detail: str) -> None:
        """Record the ref and the outcome. Never the value."""
        self._ledger.append(
            plane=Plane.KERNEL,
            actor_id=actor_id,
            action=RESOLVE_ACTION,
            subject=Subject(kind=SubjectKind.SECRET, identifier=f"{ref.service}/{ref.name}"),
            verdict=Verdict(decision=decision, reason=detail[:512], rule_id=None),
        )
