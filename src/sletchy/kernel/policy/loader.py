"""Loading a rule set from disk.

Everything here fails closed. A missing file, malformed TOML, an unknown key, a
duplicate rule id, or a rule that violates its own contract all raise at load time
rather than producing a partially-applied policy.

The distinction that matters:

- **A missing file raises.** It almost always means misconfiguration, and a system
  that silently runs with no policy because someone moved a file is exactly the
  failure this design exists to prevent.
- **An empty file is valid and denies everything.** That is a deliberate,
  reviewable statement - "grant nothing" - and it is what ships by default.
"""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import TYPE_CHECKING

from pydantic import ValidationError

from sletchy.kernel.contracts import ActorKind, Decision, Plane, PolicyRule, SubjectKind
from sletchy.kernel.policy.errors import PolicyInvalid, PolicyUnreadable

if TYPE_CHECKING:
    from collections.abc import Iterator

#: Bumped when the file format changes. An unknown version is a hard failure, never
#: a best-effort parse - a policy read under the wrong schema may silently grant.
POLICY_VERSION = 1

_ALLOWED_TOP_LEVEL = {"version", "rule"}

#: Enum-valued fields. TOML gives strings; contracts validate strictly, so the
#: conversion happens here, explicitly, at the trust boundary.
_ENUM_FIELDS: dict[str, type[Decision] | type[ActorKind] | type[Plane] | type[SubjectKind]] = {
    "decision": Decision,
    "actor_kind": ActorKind,
    "actor_plane": Plane,
    "subject_kind": SubjectKind,
}


class PolicySet:
    """An immutable, ordered set of rules.

    Ordering is by descending priority then by ascending id, computed once at
    construction so evaluation is a straight scan and two loads of the same file
    always evaluate identically.
    """

    __slots__ = ("_rules",)

    def __init__(self, rules: tuple[PolicyRule, ...] = ()) -> None:
        seen: set[str] = set()
        for rule in rules:
            if rule.id in seen:
                msg = f"duplicate rule id {rule.id!r}; ids must be unique"
                raise PolicyInvalid(msg)
            seen.add(rule.id)
        self._rules = tuple(sorted(rules, key=lambda r: (-r.priority, r.id)))

    @classmethod
    def empty(cls) -> PolicySet:
        """The deny-everything policy. Explicit, not a fallback."""
        return cls(())

    @property
    def rules(self) -> tuple[PolicyRule, ...]:
        return self._rules

    def __len__(self) -> int:
        return len(self._rules)

    def __iter__(self) -> Iterator[PolicyRule]:
        return iter(self._rules)


def load_policy(path: Path) -> PolicySet:
    """Read and validate a policy file. Raises rather than degrading."""
    try:
        raw = path.read_bytes()
    except OSError as exc:
        msg = (
            f"cannot read policy at {path}: {exc}. A missing policy is treated as a "
            "misconfiguration, not as 'deny everything' - write an empty rule set "
            "explicitly if that is what you mean."
        )
        raise PolicyUnreadable(msg) from exc

    try:
        data = tomllib.loads(raw.decode("utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        msg = f"policy at {path} is not valid TOML: {exc}"
        raise PolicyUnreadable(msg) from exc

    return parse_policy(data, source=str(path))


def parse_policy(data: dict[str, object], *, source: str = "<memory>") -> PolicySet:
    """Validate an already-parsed mapping into a `PolicySet`."""
    unknown = set(data) - _ALLOWED_TOP_LEVEL
    if unknown:
        msg = (
            f"policy at {source} has unknown top-level keys: {sorted(unknown)}. "
            "Unknown keys are rejected rather than ignored - a typo in a key name "
            "would otherwise silently drop the setting it was meant to apply."
        )
        raise PolicyInvalid(msg)

    version = data.get("version", POLICY_VERSION)
    if version != POLICY_VERSION:
        msg = (
            f"policy at {source} declares version {version!r}, expected {POLICY_VERSION}. "
            "Reading a policy under the wrong schema risks granting what it never meant to."
        )
        raise PolicyInvalid(msg)

    entries = data.get("rule", [])
    if not isinstance(entries, list):
        msg = f"policy at {source}: 'rule' must be an array of tables"
        raise PolicyInvalid(msg)

    rules: list[PolicyRule] = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            msg = f"policy at {source}: rule #{index} is not a table"
            raise PolicyInvalid(msg)
        rule_id = entry.get("id", f"#{index}")
        try:
            rules.append(PolicyRule.model_validate(_coerce_enums(entry, source, rule_id)))
        except ValidationError as exc:
            msg = f"policy at {source}: rule {rule_id!r} is invalid: {exc}"
            raise PolicyInvalid(msg) from exc

    return PolicySet(tuple(rules))


def _coerce_enums(entry: dict[str, object], source: str, rule_id: object) -> dict[str, object]:
    """Turn the enum-valued strings TOML gives us into real enum members.

    Contracts validate in **strict** mode, which is deliberate: it stops `1` being
    read as `True` and `"5"` as `5`, either of which could silently change what a
    rule matches. Strict mode also refuses to coerce a string into an enum.

    Rather than weaken strictness for the whole model, the loader converts the four
    enum fields explicitly. This is the right place for it - the loader *is* the
    boundary between untrusted text on disk and a typed contract - and an
    unrecognised value fails here with a message naming the rule and the valid
    options, instead of surfacing as a confusing Pydantic type error.
    """
    coerced = dict(entry)
    for field, enum_type in _ENUM_FIELDS.items():
        value = coerced.get(field)
        if isinstance(value, str):
            try:
                coerced[field] = enum_type(value)
            except ValueError as exc:
                valid = ", ".join(sorted(m.value for m in enum_type))
                msg = (
                    f"policy at {source}: rule {rule_id!r} has {field}={value!r}; "
                    f"valid values are {valid}"
                )
                raise PolicyInvalid(msg) from exc
    return coerced
