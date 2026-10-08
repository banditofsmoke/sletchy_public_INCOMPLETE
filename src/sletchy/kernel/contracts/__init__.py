"""Kernel contracts - the single schema source for every plane.

Everything Sletchy runs is defined by these Pydantic models. Derived artifacts -
JSON Schema, CLI arguments, UI forms, tool descriptors - are **generated** from
them. Hand-writing a parallel schema is forbidden (LAW 6), because drift in a
security boundary is a vulnerability.

No plane may define its own version of anything here.
"""

from sletchy.kernel.contracts.base import (
    ACTION_PATTERN,
    HASH_PATTERN,
    NAME_PATTERN,
    Contract,
    Hash,
    Name,
    is_hash,
)
from sletchy.kernel.contracts.capability import DEFAULT_TTL, MAX_TTL, Capability
from sletchy.kernel.contracts.identity import (
    Action,
    Actor,
    ActorKind,
    Plane,
    Subject,
    SubjectKind,
)
from sletchy.kernel.contracts.isolation import (
    CONTEXT_ID_PATTERN,
    SANDBOX_LANES,
    ContextId,
    FilesystemMount,
    HostChange,
    IsolationBackend,
    IsolationProfile,
    NetworkPolicy,
    ResourceLimits,
    lane_lock_name,
)
from sletchy.kernel.contracts.ledger import GENESIS_PREV_HASH, LedgerEntry
from sletchy.kernel.contracts.policy import Decision, PolicyRule, Verdict
from sletchy.kernel.contracts.runtime import (
    AgentEvent,
    AgentEventType,
    Flag,
    FlagRisk,
    SecretRef,
)

__all__ = [
    "ACTION_PATTERN",
    "CONTEXT_ID_PATTERN",
    "DEFAULT_TTL",
    "GENESIS_PREV_HASH",
    "HASH_PATTERN",
    "MAX_TTL",
    "NAME_PATTERN",
    "SANDBOX_LANES",
    "Action",
    "Actor",
    "ActorKind",
    "AgentEvent",
    "AgentEventType",
    "Capability",
    "ContextId",
    "Contract",
    "Decision",
    "FilesystemMount",
    "Flag",
    "FlagRisk",
    "Hash",
    "HostChange",
    "IsolationBackend",
    "IsolationProfile",
    "LedgerEntry",
    "Name",
    "NetworkPolicy",
    "Plane",
    "PolicyRule",
    "ResourceLimits",
    "SecretRef",
    "Subject",
    "SubjectKind",
    "Verdict",
    "is_hash",
    "lane_lock_name",
]
