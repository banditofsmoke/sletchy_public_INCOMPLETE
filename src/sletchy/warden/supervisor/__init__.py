"""supervisor - whether a command may run at all, decided before it exists (#69)."""

from sletchy.warden.isolation import BackendUnavailable, IsolationError
from sletchy.warden.supervisor.supervisor import (
    ALLOWED_ACTION,
    DENIED_ACTION,
    LIVING_OFF_THE_LAND,
    SHELLS,
    Allowed,
    Allowlist,
    LaunchDenied,
    Plan,
    Supervisor,
    decide,
    load_allowlist,
    plan,
    program_name,
)

#: Re-exported so the Shell, which may import only the supervisor (ADR-0011), can tell a
#: refusal by the sandbox from one by the supervisor.
__all__ = [
    "ALLOWED_ACTION",
    "DENIED_ACTION",
    "LIVING_OFF_THE_LAND",
    "SHELLS",
    "Allowed",
    "Allowlist",
    "BackendUnavailable",
    "IsolationError",
    "LaunchDenied",
    "Plan",
    "Supervisor",
    "decide",
    "load_allowlist",
    "plan",
    "program_name",
]
