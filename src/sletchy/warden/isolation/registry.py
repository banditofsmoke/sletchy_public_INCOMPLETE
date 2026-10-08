"""Choosing a backend - and refusing to, when nothing qualifies.

The rule that keeps the ladder from being a loophole: **if the minimum cannot be
met, the capability does not run.** `select()` raises `BackendUnavailable`. It never
returns something weaker, and there is no `allow_downgrade` parameter.

That is the whole point. A downgrade-on-missing-dependency is how a system ends up
believing it is sandboxed while running an untrusted agent in the open.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from sletchy.kernel.contracts import IsolationBackend
from sletchy.warden.isolation.base import BackendUnavailable, Capabilities, Sandbox
from sletchy.warden.isolation.container import ContainerSandbox
from sletchy.warden.isolation.inproc import InProcSandbox
from sletchy.warden.isolation.subproc import SubprocSandbox
from sletchy.warden.isolation.winjob import WinJobSandbox

if TYPE_CHECKING:
    from collections.abc import Mapping

#: Every backend that exists. `vm` lands later.
#:
#: `winjob` is listed here on every platform, and `available()` is what decides
#: whether it can run. Hiding it off Windows would make `select()` report "no such
#: backend" where the truth is "this host cannot provide it" - and those two
#: deserve different answers.
BACKENDS: Mapping[IsolationBackend, type[Sandbox]] = {
    IsolationBackend.INPROC: InProcSandbox,
    IsolationBackend.SUBPROC: SubprocSandbox,
    IsolationBackend.WINJOB: WinJobSandbox,
    IsolationBackend.CONTAINER: ContainerSandbox,
}


def available_backends() -> tuple[IsolationBackend, ...]:
    """Which rungs this host can actually reach, weakest first."""
    return tuple(
        backend
        for backend, cls in sorted(BACKENDS.items(), key=lambda kv: kv[0].strength)
        if cls.available()
    )


def select(
    minimum: IsolationBackend,
    *,
    required: Capabilities | None = None,
) -> type[Sandbox]:
    """The strongest available backend at or above `minimum`.

    Raises `BackendUnavailable` when nothing qualifies. **There is deliberately no
    parameter that relaxes this** - a caller who cannot get the isolation it asked
    for must not run, not run weaker.

    `required` is checked separately from the rung: a backend can sit high on the
    ladder and still not claim a specific capability, and a claim it does not make
    is one the conformance suite has not held it to.
    """
    candidates = [
        (backend, cls)
        for backend, cls in BACKENDS.items()
        if backend.satisfies(minimum) and cls.available()
    ]
    if not candidates:
        reachable = ", ".join(b.value for b in available_backends()) or "none"
        msg = (
            f"no isolation backend at or above {minimum.value!r} is available "
            f"(reachable here: {reachable}). The capability does not run. Sletchy "
            "never substitutes a weaker sandbox for the one that was required."
        )
        raise BackendUnavailable(msg)

    candidates.sort(key=lambda kv: kv[0].strength, reverse=True)

    if required is not None:
        for _backend, cls in candidates:
            ok, _missing = cls.capabilities().satisfies(required)
            if ok:
                return cls
        strongest, cls = candidates[0]
        _, missing = cls.capabilities().satisfies(required)
        msg = (
            f"no available backend provides {sorted(missing)}. The strongest "
            f"reachable is {strongest.value!r}, which does not claim them. The "
            "capability does not run."
        )
        raise BackendUnavailable(msg)

    return candidates[0][1]
