"""LAW 3's enforcement point.

`IsolationProfile.tighten()` (from the contracts in #1) computes the stricter of two
profiles. That is necessary but not sufficient: a bug in `tighten` would silently
produce a wider profile and nothing downstream would notice.

So the merge used in production does not trust `tighten`. It **verifies the result**
against both inputs and raises if the outcome grants anything either side did not.
The check is cheap, and it converts "tighten is correct" from an assumption into an
assertion that runs every time a profile is merged.

There is deliberately no counterpart that widens, and no flag that permits one.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from sletchy.kernel.policy.errors import WideningRejected

if TYPE_CHECKING:
    from sletchy.kernel.contracts import IsolationProfile


def merge_profiles(declared: IsolationProfile, policy: IsolationProfile) -> IsolationProfile:
    """Intersect a declaration with a policy override.

    The declaration says what a capability needs; the policy may only narrow it.
    Returns the intersection, having proved it is no wider than either input.

    Raises `WideningRejected` if the merge produced something either side did not
    grant. That is not recoverable: the component whose profile would have been
    widened must refuse to start.
    """
    merged = declared.tighten(policy)

    for name, side in (("declared", declared), ("policy", policy)):
        if not merged.is_tighter_than_or_equal_to(side):
            msg = (
                f"merge produced a profile wider than the {name} side. "
                f"backend={merged.backend.value} "
                f"egress={sorted(merged.network.allow_egress)} "
                f"mounts={sorted(m.path for m in merged.mounts)} "
                f"mem={merged.resources.memory_mb}MB. "
                "Policy may only tighten (LAW 3); this is a bug in the merge, not a "
                "condition to work around."
            )
            raise WideningRejected(msg)

    return merged
