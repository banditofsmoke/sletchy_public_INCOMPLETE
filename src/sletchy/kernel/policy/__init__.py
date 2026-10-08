"""Policy - deny by default, tighten only.

Two laws live here:

**LAW 2.** The answer to a question nobody wrote a rule for is DENY. There is no
code path through `PolicyEngine.evaluate()` that returns ALLOW without a matching
rule, and a policy that cannot be read raises rather than defaulting to anything.

**LAW 3.** `merge_profiles()` intersects a declaration with a policy override and
**verifies** the result is no wider than either input. Policy may tighten; it may
never loosen, and there is no flag that permits it.
"""

from sletchy.kernel.policy.engine import PolicyEngine, PolicyGate
from sletchy.kernel.policy.errors import (
    PolicyError,
    PolicyInvalid,
    PolicyUnreadable,
    WideningRejected,
)
from sletchy.kernel.policy.loader import POLICY_VERSION, PolicySet, load_policy, parse_policy
from sletchy.kernel.policy.merge import merge_profiles

__all__ = [
    "POLICY_VERSION",
    "PolicyEngine",
    "PolicyError",
    "PolicyGate",
    "PolicyInvalid",
    "PolicySet",
    "PolicyUnreadable",
    "WideningRejected",
    "load_policy",
    "merge_profiles",
    "parse_policy",
]
