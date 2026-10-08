"""Adversarial tests for LAW 3 - policy may tighten, never loosen.

The attacker model here is not only a hostile agent. It is also a well-meaning
future contributor who adds an override "just for dev", and a subtle bug in
`tighten()` that widens a bound without anyone noticing. `merge_profiles()` exists
to catch the second; these tests exist to catch the first.
"""

from __future__ import annotations

import pytest

from sletchy.kernel.contracts import (
    FilesystemMount,
    IsolationBackend,
    IsolationProfile,
    NetworkPolicy,
    ResourceLimits,
)
from sletchy.kernel.policy import WideningRejected, merge_profiles

pytestmark = pytest.mark.adversarial


# ── the merge narrows every dimension ────────────────────────────────────────


def test_egress_is_intersected_not_unioned() -> None:
    declared = IsolationProfile(network=NetworkPolicy(allow_egress=("api.groq.com", "evil.com")))
    policy = IsolationProfile(network=NetworkPolicy(allow_egress=("api.groq.com",)))

    assert merge_profiles(declared, policy).network.allow_egress == ("api.groq.com",)


def test_a_host_policy_never_mentioned_is_dropped() -> None:
    """'Policy did not mention it' must never mean 'policy allowed it'."""
    declared = IsolationProfile(network=NetworkPolicy(allow_egress=("api.groq.com",)))
    policy = IsolationProfile(network=NetworkPolicy(allow_egress=()))

    assert merge_profiles(declared, policy).network.allow_egress == ()


def test_a_host_only_policy_names_is_not_granted() -> None:
    """Policy cannot *add* a destination the capability never declared."""
    declared = IsolationProfile(network=NetworkPolicy(allow_egress=()))
    policy = IsolationProfile(network=NetworkPolicy(allow_egress=("attacker.example",)))

    assert merge_profiles(declared, policy).network.allow_egress == ()


def test_resource_ceilings_take_the_minimum() -> None:
    declared = IsolationProfile(resources=ResourceLimits(memory_mb=8192, cpu_percent=100))
    policy = IsolationProfile(resources=ResourceLimits(memory_mb=256, cpu_percent=10))

    merged = merge_profiles(declared, policy).resources
    assert merged.memory_mb == 256
    assert merged.cpu_percent == 10


def test_policy_cannot_raise_a_resource_ceiling() -> None:
    declared = IsolationProfile(resources=ResourceLimits(memory_mb=256))
    policy = IsolationProfile(resources=ResourceLimits(memory_mb=8192))

    assert merge_profiles(declared, policy).resources.memory_mb == 256


def test_the_stronger_backend_wins() -> None:
    declared = IsolationProfile(backend=IsolationBackend.SUBPROC)
    policy = IsolationProfile(backend=IsolationBackend.CONTAINER)

    assert merge_profiles(declared, policy).backend is IsolationBackend.CONTAINER


def test_policy_cannot_weaken_the_backend() -> None:
    """A policy asking for less isolation than declared gets ignored, not honoured."""
    declared = IsolationProfile(backend=IsolationBackend.CONTAINER)
    policy = IsolationProfile(backend=IsolationBackend.INPROC)

    assert merge_profiles(declared, policy).backend is IsolationBackend.CONTAINER


def test_a_writable_mount_becomes_readonly_if_either_side_says_so() -> None:
    declared = IsolationProfile(mounts=(FilesystemMount(path="/work", access="rw"),))
    policy = IsolationProfile(mounts=(FilesystemMount(path="/work", access="ro"),))

    assert merge_profiles(declared, policy).mounts[0].access == "ro"


def test_a_mount_only_one_side_declares_is_dropped() -> None:
    declared = IsolationProfile(
        mounts=(FilesystemMount(path="/work"), FilesystemMount(path="/secrets"))
    )
    policy = IsolationProfile(mounts=(FilesystemMount(path="/work"),))

    assert {m.path for m in merge_profiles(declared, policy).mounts} == {"/work"}


def test_policy_cannot_add_a_mount() -> None:
    declared = IsolationProfile(mounts=())
    policy = IsolationProfile(mounts=(FilesystemMount(path="/etc/shadow"),))

    assert merge_profiles(declared, policy).mounts == ()


# ── the result is verified, not trusted ──────────────────────────────────────


def test_the_merge_verifies_its_own_output() -> None:
    """`tighten()` being correct is asserted every time, not assumed once.

    A bug in tighten that widened a bound would otherwise pass silently. Here it
    would raise, and the component would refuse to start.
    """

    class WideningProfile(IsolationProfile):
        def tighten(self, other: IsolationProfile) -> IsolationProfile:
            # Simulate the bug: return something wider than either input.
            return IsolationProfile(
                backend=IsolationBackend.INPROC,
                network=NetworkPolicy(allow_egress=("attacker.example",)),
                resources=ResourceLimits(memory_mb=32000),
            )

    declared = WideningProfile(network=NetworkPolicy(allow_egress=("api.groq.com",)))
    policy = IsolationProfile(network=NetworkPolicy(allow_egress=("api.groq.com",)))

    with pytest.raises(WideningRejected, match="wider than the declared side"):
        merge_profiles(declared, policy)


def test_the_merged_profile_is_no_wider_than_either_input() -> None:
    declared = IsolationProfile(
        backend=IsolationBackend.SUBPROC,
        mounts=(FilesystemMount(path="/work", access="rw"),),
        network=NetworkPolicy(allow_egress=("a.example", "b.example"), allow_ports=(80, 443)),
        resources=ResourceLimits(memory_mb=4096, cpu_percent=90),
    )
    policy = IsolationProfile(
        backend=IsolationBackend.WINJOB,
        mounts=(FilesystemMount(path="/work", access="ro"),),
        network=NetworkPolicy(allow_egress=("b.example", "c.example"), allow_ports=(443,)),
        resources=ResourceLimits(memory_mb=512, cpu_percent=25),
    )

    merged = merge_profiles(declared, policy)

    assert merged.is_tighter_than_or_equal_to(declared)
    assert merged.is_tighter_than_or_equal_to(policy)
    assert merged.network.allow_egress == ("b.example",)
    assert merged.network.allow_ports == (443,)


def test_merging_is_commutative() -> None:
    """Argument order must not change what is granted."""
    a = IsolationProfile(
        backend=IsolationBackend.SUBPROC,
        network=NetworkPolicy(allow_egress=("x.example", "y.example")),
    )
    b = IsolationProfile(
        backend=IsolationBackend.WINJOB,
        network=NetworkPolicy(allow_egress=("y.example",)),
    )

    assert merge_profiles(a, b) == merge_profiles(b, a)


def test_merging_is_idempotent() -> None:
    profile = IsolationProfile(network=NetworkPolicy(allow_egress=("a.example",)))
    once = merge_profiles(profile, profile)
    assert merge_profiles(once, once) == once


def test_repeated_merges_only_ever_narrow() -> None:
    """Chained overrides cannot claw back what an earlier one removed."""
    current = IsolationProfile(
        network=NetworkPolicy(allow_egress=("a.example", "b.example", "c.example")),
        resources=ResourceLimits(memory_mb=4096),
    )
    for override in (
        IsolationProfile(network=NetworkPolicy(allow_egress=("a.example", "b.example"))),
        IsolationProfile(resources=ResourceLimits(memory_mb=1024)),
        IsolationProfile(network=NetworkPolicy(allow_egress=("a.example",))),
    ):
        nxt = merge_profiles(current, override)
        assert nxt.is_tighter_than_or_equal_to(current)
        current = nxt

    assert current.network.allow_egress == ()
    assert current.resources.memory_mb == 1024


# ── there is no way to widen ─────────────────────────────────────────────────


def test_the_policy_package_exposes_no_widening_operation() -> None:
    """If this fails, someone added the function that undoes LAW 3."""
    import sletchy.kernel.policy as policy_pkg

    forbidden = ("loosen", "widen", "relax", "override", "force", "bypass")
    for name in policy_pkg.__all__:
        member = getattr(policy_pkg, name)
        # Exception types are exempt: `WideningRejected` is how a widening is
        # *reported*, which is the opposite of offering one.
        if isinstance(member, type) and issubclass(member, Exception):
            continue
        assert not any(word in name.lower() for word in forbidden), (
            f"policy package exposes {name!r}; LAW 3 forbids a widening operation"
        )


def test_merge_profiles_takes_no_override_flag() -> None:
    import inspect

    params = set(inspect.signature(merge_profiles).parameters)
    assert params == {"declared", "policy"}, (
        "merge_profiles grew a parameter; an escape hatch here defeats LAW 3"
    )
