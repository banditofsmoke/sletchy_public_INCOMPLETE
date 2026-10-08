"""Policy evaluation, loading, and the deny-by-default guarantee."""

from __future__ import annotations

from pathlib import Path

import pytest

from sletchy.kernel.contracts import (
    Action,
    Actor,
    ActorKind,
    Decision,
    Plane,
    PolicyRule,
    Subject,
    SubjectKind,
)
from sletchy.kernel.ledger import InMemoryKeySource, Ledger
from sletchy.kernel.policy import (
    PolicyEngine,
    PolicyGate,
    PolicyInvalid,
    PolicySet,
    PolicyUnreadable,
    load_policy,
    parse_policy,
)

AGENT = Actor(id="agent_a", kind=ActorKind.AGENT, plane=Plane.MIND, trust=50)
EGRESS = Action(name="warden.egress.request")
GROQ = Subject(kind=SubjectKind.HOST, identifier="api.groq.com")

REPO_ROOT = Path(__file__).resolve().parents[2]


def engine(*rules: PolicyRule) -> PolicyEngine:
    return PolicyEngine(PolicySet(rules))


def allow(rule_id: str, **kw: object) -> PolicyRule:
    base: dict[str, object] = {
        "id": rule_id,
        "decision": Decision.ALLOW,
        "reason": "test fixture",
    }
    return PolicyRule.model_validate(base | kw)


# ── LAW 2: deny by default ───────────────────────────────────────────────────


def test_empty_policy_denies_everything() -> None:
    verdict = engine().evaluate(AGENT, EGRESS, GROQ)
    assert verdict.decision is Decision.DENY
    assert not verdict.allowed
    assert verdict.rule_id is None


def test_no_matching_rule_denies() -> None:
    rules = engine(allow("other", subject_pattern="ollama.local", subject_kind=SubjectKind.HOST))
    assert not rules.evaluate(AGENT, EGRESS, GROQ).allowed


def test_the_deny_reason_names_what_was_asked() -> None:
    """A verdict a human cannot understand is not auditable."""
    reason = engine().evaluate(AGENT, EGRESS, GROQ).reason
    assert "agent_a" in reason
    assert "warden.egress.request" in reason
    assert "api.groq.com" in reason


def test_the_shipped_default_policy_grants_nothing() -> None:
    """The file an operator actually gets on a fresh install."""
    policy = load_policy(REPO_ROOT / "config" / "policy.default.toml")
    assert len(policy) == 0
    assert not PolicyEngine(policy).evaluate(AGENT, EGRESS, GROQ).allowed


# ── matching ─────────────────────────────────────────────────────────────────


def test_an_exactly_matching_rule_allows() -> None:
    e = engine(allow("groq", action="warden.egress.request", subject_pattern="api.groq.com"))
    verdict = e.evaluate(AGENT, EGRESS, GROQ)
    assert verdict.allowed
    assert verdict.rule_id == "groq"
    assert "test fixture" in verdict.reason


def test_action_matching_is_prefix_based() -> None:
    e = engine(allow("broad", action="warden.egress"))
    assert e.evaluate(AGENT, EGRESS, GROQ).allowed


def test_action_matching_is_segment_aware() -> None:
    """`warden.egress` must not match `warden.egressive` by string prefix."""
    e = engine(allow("broad", action="warden.egress"))
    assert not e.evaluate(AGENT, Action(name="warden.egressive.thing"), GROQ).allowed


def test_a_narrower_rule_does_not_match_a_broader_action() -> None:
    e = engine(allow("narrow", action="warden.egress.request.https"))
    assert not e.evaluate(AGENT, EGRESS, GROQ).allowed


def test_trailing_wildcard_matches_a_prefix() -> None:
    e = engine(allow("groq", subject_kind=SubjectKind.HOST, subject_pattern="api.groq."))
    assert not e.evaluate(AGENT, EGRESS, GROQ).allowed

    e = engine(allow("groq", subject_kind=SubjectKind.HOST, subject_pattern="api.groq.*"))
    assert e.evaluate(AGENT, EGRESS, GROQ).allowed


def test_subject_kind_is_checked_before_the_pattern() -> None:
    """A rule about paths must never match a hostname that happens to look alike."""
    e = engine(allow("paths", subject_kind=SubjectKind.PATH, subject_pattern="api.groq.com"))
    assert not e.evaluate(AGENT, EGRESS, GROQ).allowed


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("actor_id", "someone_else"),
        ("actor_kind", ActorKind.HUMAN),
        ("actor_plane", Plane.VAULT),
    ],
)
def test_every_actor_dimension_is_checked(field: str, value: object) -> None:
    e = engine(allow("r", **{field: value}))
    assert not e.evaluate(AGENT, EGRESS, GROQ).allowed


# ── trust gating ─────────────────────────────────────────────────────────────


def test_min_trust_blocks_a_low_trust_actor() -> None:
    e = engine(allow("trusted", min_trust=70))
    assert not e.evaluate(AGENT, EGRESS, GROQ).allowed


def test_min_trust_admits_a_high_trust_actor() -> None:
    e = engine(allow("trusted", min_trust=70))
    assert e.evaluate(AGENT.with_trust(90), EGRESS, GROQ).allowed


def test_trust_is_read_live_not_cached() -> None:
    """A rule gated on trust must see the current value, not one from issue time."""
    e = engine(allow("trusted", min_trust=70))
    trusted = AGENT.with_trust(90)
    assert e.evaluate(trusted, EGRESS, GROQ).allowed
    assert not e.evaluate(trusted.with_trust(10), EGRESS, GROQ).allowed


# ── priority and ties ────────────────────────────────────────────────────────


def test_higher_priority_wins() -> None:
    e = engine(
        allow("low", priority=10),
        PolicyRule(id="high", decision=Decision.DENY, priority=100),
    )
    assert not e.evaluate(AGENT, EGRESS, GROQ).allowed
    assert e.evaluate(AGENT, EGRESS, GROQ).rule_id == "high"


def test_a_lower_priority_deny_loses_to_a_higher_priority_allow() -> None:
    """Priority genuinely outranks strictness - otherwise deny rules could not be overridden."""
    e = engine(
        allow("high", priority=100),
        PolicyRule(id="low", decision=Decision.DENY, priority=10),
    )
    assert e.evaluate(AGENT, EGRESS, GROQ).allowed


def test_a_tie_resolves_to_the_stricter_decision() -> None:
    """Ties never resolve toward permission, so rule ordering is safe to get wrong."""
    e = engine(
        allow("permit", priority=50),
        PolicyRule(id="refuse", decision=Decision.DENY, priority=50),
    )
    verdict = e.evaluate(AGENT, EGRESS, GROQ)
    assert verdict.decision is Decision.DENY
    assert verdict.rule_id == "refuse"


def test_a_tie_between_allow_and_ask_resolves_to_ask() -> None:
    e = engine(
        allow("permit", priority=50),
        PolicyRule(id="confirm", decision=Decision.ASK, priority=50),
    )
    assert e.evaluate(AGENT, EGRESS, GROQ).decision is Decision.ASK


def test_a_contested_tie_is_disclosed_in_the_reason() -> None:
    e = engine(
        allow("permit", priority=50),
        PolicyRule(id="refuse", decision=Decision.DENY, priority=50),
    )
    assert "tied at priority 50" in e.evaluate(AGENT, EGRESS, GROQ).reason


def test_evaluation_is_order_independent() -> None:
    """Two loads of the same rules must decide identically."""
    a = allow("permit", priority=50)
    b = PolicyRule(id="refuse", decision=Decision.DENY, priority=50)
    assert (
        PolicyEngine(PolicySet((a, b))).evaluate(AGENT, EGRESS, GROQ).rule_id
        == PolicyEngine(PolicySet((b, a))).evaluate(AGENT, EGRESS, GROQ).rule_id
    )


# ── loading ──────────────────────────────────────────────────────────────────


def test_an_empty_file_is_valid_and_denies_everything(tmp_path: Path) -> None:
    path = tmp_path / "policy.toml"
    path.write_text("version = 1\n", encoding="utf-8")
    assert len(load_policy(path)) == 0


def test_a_missing_file_raises_rather_than_denying_silently(tmp_path: Path) -> None:
    """A moved file must not look like a deliberate 'grant nothing'."""
    with pytest.raises(PolicyUnreadable, match="misconfiguration"):
        load_policy(tmp_path / "absent.toml")


def test_malformed_toml_raises(tmp_path: Path) -> None:
    path = tmp_path / "policy.toml"
    path.write_text("this is not [ valid toml", encoding="utf-8")
    with pytest.raises(PolicyUnreadable, match="not valid TOML"):
        load_policy(path)


def test_an_unknown_top_level_key_raises(tmp_path: Path) -> None:
    """A typo in a key name would otherwise silently drop the setting."""
    path = tmp_path / "policy.toml"
    path.write_text("version = 1\nrulez = []\n", encoding="utf-8")
    with pytest.raises(PolicyInvalid, match="unknown top-level"):
        load_policy(path)


def test_an_unknown_version_raises(tmp_path: Path) -> None:
    path = tmp_path / "policy.toml"
    path.write_text("version = 99\n", encoding="utf-8")
    with pytest.raises(PolicyInvalid, match="version"):
        load_policy(path)


def test_an_invalid_rule_raises() -> None:
    with pytest.raises(PolicyInvalid, match="invalid"):
        parse_policy({"version": 1, "rule": [{"id": "r", "decision": "allow"}]})


def test_an_allow_rule_without_a_reason_is_refused_at_load() -> None:
    """The contract-level rule from #1, proven to bite through the loader."""
    with pytest.raises(PolicyInvalid, match="no reason"):
        parse_policy({"version": 1, "rule": [{"id": "r", "decision": "allow", "reason": "  "}]})


def test_duplicate_rule_ids_are_refused() -> None:
    with pytest.raises(PolicyInvalid, match="duplicate"):
        PolicySet((allow("dup"), allow("dup")))


def test_a_valid_file_loads(tmp_path: Path) -> None:
    path = tmp_path / "policy.toml"
    path.write_text(
        "version = 1\n\n"
        "[[rule]]\n"
        'id = "groq"\n'
        'decision = "allow"\n'
        'reason = "hosted inference"\n'
        'action = "warden.egress.request"\n'
        'subject_kind = "host"\n'
        'subject_pattern = "api.groq.com"\n'
        "priority = 50\n",
        encoding="utf-8",
    )
    policy = load_policy(path)
    assert len(policy) == 1
    assert PolicyEngine(policy).evaluate(AGENT, EGRESS, GROQ).allowed


# ── the gate: LAW 1 ──────────────────────────────────────────────────────────


def make_gate(tmp_path: Path, *rules: PolicyRule) -> tuple[PolicyGate, Ledger]:
    ledger = Ledger.open(tmp_path / "ledger", InMemoryKeySource(b"k" * 32))
    return PolicyGate(engine(*rules), ledger), ledger


def test_every_decision_is_recorded(tmp_path: Path) -> None:
    gate, ledger = make_gate(tmp_path)
    gate.decide(plane=Plane.WARDEN, actor=AGENT, action=EGRESS, subject=GROQ)

    entries = list(ledger.entries())
    assert len(entries) == 1
    assert entries[0].actor_id == "agent_a"
    assert entries[0].action == "warden.egress.request"
    assert entries[0].verdict.decision is Decision.DENY


def test_denials_are_recorded_too(tmp_path: Path) -> None:
    """Especially denials - a refused action is the interesting one."""
    gate, ledger = make_gate(tmp_path)
    for _ in range(3):
        gate.decide(plane=Plane.WARDEN, actor=AGENT, action=EGRESS, subject=GROQ)
    assert len(list(ledger.entries())) == 3
    assert ledger.verify() == 3


def test_allows_are_recorded_with_the_rule_id(tmp_path: Path) -> None:
    gate, ledger = make_gate(tmp_path, allow("groq", subject_pattern="api.groq.com"))
    gate.decide(plane=Plane.WARDEN, actor=AGENT, action=EGRESS, subject=GROQ)
    assert next(iter(ledger.entries())).verdict.rule_id == "groq"


def test_allows_helper_treats_ask_as_not_allowed(tmp_path: Path) -> None:
    """An unanswered human gate is a refusal until the human answers (LAW 7)."""
    gate, _ = make_gate(tmp_path, PolicyRule(id="confirm", decision=Decision.ASK))
    assert not gate.allows(plane=Plane.WARDEN, actor=AGENT, action=EGRESS, subject=GROQ)


def test_the_gate_has_no_path_that_skips_the_ledger(tmp_path: Path) -> None:
    """If a `decide`-shaped method appears that takes no ledger, LAW 1 has a hole."""
    import inspect

    public = [n for n in dir(PolicyGate) if not n.startswith("_")]
    assert set(public) == {"decide", "allows", "engine"}
    assert "ledger" in inspect.signature(PolicyGate.__init__).parameters


def test_an_unknown_enum_value_names_the_valid_options() -> None:
    """TOML gives strings; a typo should say what was expected, not raise a type error."""
    with pytest.raises(PolicyInvalid, match="valid values are"):
        parse_policy({"version": 1, "rule": [{"id": "r", "decision": "maybe"}]})


def test_enum_coercion_does_not_weaken_strictness() -> None:
    """Only the four enum fields are coerced; ints and bools stay strict.

    Without this, `priority = "50"` would silently become 50 - and a rule whose
    priority is not what its author typed is a rule that fires in the wrong order.
    """
    with pytest.raises(PolicyInvalid):
        parse_policy({"version": 1, "rule": [{"id": "r", "priority": "50"}]})
