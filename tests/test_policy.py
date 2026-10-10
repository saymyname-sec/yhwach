"""Tests for the deterministic control policy: gating, budgets, halting."""

from __future__ import annotations

import pytest

from yhwach import policy as pol

# --- autonomy gating --------------------------------------------------------


def test_read_only_always_proceeds() -> None:
    assert pol.gate("proceed") is pol.Gate.PROCEED
    assert pol.gate("proceed", allow_gated=True) is pol.Gate.PROCEED


def test_exploit_needs_approval_unless_allowed() -> None:
    assert pol.gate("propose") is pol.Gate.NEEDS_APPROVAL
    assert pol.gate("propose", allow_gated=True) is pol.Gate.PROCEED


def test_destructive_always_needs_approval() -> None:
    assert pol.gate("ask") is pol.Gate.NEEDS_APPROVAL
    assert pol.gate("ask", allow_gated=True) is pol.Gate.NEEDS_APPROVAL


def test_unknown_autonomy_denies() -> None:
    assert pol.gate("something-weird") is pol.Gate.DENY


# --- high-consequence action-class gating (P0 guardrail) --------------------


def test_dangerous_class_denied_without_grant() -> None:
    for cls in pol.ActionClass:
        assert pol.class_gate(cls, frozenset()) is pol.Gate.NEEDS_APPROVAL


def test_dangerous_class_proceeds_only_with_named_grant() -> None:
    grants = frozenset({pol.ActionClass.PUSH})
    assert pol.class_gate(pol.ActionClass.PUSH, grants) is pol.Gate.PROCEED
    # a grant for one class does NOT cover another
    assert pol.class_gate(pol.ActionClass.CODE_CHANGE, grants) is pol.Gate.NEEDS_APPROVAL
    assert pol.class_gate(pol.ActionClass.LISTENER, grants) is pol.Gate.NEEDS_APPROVAL


def test_allow_gated_never_covers_dangerous_classes() -> None:
    # The autonomy gate may PROCEED on exploit under allow_gated, but the class
    # gate is independent: push/code_change/listener still need their own grant.
    assert pol.gate("propose", allow_gated=True) is pol.Gate.PROCEED
    assert pol.class_gate(pol.ActionClass.PUSH, frozenset()) is pol.Gate.NEEDS_APPROVAL


def test_non_dangerous_class_defers_to_autonomy_gate() -> None:
    # An untracked class returns PROCEED so callers can AND it with gate().
    assert pol.class_gate("recon", frozenset()) is pol.Gate.PROCEED


def test_parse_grants_validates_and_fails_closed() -> None:
    assert pol.parse_grants("push,code_change") == frozenset({"push", "code_change"})
    assert pol.parse_grants(" PUSH ; listener ") == frozenset({"push", "listener"})
    # unknown tokens are dropped, never widen reach
    assert pol.parse_grants("push,rm-rf,typo") == frozenset({"push"})
    assert pol.parse_grants("") == frozenset()
    assert pol.parse_grants(None) == frozenset()


# --- budgets ----------------------------------------------------------------


def test_budget_unbounded_by_default() -> None:
    b = pol.Budget()
    b.spend(actions=1000, tokens=10_000_000)
    assert not b.exhausted()
    assert b.reason() is None


def test_budget_action_ceiling() -> None:
    b = pol.Budget(max_actions=3)
    b.spend(actions=2)
    assert not b.exhausted()
    b.spend(actions=1)
    assert b.exhausted()
    assert b.reason() == "max_actions"


def test_budget_token_ceiling() -> None:
    b = pol.Budget(max_tokens=1000)
    b.spend(tokens=999)
    assert not b.exhausted()
    b.spend(tokens=1)
    assert b.reason() == "max_tokens"


def test_budget_wall_clock_with_fake_clock() -> None:
    t = {"now": 100.0}
    b = pol.Budget(max_wall_seconds=10, clock=lambda: t["now"])
    assert not b.exhausted()
    t["now"] = 111.0
    assert b.reason() == "max_wall_seconds"


def test_budget_rejects_bad_limits() -> None:
    with pytest.raises(pol.BudgetError):
        pol.Budget(max_actions=0)
    with pytest.raises(pol.BudgetError):
        pol.Budget(max_tokens=-5)


def test_budget_snapshot_is_serializable() -> None:
    b = pol.Budget(max_actions=5)
    b.spend(actions=2, tokens=42)
    snap = b.snapshot()
    assert snap["actions_spent"] == 2
    assert snap["tokens_spent"] == 42
    assert snap["max_actions"] == 5


# --- halting ----------------------------------------------------------------


def test_halt_on_budget_first() -> None:
    b = pol.Budget(max_actions=1)
    b.spend(actions=1)
    d = pol.should_halt(b, phase_done=False, candidates_left=5)
    assert d.should_halt and d.reason == "budget:max_actions"


def test_halt_on_phase_done() -> None:
    d = pol.should_halt(pol.Budget(), phase_done=True, candidates_left=5)
    assert d.should_halt and d.reason == "phase_done"


def test_halt_on_no_candidates() -> None:
    d = pol.should_halt(pol.Budget(), phase_done=False, candidates_left=0)
    assert d.should_halt and d.reason == "no_candidates"


def test_halt_awaiting_approval() -> None:
    d = pol.should_halt(pol.Budget(), phase_done=False, candidates_left=0, awaiting_approval=True)
    assert d.should_halt and d.reason == "awaiting_approval"


def test_no_halt_when_work_remains() -> None:
    d = pol.should_halt(pol.Budget(), phase_done=False, candidates_left=3)
    assert not d.should_halt and d.reason is None
