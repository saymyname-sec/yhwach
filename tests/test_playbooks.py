"""Tests for playbook loading, validation, and EV scoring."""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from yhwach.playbooks import (
    PlaybookError,
    Rule,
    default_playbook_dir,
    load_rules,
)


def test_load_real_playbooks_yields_ai_rules() -> None:
    rules = load_rules(default_playbook_dir())
    ids = {r.id for r in rules}
    # A few anchors that must exist.
    assert "ollama_unauth_api" in ids
    assert "mcp_tools_list_probe" in ids
    assert "chatbot_direct_injection_probe" in ids
    # Every rule carries the required EV inputs and is authorized-only by construction.
    for r in rules:
        assert r.likelihood in {"H", "M", "L"}
        assert r.time_cost in {"fast", "med", "slow"}
        assert 0 <= r.points <= 15


def test_meta_files_produce_no_rules(tmp_path: Path) -> None:
    # _primitives-style entries (no `when`) must be ignored.
    (tmp_path / "_primitives.yaml").write_text(
        "- id: technique_exhaustion\n  kind: invariant\n  applies_to: all\n",
        encoding="utf-8",
    )
    (tmp_path / "lore_denylist.yaml").write_text(
        "- artifact: cloudbase_init\n  match: [{user: cloudbase-init}]\n",
        encoding="utf-8",
    )
    assert load_rules(tmp_path) == []


def test_ev_score_high_fast() -> None:
    r = Rule(id="x", when={}, emits=[{"action": "a"}], points=15,
             likelihood="H", time_cost="fast", risk="read_only", autonomy="proceed")
    assert r.ev_score == 15.0


def test_ev_score_medium_med() -> None:
    r = Rule(id="x", when={}, emits=[{"action": "a"}], points=15,
             likelihood="M", time_cost="med", risk="read_only", autonomy="proceed")
    # 0.6 * 15 / 2.0 = 4.5
    assert r.ev_score == 4.5


def test_ev_ordering_high_beats_medium() -> None:
    hi = Rule(id="hi", when={}, emits=[{"action": "a"}], points=15,
              likelihood="H", time_cost="fast", risk="read_only", autonomy="proceed")
    lo = Rule(id="lo", when={}, emits=[{"action": "a"}], points=15,
              likelihood="M", time_cost="slow", risk="read_only", autonomy="proceed")
    assert hi.ev_score > lo.ev_score


def _write_rule(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "r.yaml"
    p.write_text(body, encoding="utf-8")
    return p


def test_duplicate_id_raises(tmp_path: Path) -> None:
    _write_rule(
        tmp_path,
        "- id: dup\n  when: {surface: ollama}\n  emits: [{action: a}]\n"
        "  points: 15\n  risk: read_only\n  authorized_only: true\n"
        "- id: dup\n  when: {surface: mcp}\n  emits: [{action: b}]\n"
        "  points: 15\n  risk: read_only\n  authorized_only: true\n",
    )
    with pytest.raises(PlaybookError, match="duplicate rule id"):
        load_rules(tmp_path)


def test_authorized_only_required(tmp_path: Path) -> None:
    _write_rule(
        tmp_path,
        "- id: noauth\n  when: {surface: ollama}\n  emits: [{action: a}]\n"
        "  points: 15\n  risk: read_only\n",
    )
    with pytest.raises(PlaybookError, match="authorized_only"):
        load_rules(tmp_path)


def test_invalid_points_raises(tmp_path: Path) -> None:
    _write_rule(
        tmp_path,
        "- id: bad\n  when: {surface: ollama}\n  emits: [{action: a}]\n"
        "  points: 99\n  risk: read_only\n  authorized_only: true\n",
    )
    with pytest.raises(PlaybookError, match="points"):
        load_rules(tmp_path)


def test_risk_propose_normalizes_to_exploit_and_propose(tmp_path: Path) -> None:
    _write_rule(
        tmp_path,
        "- id: a2a\n  when: {surface: a2a}\n  emits: [{action: a}]\n"
        "  points: 15\n  risk: propose\n  authorized_only: true\n",
    )
    rules = load_rules(tmp_path)
    assert rules[0].risk == "exploit"
    assert rules[0].autonomy == "propose"


def test_all_real_rules_parse_without_error() -> None:
    # Guards against a malformed hand-edited rule slipping into the repo.
    rules = load_rules(default_playbook_dir())
    assert len(rules) >= 8


def test_real_playbook_files_are_valid_yaml() -> None:
    for path in default_playbook_dir().glob("*.yaml"):
        with path.open(encoding="utf-8") as f:
            yaml.safe_load(f)  # raises if malformed
