"""Tests for the operator memory layer: the attempt ledger + the recall brief.

The invariant under test: a move the operator reported as failed must never
come back as a ranked candidate, and must be visible as a DEAD END in the
handoff — that is what survives a compacted context.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from yhwach import db as yhdb
from yhwach.memory import (
    build_recall,
    collect_recall,
    dead_ends,
    decayed_ev,
    failure_counts,
    record_outcome,
    wins,
)
from yhwach.planner import match_rules, top_tasks
from yhwach.playbooks import Rule
from yhwach.primitives import consumed_techniques


def _rule(rid: str, when: dict, **kw) -> Rule:
    defaults = dict(likelihood="H", time_cost="fast", points=15,
                    risk="read_only", autonomy="proceed")
    defaults.update(kw)
    return Rule(id=rid, when=when, emits=[{"action": "probe_ollama_models"}], **defaults)


def _seed(tmp_db: Path, ip: str = "10.0.0.5") -> tuple[int, list[Rule]]:
    """Engagement + one ollama surface + one planned task. Returns (eid, rules)."""
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.upsert_engagement(conn, lab="mem", scope="10.0.0.0/24")
        hid = conn.execute(
            "INSERT INTO host (engagement_id, ip, os, stage, first_seen) "
            "VALUES (?, ?, 'linux', 'scanned', 't')", (eid, ip)).lastrowid
        sid = conn.execute(
            "INSERT INTO service (host_id, port, proto, discovered_at) "
            "VALUES (?, 11434, 'tcp', 't')", (hid,)).lastrowid
        yhdb.upsert_surface(conn, int(hid), int(sid), "ollama", "none", "{}")
    rules = [_rule("ollama_unauth_api", {"surface": "ollama", "auth": "none"})]
    with yhdb.transaction(tmp_db) as conn:
        match_rules(conn, eid, rules)
    return eid, rules


def _only_task(tmp_db: Path) -> int:
    with yhdb.transaction(tmp_db) as conn:
        return int(conn.execute("SELECT id FROM task LIMIT 1").fetchone()["id"])


# --- the ledger -------------------------------------------------------------

def test_fail_retires_the_task_so_it_stops_being_ranked(tmp_db: Path) -> None:
    eid, rules = _seed(tmp_db)
    tid = _only_task(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        assert len(top_tasks(conn, eid)) == 1
        rep = record_outcome(conn, eid, task_id=tid, result="fail",
                             reason="model list empty", rules=rules)
        assert rep.task_status == "abandoned"
        assert top_tasks(conn, eid) == []


def test_success_consumes_the_technique_and_closes_the_task(tmp_db: Path) -> None:
    eid, rules = _seed(tmp_db)
    tid = _only_task(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        rep = record_outcome(conn, eid, task_id=tid, result="success",
                             reason="creds in system prompt", rules=rules)
        assert rep.consumed and rep.task_status == "done"
        assert "ollama_unauth_api" in consumed_techniques(conn, eid)
        assert [w["rule_id"] for w in wins(conn, eid)] == ["ollama_unauth_api"]
        # And a re-plan must not resurrect it.
        match_rules(conn, eid, rules)
        assert top_tasks(conn, eid) == []


def test_partial_keeps_the_task_queued(tmp_db: Path) -> None:
    eid, rules = _seed(tmp_db)
    tid = _only_task(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        rep = record_outcome(conn, eid, task_id=tid, result="partial",
                             reason="one endpoint answered", rules=rules)
        assert rep.task_status is None
        assert len(top_tasks(conn, eid)) == 1


def test_outcome_by_rule_and_host_without_a_task_id(tmp_db: Path) -> None:
    eid, rules = _seed(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        rep = record_outcome(conn, eid, rule_id="ollama_unauth_api", host_ip="10.0.0.5",
                             result="blocked", reason="WAF", rules=rules)
        assert rep.host_ip == "10.0.0.5"
        assert top_tasks(conn, eid) == []  # the queued task was retired too
        assert [d["rule_id"] for d in dead_ends(conn, eid)] == ["ollama_unauth_api"]


def test_outcome_rejects_bad_input(tmp_db: Path) -> None:
    eid, rules = _seed(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        with pytest.raises(ValueError, match="unknown result"):
            record_outcome(conn, eid, task_id=_only_task(tmp_db), result="nope", rules=rules)
        with pytest.raises(ValueError, match="task id or a playbook rule id"):
            record_outcome(conn, eid, result="fail", rules=rules)
        with pytest.raises(ValueError, match="not found"):
            record_outcome(conn, eid, task_id=9999, result="fail", rules=rules)


def test_repeat_failures_decay_ev_on_replan(tmp_db: Path) -> None:
    eid, rules = _seed(tmp_db)
    base = rules[0].ev_score
    with yhdb.transaction(tmp_db) as conn:
        record_outcome(conn, eid, task_id=_only_task(tmp_db), result="fail",
                       reason="nope", rules=rules)
        # A second surface of the same rule on that host is ranked lower now.
        hid = conn.execute("SELECT id FROM host LIMIT 1").fetchone()["id"]
        sid = conn.execute(
            "INSERT INTO service (host_id, port, proto, discovered_at) "
            "VALUES (?, 11435, 'tcp', 't')", (hid,)).lastrowid
        yhdb.upsert_surface(conn, int(hid), int(sid), "ollama", "none", "{}")
        match_rules(conn, eid, rules)
        ranked = top_tasks(conn, eid)
        assert len(ranked) == 1
        assert ranked[0]["ev_score"] == pytest.approx(base * 0.5)
        assert failure_counts(conn, eid)[("ollama_unauth_api", hid)] == 1


def test_decayed_ev_is_pure() -> None:
    assert decayed_ev(15.0, 0) == 15.0
    assert decayed_ev(15.0, 1) == 7.5
    assert decayed_ev(15.0, 2) == 3.75


# --- the recall brief -------------------------------------------------------

def test_recall_summarises_state_attempts_and_next(tmp_db: Path) -> None:
    eid, rules = _seed(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        yhdb.add_credential(conn, eid, "svc_sql", "S3cr3t!", "password", "dump")
        record_outcome(conn, eid, rule_id="kerberoast", host_ip="10.0.0.5",
                       result="fail", reason="no SPNs", rules=rules)
        text = build_recall(conn, eid)
        data = collect_recall(conn, eid)

    assert "YHWACH RECALL" in text
    assert "DEAD ENDS" in text and "no SPNs" in text
    assert "scanned:1" in text
    assert data["counts"]["credentials"] == 1
    assert data["dead_ends"][0]["rule_id"] == "kerberoast"
    assert any(e["kind"] == "attempt" for e in data["recent_events"])
    # The brief must stay cheap — it is read on every context reset.
    assert len(text) < 4000


def test_recall_on_an_empty_engagement_still_renders(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.upsert_engagement(conn, lab="empty", scope="10.0.0.0/24")
        text = build_recall(conn, eid)
    assert "no hosts" in text
    assert "yhwach probe" in text
