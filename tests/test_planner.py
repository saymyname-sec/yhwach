"""Tests for the deterministic rule-matcher / task planner."""
from __future__ import annotations

from pathlib import Path

from yhwach import db as yhdb
from yhwach.planner import match_rules, top_tasks
from yhwach.playbooks import Rule


def _rule(rid: str, when: dict, *, likelihood="H", time_cost="fast",
          points=15, risk="read_only", autonomy="proceed") -> Rule:
    return Rule(id=rid, when=when, emits=[{"action": "x"}], points=points,
                likelihood=likelihood, time_cost=time_cost, risk=risk, autonomy=autonomy)


def _seed_surface(tmp_db: Path, kind: str, auth: str = "none",
                  os: str = "linux", ip: str = "10.0.0.5") -> int:
    """Create engagement + host + service + surface. Returns engagement_id."""
    with yhdb.transaction(tmp_db) as conn:
        eng_id = yhdb.upsert_engagement(conn, lab="fixt", scope="10.0.0.0/24")
        cur = conn.execute(
            "INSERT INTO host (engagement_id, ip, os, stage, first_seen) "
            "VALUES (?, ?, ?, 'scanned', '2026-01-01T00:00:00Z')",
            (eng_id, ip, os),
        )
        host_id = int(cur.lastrowid)
        cur = conn.execute(
            "INSERT INTO service (host_id, port, proto, discovered_at) "
            "VALUES (?, 11434, 'tcp', '2026-01-01T00:00:00Z')",
            (host_id,),
        )
        svc_id = int(cur.lastrowid)
        yhdb.upsert_surface(conn, host_id, svc_id, kind, auth, "{}")
    return eng_id


def test_match_creates_task_for_matching_surface(tmp_db: Path) -> None:
    eng_id = _seed_surface(tmp_db, kind="ollama", auth="none")
    with yhdb.transaction(tmp_db) as conn:
        report = match_rules(conn, eng_id, [_rule("ollama_unauth_api", {"surface": "ollama", "auth": "none"})])
        tasks = top_tasks(conn, eng_id)
    assert report.tasks_created == 1
    assert report.rules_matched == 1
    assert len(tasks) == 1
    assert tasks[0]["playbook_rule_id"] == "ollama_unauth_api"
    assert tasks[0]["autonomy"] == "proceed"


def test_auth_mismatch_does_not_match(tmp_db: Path) -> None:
    eng_id = _seed_surface(tmp_db, kind="ollama", auth="bearer")
    with yhdb.transaction(tmp_db) as conn:
        report = match_rules(conn, eng_id, [_rule("r", {"surface": "ollama", "auth": "none"})])
    assert report.tasks_created == 0
    assert report.rules_matched == 0


def test_match_is_idempotent(tmp_db: Path) -> None:
    eng_id = _seed_surface(tmp_db, kind="ollama")
    rule = _rule("ollama_unauth_api", {"surface": "ollama"})
    with yhdb.transaction(tmp_db) as conn:
        r1 = match_rules(conn, eng_id, [rule])
        r2 = match_rules(conn, eng_id, [rule])
        n = conn.execute("SELECT COUNT(*) AS n FROM task").fetchone()["n"]
    assert r1.tasks_created == 1
    assert r2.tasks_created == 0
    assert r2.tasks_updated == 1
    assert n == 1


def test_unsupported_when_key_is_skipped(tmp_db: Path) -> None:
    eng_id = _seed_surface(tmp_db, kind="chatbot")
    rule = _rule("aws_ssrf", {"surface": "web", "findings_include": "ssrf_confirmed"})
    with yhdb.transaction(tmp_db) as conn:
        report = match_rules(conn, eng_id, [rule])
    assert "aws_ssrf" in report.rules_skipped_unsupported
    assert report.tasks_created == 0


def test_multiple_rules_on_one_surface_make_multiple_tasks(tmp_db: Path) -> None:
    eng_id = _seed_surface(tmp_db, kind="chatbot")
    rules = [
        _rule("chatbot_direct_injection_probe", {"surface": "chatbot"}, likelihood="H", time_cost="med"),
        _rule("chatbot_session_enumeration", {"surface": "chatbot"}, likelihood="M", time_cost="med"),
        _rule("rag_upload_discovery", {"surface": "chatbot"}, likelihood="M", time_cost="med"),
    ]
    with yhdb.transaction(tmp_db) as conn:
        report = match_rules(conn, eng_id, rules)
        tasks = top_tasks(conn, eng_id)
    assert report.tasks_created == 3
    assert len(tasks) == 3
    # Highest EV (H/med) ranks first.
    assert tasks[0]["playbook_rule_id"] == "chatbot_direct_injection_probe"


def test_top_tasks_orders_by_ev_desc(tmp_db: Path) -> None:
    eng_id = _seed_surface(tmp_db, kind="ollama")
    rules = [
        _rule("low", {"surface": "ollama"}, likelihood="M", time_cost="slow"),   # 0.6*15/4 = 2.25
        _rule("high", {"surface": "ollama"}, likelihood="H", time_cost="fast"),  # 1.0*15/1 = 15
    ]
    with yhdb.transaction(tmp_db) as conn:
        match_rules(conn, eng_id, rules)
        tasks = top_tasks(conn, eng_id)
    assert [t["playbook_rule_id"] for t in tasks] == ["high", "low"]
    assert tasks[0]["ev_score"] > tasks[1]["ev_score"]


def test_no_surface_no_task(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        eng_id = yhdb.upsert_engagement(conn, lab="empty", scope="10.0.0.0/24")
        report = match_rules(conn, eng_id, [_rule("r", {"surface": "ollama"})])
    assert report.tasks_created == 0


def test_os_filter_matches(tmp_db: Path) -> None:
    eng_id = _seed_surface(tmp_db, kind="chatbot", os="windows")
    with yhdb.transaction(tmp_db) as conn:
        match_lin = match_rules(conn, eng_id, [_rule("lin", {"surface": "chatbot", "os": "linux"})])
    assert match_lin.tasks_created == 0
    with yhdb.transaction(tmp_db) as conn:
        match_win = match_rules(conn, eng_id, [_rule("win", {"surface": "chatbot", "os": "windows"})])
    assert match_win.tasks_created == 1
