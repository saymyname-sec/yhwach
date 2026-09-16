"""Tests for the cross-cutting primitives: lore denylist + technique exhaustion."""
from __future__ import annotations

from pathlib import Path

from yhwach import db as yhdb
from yhwach.planner import match_rules, top_tasks
from yhwach.playbooks import Rule, default_playbook_dir
from yhwach.primitives import (
    check_denylist,
    consumed_techniques,
    denylisted_host_ids,
    load_denylist,
    mark_technique_consumed,
    record_denylist_hit,
)


def _rule(rid, when, technique=None, **kw):
    defaults = dict(likelihood="H", time_cost="fast", points=15,
                    risk="read_only", autonomy="proceed", maps=["LLM06"])
    defaults.update(kw)
    r = Rule(id=rid, when=when, emits=[{"action": "probe_ollama_models"}], **defaults)
    r._technique = technique
    return r


def _seed(tmp_db, kind="ollama", ip="10.0.0.5"):
    with yhdb.transaction(tmp_db) as conn:
        eng = yhdb.upsert_engagement(conn, lab="p", scope="10.0.0.0/24")
        cur = conn.execute(
            "INSERT INTO host (engagement_id, ip, os, stage, first_seen) "
            "VALUES (?, ?, 'linux', 'scanned', '2026-01-01T00:00:00Z')", (eng, ip))
        hid = int(cur.lastrowid)
        cur = conn.execute(
            "INSERT INTO service (host_id, port, proto, discovered_at) "
            "VALUES (?, 11434, 'tcp', '2026-01-01T00:00:00Z')", (hid,))
        yhdb.upsert_surface(conn, hid, int(cur.lastrowid), kind, "none", "{}")
    return eng, hid


# --- denylist ---

def test_load_real_denylist_has_cloudbase() -> None:
    entries = load_denylist(default_playbook_dir())
    arts = {e.artifact for e in entries}
    assert "cloudbase_init" in arts


def test_check_denylist_matches_cloudbase() -> None:
    entries = load_denylist(default_playbook_dir())
    text = "User accounts: Administrator, cloudbase-init, Guest"
    assert check_denylist(text, entries) == "cloudbase_init"


def test_check_denylist_no_match() -> None:
    entries = load_denylist(default_playbook_dir())
    assert check_denylist("nothing interesting here", entries) is None


def test_record_denylist_hit_tags_host(tmp_db: Path) -> None:
    eng, hid = _seed(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        assert record_denylist_hit(conn, eng, hid, "cloudbase_init") is True
        assert record_denylist_hit(conn, eng, hid, "cloudbase_init") is False  # dedupe
        tags = conn.execute("SELECT tags FROM host WHERE id = ?", (hid,)).fetchone()["tags"]
        assert "dev_artifact" in tags
        assert hid in denylisted_host_ids(conn, eng)


def test_planner_filters_denylisted_host(tmp_db: Path) -> None:
    eng, hid = _seed(tmp_db)
    rule = _rule("ollama_unauth_api", {"surface": "ollama"})
    with yhdb.transaction(tmp_db) as conn:
        record_denylist_hit(conn, eng, hid, "cloudbase_init")
        report = match_rules(conn, eng, [rule])
        tasks = top_tasks(conn, eng)
    assert report.tasks_created == 0
    assert report.surfaces_filtered_denylist == 1
    assert tasks == []


# --- technique exhaustion ---

def test_mark_and_query_consumed(tmp_db: Path) -> None:
    eng, _ = _seed(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        assert mark_technique_consumed(conn, eng, "ollama_unauth_api") is True
        assert "ollama_unauth_api" in consumed_techniques(conn, eng)


def test_planner_skips_consumed_technique(tmp_db: Path) -> None:
    eng, _ = _seed(tmp_db)
    rule = _rule("ollama_unauth_api", {"surface": "ollama"})
    with yhdb.transaction(tmp_db) as conn:
        mark_technique_consumed(conn, eng, "ollama_unauth_api")
        report = match_rules(conn, eng, [rule])
    assert report.tasks_created == 0
    assert "ollama_unauth_api" in report.rules_skipped_consumed


def test_consume_by_shared_technique_key(tmp_db: Path) -> None:
    # Two rules sharing a `technique:` — consuming it retires both.
    eng, _ = _seed(tmp_db, kind="chatbot")
    r1 = _rule("chatbot_a", {"surface": "chatbot"}, technique="chatbot_injection")
    r2 = _rule("chatbot_b", {"surface": "chatbot"}, technique="chatbot_injection")
    with yhdb.transaction(tmp_db) as conn:
        mark_technique_consumed(conn, eng, "chatbot_injection")
        report = match_rules(conn, eng, [r1, r2])
    assert report.tasks_created == 0
    assert set(report.rules_skipped_consumed) == {"chatbot_a", "chatbot_b"}
