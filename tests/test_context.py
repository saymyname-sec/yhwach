"""Tests for the operator context assembly (`yhwach next --contract`)."""
from __future__ import annotations

from pathlib import Path

from yhwach import db as yhdb
from yhwach.context import build_context, load_persona
from yhwach.planner import match_rules
from yhwach.playbooks import Rule


def _rule(rid: str, when: dict, **kw) -> Rule:
    defaults = dict(likelihood="H", time_cost="fast", points=15,
                    risk="read_only", autonomy="proceed",
                    maps=["LLM06"], routes="/osai-mcp-attack", source="osai/07")
    defaults.update(kw)
    return Rule(id=rid, when=when, emits=[{"action": "probe_ollama_models"}], **defaults)


def _seed(tmp_db: Path, kind="ollama", auth="none") -> tuple[int, list[Rule]]:
    with yhdb.transaction(tmp_db) as conn:
        eng_id = yhdb.upsert_engagement(conn, lab="ctx", scope="10.0.0.0/24", domain="corp.local")
        cur = conn.execute(
            "INSERT INTO host (engagement_id, ip, os, stage, first_seen) "
            "VALUES (?, '10.0.0.5', 'linux', 'scanned', '2026-01-01T00:00:00Z')",
            (eng_id,),
        )
        host_id = int(cur.lastrowid)
        cur = conn.execute(
            "INSERT INTO service (host_id, port, proto, discovered_at) "
            "VALUES (?, 11434, 'tcp', '2026-01-01T00:00:00Z')",
            (host_id,),
        )
        svc_id = int(cur.lastrowid)
        yhdb.upsert_surface(conn, host_id, svc_id, kind, auth, "{}")
    rules = [_rule("ollama_unauth_api", {"surface": "ollama", "auth": "none"})]
    with yhdb.transaction(tmp_db) as conn:
        match_rules(conn, eng_id, rules)
    return eng_id, rules


def test_load_persona_nonempty() -> None:
    text = load_persona()
    assert "Autonomy Contract" in text
    assert "AUTONOMY:" in text


def test_context_includes_frame_state_and_candidates(tmp_db: Path) -> None:
    eng_id, rules = _seed(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        block = build_context(conn, eng_id, rules=rules)

    # Frame section carries the persona.
    assert "## FRAME" in block
    assert "Autonomy Contract" in block
    # State section.
    assert "## STATE" in block
    assert "scope 10.0.0.0/24" in block
    assert "domain corp.local" in block
    assert "scanned:1" in block
    # Candidate section with enriched rule detail.
    assert "## RANKED CANDIDATES (1)" in block
    assert "ollama_unauth_api" in block
    assert "EV=15.0" in block
    assert "LLM06" in block
    # The candidate now shows the rendered concrete command, not the action name.
    assert "curl -sk http://10.0.0.5:11434/api/tags" in block
    assert "/osai-mcp-attack" in block
    # Task instruction.
    assert "## YOUR TASK" in block
    assert "playbook_rule_id" in block


def test_context_no_candidates_message(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        eng_id = yhdb.upsert_engagement(conn, lab="empty", scope="10.0.0.0/24")
        block = build_context(conn, eng_id, rules=[])
    assert "## RANKED CANDIDATES (0)" in block
    assert "run `yhwach probe`" in block


def test_context_host_filter(tmp_db: Path) -> None:
    eng_id, rules = _seed(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        # Non-matching host filter -> zero candidates but block still renders.
        block = build_context(conn, eng_id, host_ip="10.9.9.9", rules=rules)
    assert "## RANKED CANDIDATES (0)" in block


def test_context_is_deterministic(tmp_db: Path) -> None:
    eng_id, rules = _seed(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        b1 = build_context(conn, eng_id, rules=rules)
        b2 = build_context(conn, eng_id, rules=rules)
    assert b1 == b2
