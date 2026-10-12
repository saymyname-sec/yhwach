"""Tests for the phase synthesis report."""

from __future__ import annotations

from pathlib import Path

from yhwach import db as yhdb
from yhwach import synthesis as syn
from yhwach.synthesis import PhaseVerdict as Verdict


def _engagement(conn):
    eid = yhdb.upsert_engagement(conn, lab="t", scope="10.0.0.0/24")
    cur = conn.execute(
        "INSERT INTO host (engagement_id, ip, os, stage, first_seen) "
        "VALUES (?, '10.0.0.5', 'linux', 'scanned', '2026-01-01T00:00:00Z')",
        (eid,),
    )
    hid = int(cur.lastrowid)
    yhdb.upsert_surface(conn, hid, None, "ollama", "none", "{}")
    return eid, hid


def test_report_has_core_sections(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        eid, _ = _engagement(conn)
        text = syn.phase_report(conn, eid)
    for header in ("ENGAGEMENT STATE", "What we know", "Confirmed leads", "Recommended next steps"):
        assert header in text


def test_report_includes_verdict(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        eid, _ = _engagement(conn)
        v = Verdict(done=False, reasoning="two hosts unscanned", whats_left=["scan .6"])
        text = syn.phase_report(conn, eid, verdict=v)
    assert "NOT COMPLETE" in text
    assert "two hosts unscanned" in text
    assert "left: scan .6" in text


def test_report_lists_next_steps_split_by_gating(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        eid, hid = _engagement(conn)
        # open finding lights the exploit-tier probllama chain (gated)
        yhdb.add_finding(
            conn,
            host_id=hid,
            surface_id=None,
            cls="LLM01",
            title="probllama",
            severity="high",
            evidence="x",
            tag="ollama_probllama",
            engagement_id=eid,
        )
        text = syn.phase_report(conn, eid)
    assert "Read-only (agent can run unattended):" in text
    assert "ollama_unauth_api" in text
    assert "Gated (needs your go-ahead):" in text
    assert "ollama_probllama_rce" in text


def test_report_shows_leads_and_dead_ends(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        eid, hid = _engagement(conn)
        yhdb.add_finding(
            conn,
            host_id=hid,
            surface_id=None,
            cls="LLM06",
            title="unauth ollama",
            severity="high",
            evidence="3 models",
            tag="ollama_models",
            engagement_id=eid,
        )
        yhdb.add_attempt(
            conn, eid, result="fail", host_id=hid, playbook_rule_id="x_exploit", reason="patched"
        )
        text = syn.phase_report(conn, eid)
    assert "`ollama_models`" in text
    assert "Dead ends" in text
    assert "x_exploit" in text


def test_report_excludes_already_succeeded_next_steps(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        eid, hid = _engagement(conn)
        yhdb.add_attempt(
            conn, eid, result="success", host_id=hid, playbook_rule_id="ollama_unauth_api"
        )
        text = syn.phase_report(conn, eid)
    assert "ollama_unauth_api" not in text
    # Post-arsenal-wiring: an os=linux host will still surface the os-only
    # revshell generator rule as an always-available payload hint. The
    # invariant we care about here — the succeeded ollama technique doesn't
    # come back — still holds; the "no applicable techniques remain"
    # phrasing only fires when NOTHING matches, which is no longer true.
    assert (
        "no applicable techniques remain" in text
        or "generate_linux_revshell" in text
    )
