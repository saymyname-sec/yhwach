"""Tests for Markdown report generation."""
from __future__ import annotations

from pathlib import Path

from yhwach import db as yhdb
from yhwach.report import build_report


def _seed(tmp_db: Path) -> int:
    with yhdb.transaction(tmp_db) as conn:
        eng = yhdb.upsert_engagement(conn, lab="rep", scope="10.0.0.0/24", domain="corp.local")
        cur = conn.execute(
            "INSERT INTO host (engagement_id, ip, hostname, os, stage, first_seen) "
            "VALUES (?, '10.0.0.5', 'ai01', 'linux', 'foothold', '2026-01-01T00:00:00Z')", (eng,))
        hid = int(cur.lastrowid)
        conn.execute(
            "INSERT INTO service (host_id, port, proto, product, version, discovered_at) "
            "VALUES (?, 11434, 'tcp', 'ollama', '0.1.28', '2026-01-01T00:00:00Z')", (hid,))
        yhdb.upsert_surface(conn, hid, None, "ollama", "none", "{}")
        yhdb.add_finding(conn, hid, None, "LLM06", "Unauthenticated Ollama API exposes models",
                         "high", "2 models")
        yhdb.add_finding(conn, hid, None, "CWE-200", "Jenkins API", "medium", "reachable")
    return eng


def test_report_has_core_sections(tmp_db: Path) -> None:
    eng = _seed(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        md = build_report(conn, eng)
    assert "# Yhwach Engagement Report — rep" in md
    assert "## Scoreboard" in md
    assert "## Findings" in md
    assert "## Hosts" in md
    assert "## Proofs" in md
    assert "corp.local" in md


def test_report_orders_findings_by_severity(tmp_db: Path) -> None:
    eng = _seed(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        md = build_report(conn, eng)
    high_pos = md.index("Unauthenticated Ollama API")
    med_pos = md.index("Jenkins API")
    assert high_pos < med_pos  # high before medium


def test_report_lists_host_services_and_surfaces(tmp_db: Path) -> None:
    eng = _seed(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        md = build_report(conn, eng)
    assert "10.0.0.5" in md
    assert "11434/tcp ollama" in md
    assert "ollama(none)" in md


def test_report_no_findings_message(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        eng = yhdb.upsert_engagement(conn, lab="empty", scope="10.0.0.0/24")
        md = build_report(conn, eng)
    assert "_None recorded._" in md
    assert "_None captured._" in md
