"""yhwach brief — the AI-legible read surface over the memory DB."""
from __future__ import annotations

from pathlib import Path

from yhwach import db as yhdb
from yhwach.brief import build_brief


def _seed(tmp_db: Path) -> int:
    with yhdb.transaction(tmp_db) as conn:
        eng = yhdb.upsert_engagement(conn, lab="brieftest", scope="10.0.0.0/24")
        cur = conn.execute(
            "INSERT INTO host (engagement_id, ip, hostname, os, stage, first_seen) "
            "VALUES (?, '10.0.0.5', 'web01', 'linux', 'scanned', '2026-01-01T00:00:00Z')", (eng,))
        hid = int(cur.lastrowid)
        svc = conn.execute(
            "INSERT INTO service (host_id, port, proto, product, discovered_at) "
            "VALUES (?, 80, 'tcp', 'nginx', '2026-01-01T00:00:00Z')", (hid,))
        yhdb.upsert_surface(conn, hid, int(svc.lastrowid), "chatbot", "none", "{}")
        yhdb.add_credential(conn, eng, "svc_x", "P@ss", "password", "dump")
        return eng


def test_brief_has_all_sections(tmp_db: Path) -> None:
    eng = _seed(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        out = build_brief(conn, eng)
    for h in ("REACH", "HOLD", "SURFACES", "UNLOCKS", "UNEXPLORED"):
        assert h in out
    assert "10.0.0.5" in out and "web01" in out          # REACH
    assert "svc_x" in out and "untried" in out            # HOLD (cred not validated)
    assert "chatbot" in out                               # SURFACES
    assert "Untried creds" in out or "svc_x" in out       # UNEXPLORED


def test_brief_section_filter(tmp_db: Path) -> None:
    eng = _seed(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        out = build_brief(conn, eng, section="hold")
    assert "HOLD" in out and "REACH" not in out
