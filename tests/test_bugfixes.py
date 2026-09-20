"""Regression tests for the correctness fixes from the senior audit pass."""
from __future__ import annotations

from pathlib import Path

from yhwach import db as yhdb
from yhwach.interpret import _first_json

# --- #1 command injection: run_action refuses tainted context ----------------

def _seed_two_hosts_with_tasks(tmp_db: Path) -> int:
    with yhdb.transaction(tmp_db) as conn:
        eng = yhdb.upsert_engagement(conn, lab="t", scope="10.0.0.0/24")
        # High-EV AI tasks on host A; a lower-EV task on host B.
        a = conn.execute("INSERT INTO host (engagement_id, ip, stage, first_seen) "
                         "VALUES (?, '10.0.0.1', 'scanned', '2026-01-01T00:00:00Z')",
                         (eng,)).lastrowid
        b = conn.execute("INSERT INTO host (engagement_id, ip, stage, first_seen) "
                         "VALUES (?, '10.0.0.2', 'scanned', '2026-01-01T00:00:00Z')",
                         (eng,)).lastrowid
        for i in range(5):  # 5 high-EV tasks on host A
            conn.execute(
                "INSERT INTO task (engagement_id, target_host_id, kind, playbook_rule_id, "
                "technique_class, rationale, risk, autonomy, ev_score, status, created_at) "
                "VALUES (?, ?, 'probe', ?, 'ai', 'r', 'read_only', 'proceed', 15.0, 'pending', ?)",
                (eng, a, f"ruleA{i}", "2026-01-01T00:00:00Z"))
        conn.execute(
            "INSERT INTO task (engagement_id, target_host_id, kind, playbook_rule_id, "
            "technique_class, rationale, risk, autonomy, ev_score, status, created_at) "
            "VALUES (?, ?, 'probe', 'ruleB', 'traditional', 'r', 'read_only', 'proceed', 1.0, 'pending', ?)",
            (eng, b, "2026-01-01T00:00:00Z"))
    return eng


def test_first_json_trailing_text() -> None:
    assert _first_json('{"a": 1} trailing junk here') == {"a": 1}


def test_first_json_skips_non_json_brace() -> None:
    assert _first_json('prefix { not json } then {"b": 2}') == {"b": 2}


def test_first_json_large_input_fast() -> None:
    big = '{"models": [1,2,3]}' + "x" * 500_000
    assert _first_json(big) == {"models": [1, 2, 3]}


def test_finding_scoped_to_engagement(tmp_db: Path) -> None:
    """A host-derived finding is scoped to its engagement; a second lab sees none."""
    with yhdb.transaction(tmp_db) as conn:
        e1 = yhdb.upsert_engagement(conn, lab="lab_a", scope="10.0.0.0/24")
        e2 = yhdb.upsert_engagement(conn, lab="lab_b", scope="10.0.0.0/24")
        h1 = conn.execute("INSERT INTO host (engagement_id, ip, stage, first_seen) "
                          "VALUES (?, '10.0.0.1', 'scanned', 't')", (e1,)).lastrowid
        yhdb.add_finding(conn, int(h1), None, "CWE-89", "sqli", "critical", "ev")
        n1 = conn.execute("SELECT COUNT(*) n FROM finding WHERE engagement_id=?", (e1,)).fetchone()["n"]
        n2 = conn.execute("SELECT COUNT(*) n FROM finding WHERE engagement_id=?", (e2,)).fetchone()["n"]
    assert n1 == 1 and n2 == 0


def test_migrate_self_heals_old_db(tmp_path: Path) -> None:
    """An older DB (no finding.tag/engagement_id, no tunnel, no source_host_id)
    is brought current on open — the 'no such column' friction can't recur."""
    import sqlite3
    p = tmp_path / "old.db"
    raw = sqlite3.connect(str(p))
    raw.executescript(
        "CREATE TABLE engagement (id INTEGER PRIMARY KEY, lab TEXT, scope TEXT, started_at TEXT);"
        "CREATE TABLE host (id INTEGER PRIMARY KEY, engagement_id INTEGER, ip TEXT);"
        "CREATE TABLE finding (id INTEGER PRIMARY KEY, host_id INTEGER, class TEXT, title TEXT, severity TEXT);"
        "CREATE TABLE credential (id INTEGER PRIMARY KEY, engagement_id INTEGER, identifier TEXT);"
    )
    raw.commit()
    raw.close()

    conn = yhdb.connect(str(p))          # self-heals on open
    try:
        fcols = {r["name"] for r in conn.execute("PRAGMA table_info(finding)")}
        ccols = {r["name"] for r in conn.execute("PRAGMA table_info(credential)")}
        tables = {r["name"] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
    finally:
        conn.close()
    assert {"tag", "engagement_id"} <= fcols
    assert "source_host_id" in ccols
    assert "tunnel" in tables
