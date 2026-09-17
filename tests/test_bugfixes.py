"""Regression tests for the correctness fixes from the senior audit pass."""
from __future__ import annotations

from pathlib import Path

from yhwach import db as yhdb
from yhwach.actions import Action, run_action
from yhwach.interpret import _first_json
from yhwach.planner import match_rules, top_tasks
from yhwach.playbooks import Rule

# --- #1 command injection: run_action refuses tainted context ----------------

def test_run_action_refuses_tainted_context(tmp_path: Path) -> None:
    a = Action(id="probe", commands=["curl -s $URL"], risk="read_only", runnable=True)
    ctx = {"URL": "http://x", "MODEL": "m'; touch pwned; echo '", "IP": "10.0.0.1", "PORT": "80"}
    res = run_action(a, ctx, loot_dir=tmp_path)
    assert res and all(r.get("refused") for r in res)
    assert all(r["returncode"] is None for r in res)
    # nothing executed -> no loot written
    assert not list(tmp_path.iterdir())


def test_run_action_allows_clean_context(tmp_path: Path) -> None:
    a = Action(id="echoer", commands=["echo hello"], risk="read_only", runnable=True)
    ctx = {"IP": "10.0.0.1", "PORT": "80"}
    res = run_action(a, ctx, loot_dir=tmp_path)
    assert res[0]["returncode"] == 0
    assert "hello" in res[0]["output"]


# --- #4 multi-command actions must not clobber their own loot file ------------

def test_run_action_indexes_loot_per_command(tmp_path: Path) -> None:
    a = Action(id="multi", commands=["echo one", "echo two"], risk="read_only", runnable=True)
    res = run_action(a, {"IP": "10.0.0.1", "PORT": "80"}, loot_dir=tmp_path)
    loot = {r["loot_file"] for r in res}
    assert len(loot) == 2  # distinct files, not overwritten
    contents = sorted(Path(p).read_text().strip() for p in loot)
    assert contents == ["one", "two"]


# --- #3 set_host_stage rejects an unknown target stage -----------------------

def test_set_host_stage_rejects_unknown_stage(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        eng = yhdb.upsert_engagement(conn, lab="b", scope="10.0.0.0/24")
        conn.execute("INSERT INTO host (engagement_id, ip, stage, first_seen) "
                     "VALUES (?, '10.0.0.5', 'foothold', '2026-01-01T00:00:00Z')", (eng,))
        changed, msg = yhdb.set_host_stage(conn, eng, "10.0.0.5", "owned")
    assert changed is False
    assert "unknown stage" in msg


# --- #2 top_tasks host filter must apply BEFORE the limit --------------------

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


def test_top_tasks_host_filter_before_limit(tmp_db: Path) -> None:
    eng = _seed_two_hosts_with_tasks(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        # Global top-4 are all host A; without a pre-limit filter, host B's task is lost.
        got = top_tasks(conn, eng, limit=4, host_ip="10.0.0.2")
    assert len(got) == 1
    assert got[0]["playbook_rule_id"] == "ruleB"


# --- #5 consume by rule id retires a rule that defines a technique alias ------

def test_consume_by_rule_id_retires_aliased_rule(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        eng = yhdb.upsert_engagement(conn, lab="c", scope="10.0.0.0/24")
        hid = conn.execute("INSERT INTO host (engagement_id, ip, os, stage, first_seen) "
                           "VALUES (?, '10.0.0.5', 'linux', 'scanned', '2026-01-01T00:00:00Z')",
                           (eng,)).lastrowid
        sid = conn.execute("INSERT INTO service (host_id, port, proto, discovered_at) "
                           "VALUES (?, 11434, 'tcp', '2026-01-01T00:00:00Z')", (hid,)).lastrowid
        yhdb.upsert_surface(conn, hid, int(sid), "ollama", "none", "{}")

        rule = Rule(id="my_rule", when={"surface": "ollama"},
                    emits=[{"action": "probe_ollama_models"}], points=15, likelihood="H",
                    time_cost="fast", risk="read_only", autonomy="proceed", maps=["LLM06"])
        rule._technique = "ollama_family"  # alias differs from id

        from yhwach.primitives import mark_technique_consumed
        mark_technique_consumed(conn, eng, "my_rule")  # consume by RULE ID, not alias

        report = match_rules(conn, eng, [rule])
    assert "my_rule" in report.rules_skipped_consumed
    assert report.tasks_created == 0


# --- #7 _first_json tolerates trailing text and large input ------------------

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
