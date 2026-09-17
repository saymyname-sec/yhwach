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
    rule = _rule("future_rule", {"surface": "web", "banner_matches": "nginx/1.2"})
    with yhdb.transaction(tmp_db) as conn:
        report = match_rules(conn, eng_id, [rule])
    assert "future_rule" in report.rules_skipped_unsupported
    assert report.tasks_created == 0


def _add_finding(tmp_db: Path, eng_id: int, tag: str, ip: str = "10.0.0.5") -> None:
    with yhdb.transaction(tmp_db) as conn:
        hid = conn.execute("SELECT id FROM host WHERE engagement_id=? AND ip=?",
                           (eng_id, ip)).fetchone()["id"]
        yhdb.add_finding(conn, hid, None, "LLM04", f"finding {tag}", "high", "ev", tag=tag)


def test_findings_include_gates_surface_rule(tmp_db: Path) -> None:
    """A surface+findings_include rule fires only once the host carries the tag."""
    eng_id = _seed_surface(tmp_db, kind="chatbot")
    rule = _rule("rag_adv", {"surface": "chatbot", "findings_include": "rag_upload"})
    with yhdb.transaction(tmp_db) as conn:
        before = match_rules(conn, eng_id, [rule])
    assert before.tasks_created == 0  # no rag_upload finding yet

    _add_finding(tmp_db, eng_id, "rag_upload")
    with yhdb.transaction(tmp_db) as conn:
        after = match_rules(conn, eng_id, [rule])
        tasks = top_tasks(conn, eng_id)
    assert after.tasks_created == 1
    assert tasks[0]["playbook_rule_id"] == "rag_adv"


def test_ad_ldap_anon_chain(tmp_db: Path) -> None:
    """An `ldap_anon` finding unlocks the ldap_anon_dump attack rule."""
    from yhwach.playbooks import default_playbook_dir, load_rules
    eng = _seed_surface(tmp_db, kind="ldap")
    rules = load_rules(default_playbook_dir())
    _add_finding(tmp_db, eng, "ldap_anon")
    with yhdb.transaction(tmp_db) as conn:
        match_rules(conn, eng, rules)
        ids = [t["playbook_rule_id"] for t in top_tasks(conn, eng, 50)]
    assert "ldap_anon_dump" in ids


def test_ad_kerberoast_host_scoped(tmp_db: Path) -> None:
    """`kerberoastable` (no surface) fires the host-scoped kerberoast rule."""
    from yhwach.playbooks import default_playbook_dir, load_rules
    eng = _seed_surface(tmp_db, kind="smb")
    rules = load_rules(default_playbook_dir())
    _add_finding(tmp_db, eng, "kerberoastable")
    with yhdb.transaction(tmp_db) as conn:
        match_rules(conn, eng, rules)
        ids = [t["playbook_rule_id"] for t in top_tasks(conn, eng, 50)]
    assert "kerberoast" in ids


def test_vault_gated_rule_needs_credentials(tmp_db: Path) -> None:
    """`kerberoast_with_creds` (surface: ldap, vault: nonempty) fires only once the
    vault holds a credential."""
    from yhwach.playbooks import default_playbook_dir, load_rules
    eng = _seed_surface(tmp_db, kind="ldap")
    rules = load_rules(default_playbook_dir())
    with yhdb.transaction(tmp_db) as conn:
        match_rules(conn, eng, rules)
        ids = [t["playbook_rule_id"] for t in top_tasks(conn, eng, 50)]
    assert "kerberoast_with_creds" not in ids          # empty vault

    with yhdb.transaction(tmp_db) as conn:
        yhdb.add_credential(conn, eng, "admin", "P@ss", "password", "dump")
        match_rules(conn, eng, rules)
        ids = [t["playbook_rule_id"] for t in top_tasks(conn, eng, 50)]
    assert "kerberoast_with_creds" in ids              # creds present


def test_ollama_probllama_chain(tmp_db: Path) -> None:
    """A version fingerprint tagging `ollama_probllama` unlocks the CVE-2024-37032
    rogue-registry RCE rule on the ollama surface."""
    from yhwach.playbooks import default_playbook_dir, load_rules
    eng = _seed_surface(tmp_db, kind="ollama")
    rules = load_rules(default_playbook_dir())
    with yhdb.transaction(tmp_db) as conn:
        match_rules(conn, eng, rules)
        ids = [t["playbook_rule_id"] for t in top_tasks(conn, eng, 50)]
    assert "ollama_probllama_rce" not in ids   # not vulnerable until fingerprinted
    _add_finding(tmp_db, eng, "ollama_probllama")
    with yhdb.transaction(tmp_db) as conn:
        match_rules(conn, eng, rules)
        ids = [t["playbook_rule_id"] for t in top_tasks(conn, eng, 50)]
    assert "ollama_probllama_rce" in ids


def test_shadow_credential_chain(tmp_db: Path) -> None:
    """A `shadow_cred_target` bloodhound fact unlocks the shadow_credential_abuse
    rule (GenericWrite on a DA member -> PKINIT -> NT hash -> PtH)."""
    from yhwach.playbooks import default_playbook_dir, load_rules
    eng = _seed_surface(tmp_db, kind="smb", os="windows")
    rules = load_rules(default_playbook_dir())
    _add_finding(tmp_db, eng, "shadow_cred_target")
    with yhdb.transaction(tmp_db) as conn:
        match_rules(conn, eng, rules)
        ids = [t["playbook_rule_id"] for t in top_tasks(conn, eng, 50)]
    assert "shadow_credential_abuse" in ids


def test_gpp_password_chain(tmp_db: Path) -> None:
    from yhwach.playbooks import default_playbook_dir, load_rules
    eng = _seed_surface(tmp_db, kind="smb")
    rules = load_rules(default_playbook_dir())
    _add_finding(tmp_db, eng, "gpp_password")
    with yhdb.transaction(tmp_db) as conn:
        match_rules(conn, eng, rules)
        ids = [t["playbook_rule_id"] for t in top_tasks(conn, eng, 50)]
    assert "gpp_decrypt" in ids


def test_findings_include_only_rule_is_host_scoped(tmp_db: Path) -> None:
    """A findings_include-only rule (no surface) fires on the host, surface-less."""
    eng_id = _seed_surface(tmp_db, kind="chatbot")
    rule = _rule("dpapi", {"findings_include": "dpapi_master_key"})
    _add_finding(tmp_db, eng_id, "dpapi_master_key")
    with yhdb.transaction(tmp_db) as conn:
        r1 = match_rules(conn, eng_id, [rule])
        r2 = match_rules(conn, eng_id, [rule])  # idempotent
        row = conn.execute("SELECT target_surface_id FROM task WHERE playbook_rule_id='dpapi'").fetchone()
        n = conn.execute("SELECT COUNT(*) AS n FROM task WHERE playbook_rule_id='dpapi'").fetchone()["n"]
    assert r1.tasks_created == 1
    assert r2.tasks_created == 0 and r2.tasks_updated == 1
    assert n == 1  # host-scoped task deduped across re-runs
    assert row["target_surface_id"] is None


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


def test_ai_ranks_above_traditional_regardless_of_ev(tmp_db: Path) -> None:
    # An AI move with LOW EV must still outrank a traditional move with HIGH EV.
    with yhdb.transaction(tmp_db) as conn:
        eng_id = yhdb.upsert_engagement(conn, lab="tier", scope="10.0.0.0/24")
        cur = conn.execute(
            "INSERT INTO host (engagement_id, ip, os, stage, first_seen) "
            "VALUES (?, '10.0.0.5', 'linux', 'scanned', '2026-01-01T00:00:00Z')",
            (eng_id,),
        )
        host_id = int(cur.lastrowid)
        cur = conn.execute(
            "INSERT INTO service (host_id, port, proto, discovered_at) "
            "VALUES (?, 11434, 'tcp', '2026-01-01T00:00:00Z')", (host_id,))
        ai_svc = int(cur.lastrowid)
        cur = conn.execute(
            "INSERT INTO service (host_id, port, proto, discovered_at) "
            "VALUES (?, 445, 'tcp', '2026-01-01T00:00:00Z')", (host_id,))
        smb_svc = int(cur.lastrowid)
        yhdb.upsert_surface(conn, host_id, ai_svc, "ollama", "none", "{}")
        yhdb.upsert_surface(conn, host_id, smb_svc, "smb", "unknown", "{}")

    ai_rule = _rule("ollama_unauth_api", {"surface": "ollama"},
                    likelihood="M", time_cost="slow", risk="read_only")  # EV 2.25, class ai
    ai_rule.maps = ["LLM06"]
    trad_rule = _rule("smb_enumeration", {"surface": "smb"},
                      likelihood="H", time_cost="fast", risk="read_only")  # EV 10, traditional
    trad_rule.maps = ["CWE-200"]

    with yhdb.transaction(tmp_db) as conn:
        match_rules(conn, eng_id, [trad_rule, ai_rule])
        tasks = top_tasks(conn, eng_id)

    assert tasks[0]["playbook_rule_id"] == "ollama_unauth_api"  # AI first, despite EV 2.25 < 10
    assert tasks[0]["technique_class"] == "ai"
    assert tasks[1]["playbook_rule_id"] == "smb_enumeration"


def test_real_traditional_playbook_rules_load() -> None:
    from yhwach.playbooks import default_playbook_dir, load_rules
    ids = {r.id for r in load_rules(default_playbook_dir())}
    assert "jenkins_script_console_rce" in ids
    assert "smb_enumeration" in ids
    # class derivation: jenkins rule is traditional, ollama rule is ai
    rules = {r.id: r for r in load_rules(default_playbook_dir())}
    assert rules["jenkins_script_console_rce"].technique_class == "traditional"
    assert rules["ollama_unauth_api"].technique_class == "ai"


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
