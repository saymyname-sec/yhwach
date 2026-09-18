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


def test_coercion_chain(tmp_db: Path) -> None:
    """With a vault cred, SMB offers the coercible-service check; a coercion_target
    finding then unlocks the coerce-to-relay rule."""
    from yhwach.playbooks import default_playbook_dir, load_rules
    eng = _seed_surface(tmp_db, kind="smb")
    rules = load_rules(default_playbook_dir())
    with yhdb.transaction(tmp_db) as conn:
        yhdb.add_credential(conn, eng, "svc", "P@ss", "password", "dump")
        match_rules(conn, eng, rules)
        ids = [t["playbook_rule_id"] for t in top_tasks(conn, eng, 50)]
    assert "smb_coercible_service_check" in ids
    assert "coerce_authentication_to_relay" not in ids
    _add_finding(tmp_db, eng, "coercion_target")
    with yhdb.transaction(tmp_db) as conn:
        match_rules(conn, eng, rules)
        ids = [t["playbook_rule_id"] for t in top_tasks(conn, eng, 50)]
    assert "coerce_authentication_to_relay" in ids


def test_kerberos_timeroast_chain(tmp_db: Path) -> None:
    """A kerberos surface offers timeroasting (no creds)."""
    from yhwach.playbooks import default_playbook_dir, load_rules
    eng = _seed_surface(tmp_db, kind="kerberos")
    rules = load_rules(default_playbook_dir())
    with yhdb.transaction(tmp_db) as conn:
        match_rules(conn, eng, rules)
        ids = [t["playbook_rule_id"] for t in top_tasks(conn, eng, 50)]
    assert "kerberos_timeroast" in ids


def test_smb_password_policy_chain(tmp_db: Path) -> None:
    """An SMB surface offers password-policy enumeration (pre-spray)."""
    from yhwach.playbooks import default_playbook_dir, load_rules
    eng = _seed_surface(tmp_db, kind="smb")
    rules = load_rules(default_playbook_dir())
    with yhdb.transaction(tmp_db) as conn:
        match_rules(conn, eng, rules)
        ids = [t["playbook_rule_id"] for t in top_tasks(conn, eng, 50)]
    assert "smb_password_policy" in ids


def test_relay_adcs_esc8_chain(tmp_db: Path) -> None:
    """A webclient_running fact unlocks the coerce->relay-to-ADCS (ESC8) rule."""
    from yhwach.playbooks import default_playbook_dir, load_rules
    eng = _seed_surface(tmp_db, kind="smb")
    rules = load_rules(default_playbook_dir())
    _add_finding(tmp_db, eng, "webclient_running")
    with yhdb.transaction(tmp_db) as conn:
        match_rules(conn, eng, rules)
        ids = [t["playbook_rule_id"] for t in top_tasks(conn, eng, 50)]
    assert "ntlm_relay_to_adcs_esc8" in ids


def test_relay_dc_ldap_chain(tmp_db: Path) -> None:
    """An ntlm_relay_dc fact unlocks the relay-to-LDAP (RBCD/DCSync) rule."""
    from yhwach.playbooks import default_playbook_dir, load_rules
    eng = _seed_surface(tmp_db, kind="smb")
    rules = load_rules(default_playbook_dir())
    _add_finding(tmp_db, eng, "ntlm_relay_dc")
    with yhdb.transaction(tmp_db) as conn:
        match_rules(conn, eng, rules)
        ids = [t["playbook_rule_id"] for t in top_tasks(conn, eng, 50)]
    assert "ntlm_relay_dc_ldap" in ids


def test_smb_rid_cycling_chain(tmp_db: Path) -> None:
    """An SMB surface offers RID cycling for first-contact user enumeration."""
    from yhwach.playbooks import default_playbook_dir, load_rules
    eng = _seed_surface(tmp_db, kind="smb")
    rules = load_rules(default_playbook_dir())
    with yhdb.transaction(tmp_db) as conn:
        match_rules(conn, eng, rules)
        ids = [t["playbook_rule_id"] for t in top_tasks(conn, eng, 50)]
    assert "smb_rid_cycling" in ids


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


def test_writable_scheduled_task_chain(tmp_db: Path) -> None:
    from yhwach.playbooks import default_playbook_dir, load_rules
    eng = _seed_surface(tmp_db, kind="smb", os="windows")
    rules = load_rules(default_playbook_dir())
    _add_finding(tmp_db, eng, "writable_scheduled_task")
    with yhdb.transaction(tmp_db) as conn:
        match_rules(conn, eng, rules)
        ids = [t["playbook_rule_id"] for t in top_tasks(conn, eng, 50)]
    assert "writable_scheduled_task_privesc" in ids


def test_lsa_defaultpassword_chain(tmp_db: Path) -> None:
    from yhwach.playbooks import default_playbook_dir, load_rules
    eng = _seed_surface(tmp_db, kind="smb", os="windows")
    rules = load_rules(default_playbook_dir())
    _add_finding(tmp_db, eng, "lsa_defaultpassword")
    with yhdb.transaction(tmp_db) as conn:
        match_rules(conn, eng, rules)
        ids = [t["playbook_rule_id"] for t in top_tasks(conn, eng, 50)]
    assert "lsa_defaultpassword_recover" in ids


def test_text_to_sql_bypass_chain(tmp_db: Path) -> None:
    """A chatbot surface ranks the text-to-SQL guardrail-bypass move."""
    from yhwach.playbooks import default_playbook_dir, load_rules
    eng = _seed_surface(tmp_db, kind="chatbot")
    rules = load_rules(default_playbook_dir())
    with yhdb.transaction(tmp_db) as conn:
        match_rules(conn, eng, rules)
        ids = [t["playbook_rule_id"] for t in top_tasks(conn, eng, 50)]
    assert "text_to_sql_guardrail_bypass" in ids


def test_excessive_agency_chain(tmp_db: Path) -> None:
    """A chatbot surface ranks the excessive-agency tool-abuse move."""
    from yhwach.playbooks import default_playbook_dir, load_rules
    eng = _seed_surface(tmp_db, kind="chatbot")
    rules = load_rules(default_playbook_dir())
    with yhdb.transaction(tmp_db) as conn:
        match_rules(conn, eng, rules)
        ids = [t["playbook_rule_id"] for t in top_tasks(conn, eng, 50)]
    assert "chatbot_excessive_agency" in ids


def test_supply_chain_tag_chains(tmp_db: Path) -> None:
    """gitlab_token (gitlab surface), python_requirements (web surface), and
    mcp_config_writable (host-scoped) each unlock their supply-chain rule."""
    from yhwach.playbooks import default_playbook_dir, load_rules
    rules = load_rules(default_playbook_dir())
    eng = _seed_surface(tmp_db, kind="gitlab", ip="10.0.0.5")
    with yhdb.transaction(tmp_db) as conn:  # add a web surface on the same host
        hid = conn.execute("SELECT id FROM host WHERE engagement_id=?", (eng,)).fetchone()["id"]
        sid = conn.execute("SELECT id FROM service WHERE host_id=?", (hid,)).fetchone()["id"]
        yhdb.upsert_surface(conn, hid, sid, "web", "none", "{}")
    for tag in ("gitlab_token", "python_requirements", "mcp_config_writable"):
        _add_finding(tmp_db, eng, tag)
    with yhdb.transaction(tmp_db) as conn:
        match_rules(conn, eng, rules)
        ids = [t["playbook_rule_id"] for t in top_tasks(conn, eng, 80)]
    assert "gitlab_ci_variable_exfil" in ids
    assert "pypi_supply_chain_inspect" in ids
    assert "mcp_remote_oauth_exploitation" in ids


def test_k8s_sa_token_chain(tmp_db: Path) -> None:
    """A mounted SA-token finding unlocks the K8s enumeration rule."""
    from yhwach.playbooks import default_playbook_dir, load_rules
    eng = _seed_surface(tmp_db, kind="ssh")
    rules = load_rules(default_playbook_dir())
    _add_finding(tmp_db, eng, "k8s_sa_token")
    with yhdb.transaction(tmp_db) as conn:
        match_rules(conn, eng, rules)
        ids = [t["playbook_rule_id"] for t in top_tasks(conn, eng, 50)]
    assert "k8s_sa_token_and_secrets" in ids


def test_k8s_privileged_and_gpu_chains(tmp_db: Path) -> None:
    """pod_create_permission and nvidia_toolkit each unlock their escape rule
    (now that the never-emitted kubernetes surface no longer gates them)."""
    from yhwach.playbooks import default_playbook_dir, load_rules
    eng = _seed_surface(tmp_db, kind="ssh")
    rules = load_rules(default_playbook_dir())
    _add_finding(tmp_db, eng, "pod_create_permission")
    _add_finding(tmp_db, eng, "nvidia_toolkit")
    with yhdb.transaction(tmp_db) as conn:
        match_rules(conn, eng, rules)
        ids = [t["playbook_rule_id"] for t in top_tasks(conn, eng, 50)]
    assert "k8s_privileged_escape" in ids
    assert "gpu_container_escape" in ids


def test_aws_credentials_iam_chain(tmp_db: Path) -> None:
    """IMDS-leaked AWS creds (tag aws_credentials) unlock the IAM role-chain rule."""
    from yhwach.playbooks import default_playbook_dir, load_rules
    eng = _seed_surface(tmp_db, kind="web")
    rules = load_rules(default_playbook_dir())
    _add_finding(tmp_db, eng, "aws_credentials")
    with yhdb.transaction(tmp_db) as conn:
        match_rules(conn, eng, rules)
        ids = [t["playbook_rule_id"] for t in top_tasks(conn, eng, 50)]
    assert "aws_iam_role_chain_escalation" in ids


def test_sagemaker_notebook_privesc_chain(tmp_db: Path) -> None:
    """sagemaker_create_notebook unlocks the SageMaker notebook privesc rule."""
    from yhwach.playbooks import default_playbook_dir, load_rules
    eng = _seed_surface(tmp_db, kind="web")
    rules = load_rules(default_playbook_dir())
    _add_finding(tmp_db, eng, "sagemaker_create_notebook")
    with yhdb.transaction(tmp_db) as conn:
        match_rules(conn, eng, rules)
        ids = [t["playbook_rule_id"] for t in top_tasks(conn, eng, 50)]
    assert "aws_sagemaker_notebook_privesc" in ids


def test_agent_ssrf_and_imds_chain(tmp_db: Path) -> None:
    """An a2a agent hub offers the egress-proxy SSRF recon; a confirmed SSRF then
    unlocks the pre-existing IMDS/cloud-metadata rule."""
    from yhwach.playbooks import default_playbook_dir, load_rules
    eng = _seed_surface(tmp_db, kind="a2a")
    rules = load_rules(default_playbook_dir())
    with yhdb.transaction(tmp_db) as conn:
        match_rules(conn, eng, rules)
        ids = [t["playbook_rule_id"] for t in top_tasks(conn, eng, 50)]
    assert "agent_egress_proxy_ssrf" in ids
    # ssrf_confirmed is what the file:// extractor sets; it lights up aws_ml_infra_ssrf
    # (which is gated on surface: web) -> seed a web surface on the same host too.
    with yhdb.transaction(tmp_db) as conn:
        hid = conn.execute("SELECT id FROM host WHERE engagement_id=?", (eng,)).fetchone()["id"]
        sid = conn.execute("SELECT id FROM service WHERE host_id=?", (hid,)).fetchone()["id"]
        yhdb.upsert_surface(conn, hid, sid, "web", "none", "{}")
    _add_finding(tmp_db, eng, "ssrf_confirmed")
    with yhdb.transaction(tmp_db) as conn:
        match_rules(conn, eng, rules)
        ids = [t["playbook_rule_id"] for t in top_tasks(conn, eng, 50)]
    assert "aws_ml_infra_ssrf" in ids


def test_oauth2proxy_jenkins_bypass_chain(tmp_db: Path) -> None:
    """A web surface offers the oauth2-proxy suffix-bypass recon; the
    jenkins_unsecured tag then unlocks the anonymous console RCE."""
    from yhwach.playbooks import default_playbook_dir, load_rules
    eng = _seed_surface(tmp_db, kind="web")
    rules = load_rules(default_playbook_dir())
    with yhdb.transaction(tmp_db) as conn:
        match_rules(conn, eng, rules)
        ids = [t["playbook_rule_id"] for t in top_tasks(conn, eng, 50)]
    assert "oauth2proxy_static_suffix_bypass" in ids
    assert "jenkins_unsecured_console_rce" not in ids   # not until the bypass lands
    _add_finding(tmp_db, eng, "jenkins_unsecured")
    with yhdb.transaction(tmp_db) as conn:
        match_rules(conn, eng, rules)
        ids = [t["playbook_rule_id"] for t in top_tasks(conn, eng, 50)]
    assert "jenkins_unsecured_console_rce" in ids


def test_agent_tool_lfi_chain(tmp_db: Path) -> None:
    """A gradio tool console surfaces the LFI recon rule (read_log traversal +
    unsafe YAML include)."""
    from yhwach.playbooks import default_playbook_dir, load_rules
    eng = _seed_surface(tmp_db, kind="gradio")
    rules = load_rules(default_playbook_dir())
    with yhdb.transaction(tmp_db) as conn:
        match_rules(conn, eng, rules)
        ids = [t["playbook_rule_id"] for t in top_tasks(conn, eng, 50)]
    assert "agent_tool_file_read" in ids


def test_jinja2_ssti_rce_chain(tmp_db: Path) -> None:
    """A `jinja2_template` finding (from the 7*7 reflection probe) unlocks the
    direct polyglot SSTI RCE rule."""
    from yhwach.playbooks import default_playbook_dir, load_rules
    eng = _seed_surface(tmp_db, kind="chatbot")
    rules = load_rules(default_playbook_dir())
    _add_finding(tmp_db, eng, "jinja2_template")
    with yhdb.transaction(tmp_db) as conn:
        match_rules(conn, eng, rules)
        ids = [t["playbook_rule_id"] for t in top_tasks(conn, eng, 50)]
    assert "jinja2_ssti_rce" in ids


def test_langflow_exec_chain(tmp_db: Path) -> None:
    """A `langflow_exec` finding unlocks the unauth PythonComponent RCE rule."""
    from yhwach.playbooks import default_playbook_dir, load_rules
    eng = _seed_surface(tmp_db, kind="openai_compat")
    rules = load_rules(default_playbook_dir())
    _add_finding(tmp_db, eng, "langflow_exec")
    with yhdb.transaction(tmp_db) as conn:
        match_rules(conn, eng, rules)
        ids = [t["playbook_rule_id"] for t in top_tasks(conn, eng, 50)]
    assert "langflow_component_exec_rce" in ids


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


def test_ldap_laps_read_chain(tmp_db: Path) -> None:
    """With a vault cred, LDAP offers the LAPS read."""
    from yhwach.playbooks import default_playbook_dir, load_rules
    eng = _seed_surface(tmp_db, kind="ldap")
    rules = load_rules(default_playbook_dir())
    with yhdb.transaction(tmp_db) as conn:
        yhdb.add_credential(conn, eng, "svc", "P@ss", "password", "dump")
        match_rules(conn, eng, rules)
        ids = [t["playbook_rule_id"] for t in top_tasks(conn, eng, 50)]
    assert "ldap_laps_read" in ids


def test_ldap_user_descriptions_chain(tmp_db: Path) -> None:
    """With a vault cred, LDAP offers the description-password hunt."""
    from yhwach.playbooks import default_playbook_dir, load_rules
    eng = _seed_surface(tmp_db, kind="ldap")
    rules = load_rules(default_playbook_dir())
    with yhdb.transaction(tmp_db) as conn:
        yhdb.add_credential(conn, eng, "svc", "P@ss", "password", "dump")
        match_rules(conn, eng, rules)
        ids = [t["playbook_rule_id"] for t in top_tasks(conn, eng, 50)]
    assert "ldap_user_descriptions" in ids


def test_badsuccessor_chain(tmp_db: Path) -> None:
    """LDAP+cred offers the BadSuccessor check; the tag unlocks the dMSA abuse."""
    from yhwach.playbooks import default_playbook_dir, load_rules
    eng = _seed_surface(tmp_db, kind="ldap")
    rules = load_rules(default_playbook_dir())
    with yhdb.transaction(tmp_db) as conn:
        yhdb.add_credential(conn, eng, "svc", "P@ss", "password", "dump")
        match_rules(conn, eng, rules)
        ids = [t["playbook_rule_id"] for t in top_tasks(conn, eng, 60)]
    assert "ldap_badsuccessor_check" in ids
    _add_finding(tmp_db, eng, "dmsa_badsuccessor")
    with yhdb.transaction(tmp_db) as conn:
        match_rules(conn, eng, rules)
        ids = [t["playbook_rule_id"] for t in top_tasks(conn, eng, 60)]
    assert "badsuccessor_abuse" in ids


def test_constrained_delegation_chain(tmp_db: Path) -> None:
    """LDAP+cred offers the constrained-deleg enum; the tag unlocks S4U abuse."""
    from yhwach.playbooks import default_playbook_dir, load_rules
    eng = _seed_surface(tmp_db, kind="ldap")
    rules = load_rules(default_playbook_dir())
    with yhdb.transaction(tmp_db) as conn:
        yhdb.add_credential(conn, eng, "svc", "P@ss", "password", "dump")
        match_rules(conn, eng, rules)
        ids = [t["playbook_rule_id"] for t in top_tasks(conn, eng, 60)]
    assert "ldap_constrained_delegation_enum" in ids
    _add_finding(tmp_db, eng, "constrained_delegation")
    with yhdb.transaction(tmp_db) as conn:
        match_rules(conn, eng, rules)
        ids = [t["playbook_rule_id"] for t in top_tasks(conn, eng, 60)]
    assert "constrained_delegation_abuse" in ids


def test_machineaccountquota_and_rbcd_chain(tmp_db: Path) -> None:
    """With a vault cred, LDAP offers MAQ enumeration; a positive quota finding
    then unlocks the RBCD abuse rule."""
    from yhwach.playbooks import default_playbook_dir, load_rules
    eng = _seed_surface(tmp_db, kind="ldap")
    rules = load_rules(default_playbook_dir())
    with yhdb.transaction(tmp_db) as conn:
        yhdb.add_credential(conn, eng, "svc", "P@ss", "password", "dump")
        match_rules(conn, eng, rules)
        ids = [t["playbook_rule_id"] for t in top_tasks(conn, eng, 50)]
    assert "ldap_machineaccountquota" in ids
    assert "rbcd_machineaccountquota_abuse" not in ids   # not until MAQ>0 confirmed
    _add_finding(tmp_db, eng, "machine_account_quota")
    with yhdb.transaction(tmp_db) as conn:
        match_rules(conn, eng, rules)
        ids = [t["playbook_rule_id"] for t in top_tasks(conn, eng, 50)]
    assert "rbcd_machineaccountquota_abuse" in ids


def test_trust_forge_chain(tmp_db: Path) -> None:
    """LDAP+cred offers trust enumeration; a domain_trust finding unlocks the
    inter-realm SID-history forge."""
    from yhwach.playbooks import default_playbook_dir, load_rules
    eng = _seed_surface(tmp_db, kind="ldap")
    rules = load_rules(default_playbook_dir())
    with yhdb.transaction(tmp_db) as conn:
        yhdb.add_credential(conn, eng, "svc", "P@ss", "password", "dump")
        match_rules(conn, eng, rules)
        ids = [t["playbook_rule_id"] for t in top_tasks(conn, eng, 80)]
    assert "ldap_trust_enum" in ids
    _add_finding(tmp_db, eng, "domain_trust")
    with yhdb.transaction(tmp_db) as conn:
        match_rules(conn, eng, rules)
        ids = [t["playbook_rule_id"] for t in top_tasks(conn, eng, 80)]
    assert "trust_ticket_forge" in ids


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


def test_model_checkpoint_pickle_chain(tmp_db: Path) -> None:
    """A model server tagged model_checkpoint_load ranks the torch.load poison RCE."""
    from yhwach.playbooks import default_playbook_dir, load_rules
    eng = _seed_surface(tmp_db, kind="openai_compat")
    rules = load_rules(default_playbook_dir())
    _add_finding(tmp_db, eng, "model_checkpoint_load")
    with yhdb.transaction(tmp_db) as conn:
        match_rules(conn, eng, rules)
        ids = [t["playbook_rule_id"] for t in top_tasks(conn, eng, 50)]
    assert "model_checkpoint_pickle_rce" in ids


def test_gpo_abuse_chain(tmp_db: Path) -> None:
    """LDAP+cred offers GPO enumeration; a gpo_control finding unlocks GPO abuse."""
    from yhwach.playbooks import default_playbook_dir, load_rules
    eng = _seed_surface(tmp_db, kind="ldap")
    rules = load_rules(default_playbook_dir())
    with yhdb.transaction(tmp_db) as conn:
        yhdb.add_credential(conn, eng, "svc", "P@ss", "password", "dump")
        match_rules(conn, eng, rules)
        ids = [t["playbook_rule_id"] for t in top_tasks(conn, eng, 80)]
    assert "ldap_gpo_enum" in ids
    _add_finding(tmp_db, eng, "gpo_control")
    with yhdb.transaction(tmp_db) as conn:
        match_rules(conn, eng, rules)
        ids = [t["playbook_rule_id"] for t in top_tasks(conn, eng, 80)]
    assert "gpo_abuse" in ids


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


def test_n8n_ni8mare_chain(tmp_db: Path) -> None:
    """A web surface whose service product is n8n offers the version recon; the
    n8n_ni8mare tag then unlocks the unauth file read, and n8n_encryption_key
    unlocks both the JWT forge and the credential-store decrypt."""
    from yhwach.playbooks import default_playbook_dir, load_rules
    eng = _seed_surface(tmp_db, kind="web", ip="10.0.0.30")
    with yhdb.transaction(tmp_db) as conn:
        conn.execute(
            "UPDATE service SET product='n8n 1.120.4' WHERE host_id="
            "(SELECT id FROM host WHERE engagement_id=? AND ip='10.0.0.30')", (eng,))
    rules = load_rules(default_playbook_dir())
    with yhdb.transaction(tmp_db) as conn:
        match_rules(conn, eng, rules)
        ids = [t["playbook_rule_id"] for t in top_tasks(conn, eng, 200)]
    assert "n8n_workflow_recon" in ids
    _add_finding(tmp_db, eng, "n8n_ni8mare", ip="10.0.0.30")
    with yhdb.transaction(tmp_db) as conn:
        match_rules(conn, eng, rules)
        ids = [t["playbook_rule_id"] for t in top_tasks(conn, eng, 200)]
    assert "n8n_ni8mare_fileread" in ids
    _add_finding(tmp_db, eng, "n8n_encryption_key", ip="10.0.0.30")
    with yhdb.transaction(tmp_db) as conn:
        match_rules(conn, eng, rules)
        ids = [t["playbook_rule_id"] for t in top_tasks(conn, eng, 200)]
    assert "n8n_auth_jwt_forge" in ids
    assert "n8n_credential_store_decrypt" in ids


def test_rag_readpage_bypass_chain(tmp_db: Path) -> None:
    """A rag surface offers recon; with a vault cred it offers the authenticated
    import (obj8); a rag_import_ok finding unlocks the read_page retrieval-poison
    (obj9)."""
    from yhwach.playbooks import default_playbook_dir, load_rules
    eng = _seed_surface(tmp_db, kind="rag")
    rules = load_rules(default_playbook_dir())
    with yhdb.transaction(tmp_db) as conn:
        match_rules(conn, eng, rules)
        ids = [t["playbook_rule_id"] for t in top_tasks(conn, eng, 200)]
    assert "rag_surface_recon" in ids
    assert "rag_authenticated_import" not in ids  # no cred yet
    with yhdb.transaction(tmp_db) as conn:
        yhdb.add_credential(conn, eng, "svc_wiki", "W1k1", "password", "rag")
        match_rules(conn, eng, rules)
        ids = [t["playbook_rule_id"] for t in top_tasks(conn, eng, 200)]
    assert "rag_authenticated_import" in ids
    _add_finding(tmp_db, eng, "rag_import_ok")
    with yhdb.transaction(tmp_db) as conn:
        match_rules(conn, eng, rules)
        ids = [t["playbook_rule_id"] for t in top_tasks(conn, eng, 200)]
    assert "rag_readpage_poison_unlock" in ids
