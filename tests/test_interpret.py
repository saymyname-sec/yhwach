"""Tests for deterministic finding extraction from action output."""
from __future__ import annotations

from pathlib import Path

from yhwach import db as yhdb
from yhwach.interpret import interpret_all, interpret_output


def test_ollama_models_finding() -> None:
    out = '{"models":[{"name":"llama3.2"},{"name":"mistral"}]}'
    f = interpret_output("probe_ollama_models", out, {"URL": "http://10.0.0.5:11434"})
    assert f is not None
    assert f.cls == "LLM06"
    assert f.severity == "high"
    assert "2 models" in f.evidence


def test_ollama_empty_is_no_finding() -> None:
    assert interpret_output("probe_ollama_models", '{"models":[]}', {}) is None


def test_openai_models_finding() -> None:
    out = 'HTTP noise\n{"object":"list","data":[{"id":"gpt-4"},{"id":"gpt-3.5"}]}'
    f = interpret_output("enumerate_models", out, {"URL": "http://x"})
    assert f is not None and f.cls == "LLM02"


def test_mcp_tools_finding_is_critical() -> None:
    out = '{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"run_command"}]}}'
    f = interpret_output("mcp_tools_list", out, {"URL": "http://x"})
    assert f is not None
    assert f.cls == "LLM06"
    assert f.severity == "critical"


def test_jenkins_api_finding() -> None:
    out = '{"_class":"hudson.model.Hudson","mode":"NORMAL"}'
    f = interpret_output("jenkins_auth_check", out, {"URL": "http://x"})
    assert f is not None and f.cls == "CWE-200"


def test_smb_pwn3d_is_critical() -> None:
    out = "SMB  10.0.0.1  445  DC01  [+] domain\\admin (Pwn3d!)"
    f = interpret_output("netexec_smb_null", out, {"IP": "10.0.0.1"})
    assert f is not None and f.severity == "critical"


def test_rag_upload_finding() -> None:
    out = "FOUND /api/documents -> 200\nFOUND /upload -> 401"
    f = interpret_output("probe_rag_upload_paths", out, {"URL": "http://x"})
    assert f is not None and f.cls == "LLM04"


def test_unknown_action_returns_none() -> None:
    assert interpret_output("no_such_action", "whatever", {}) is None


def test_garbage_output_returns_none() -> None:
    assert interpret_output("probe_ollama_models", "not json at all", {}) is None


def test_add_finding_dedupes(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        eng = yhdb.upsert_engagement(conn, lab="f", scope="10.0.0.0/24")
        cur = conn.execute(
            "INSERT INTO host (engagement_id, ip, stage, first_seen) "
            "VALUES (?, '10.0.0.5', 'scanned', '2026-01-01T00:00:00Z')", (eng,))
        hid = int(cur.lastrowid)
        id1, c1 = yhdb.add_finding(conn, hid, None, "LLM06", "Ollama exposed", "high", "2 models")
        id2, c2 = yhdb.add_finding(conn, hid, None, "LLM06", "Ollama exposed", "high", "3 models")
        n = conn.execute("SELECT COUNT(*) AS n FROM finding").fetchone()["n"]
    assert id1 == id2
    assert c1 is True and c2 is False
    assert n == 1


def test_sqli_error_sqlite() -> None:
    out = "<pre class=err>SQL error: unrecognized token: \"'\"</pre>"
    f = interpret_output("sqli_error_probe", out, {"URL": "http://10.0.0.1"})
    assert f is not None and f.cls == "CWE-89" and f.severity == "critical"


def test_sqli_marker_extracts_location() -> None:
    out = "[SQLi] http://10.0.0.1/search.php?q"
    f = interpret_output("sqli_error_probe", out, {})
    assert f is not None and "search.php?q" in f.evidence


def test_sqli_clean_output_none() -> None:
    assert interpret_output("sqli_error_probe", "all results returned normally", {}) is None


# --- AD enumeration extractors (multi-finding) ------------------------------

def test_smb_multi_signal_pwn3d_and_signing() -> None:
    out = "SMB  10.0.0.1  445  DC01  [+] corp\\admin (Pwn3d!) (signing:False)"
    fs = interpret_all("netexec_smb_null", out, {"IP": "10.0.0.1"})
    assert any(f.severity == "critical" for f in fs)          # Pwn3d first
    assert "smb_signing_off" in {f.tag for f in fs}
    # interpret_output back-compat still returns the critical one
    assert interpret_output("netexec_smb_null", out, {}).severity == "critical"


def test_ldap_anon_naming_context_tag() -> None:
    f = interpret_output("ldapsearch_anon", "namingContexts: DC=corp,DC=local", {"IP": "10.0.0.1"})
    assert f is not None and f.tag == "ldap_anon" and "corp.local" in f.evidence


def test_kerberos_roast_tags_both() -> None:
    out = "$krb5asrep$23$user@CORP:ab...\nsvc  $krb5tgs$23$*svc*$..."
    tags = {f.tag for f in interpret_all("asreproast_users", out, {})}
    assert tags == {"asreproastable", "kerberoastable"}


def test_domain_users_tag() -> None:
    out = "[+] Valid user: alice\n[+] Valid user: bob\n[+] Valid user: carol"
    f = interpret_output("kerbrute_userenum", out, {"IP": "10.0.0.1"})
    assert f is not None and f.tag == "domain_users"


def test_interpret_all_empty_for_unknown() -> None:
    assert interpret_all("no_such_action", "x", {}) == []
