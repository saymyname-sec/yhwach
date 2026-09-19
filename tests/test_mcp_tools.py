"""Tests for the MCP tool logic (no SDK dependency)."""
from __future__ import annotations

from pathlib import Path

from yhwach import db as yhdb
from yhwach.mcp_tools import (
    TOOL_SPECS,
    tool_add_cred,
    tool_advance,
    tool_consume,
    tool_creds,
    tool_findings,
    tool_ingest,
    tool_next,
    tool_pivot,
    tool_plan,
    tool_proof,
    tool_report,
    tool_run,
    tool_spray,
    tool_status,
)


def _seed(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        eng = yhdb.upsert_engagement(conn, lab="m", scope="10.0.0.0/24")
        cur = conn.execute(
            "INSERT INTO host (engagement_id, ip, os, stage, first_seen) "
            "VALUES (?, '10.0.0.5', 'linux', 'scanned', '2026-01-01T00:00:00Z')", (eng,))
        hid = int(cur.lastrowid)
        cur = conn.execute(
            "INSERT INTO service (host_id, port, proto, discovered_at) "
            "VALUES (?, 11434, 'tcp', '2026-01-01T00:00:00Z')", (hid,))
        yhdb.upsert_surface(conn, hid, int(cur.lastrowid), "ollama", "none", "{}")


def test_status(tmp_db: Path) -> None:
    _seed(tmp_db)
    out = tool_status(tmp_db, "m")
    assert "Engagement 'm'" in out
    assert "scanned: 1" in out


def test_engage_creates_and_status_works(tmp_path: Path) -> None:
    from yhwach.mcp_tools import tool_engage
    db = tmp_path / "fresh.db"          # does not exist yet
    out = tool_engage(str(db), "z", "10.0.0.0/24", domain="corp.local")
    assert "ready" in out and db.exists()
    assert "Engagement 'z'" in tool_status(str(db), "z")


def test_engage_rejects_bad_scope(tmp_path: Path) -> None:
    import pytest

    from yhwach.mcp_tools import tool_engage
    with pytest.raises(ValueError):
        tool_engage(str(tmp_path / "x.db"), "z", "not-a-cidr")


def test_plan_and_next(tmp_db: Path) -> None:
    _seed(tmp_db)
    assert "rules matched" in tool_plan(tmp_db, "m")
    ctx = tool_next(tmp_db, "m")
    assert "## FRAME" in ctx
    assert "ollama_unauth_api" in ctx


def test_add_cred_then_spray_needs_surface(tmp_db: Path) -> None:
    _seed(tmp_db)
    assert "added" in tool_add_cred(tmp_db, "m", "admin", "P@ss")
    # ollama isn't a sprayable surface -> nothing to spray
    assert "nothing to spray" in tool_spray(tmp_db, "m")


def test_advance(tmp_db: Path) -> None:
    _seed(tmp_db)
    assert "foothold" in tool_advance(tmp_db, "m", "10.0.0.5", "foothold")


def test_report_and_findings(tmp_db: Path) -> None:
    _seed(tmp_db)
    assert "# Yhwach Engagement Report" in tool_report(tmp_db, "m")
    assert tool_findings(tmp_db, "m") == "no findings"


def test_unknown_lab_raises(tmp_db: Path) -> None:
    import pytest
    with pytest.raises(ValueError):
        tool_status(tmp_db, "nope")


def test_tool_specs_shape() -> None:
    names = {t[0] for t in TOOL_SPECS}
    # yhwach_creds is the vault-read surface; without it the operator can't
    # reuse creds via MCP and re-derives what's already stored.
    assert {"yhwach_status", "yhwach_next", "yhwach_report",
            "yhwach_creds", "yhwach_add_cred"}.issubset(names)
    for name, fn, desc in TOOL_SPECS:
        assert name.startswith("yhwach_") and callable(fn) and desc


def test_creds_empty_and_populated(tmp_db: Path) -> None:
    _seed(tmp_db)
    assert "vault empty" in tool_creds(tmp_db, "m")
    tool_add_cred(tmp_db, "m", "svc_portal", "P0rt@l!Svc#2025",
                  kind="password", source="jenkins_xml")
    out = tool_creds(tmp_db, "m")
    # Full secret must appear — the vault is the operator's own working data.
    assert "svc_portal" in out
    assert "P0rt@l!Svc#2025" in out
    assert "jenkins_xml" in out


def test_creds_filter_by_kind(tmp_db: Path) -> None:
    _seed(tmp_db)
    tool_add_cred(tmp_db, "m", "webservice", "pw", kind="password", source="s")
    tool_add_cred(tmp_db, "m", "svc_ci",
                  "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END-----",
                  kind="ssh_key", source="loot")
    out = tool_creds(tmp_db, "m", kind="ssh_key")
    assert "svc_ci" in out and "webservice" not in out
    # Multiline secrets are one-line-summarised in the table view.
    assert "multiline" in out


def test_add_cred_appends_source(tmp_db: Path) -> None:
    """Re-adding a cred with a new source must preserve the original."""
    _seed(tmp_db)
    tool_add_cred(tmp_db, "m", "svc_portal", "P0rt@l!", source="sqli")
    tool_add_cred(tmp_db, "m", "svc_portal", "P0rt@l!", source="jenkins_xml")
    out = tool_creds(tmp_db, "m")
    assert "sqli,jenkins_xml" in out


def test_status_shows_vault_ids(tmp_db: Path) -> None:
    _seed(tmp_db)
    tool_add_cred(tmp_db, "m", "svc_portal", "P0rt@l!Svc#2025", source="dump")
    out = tool_status(tmp_db, "m")
    assert "vault_ids: svc_portal(password)" in out


def test_next_surfaces_p0_leads(tmp_db: Path) -> None:
    _seed(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.engagement_id_for(conn, "m")
        hid = conn.execute("SELECT id FROM host WHERE engagement_id=? AND ip='10.0.0.5'",
                           (eid,)).fetchone()["id"]
        yhdb.add_finding(conn, hid, None, "T1003.006", "DCSync rights: svc_bkp",
                         "critical", "replication rights", tag="dcsync")
    ctx = tool_next(tmp_db, "m")
    assert "P0 LEADS" in ctx and "dcsync" in ctx


def test_ingest_nmap(tmp_db: Path, sample_nmap_xml: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        yhdb.upsert_engagement(conn, lab="m", scope="10.0.0.0/24")
    out = tool_ingest(tmp_db, "m", str(sample_nmap_xml), kind="nmap")
    assert "nmap ingested" in out and "hosts" in out


def test_ingest_peas_requires_host(tmp_db: Path) -> None:
    import pytest
    _seed(tmp_db)
    with pytest.raises(ValueError):
        tool_ingest(tmp_db, "m", "whatever.txt", kind="linpeas")


def test_run_renders_task(tmp_db: Path) -> None:
    _seed(tmp_db)
    tool_plan(tmp_db, "m")
    with yhdb.transaction(tmp_db) as conn:
        tid = conn.execute("SELECT id FROM task LIMIT 1").fetchone()["id"]
    out = tool_run(tmp_db, "m", tid)   # render only (go defaults False)
    assert "curl" in out               # the ollama probe command is rendered


def test_proof_binds_and_advances(tmp_db: Path, tmp_path: Path) -> None:
    _seed(tmp_db)
    tool_advance(tmp_db, "m", "10.0.0.5", "foothold")
    shot = tmp_path / "flag.png"
    shot.write_bytes(b"png")
    out = tool_proof(tmp_db, "m", "10.0.0.5", str(shot), flag_content="OSAI{x}")
    assert "proof #" in out and "looted" in out


def test_proof_refuses_missing_screenshot(tmp_db: Path, tmp_path: Path) -> None:
    import pytest
    _seed(tmp_db)
    with pytest.raises(ValueError):
        tool_proof(tmp_db, "m", "10.0.0.5", str(tmp_path / "nope.png"))


def test_pivot_records_and_advances(tmp_db: Path) -> None:
    _seed(tmp_db)
    out = tool_pivot(tmp_db, "m", "10.0.0.5", "10.1.0.0/24")
    assert "10.1.0.0/24" in out and "pivoted" in out
    # tunnel now gates nothing further; advancing again is idempotent-safe
    assert "already known" in tool_pivot(tmp_db, "m", "10.0.0.5", "10.1.0.0/24")


def test_consume_marks_technique(tmp_db: Path) -> None:
    _seed(tmp_db)
    tool_plan(tmp_db, "m")
    assert "consumed" in tool_consume(tmp_db, "m", "ollama_unauth_api")
    # re-planning now skips the consumed rule
    assert "matched 0" in tool_plan(tmp_db, "m")


def test_next_context_inlines_vault(tmp_db: Path) -> None:
    """`build_context` — the block yhwach_next returns — must quote the vault
    inline, otherwise the persona rule 'reuse before you work' is aspirational."""
    _seed(tmp_db)
    tool_add_cred(tmp_db, "m", "svc_portal", "P0rt@l!Svc#2025",
                  kind="password", source="jenkins_xml")
    ctx = tool_next(tmp_db, "m")
    assert "## VAULT" in ctx
    assert "svc_portal" in ctx and "P0rt@l!Svc#2025" in ctx


# --- operator memory + coverage (MCP parity) --------------------------------

def test_outcome_fail_removes_the_task_and_marks_a_dead_end(tmp_db: Path) -> None:
    from yhwach.mcp_tools import tool_outcome, tool_recall

    _seed(tmp_db)
    tool_plan(tmp_db, "m")
    with yhdb.transaction(tmp_db) as conn:
        tid = int(conn.execute("SELECT id FROM task LIMIT 1").fetchone()["id"])
    out = tool_outcome(tmp_db, "m", "fail", task_id=tid, why="endpoint 404s")
    assert "fail" in out and "abandoned" in out
    assert "no pending tasks" in tool_next(tmp_db, "m").lower() or \
           "RANKED CANDIDATES (0)" in tool_next(tmp_db, "m")
    recall = tool_recall(tmp_db, "m")
    assert "DEAD ENDS" in recall and "endpoint 404s" in recall


def test_outcome_success_consumes_the_technique(tmp_db: Path) -> None:
    from yhwach.mcp_tools import tool_outcome

    _seed(tmp_db)
    tool_plan(tmp_db, "m")
    out = tool_outcome(tmp_db, "m", "success", rule_id="ollama_unauth_api",
                       host="10.0.0.5", why="model list leaked a key")
    assert "consumed" in out
    assert "matched 0" in tool_plan(tmp_db, "m")


def test_recall_is_compact_and_persona_free(tmp_db: Path) -> None:
    from yhwach.mcp_tools import tool_recall

    _seed(tmp_db)
    out = tool_recall(tmp_db, "m")
    assert "YHWACH RECALL" in out
    assert "Silence is not a valid state" not in out   # no persona body
    assert len(out) < 4000


def test_next_persona_false_swaps_the_body_for_a_digest(tmp_db: Path) -> None:
    _seed(tmp_db)
    full = tool_next(tmp_db, "m")
    cheap = tool_next(tmp_db, "m", persona=False)
    assert "Silence is not a valid state" in full      # a persona-body marker
    assert "Silence is not a valid state" not in cheap
    assert "persona omitted — sha256:" in cheap
    assert len(cheap) < len(full) / 2
    assert "## RANKED CANDIDATES" in cheap     # the state slice is untouched


def test_next_json_format_is_parseable(tmp_db: Path) -> None:
    import json

    _seed(tmp_db)
    tool_plan(tmp_db, "m")
    data = json.loads(tool_next(tmp_db, "m", fmt="json"))
    assert data["engagement"]["lab"] == "m"
    assert len(data["persona_sha256"]) == 12
    assert data["candidates"][0]["rule_id"] == "ollama_unauth_api"
    assert data["candidates"][0]["commands"][0]["cmd"]


def test_gaps_tool_reports_under_enumeration(tmp_db: Path) -> None:
    from yhwach.mcp_tools import tool_gaps

    _seed(tmp_db)
    out = tool_gaps(tmp_db, "m")
    assert "10.0.0.5" in out and "no scan coverage recorded" in out


def test_ingest_reports_coverage_and_gaps(tmp_db: Path, tmp_path: Path) -> None:
    _seed(tmp_db)
    xml = tmp_path / "scan.xml"
    xml.write_text(
        '<?xml version="1.0"?><nmaprun args="nmap -p- -sV -oX - 10.0.0.5">'
        '<scaninfo type="syn" protocol="tcp" numservices="65535" services="1-65535"/>'
        '<host><status state="up"/><address addr="10.0.0.5" addrtype="ipv4"/>'
        '<ports><port protocol="tcp" portid="22"><state state="open"/>'
        '<service name="ssh"/></port></ports></host></nmaprun>', encoding="utf-8")
    out = tool_ingest(tmp_db, "m", str(xml))
    assert "coverage tcp 1-65535" in out
    assert "under-enumerated" in out          # UDP sweep still missing


def test_advance_to_enumerated_warns_about_gaps(tmp_db: Path) -> None:
    _seed(tmp_db)
    out = tool_advance(tmp_db, "m", "10.0.0.5", "enumerated")
    assert "enumerated" in out
    assert "NOT fully enumerated" in out


def test_new_tools_are_registered(tmp_db: Path) -> None:
    names = {name for name, _fn, _desc in TOOL_SPECS}
    assert {"yhwach_recall", "yhwach_outcome", "yhwach_gaps"} <= names
