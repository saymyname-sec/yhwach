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
