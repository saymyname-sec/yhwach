"""Tests for the MCP tool logic (no SDK dependency)."""
from __future__ import annotations

from pathlib import Path

from yhwach import db as yhdb
from yhwach.mcp_tools import (
    tool_add_cred,
    tool_add_finding,
    tool_add_loot,
    tool_advance,
    tool_creds,
    tool_findings,
    tool_ingest,
    tool_pivot,
    tool_report,
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


def test_creds_empty_and_populated(tmp_db: Path) -> None:
    _seed(tmp_db)
    assert "vault empty" in tool_creds(tmp_db, "m")
    tool_add_cred(tmp_db, "m", "svc_app", "@ppS3rv!Svc#2025",
                  kind="password", source="jenkins_xml")
    out = tool_creds(tmp_db, "m")
    # Full secret must appear — the vault is the operator's own working data.
    assert "svc_app" in out
    assert "@ppS3rv!Svc#2025" in out
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
    tool_add_cred(tmp_db, "m", "svc_app", "@ppS3rv!", source="sqli")
    tool_add_cred(tmp_db, "m", "svc_app", "@ppS3rv!", source="jenkins_xml")
    out = tool_creds(tmp_db, "m")
    assert "sqli,jenkins_xml" in out


def test_status_shows_vault_ids(tmp_db: Path) -> None:
    _seed(tmp_db)
    tool_add_cred(tmp_db, "m", "svc_app", "@ppS3rv!Svc#2025", source="dump")
    out = tool_status(tmp_db, "m")
    assert "vault_ids: svc_app(password)" in out


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


def test_pivot_records_and_advances(tmp_db: Path) -> None:
    _seed(tmp_db)
    out = tool_pivot(tmp_db, "m", "10.0.0.5", "10.1.0.0/24")
    assert "10.1.0.0/24" in out and "pivoted" in out
    # tunnel now gates nothing further; advancing again is idempotent-safe
    assert "already known" in tool_pivot(tmp_db, "m", "10.0.0.5", "10.1.0.0/24")


def test_gaps_tool_reports_under_enumeration(tmp_db: Path) -> None:
    from yhwach.mcp_tools import tool_gaps

    _seed(tmp_db)
    out = tool_gaps(tmp_db, "m")
    assert "10.0.0.5" in out and "no scan coverage recorded" in out


def test_audit_tool_reports_methodology(tmp_db: Path) -> None:
    from yhwach.mcp_tools import TOOL_SPECS, tool_audit

    _seed(tmp_db)
    out = tool_audit(tmp_db, "m")
    assert "METHODOLOGY AUDIT" in out
    assert "Paths not yet checked" in out
    assert "yhwach_audit" in {name for name, _fn, _desc in TOOL_SPECS}


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




def test_add_finding_host_scoped_shows_in_findings(tmp_db: Path) -> None:
    _seed(tmp_db)
    out = tool_add_finding(
        tmp_db, "m", title="n8n auth JWT structure disclosed in wiki",
        severity="high", evidence="/wiki/runbooks/n8n-auth-troubleshooting leaks n8n-auth payload",
        cls="CWE-200", host="10.0.0.5", tag="n8n_jwt_leak")
    assert "recorded" in out and "high" in out
    listed = tool_findings(tmp_db, "m")
    assert "n8n auth JWT structure disclosed in wiki" in listed


def test_add_finding_engagement_wide(tmp_db: Path) -> None:
    _seed(tmp_db)
    out = tool_add_finding(tmp_db, "m", title="Gitea open registration",
                           severity="medium", evidence="/user/sign_up -> 200")
    assert "recorded" in out
    assert "Gitea open registration" in tool_findings(tmp_db, "m")


def test_add_finding_rejects_bad_severity(tmp_db: Path) -> None:
    _seed(tmp_db)
    out = tool_add_finding(tmp_db, "m", title="x", severity="spicy", evidence="e")
    assert "error" in out.lower()


def test_add_finding_out_of_scope_host_errors(tmp_db: Path) -> None:
    """Truly out-of-scope IPs still error — guards against operator typos.

    (In-scope-but-unmaterialised hosts now auto-upsert instead of erroring;
    that behaviour is covered in tests/test_discovery.py.)
    """
    _seed(tmp_db)
    out = tool_add_finding(tmp_db, "m", title="x", severity="low", evidence="e", host="10.9.9.9")
    assert "out of scope" in out


def test_add_loot_records_artifact(tmp_db: Path) -> None:
    _seed(tmp_db)
    out = tool_add_loot(tmp_db, "m", summary="n8n database.sqlite exfiltrated",
                        host="10.0.0.5", path="/opt/n8n/.n8n/database.sqlite",
                        local_path="/tmp/n8n.sqlite", type="db", contains_secret=True)
    assert "loot #" in out and "contains secret" in out
    with yhdb.transaction(tmp_db) as conn:
        row = conn.execute("SELECT summary, type, contains_secret FROM loot").fetchone()
    assert row["type"] == "db" and row["contains_secret"] == 1


def test_add_loot_out_of_scope_host_errors(tmp_db: Path) -> None:
    """Same guard as add_finding — out-of-scope IPs are refused; in-scope
    unmaterialised ones auto-upsert (covered in tests/test_discovery.py)."""
    _seed(tmp_db)
    out = tool_add_loot(tmp_db, "m", summary="x", host="10.9.9.9")
    assert "out of scope" in out


# ── tool_pivot: kind + os_hint (arsenal-wired) ──────────────────────────────

import pytest  # noqa: E402

from yhwach import arsenal as _arsenal  # noqa: E402


def _seed_windows(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        eng = yhdb.upsert_engagement(conn, lab="m", scope="10.0.0.0/24")
        conn.execute(
            "INSERT INTO host (engagement_id, ip, os, stage, first_seen) "
            "VALUES (?, '10.0.0.9', 'windows', 'looted', '2026-01-01T00:00:00Z')",
            (eng,),
        )


def test_tool_pivot_linux_defaults_to_chisel(tmp_db: Path) -> None:
    _seed(tmp_db)
    out = tool_pivot(tmp_db, "m", "10.0.0.5", "10.1.0.0/24")
    # Auto-picks chisel because the seeded host is Linux.
    assert "kind=chisel" in out
    assert "agent=CHISEL" in out
    assert str(_arsenal.get("CHISEL").path) in out


def test_tool_pivot_windows_defaults_to_svcmon(tmp_db: Path) -> None:
    _seed_windows(tmp_db)
    out = tool_pivot(tmp_db, "m", "10.0.0.9", "10.2.0.0/24")
    assert "kind=ligolo" in out
    assert "agent=SVCMON_WIN" in out
    assert str(_arsenal.get("SVCMON_WIN").path) in out
    assert "svcmon" in out


def test_tool_pivot_kind_override_respected(tmp_db: Path) -> None:
    _seed(tmp_db)  # linux host, would default to chisel
    out = tool_pivot(tmp_db, "m", "10.0.0.5", "10.1.0.0/24", kind="ligolo")
    assert "kind=ligolo" in out
    assert "agent=LIGOLO_AGENT_LINUX" in out
    assert str(_arsenal.get("LIGOLO_AGENT_LINUX").path) in out


def test_tool_pivot_rejects_unknown_kind(tmp_db: Path) -> None:
    _seed(tmp_db)
    with pytest.raises(ValueError, match="unknown pivot kind"):
        tool_pivot(tmp_db, "m", "10.0.0.5", "10.1.0.0/24", kind="wireguard")


def test_tool_pivot_records_agent_path_on_tunnel_row(tmp_db: Path) -> None:
    _seed_windows(tmp_db)
    tool_pivot(tmp_db, "m", "10.0.0.9", "10.2.0.0/24")
    with yhdb.transaction(tmp_db) as conn:
        row = conn.execute(
            "SELECT kind, agent_path FROM tunnel WHERE subnet = ?", ("10.2.0.0/24",)
        ).fetchone()
    assert row["kind"] == "ligolo"
    assert row["agent_path"] == "SVCMON_WIN"


def test_tool_pivot_os_hint_overrides_db(tmp_db: Path) -> None:
    """When the DB has no OS recorded, os_hint drives the pick."""
    with yhdb.transaction(tmp_db) as conn:
        eng = yhdb.upsert_engagement(conn, lab="m", scope="10.0.0.0/24")
        conn.execute(
            "INSERT INTO host (engagement_id, ip, os, stage, first_seen) "
            "VALUES (?, '10.0.0.42', NULL, 'looted', '2026-01-01T00:00:00Z')",
            (eng,),
        )
    out = tool_pivot(tmp_db, "m", "10.0.0.42", "10.3.0.0/24", os_hint="windows")
    assert "kind=ligolo" in out
    assert "agent=SVCMON_WIN" in out
