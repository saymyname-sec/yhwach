"""G2a — Nessus / OpenVAS XML into keyed vulnerability rows + promote pack.

yhwach parses the scanner export into typed rows (plugin id, port, CVSS,
solution, output excerpt) and promotes a few high-signal plugins to the chaining
tags recall already consumes. Qualys/Nexpose CSV are intentionally not parsed.
"""
from __future__ import annotations

from pathlib import Path

from yhwach import db as yhdb
from yhwach.mcp_tools import tool_interpret, tool_query
from yhwach.parsers.nessus import parse_nessus, parse_openvas, promote_tag

_NESSUS = (
    '<?xml version="1.0"?><NessusClientData_v2><Report name="r">'
    '<ReportHost name="10.0.0.5">'
    '<ReportItem port="445" protocol="tcp" severity="3" pluginID="57608" '
    'pluginName="SMB Signing not required"><cvss_base_score>5.0</cvss_base_score>'
    "<solution>Enforce SMB signing.</solution>"
    "<plugin_output>Signing not required</plugin_output></ReportItem>"
    '<ReportItem port="445" protocol="tcp" severity="4" pluginID="97833" '
    'pluginName="MS17-010"><cve>CVE-2017-0144</cve>'
    "<cvss_base_score>9.3</cvss_base_score></ReportItem>"
    '<ReportItem port="0" protocol="tcp" severity="0" pluginID="19506" '
    'pluginName="Nessus Scan Information"></ReportItem>'
    "</ReportHost></Report></NessusClientData_v2>"
)
_OPENVAS = (
    '<?xml version="1.0"?><report><results><result>'
    "<host>10.0.0.7</host><port>445/tcp</port><severity>9.8</severity>"
    '<nvt oid="1.3.6.1.4.1.25623.1.0.123"><name>MS17-010 SMB RCE (EternalBlue)</name>'
    "<cvss_base>9.8</cvss_base><solution>Patch.</solution>"
    '<refs><ref type="cve" id="CVE-2017-0144"/></refs></nvt>'
    "<description>Vulnerable to EternalBlue</description></result></results></report>"
)


# --- parsers ----------------------------------------------------------------


def test_parse_nessus_fields() -> None:
    vs = {v.plugin_id: v for v in parse_nessus(_NESSUS)}
    assert set(vs) == {"57608", "97833", "19506"}
    smb = vs["57608"]
    assert smb.host_ip == "10.0.0.5"
    assert smb.port == 445
    assert smb.cvss == 5.0
    assert smb.severity == "high"
    assert smb.solution == "Enforce SMB signing."
    assert vs["97833"].cves == ["CVE-2017-0144"]
    assert vs["19506"].port is None   # port 0 -> no port


def test_parse_openvas_fields() -> None:
    v = parse_openvas(_OPENVAS)[0]
    assert v.host_ip == "10.0.0.7"
    assert v.port == 445
    assert v.cvss == 9.8
    assert v.severity == "critical"
    assert v.cves == ["CVE-2017-0144"]


def test_promote_pack() -> None:
    nv = {v.plugin_id: v for v in parse_nessus(_NESSUS)}
    assert promote_tag(nv["57608"]) == "smb_signing_off"
    assert promote_tag(nv["97833"]) == "exploitable_cve"
    assert promote_tag(nv["19506"]) is None
    assert promote_tag(parse_openvas(_OPENVAS)[0]) == "exploitable_cve"


def test_bad_xml_is_empty_not_a_crash() -> None:
    assert parse_nessus("not xml") == []
    assert parse_openvas("<broken") == []


# --- ingest -----------------------------------------------------------------


def _eng(path: Path) -> int:
    with yhdb.transaction(path) as conn:
        return yhdb.upsert_engagement(conn, lab="L", scope="10.0.0.0/24")


def test_nessus_ingest_rows_and_promotes(tmp_db: Path) -> None:
    _eng(tmp_db)
    out = tool_interpret(tmp_db, "L", _NESSUS)
    assert "3 vulnerability row(s)" in out
    assert "2 promoted" in out
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.engagement_id_for(conn, "L")
        tags = sorted(r[0] for r in conn.execute(
            "SELECT tag FROM finding WHERE engagement_id=? AND tag IS NOT NULL", (eid,)))
    assert tags == ["exploitable_cve", "smb_signing_off"]


def test_nessus_ingest_creates_host_and_is_idempotent(tmp_db: Path) -> None:
    _eng(tmp_db)
    tool_interpret(tmp_db, "L", _NESSUS)
    tool_interpret(tmp_db, "L", _NESSUS)   # re-ingest
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.engagement_id_for(conn, "L")
        hosts = conn.execute("SELECT COUNT(*) n FROM host WHERE engagement_id=?", (eid,)).fetchone()["n"]
        vulns = conn.execute("SELECT COUNT(*) n FROM vulnerability WHERE engagement_id=?", (eid,)).fetchone()["n"]
        alive = conn.execute("SELECT alive FROM host WHERE ip='10.0.0.5'").fetchone()["alive"]
    assert hosts == 1
    assert vulns == 3          # no duplication on re-ingest
    assert alive == "alive"    # the scanner reached it


def test_vulns_view_exposes_plugin_and_solution(tmp_db: Path) -> None:
    _eng(tmp_db)
    tool_interpret(tmp_db, "L", _NESSUS)
    out = tool_query(tmp_db, "L", "vulns", fields=["plugin_id", "solution"])
    assert "57608" in out
    assert "Enforce SMB signing." in out
