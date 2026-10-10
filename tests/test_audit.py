"""The audit / methodology lens — coverage by standard + what wasn't checked."""
from __future__ import annotations

from pathlib import Path

from yhwach import db as yhdb
from yhwach.audit import _family, findings_by_standard, methodology_audit


def test_family_classifier() -> None:
    assert _family("T1649") == "ATT&CK"
    assert _family("T1078.002") == "ATT&CK"
    assert _family("LLM01") == "OWASP-LLM"
    assert _family("ATLAS-AML.T0051.001") == "ATLAS"
    assert _family("AML.T0051") == "ATLAS"
    assert _family("CWE-79") == "CWE"
    assert _family("CVE-2024-27198") == "CVE"
    assert _family("mystery") == "other"


def _host(conn, eid, ip, stage="foothold") -> int:
    return conn.execute(
        "INSERT INTO host (engagement_id, ip, stage, first_seen) VALUES (?, ?, ?, 't')",
        (eid, ip, stage),
    ).lastrowid


def test_findings_by_standard_buckets(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.upsert_engagement(conn, lab="a", scope="10.0.0.0/24")
        hid = _host(conn, eid, "10.0.0.5")
        for cls, title in [("T1649", "a"), ("T1078", "b"), ("LLM01", "c"),
                           ("CWE-79", "d"), ("CVE-2024-27198", "e")]:
            yhdb.add_finding(conn, host_id=hid, surface_id=None, cls=cls,
                             title=title, severity="high", evidence="x")
        fam = findings_by_standard(conn, eid)
    assert fam["ATT&CK"]["count"] == 2
    assert fam["ATT&CK"]["ids"] == ["T1078", "T1649"]
    assert fam["OWASP-LLM"]["count"] == 1
    assert "CWE" in fam and "CVE" in fam


def test_methodology_audit_renders_coverage_and_gaps(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.upsert_engagement(conn, lab="b", scope="10.0.0.0/24")
        hid = _host(conn, eid, "10.0.0.6", stage="scanned")
        # a redis surface with no triage -> a service_enum gap
        sid = conn.execute(
            "INSERT INTO service (host_id, port, proto, discovered_at) VALUES (?, 6379, 'tcp', 't')",
            (hid,),
        ).lastrowid
        yhdb.upsert_surface(conn, host_id=hid, service_id=sid, kind="redis",
                            auth="none", meta_json="{}")
        yhdb.add_finding(conn, host_id=hid, surface_id=None, cls="T1649",
                         title="adcs", severity="high", evidence="e")
        report = methodology_audit(conn, eid)
    assert "METHODOLOGY AUDIT" in report
    assert "Coverage by standard" in report and "ATT&CK" in report
    assert "not yet checked" in report and "service_enum" in report


# --- OWASP-LLM Top-10 methodology matrix ------------------------------------

def _ai_host(conn, eid, ip="10.0.0.9"):
    hid = _host(conn, eid, ip, stage="scanned")
    yhdb.upsert_surface(conn, hid, None, "chatbot", "none", "{}")
    return hid


def test_llm_coverage_unknown_without_ai_surface(tmp_db: Path) -> None:
    from yhwach.audit import llm_coverage

    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.upsert_engagement(conn, lab="a", scope="10.0.0.0/24")
        _host(conn, eid, "10.0.0.5")
        rows = llm_coverage(conn, eid)
    assert [r["id"] for r in rows] == [f"LLM{n:02d}" for n in range(1, 11)]
    assert all(r["status"] == "UNKNOWN" for r in rows)


def test_llm_coverage_absent_with_ai_surface(tmp_db: Path) -> None:
    from yhwach.audit import llm_coverage

    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.upsert_engagement(conn, lab="a", scope="10.0.0.0/24")
        _ai_host(conn, eid)
        statuses = {r["status"] for r in llm_coverage(conn, eid)}
    assert statuses == {"ABSENT"}   # surface exists, nothing tested yet


def test_llm_coverage_present_for_classified_findings(tmp_db: Path) -> None:
    from yhwach.audit import llm_coverage

    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.upsert_engagement(conn, lab="a", scope="10.0.0.0/24")
        hid = _ai_host(conn, eid)
        yhdb.add_finding(conn, host_id=hid, surface_id=None, cls="LLM07",
                         title="sysprompt", severity="high", evidence="x")
        yhdb.add_finding(conn, host_id=hid, surface_id=None, cls="LLM01",
                         title="inj", severity="high", evidence="x")
        rows = {r["id"]: r["status"] for r in llm_coverage(conn, eid)}
    assert rows["LLM01"] == "PRESENT" and rows["LLM07"] == "PRESENT"
    assert rows["LLM02"] == "ABSENT"    # surface exists but class untested


def test_methodology_audit_includes_llm_matrix_when_relevant(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.upsert_engagement(conn, lab="a", scope="10.0.0.0/24")
        hid = _ai_host(conn, eid)
        yhdb.add_finding(conn, host_id=hid, surface_id=None, cls="LLM07",
                         title="sp", severity="high", evidence="x")
        out = methodology_audit(conn, eid)
    assert "OWASP-LLM Top-10 coverage" in out
    assert "LLM07 System Prompt Leakage" in out


def test_methodology_audit_omits_llm_matrix_without_ai(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.upsert_engagement(conn, lab="a", scope="10.0.0.0/24")
        _host(conn, eid, "10.0.0.5")
        out = methodology_audit(conn, eid)
    assert "OWASP-LLM Top-10 coverage" not in out
