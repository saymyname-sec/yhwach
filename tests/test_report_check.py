"""I13 — `report --check` readiness gate.

Blocks a write-up that is not reproducible: a proven finding with no evidence, a
PoC step with a $VAR/TODO placeholder, a secret inline in evidence, an
uncommunicated critical, or outstanding cleanup artefacts. CVSS/remediation are
intentionally NOT checked (report generation is out of scope).
"""
from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from yhwach import db as yhdb
from yhwach import poc
from yhwach.cli import main
from yhwach.mcp_tools import tool_report_check
from yhwach.report import report_check


def _eng(path: Path) -> int:
    with yhdb.transaction(path) as conn:
        return yhdb.upsert_engagement(conn, lab="L", scope="10.0.0.0/24")


def _levels(path: Path) -> list[str]:
    with yhdb.transaction(path) as conn:
        eid = yhdb.engagement_id_for(conn, "L")
        return [m for lvl, m in report_check(conn, eid) if lvl == "fail"]


def test_clean_engagement_is_ready(tmp_db: Path) -> None:
    _eng(tmp_db)
    assert "report-ready" in tool_report_check(tmp_db, "L")
    assert _levels(tmp_db) == []


def test_proven_finding_without_evidence_fails(tmp_db: Path) -> None:
    eid = _eng(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        fid, _ = yhdb.add_finding(conn, None, None, "idor", "IDOR", "high", "x",
                                  engagement_id=eid)
        yhdb.set_finding(conn, fid, status="confirmed")
    fails = _levels(tmp_db)
    assert any("no evidence" in f for f in fails)


def test_evidence_clears_the_no_evidence_fail(tmp_db: Path) -> None:
    eid = _eng(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        fid, _ = yhdb.add_finding(conn, None, None, "idor", "IDOR", "high", "x",
                                  engagement_id=eid)
        yhdb.set_finding(conn, fid, status="confirmed")
        yhdb.add_evidence(conn, eid, kind="output", text="proof output", finding_id=fid)
    assert not any("no evidence" in f for f in _levels(tmp_db))


def test_open_lead_without_evidence_does_not_fail(tmp_db: Path) -> None:
    # Only PROVEN findings (confirmed/exploited) need evidence; an open lead doesn't.
    eid = _eng(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        yhdb.add_finding(conn, None, None, "idor", "lead", "medium", "x", engagement_id=eid)
    assert not any("no evidence" in f for f in _levels(tmp_db))


def test_placeholder_in_poc_step_fails(tmp_db: Path) -> None:
    eid = _eng(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        poc.add_step(conn, eid, objective="chain", title="x",
                     command="curl http://$TARGET/a", output="TODO")
    assert any("placeholder" in f for f in _levels(tmp_db))


def test_uncommunicated_critical_fails(tmp_db: Path) -> None:
    eid = _eng(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        yhdb.add_finding(conn, None, None, "rce", "RCE", "critical", "x", engagement_id=eid)
    assert any("not communicated" in f for f in _levels(tmp_db))


def test_inline_secret_in_evidence_fails(tmp_db: Path) -> None:
    eid = _eng(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        fid, _ = yhdb.add_finding(conn, None, None, "cred", "leak", "high", "x",
                                  engagement_id=eid)
        yhdb.set_finding(conn, fid, status="confirmed")
        yhdb.add_evidence(conn, eid, kind="output", text="password=hunter2",
                          finding_id=fid, contains_secret=True)
    assert any("holds a secret" in f for f in _levels(tmp_db))


def test_cli_check_exits_nonzero_on_fail(tmp_db: Path) -> None:
    eid = _eng(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        yhdb.add_finding(conn, None, None, "rce", "RCE", "critical", "x", engagement_id=eid)
    r = CliRunner().invoke(main, ["report", "--lab", "L", "--check", "--db", str(tmp_db)])
    assert r.exit_code == 1
    assert "FAIL" in r.output


def test_cli_check_exits_zero_when_clean(tmp_db: Path) -> None:
    _eng(tmp_db)
    r = CliRunner().invoke(main, ["report", "--lab", "L", "--check", "--db", str(tmp_db)])
    assert r.exit_code == 0
    assert "report-ready" in r.output
