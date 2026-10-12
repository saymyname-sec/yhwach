"""Phase 3 — engagement-memory ledgers (schema v4).

Four typed logs an operator pulls from at write-up time. Memory only: nothing
here scores or renders a report. These tests lock each ledger plus the two
auto-population wirings (sprayer -> activity, pivot -> artifact) and the two
advisory/QA rules (uncommunicated criticals, duplicate-risk).
"""
from __future__ import annotations

from pathlib import Path

import pytest

from yhwach import db as yhdb
from yhwach import sprayer
from yhwach.mcp_tools import (
    tool_artifact,
    tool_log,
    tool_notice,
    tool_pivot,
    tool_query,
    tool_submission,
)


def _eng(path: Path, **kw) -> int:
    with yhdb.transaction(path) as conn:
        return yhdb.upsert_engagement(conn, lab="L", scope="10.0.0.0/24", **kw)


def _host(path: Path, eid: int, ip: str = "10.0.0.5", os: str = "linux",
          stage: str = "scanned") -> int:
    with yhdb.transaction(path) as conn:
        cur = conn.execute(
            "INSERT INTO host (engagement_id, ip, os, stage, first_seen) "
            "VALUES (?, ?, ?, ?, '2026-01-01T00:00:00Z')", (eid, ip, os, stage))
        return int(cur.lastrowid)


# --- schema -----------------------------------------------------------------


def test_v4_tables_exist_and_version_stamped(tmp_db: Path) -> None:
    import sqlite3

    raw = sqlite3.connect(str(tmp_db))
    try:
        tables = {r[0] for r in
                  raw.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert {"notice", "activity", "artifact", "submission"} <= tables
        assert raw.execute("PRAGMA user_version").fetchone()[0] == yhdb.SCHEMA_VERSION
    finally:
        raw.close()


# --- G4a notice -------------------------------------------------------------


def test_notice_add_list_and_critical_qa(tmp_db: Path) -> None:
    eid = _eng(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        fid, _ = yhdb.add_finding(conn, None, None, "rce", "RCE on web", "critical",
                                  "proof", engagement_id=eid)
    # a live critical with no notification is flagged
    out = tool_notice(tmp_db, "L")
    assert "not yet notified" in out
    # record the notification -> flag clears
    rec = tool_notice(tmp_db, "L", body="phoned the client", kind="critical_notification",
                      finding=fid, channel="call")
    assert "recorded notice" in rec
    assert "not yet notified" not in tool_notice(tmp_db, "L")


def test_notice_rejects_unknown_kind(tmp_db: Path) -> None:
    _eng(tmp_db)
    out = tool_notice(tmp_db, "L", body="x", kind="nonsense")
    assert "unknown notice kind" in out


# --- I05 activity -----------------------------------------------------------


def test_redact_argv_masks_secret_flags() -> None:
    assert yhdb.redact_argv("nxc smb h -u a -p Secret --shares") == \
        "nxc smb h -u a -p *** --shares"
    assert yhdb.redact_argv("nxc smb h -u a -pSecret") == "nxc smb h -u a -p***"
    assert yhdb.redact_argv("tool --password=Secret --x y") == "tool --password=*** --x y"
    assert yhdb.redact_argv("nxc smb h -H deadbeef") == "nxc smb h -H ***"
    assert yhdb.redact_argv(None) is None


def test_tool_log_records_redacted_activity(tmp_db: Path) -> None:
    eid = _eng(tmp_db)
    _host(tmp_db, eid)
    tool_log(tmp_db, "L", "command", command="nxc smb 10.0.0.5 -u a -p Sekret --shares",
             host="10.0.0.5")
    with yhdb.transaction(tmp_db) as conn:
        rows = yhdb.list_activity(conn, eid)
    assert len(rows) == 1
    assert rows[0]["actor"] == "model"
    assert "Sekret" not in rows[0]["command"]
    assert "-p ***" in rows[0]["command"]


def test_add_activity_rejects_unknown_actor(tmp_db: Path) -> None:
    eid = _eng(tmp_db)
    with yhdb.transaction(tmp_db) as conn, pytest.raises(ValueError, match="unknown actor"):
        yhdb.add_activity(conn, eid, actor="intruder", action="x")


def test_spray_logs_one_summary_row_and_dry_run_logs_nothing(tmp_db: Path) -> None:
    eid = _eng(tmp_db)
    hid = _host(tmp_db, eid)
    with yhdb.transaction(tmp_db) as conn:
        conn.execute("INSERT INTO service (host_id, port, proto, product, discovered_at) "
                     "VALUES (?, 22, 'tcp', 'ssh', '2026-01-01T00:00:00Z')", (hid,))
        yhdb.add_credential(conn, eid, "root", "toor", "password", "dump")
        sprayer.spray_all(conn, eid, dry_run=True)
        assert yhdb.list_activity(conn, eid) == []
        sprayer.spray_all(conn, eid)
        rows = yhdb.list_activity(conn, eid)
    assert len(rows) == 1
    assert rows[0]["action"] == "spray"
    assert rows[0]["actor"] == "yhwach"


# --- I39 artifact -----------------------------------------------------------


def test_artifact_add_outstanding_and_remove(tmp_db: Path) -> None:
    _eng(tmp_db)
    add = tool_artifact(tmp_db, "L", location="/tmp/sh", kind="webshell")
    assert "recorded artifact #1" in add
    assert "not confirmed removed" in tool_artifact(tmp_db, "L")
    rm = tool_artifact(tmp_db, "L", remove=1)
    assert "marked removed" in rm
    assert "not confirmed removed" not in tool_artifact(tmp_db, "L")


def test_pivot_records_client_agent_once_not_the_proxy(tmp_db: Path) -> None:
    eid = _eng(tmp_db)
    _host(tmp_db, eid, os="linux", stage="looted")
    tool_pivot(tmp_db, "L", "10.0.0.5", "10.0.1.0/24")
    with yhdb.transaction(tmp_db) as conn:
        arts = yhdb.list_artifacts(conn, eid)
    assert len(arts) == 1
    assert arts[0]["kind"] == "tunnel_agent"
    assert arts[0]["state"] == "rendered"
    assert "10.0.0.5" in arts[0]["location"]
    # re-rendering the same tunnel must not duplicate the artefact
    tool_pivot(tmp_db, "L", "10.0.0.5", "10.0.1.0/24")
    with yhdb.transaction(tmp_db) as conn:
        assert len(yhdb.list_artifacts(conn, eid)) == 1


# --- I20 submission ---------------------------------------------------------


def test_submission_add_and_duplicate_risk(tmp_db: Path) -> None:
    _eng(tmp_db)
    first = tool_submission(tmp_db, "L", program="acme", endpoint="/api/u",
                            param="id", cls="idor")
    assert "recorded submission" in first
    assert "~" not in first  # nothing prior -> no advisory
    second = tool_submission(tmp_db, "L", program="acme", endpoint="/api/u",
                             param="id", cls="idor")
    assert "likely duplicate" in second
    assert "program noise" in second


def test_submission_list(tmp_db: Path) -> None:
    _eng(tmp_db)
    tool_submission(tmp_db, "L", program="acme", endpoint="/x")
    out = tool_submission(tmp_db, "L")
    assert "#1" in out and "acme" in out


# --- query views ------------------------------------------------------------


def test_ledger_views_queryable(tmp_db: Path) -> None:
    eid = _eng(tmp_db)
    _host(tmp_db, eid)
    tool_log(tmp_db, "L", "command", command="nxc smb 10.0.0.5 -p Sekret", host="10.0.0.5")
    tool_notice(tmp_db, "L", body="update", kind="status_update")
    tool_artifact(tmp_db, "L", location="/tmp/x", kind="file")
    tool_submission(tmp_db, "L", program="acme", endpoint="/x")
    assert "command" in tool_query(tmp_db, "L", "activity")
    assert "Sekret" not in tool_query(tmp_db, "L", "activity")  # redacted at write
    assert "status_update" in tool_query(tmp_db, "L", "notices")
    assert "/tmp/x" in tool_query(tmp_db, "L", "artifacts")
    assert "acme" in tool_query(tmp_db, "L", "submissions")
