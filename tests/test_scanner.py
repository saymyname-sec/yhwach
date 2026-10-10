"""Tests for yhwach.scanner — auto full-scan.

Regression: wiki01:8001 (a RAG import API on a non-default port) sat
undiscovered because the operator only ran a targeted top-1000 sweep across
the /24 and never followed up with per-host ``-p-``. Now every
scope-materialised host lands with ``scan_needed=1`` and ``yhwach_scan``
walks the queue automatically, ingesting each result through the same
pipeline as ``yhwach_ingest kind=nmap`` so downstream hooks (sprayer's
new-service handler in PR-3) fire naturally.

Nmap is patched out — these tests exercise the queue logic, mode dispatch,
scan_needed clearing, and the tool_scan facade. Live nmap behaviour is an
integration concern.
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from yhwach import db as yhdb
from yhwach import scanner as yhscan
from yhwach.mcp_tools import tool_engage, tool_gaps, tool_scan

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


# A minimal, well-formed nmap XML with one host + one service. The scanner
# writes this to disk (via a patched subprocess) so the real parser code
# path runs and inserts a service row.
_SAMPLE_XML = """<?xml version="1.0"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV -sC -p- {ip}" start="1790000000" version="7.99">
  <scaninfo type="connect" protocol="tcp" numservices="65535" services="1-65535"/>
  <host starttime="1790000000" endtime="1790000005">
    <status state="up" reason="user-set"/>
    <address addr="{ip}" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="8001">
        <state state="open" reason="syn-ack" reason_ttl="64"/>
        <service name="http" product="retrieval-api" method="probed" conf="10"/>
      </port>
    </ports>
    <times srtt="1000" rttvar="500" to="100000"/>
  </host>
  <runstats>
    <finished time="1790000005" timestr="scan finished" elapsed="5"/>
  </runstats>
</nmaprun>
"""


def _fake_nmap(xml_body: str = _SAMPLE_XML):
    """Return a fake subprocess.run that writes ``xml_body`` to the -oX path.

    Mirrors nmap's real contract: write to -oX, exit 0. The scanner then
    reads the file back and hands it to the parser.
    """
    def runner(cmd, *args, **kwargs):
        out_path = None
        for i, tok in enumerate(cmd):
            if tok == "-oX" and i + 1 < len(cmd):
                out_path = Path(cmd[i + 1])
                break
        if out_path is None:
            raise AssertionError(f"nmap invocation missing -oX in {cmd!r}")
        # Body carries the target IP so tests can pin attribution.
        target = cmd[-1]
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(xml_body.replace("{ip}", target))

        class _Proc:
            returncode = 0
            stdout = ""
            stderr = ""
        return _Proc()
    return runner


# ---------------------------------------------------------------------------
# scanner core
# ---------------------------------------------------------------------------


def test_scan_host_full_ingests_and_clears_scan_needed(tmp_db: Path, tmp_path: Path) -> None:
    """The unhappy path made real: a scope host lands undiscovered with
    scan_needed=1; after scan_host it has services + scan_needed=0."""
    tool_engage(tmp_db, "sc", "10.5.5.0/29")
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.engagement_id_for(conn, "sc")
        before = conn.execute(
            "SELECT scan_needed FROM host WHERE engagement_id=? AND ip=?",
            (eid, "10.5.5.1"),
        ).fetchone()
    assert before["scan_needed"] == 1

    with patch("yhwach.scanner.subprocess.run", side_effect=_fake_nmap()):
        with patch("yhwach.scanner.shutil.which", return_value="/usr/bin/nmap"):
            with yhdb.transaction(tmp_db) as conn:
                eid = yhdb.engagement_id_for(conn, "sc")
                res = yhscan.scan_host(
                    conn, eid, "10.5.5.1", mode="full", output_dir=tmp_path,
                )

    assert res.success
    assert res.hosts_ingested == 1
    assert res.services_ingested == 1
    assert res.output_path is not None and res.output_path.exists()
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.engagement_id_for(conn, "sc")
        after = conn.execute(
            "SELECT scan_needed, stage FROM host WHERE engagement_id=? AND ip=?",
            (eid, "10.5.5.1"),
        ).fetchone()
        svc = conn.execute(
            "SELECT port, product FROM service s "
            "JOIN host h ON h.id=s.host_id "
            "WHERE h.engagement_id=? AND h.ip=?", (eid, "10.5.5.1"),
        ).fetchone()
    assert after["scan_needed"] == 0
    assert after["stage"] == "scanned"
    assert svc["port"] == 8001
    assert svc["product"] == "retrieval-api"


def test_scan_host_udp_does_not_clear_flag(tmp_db: Path, tmp_path: Path) -> None:
    """UDP is additive coverage — it doesn't fulfil the 'first TCP scan owed'
    promise, so scan_needed stays 1 until a quick/full runs."""
    tool_engage(tmp_db, "sc", "10.5.5.0/29")
    with patch("yhwach.scanner.subprocess.run", side_effect=_fake_nmap()):
        with patch("yhwach.scanner.shutil.which", return_value="/usr/bin/nmap"):
            with yhdb.transaction(tmp_db) as conn:
                eid = yhdb.engagement_id_for(conn, "sc")
                yhscan.scan_host(
                    conn, eid, "10.5.5.1", mode="udp", output_dir=tmp_path,
                )
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.engagement_id_for(conn, "sc")
        after = conn.execute(
            "SELECT scan_needed FROM host WHERE engagement_id=? AND ip=?",
            (eid, "10.5.5.1"),
        ).fetchone()
    assert after["scan_needed"] == 1


def test_scan_host_returns_failure_on_timeout(tmp_db: Path, tmp_path: Path) -> None:
    tool_engage(tmp_db, "sc", "10.5.5.0/29")
    import subprocess

    def timeout_run(*a, **kw):
        raise subprocess.TimeoutExpired(cmd=a[0], timeout=1)

    with patch("yhwach.scanner.shutil.which", return_value="/usr/bin/nmap"):
        with patch("yhwach.scanner.subprocess.run", side_effect=timeout_run):
            with yhdb.transaction(tmp_db) as conn:
                eid = yhdb.engagement_id_for(conn, "sc")
                res = yhscan.scan_host(
                    conn, eid, "10.5.5.1", mode="quick", output_dir=tmp_path,
                )
    assert not res.success
    assert "timeout" in res.detail
    # scan_needed stays 1 so the operator can retry the host.
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.engagement_id_for(conn, "sc")
        row = conn.execute(
            "SELECT scan_needed FROM host WHERE engagement_id=? AND ip=?",
            (eid, "10.5.5.1"),
        ).fetchone()
    assert row["scan_needed"] == 1


def test_scan_host_unknown_mode_raises(tmp_db: Path, tmp_path: Path) -> None:
    import pytest

    tool_engage(tmp_db, "sc", "10.5.5.0/29")
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.engagement_id_for(conn, "sc")
        with pytest.raises(ValueError):
            yhscan.scan_host(conn, eid, "10.5.5.1", mode="paranoid", output_dir=tmp_path)


def test_scan_host_missing_nmap_raises(tmp_db: Path, tmp_path: Path) -> None:
    import pytest

    tool_engage(tmp_db, "sc", "10.5.5.0/29")
    with patch("yhwach.scanner.shutil.which", return_value=None):
        with yhdb.transaction(tmp_db) as conn:
            eid = yhdb.engagement_id_for(conn, "sc")
            with pytest.raises(RuntimeError, match="nmap"):
                yhscan.scan_host(conn, eid, "10.5.5.1", mode="full", output_dir=tmp_path)


# ---------------------------------------------------------------------------
# Queue helpers
# ---------------------------------------------------------------------------


def test_pending_hosts_lists_only_scan_needed_true(tmp_db: Path) -> None:
    tool_engage(tmp_db, "sc", "10.5.5.0/29")
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.engagement_id_for(conn, "sc")
        # Clear scan_needed on one host to simulate a completed scan.
        conn.execute(
            "UPDATE host SET scan_needed=0 WHERE engagement_id=? AND ip=?",
            (eid, "10.5.5.1"),
        )
        pending = yhscan.pending_hosts(conn, eid)
    assert "10.5.5.1" not in pending
    assert "10.5.5.2" in pending
    assert len(pending) == 5  # 6 hosts in /29 minus the one cleared


def test_scan_pending_walks_queue_up_to_limit(tmp_db: Path, tmp_path: Path) -> None:
    """max_hosts=2 -> only 2 nmap invocations even though 6 are pending."""
    tool_engage(tmp_db, "sc", "10.5.5.0/29")

    called = {"n": 0}

    def counted_nmap(cmd, *a, **kw):
        called["n"] += 1
        return _fake_nmap()(cmd, *a, **kw)

    with patch("yhwach.scanner.shutil.which", return_value="/usr/bin/nmap"):
        with patch("yhwach.scanner.subprocess.run", side_effect=counted_nmap):
            with yhdb.transaction(tmp_db) as conn:
                eid = yhdb.engagement_id_for(conn, "sc")
                results = yhscan.scan_pending(
                    conn, eid, max_hosts=2, mode="full", output_dir=tmp_path,
                )
    assert called["n"] == 2
    assert len(results) == 2
    assert all(r.success for r in results)


# ---------------------------------------------------------------------------
# tool_scan facade + tool_gaps integration
# ---------------------------------------------------------------------------


def test_tool_scan_pending_drains_batch(tmp_db: Path, tmp_path: Path) -> None:
    tool_engage(tmp_db, "sc", "10.5.5.0/29")
    with patch("yhwach.scanner._RECON_DIR", tmp_path):
        with patch("yhwach.scanner.shutil.which", return_value="/usr/bin/nmap"):
            with patch("yhwach.scanner.subprocess.run", side_effect=_fake_nmap()):
                out = tool_scan(tmp_db, "sc", max_hosts=3, mode="full")
    assert "scan full: 3 host(s)" in out
    assert out.count("[OK ]") == 3


def test_tool_scan_empty_queue(tmp_db: Path, tmp_path: Path) -> None:
    tool_engage(tmp_db, "sc", "10.5.5.0/29")
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.engagement_id_for(conn, "sc")
        conn.execute("UPDATE host SET scan_needed=0 WHERE engagement_id=?", (eid,))
    out = tool_scan(tmp_db, "sc", mode="full")
    assert "nothing pending" in out


def test_tool_scan_explicit_host_runs_even_if_flag_cleared(tmp_db: Path, tmp_path: Path) -> None:
    """Explicit host= is operator intent — run even with scan_needed=0."""
    tool_engage(tmp_db, "sc", "10.5.5.0/29")
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.engagement_id_for(conn, "sc")
        conn.execute(
            "UPDATE host SET scan_needed=0 WHERE engagement_id=? AND ip=?",
            (eid, "10.5.5.1"),
        )
    with patch("yhwach.scanner._RECON_DIR", tmp_path):
        with patch("yhwach.scanner.shutil.which", return_value="/usr/bin/nmap"):
            with patch("yhwach.scanner.subprocess.run", side_effect=_fake_nmap()):
                out = tool_scan(tmp_db, "sc", host="10.5.5.1", mode="full")
    assert "scan full: 1 host(s)" in out
    assert "[OK ]" in out
    assert "10.5.5.1" in out


def test_tool_gaps_reports_pending_scan_count(tmp_db: Path) -> None:
    """The 'why the UI shows 254 undiscovered' answer: pending scan count in the header."""
    tool_engage(tmp_db, "sc", "10.5.5.0/29")
    out = tool_gaps(tmp_db, "sc")
    assert "pending scan" in out
    assert "yhwach_scan --pending" in out
