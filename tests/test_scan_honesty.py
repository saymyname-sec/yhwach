"""I44 — discovery-first scan honesty.

A ping/list scan touches no ports, so it must record NO port coverage (recording
top-1000 for a `-sn` sweep was the bug), confirm hosts as alive without advancing
the port-scan stage, and mark a ping miss 'unanswered' — never dead. A full
`-p-` pass settles the scan debt. These tests lock all of that.
"""
from __future__ import annotations

from pathlib import Path

from yhwach import db as yhdb
from yhwach.mcp_tools import tool_ingest, tool_query, tool_status
from yhwach.parsers.nmap import (
    _meta_from_args,
    insert_hosts,
    parse_nmap,
    parse_scan_meta,
)

_PING_XML = (
    '<?xml version="1.0"?><nmaprun args="nmap -sn 10.0.0.0/24">'
    '<host><status state="up"/><address addr="10.0.0.5" addrtype="ipv4"/></host>'
    '<host><status state="down"/><address addr="10.0.0.9" addrtype="ipv4"/></host>'
    "</nmaprun>"
)
_FULL_XML = (
    '<?xml version="1.0"?><nmaprun args="nmap -p- -sV 10.0.0.5">'
    '<scaninfo protocol="tcp" services="1-65535" numservices="65535"/>'
    '<host><status state="up"/><address addr="10.0.0.5" addrtype="ipv4"/>'
    '<ports><port protocol="tcp" portid="445"><state state="open"/></port></ports>'
    "</host></nmaprun>"
)


# --- the bug: a ping scan records no coverage --------------------------------


def test_ping_scan_records_no_coverage_from_args() -> None:
    m = _meta_from_args("nmap -sn 10.0.0.0/24")
    assert m.ping_only is True
    assert m.coverage == []


def test_list_scan_is_also_ping_only() -> None:
    assert _meta_from_args("nmap -sL 10.0.0.0/24").coverage == []


def test_ping_scan_xml_records_no_coverage_and_captures_down() -> None:
    m = parse_scan_meta(_PING_XML)
    assert m.ping_only is True
    assert m.coverage == []
    assert m.down_ips == ["10.0.0.9"]


def test_real_port_scan_still_derives_coverage() -> None:
    m = _meta_from_args("nmap -p- -sV 10.0.0.5")
    assert m.ping_only is False
    assert m.coverage and m.coverage[0].full_range is True
    assert m.version_scan is True


# --- ingest: alive tri-state, no false stage, scan_needed --------------------


def _eng(path: Path) -> int:
    with yhdb.transaction(path) as conn:
        return yhdb.upsert_engagement(conn, lab="L", scope="10.0.0.0/24")


def test_ping_sweep_confirms_alive_without_advancing_stage(tmp_db: Path) -> None:
    eid = _eng(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        insert_hosts(conn, eid, parse_nmap(_PING_XML), parse_scan_meta(_PING_XML))
        row = conn.execute(
            "SELECT stage, alive, scan_needed FROM host WHERE ip='10.0.0.5'").fetchone()
        cov = conn.execute("SELECT COUNT(*) n FROM scan_coverage").fetchone()["n"]
    assert row["alive"] == "alive"
    assert row["stage"] == "undiscovered"   # pinged, not port-scanned
    assert row["scan_needed"] == 1          # still owes a scan
    assert cov == 0                         # THE BUG: no coverage from a ping sweep


def test_down_host_is_unanswered_not_dead(tmp_db: Path) -> None:
    eid = _eng(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        conn.execute("INSERT INTO host (engagement_id, ip, stage, discovery_source, first_seen) "
                     "VALUES (?, '10.0.0.9', 'undiscovered', 'scope', 't')", (eid,))
        insert_hosts(conn, eid, parse_nmap(_PING_XML), parse_scan_meta(_PING_XML))
        alive = conn.execute("SELECT alive FROM host WHERE ip='10.0.0.9'").fetchone()["alive"]
    assert alive == "unanswered"


def test_down_host_never_created_as_a_row(tmp_db: Path) -> None:
    # a down IP not already tracked must NOT manufacture a host row (/24 noise).
    eid = _eng(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        insert_hosts(conn, eid, parse_nmap(_PING_XML), parse_scan_meta(_PING_XML))
        exists = conn.execute("SELECT COUNT(*) n FROM host WHERE ip='10.0.0.9'").fetchone()["n"]
    assert exists == 0


def test_full_scan_via_ingest_clears_scan_needed(tmp_db: Path, tmp_path: Path) -> None:
    # The clear lives on the out-of-band ingest path (the scanner clears its own
    # quick/full runs by mode); a hand-ingested -p- file settles the debt.
    eid = _eng(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        insert_hosts(conn, eid, parse_nmap(_PING_XML), parse_scan_meta(_PING_XML))
    f = tmp_path / "full.xml"
    f.write_text(_FULL_XML, encoding="utf-8")
    tool_ingest(tmp_db, "L", str(f), kind="nmap")
    with yhdb.transaction(tmp_db) as conn:
        row = conn.execute(
            "SELECT stage, alive, scan_needed FROM host WHERE ip='10.0.0.5'").fetchone()
    assert row["stage"] == "scanned"
    assert row["alive"] == "alive"
    assert row["scan_needed"] == 0


def test_udp_full_via_ingest_does_not_clear_scan_needed(tmp_db: Path, tmp_path: Path) -> None:
    # UDP coverage is additive — even a full UDP range must not settle the
    # TCP-scan debt (the regression the scanner test guards, now on the ingest path).
    eid = _eng(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        insert_hosts(conn, eid, parse_nmap(_PING_XML), parse_scan_meta(_PING_XML))
    udp = ('<?xml version="1.0"?><nmaprun args="nmap -sU -p- 10.0.0.5">'
           '<scaninfo protocol="udp" services="1-65535" numservices="65535"/>'
           '<host><status state="up"/><address addr="10.0.0.5" addrtype="ipv4"/></host>'
           "</nmaprun>")
    f = tmp_path / "udp.xml"
    f.write_text(udp, encoding="utf-8")
    tool_ingest(tmp_db, "L", str(f), kind="nmap")
    with yhdb.transaction(tmp_db) as conn:
        sn = conn.execute("SELECT scan_needed FROM host WHERE ip='10.0.0.5'").fetchone()["scan_needed"]
    assert sn == 1


def test_alive_confirmed_not_downgraded_by_later_ping_miss(tmp_db: Path) -> None:
    eid = _eng(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        insert_hosts(conn, eid, parse_nmap(_FULL_XML), parse_scan_meta(_FULL_XML))
        # a later sweep that reports 10.0.0.5 down must NOT flip it to unanswered
        down = ('<?xml version="1.0"?><nmaprun args="nmap -sn 10.0.0.5">'
                '<host><status state="down"/><address addr="10.0.0.5" addrtype="ipv4"/></host>'
                "</nmaprun>")
        insert_hosts(conn, eid, parse_nmap(down), parse_scan_meta(down))
        alive = conn.execute("SELECT alive FROM host WHERE ip='10.0.0.5'").fetchone()["alive"]
    assert alive == "alive"


# --- surfaces: counts + view ------------------------------------------------


def test_status_shows_reach_counts(tmp_db: Path) -> None:
    eid = _eng(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        conn.execute("INSERT INTO host (engagement_id, ip, stage, discovery_source, first_seen) "
                     "VALUES (?, '10.0.0.9', 'undiscovered', 'scope', 't')", (eid,))
        conn.execute("INSERT INTO host (engagement_id, ip, stage, discovery_source, first_seen) "
                     "VALUES (?, '10.0.0.50', 'undiscovered', 'scope', 't')", (eid,))
        insert_hosts(conn, eid, parse_nmap(_PING_XML), parse_scan_meta(_PING_XML))
    out = tool_status(tmp_db, "L")
    assert "reach:" in out
    assert "alive=1" in out
    assert "unanswered=1" in out
    assert "unseen=1" in out   # 10.0.0.50 never confirmed


def test_hosts_view_exposes_alive(tmp_db: Path) -> None:
    eid = _eng(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        conn.execute("INSERT INTO host (engagement_id, ip, stage, discovery_source, first_seen) "
                     "VALUES (?, '10.0.0.50', 'undiscovered', 'scope', 't')", (eid,))
        insert_hosts(conn, eid, parse_nmap(_PING_XML), parse_scan_meta(_PING_XML))
    out = tool_query(tmp_db, "L", "hosts", fields=["ip", "alive"])
    assert "alive" in out
    assert "unseen" in out   # the scope-only host defaults to unseen
