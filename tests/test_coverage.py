"""Tests for scan-coverage recording and the enumeration-gap verdict.

The point of this layer: the world model must be able to tell a `-p 1-1000`
scan from a `-p-` scan. Everything else (the `gaps` command, the handoff
warning, the advance advisory) is a view over that.
"""
from __future__ import annotations

from pathlib import Path

from yhwach import db as yhdb
from yhwach.coverage import enum_gaps, gaps_as_dicts, render_gaps
from yhwach.parsers.nmap import insert_hosts, parse_nmap, parse_scan_meta

_XML_FULL = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -p- -sV -oX - 10.0.0.5" start="1">
  <scaninfo type="syn" protocol="tcp" numservices="65535" services="1-65535"/>
  <host><status state="up"/><address addr="10.0.0.5" addrtype="ipv4"/>
    <ports><port protocol="tcp" portid="11434"><state state="open"/>
      <service name="http" product="Ollama" method="probed"/></port></ports>
  </host>
</nmaprun>
"""

_XML_NARROW = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -p 1-1000 -oX - 10.0.0.9" start="1">
  <scaninfo type="syn" protocol="tcp" numservices="1000" services="1-1000"/>
  <host><status state="up"/><address addr="10.0.0.9" addrtype="ipv4"/>
    <ports><port protocol="tcp" portid="80"><state state="open"/>
      <service name="http" method="table"/></port></ports>
  </host>
</nmaprun>
"""

_NORMAL_UDP = """# Nmap 7.94 scan initiated Tue Sep 17 10:00:00 2026 as: nmap -sU --top-ports 100 -oN u.txt 10.0.0.5
Nmap scan report for 10.0.0.5
PORT    STATE SERVICE
161/udp open  snmp
"""


# --- parsing ----------------------------------------------------------------

def test_scaninfo_gives_full_range_and_version_scan() -> None:
    meta = parse_scan_meta(_XML_FULL)
    assert meta.version_scan is True
    assert len(meta.coverage) == 1
    cov = meta.coverage[0]
    assert (cov.proto, cov.port_count, cov.full_range) == ("tcp", 65535, True)


def test_narrow_scan_is_not_full_range() -> None:
    meta = parse_scan_meta(_XML_NARROW)
    assert meta.version_scan is False
    assert meta.coverage[0].full_range is False
    assert meta.coverage[0].port_count == 1000


def test_probed_service_proves_version_scan_without_args() -> None:
    xml = _XML_FULL.replace('args="nmap -p- -sV -oX - 10.0.0.5" ', "")
    assert parse_scan_meta(xml).version_scan is True


def test_normal_output_args_drive_coverage() -> None:
    meta = parse_scan_meta(_NORMAL_UDP)
    assert meta.coverage[0].proto == "udp"
    assert meta.coverage[0].ports == "top-100"
    assert meta.version_scan is False


def test_unparseable_text_yields_empty_meta() -> None:
    meta = parse_scan_meta("not an nmap file at all")
    assert meta.coverage == [] and meta.args is None


# --- recording + verdict ----------------------------------------------------

def _ingest(tmp_db: Path, eid: int, text: str) -> None:
    with yhdb.transaction(tmp_db) as conn:
        insert_hosts(conn, eid, parse_nmap(text), parse_scan_meta(text))


def _engage(tmp_db: Path) -> int:
    with yhdb.transaction(tmp_db) as conn:
        return yhdb.upsert_engagement(conn, lab="cov", scope="10.0.0.0/24")


def test_full_scan_plus_udp_sweep_leaves_no_gaps(tmp_db: Path) -> None:
    eid = _engage(tmp_db)
    _ingest(tmp_db, eid, _XML_FULL)
    _ingest(tmp_db, eid, _NORMAL_UDP)
    with yhdb.transaction(tmp_db) as conn:
        assert enum_gaps(conn, eid) == []
        complete = enum_gaps(conn, eid, include_complete=True)
    assert len(complete) == 1 and complete[0].complete
    assert complete[0].tcp_full and complete[0].tcp_version
    assert complete[0].udp_ports == 100


def test_narrow_scan_reports_every_missing_piece(tmp_db: Path) -> None:
    eid = _engage(tmp_db)
    _ingest(tmp_db, eid, _XML_NARROW)
    with yhdb.transaction(tmp_db) as conn:
        gaps = enum_gaps(conn, eid)
    assert len(gaps) == 1
    kinds = {g.kind for g in gaps[0].gaps}
    assert kinds == {"full_tcp", "version", "udp"}
    # Every gap names the command that closes it.
    assert all(g.fix.startswith(("nmap", "sudo nmap")) for g in gaps[0].gaps)
    assert "10.0.0.9" in "\n".join(render_gaps(gaps))


def test_host_with_no_coverage_rows_is_the_loudest_gap(tmp_db: Path) -> None:
    eid = _engage(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        conn.execute("INSERT INTO host (engagement_id, ip, stage, first_seen) "
                     "VALUES (?, '10.0.0.77', 'scanned', 't')", (eid,))
        gaps = enum_gaps(conn, eid)
    assert [g.kind for g in gaps[0].gaps] == ["none"]
    assert "no scan coverage recorded" in gaps[0].summary


def test_coverage_never_regresses_and_dedupes(tmp_db: Path) -> None:
    eid = _engage(tmp_db)
    no_version = _XML_FULL.replace(' method="probed"', "").replace("-sV ", "")
    _ingest(tmp_db, eid, no_version)
    with yhdb.transaction(tmp_db) as conn:
        assert {g.kind for g in enum_gaps(conn, eid)[0].gaps} == {"version", "udp"}
    _ingest(tmp_db, eid, _XML_FULL)          # same range, now with -sV
    with yhdb.transaction(tmp_db) as conn:
        assert {g.kind for g in enum_gaps(conn, eid)[0].gaps} == {"udp"}
        rows = yhdb.coverage_for_engagement(conn, eid)
    assert len(rows) == 1  # deduped on (host, proto, ports)


def test_host_filter_and_json_shape(tmp_db: Path) -> None:
    eid = _engage(tmp_db)
    _ingest(tmp_db, eid, _XML_NARROW)
    _ingest(tmp_db, eid, _XML_FULL)
    with yhdb.transaction(tmp_db) as conn:
        only = enum_gaps(conn, eid, host_ip="10.0.0.9")
        payload = gaps_as_dicts(only)
    assert [c.ip for c in only] == ["10.0.0.9"]
    assert payload[0]["tcp_full"] is False
    assert payload[0]["gaps"][0]["fix"]


def test_pivoted_hosts_are_out_of_scope_for_gaps(tmp_db: Path) -> None:
    eid = _engage(tmp_db)
    _ingest(tmp_db, eid, _XML_NARROW)
    with yhdb.transaction(tmp_db) as conn:
        conn.execute("UPDATE host SET stage = 'pivoted' WHERE ip = '10.0.0.9'")
        assert enum_gaps(conn, eid) == []
