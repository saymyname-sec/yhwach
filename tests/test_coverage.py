"""Tests for scan-coverage recording and the enumeration-gap verdict.

The point of this layer: the world model must be able to tell a `-p 1-1000`
scan from a `-p-` scan. Everything else (the `gaps` command, the handoff
warning, the advance advisory) is a view over that.
"""
from __future__ import annotations

from pathlib import Path

from yhwach import db as yhdb
from yhwach.coverage import _service_enum_gaps, enum_gaps, gaps_as_dicts, render_gaps
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


# --- per-service completeness: the service_enum gap (P0.5) ------------------

def _host_with_surface(tmp_db: Path, eid: int, kind: str, port: int) -> tuple[int, int]:
    """Create a scanned host with one service+surface of `kind`. Returns (host_id, surface_id)."""
    with yhdb.transaction(tmp_db) as conn:
        hid = conn.execute(
            "INSERT INTO host (engagement_id, ip, stage, first_seen) "
            "VALUES (?, '10.0.0.42', 'scanned', 't')", (eid,)
        ).lastrowid
        sid = conn.execute(
            "INSERT INTO service (host_id, port, proto, product, discovered_at) "
            "VALUES (?, ?, 'tcp', ?, 't')", (hid, port, kind)
        ).lastrowid
        surf_id, _ = yhdb.upsert_surface(
            conn, host_id=hid, service_id=sid, kind=kind, auth="none", meta_json="{}")
        return hid, surf_id


def test_untriaged_service_raises_service_enum_gap(tmp_db: Path) -> None:
    eid = _engage(tmp_db)
    hid, _ = _host_with_surface(tmp_db, eid, "redis", 6379)
    with yhdb.transaction(tmp_db) as conn:
        gaps = _service_enum_gaps(conn, hid)
    assert [g.kind for g in gaps] == ["service_enum"]
    assert "redis" in gaps[0].detail
    assert gaps[0].fix  # names how to triage it


def test_finding_on_surface_clears_service_enum_gap(tmp_db: Path) -> None:
    eid = _engage(tmp_db)
    hid, surf_id = _host_with_surface(tmp_db, eid, "redis", 6379)
    with yhdb.transaction(tmp_db) as conn:
        yhdb.add_finding(conn, host_id=hid, surface_id=surf_id, cls="T1213",
                         title="redis unauth loot", severity="high", evidence="KEYS *")
        assert _service_enum_gaps(conn, hid) == []


def test_non_enumerable_surface_never_raises(tmp_db: Path) -> None:
    # A plain web surface is not in SERVICE_ENUM_KINDS -> no service_enum gap.
    eid = _engage(tmp_db)
    hid, _ = _host_with_surface(tmp_db, eid, "web", 80)
    with yhdb.transaction(tmp_db) as conn:
        assert _service_enum_gaps(conn, hid) == []


def test_service_enum_surfaces_through_enum_gaps(tmp_db: Path) -> None:
    eid = _engage(tmp_db)
    _host_with_surface(tmp_db, eid, "mongodb", 27017)
    with yhdb.transaction(tmp_db) as conn:
        gaps = enum_gaps(conn, eid)
    assert len(gaps) == 1
    kinds = {g.kind for g in gaps[0].gaps}
    assert "service_enum" in kinds  # alongside the scan-coverage 'none' gap


def test_recon_attempt_clears_service_enum_gap(tmp_db: Path) -> None:
    """Running a kind-prefixed recon rule records an attempt that marks the
    surface triaged — closing the loop between the P1 recon rules and the gap."""
    eid = _engage(tmp_db)
    hid, _ = _host_with_surface(tmp_db, eid, "redis", 6379)
    with yhdb.transaction(tmp_db) as conn:
        assert [g.kind for g in _service_enum_gaps(conn, hid)] == ["service_enum"]
        conn.execute(
            "INSERT INTO attempt (engagement_id, host_id, playbook_rule_id, result, attempted_at) "
            "VALUES (?, ?, 'redis_enumeration', 'success', 't')", (eid, hid))
        assert _service_enum_gaps(conn, hid) == []


# --- honesty score + started-hosts scoping ----------------------------------

def test_coverage_score_all_complete(tmp_db: Path) -> None:
    from yhwach.coverage import coverage_score

    eid = _engage(tmp_db)
    _ingest(tmp_db, eid, _XML_FULL)   # full-port + -sV
    _ingest(tmp_db, eid, _NORMAL_UDP)  # UDP top-100
    with yhdb.transaction(tmp_db) as conn:
        cs = coverage_score(conn, eid)
    assert cs.considered == 1
    assert cs.complete == 1
    assert cs.pct == 100


def test_coverage_score_incomplete_and_zero_pct(tmp_db: Path) -> None:
    from yhwach.coverage import coverage_score

    eid = _engage(tmp_db)
    _host_with_surface(tmp_db, eid, "redis", 6379)  # scanned, no coverage rows, untriaged
    with yhdb.transaction(tmp_db) as conn:
        cs = coverage_score(conn, eid)
    assert cs.considered == 1
    assert cs.complete == 0
    assert cs.pct == 0
    assert cs.service_enum_gaps >= 1


def test_started_gaps_excludes_undiscovered(tmp_db: Path) -> None:
    """Undiscovered hosts are the scan queue (pending_scan), not a coverage gap —
    started_gaps drops them; enum_gaps still reports them."""
    from yhwach.coverage import enum_gaps, started_gaps

    eid = _engage(tmp_db)
    _host_with_surface(tmp_db, eid, "redis", 6379)  # 10.0.0.42, scanned
    with yhdb.transaction(tmp_db) as conn:
        conn.execute(
            "INSERT INTO host (engagement_id, ip, stage, first_seen) "
            "VALUES (?, '10.0.0.99', 'undiscovered', 't')", (eid,))
        all_ips = {c.ip for c in enum_gaps(conn, eid)}
        started_ips = {c.ip for c in started_gaps(conn, eid)}
    assert "10.0.0.99" in all_ips
    assert "10.0.0.99" not in started_ips
    assert "10.0.0.42" in started_ips


def test_coverage_score_pct_is_none_before_anything_is_reached(tmp_db: Path) -> None:
    """An empty engagement used to report 100% enumeration honesty — a green
    all-clear from the one number whose job is to catch under-enumeration."""
    from yhwach.coverage import coverage_score

    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.upsert_engagement(conn, lab="empty", scope="10.0.0.0/24")
        cs = coverage_score(conn, eid)
    assert cs.considered == 0
    assert cs.pct is None


def test_render_gaps_distinguishes_all_clear_from_nothing_reached() -> None:
    from yhwach.coverage import render_gaps

    assert "every active host" in render_gaps([])[0]
    assert "every active host" in render_gaps([], considered=3)[0]
    assert "nothing reached yet" in render_gaps([], considered=0)[0]
