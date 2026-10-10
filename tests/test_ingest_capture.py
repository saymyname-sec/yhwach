"""Phase 3: coverage-from-args fix, host labelling, interfaces, netexec cred proof."""
from __future__ import annotations

from pathlib import Path

from yhwach import db as yhdb
from yhwach.ingest import ingest_netexec
from yhwach.parsers.nmap import parse_scan_meta


def _host(conn, eid: int, ip: str) -> int:
    cur = conn.execute(
        "INSERT INTO host (engagement_id, ip, stage, first_seen) VALUES (?, ?, 'scanned', 't')",
        (eid, ip))
    return int(cur.lastrowid)


def test_coverage_parses_pathed_nmap_argv() -> None:
    """The `as:` header often carries a full path (run privileged), not bare
    `nmap` — coverage must still parse (regression: silently dropped before)."""
    text = (
        "# Nmap 7.99 scan initiated Mon Sep 28 as: /usr/lib/nmap/nmap --privileged "
        "-Pn -sT -sV -n -p- --max-retries 2 -oN out.nmap 10.0.0.72\n"
        "Nmap scan report for 10.0.0.72\n"
        "22/tcp open ssh\n"
    )
    meta = parse_scan_meta(text)
    assert meta.coverage, "no coverage parsed from pathed argv"
    assert meta.coverage[0].full_range is True
    assert meta.version_scan is True


def test_coverage_parses_specific_ports_pathed() -> None:
    text = (
        "# Nmap 7.99 scan initiated X as: /usr/bin/nmap -sT -p 135,445,5985 -oN o 10.0.0.1\n"
        "Nmap scan report for 10.0.0.1\n"
    )
    meta = parse_scan_meta(text)
    assert meta.coverage[0].ports == "135,445,5985"
    assert meta.coverage[0].full_range is False


def test_set_host_meta(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.upsert_engagement(conn, lab="p3a", scope="10.0.0.0/24")
        _host(conn, eid, "10.0.0.5")
        assert yhdb.set_host_meta(conn, eid, "10.0.0.5", hostname="DC01", os="windows",
                                  role="Domain Controller")
        row = conn.execute("SELECT hostname, os, role FROM host WHERE ip='10.0.0.5'").fetchone()
        assert (row["hostname"], row["os"], row["role"]) == ("DC01", "windows", "Domain Controller")
        # COALESCE: a later call that omits os keeps it
        yhdb.set_host_meta(conn, eid, "10.0.0.5", role="DC")
        row = conn.execute("SELECT os, role FROM host WHERE ip='10.0.0.5'").fetchone()
        assert row["os"] == "windows" and row["role"] == "DC"
        assert yhdb.set_host_meta(conn, eid, "10.9.9.9", hostname="x") is False  # missing host


def test_host_interface_records_dual_homing(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.upsert_engagement(conn, lab="p3b", scope="172.16.0.0/24")
        hid = _host(conn, eid, "172.16.10.31")
        yhdb.add_host_interface(conn, hid, "172.16.10.31", segment="172.16.10.0/24",
                                is_primary=True, source="nmap")
        yhdb.add_host_interface(conn, hid, "10.0.0.254", segment="10.0.0.0/24",
                                source="operator")
        rows = conn.execute("SELECT ip, segment FROM host_interface WHERE host_id=? ORDER BY ip",
                            (hid,)).fetchall()
    segs = {r["ip"]: r["segment"] for r in rows}
    assert segs == {"10.0.0.254": "10.0.0.0/24", "172.16.10.31": "172.16.10.0/24"}


def test_netexec_ingest_proves_vault_cred(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.upsert_engagement(conn, lab="p3c", scope="10.0.0.0/24")
        hid = _host(conn, eid, "10.0.0.72")
        cid, _ = yhdb.add_credential(conn, eid, "svc_app", "@ppS3rv", "password", "sqli")
        nxc = ("SMB 10.0.0.72 445 DC01 [*] Windows Server 2025 (name:DC01) (domain:corp.local) "
               "(signing:True) (SMBv1:False)\n"
               "SMB 10.0.0.72 445 DC01 [+] corp.local\\svc_app:@ppS3rv (Pwn3d!)\n")
        summ = ingest_netexec(conn, eid, hid, nxc)
        assert summ["creds_proven"] == 1
        # validated_on set + access row recorded as admin on smb/445
        row = conn.execute("SELECT validated_on_host_id FROM credential WHERE id=?",
                          (cid,)).fetchone()
        assert row["validated_on_host_id"] == hid
        acc = conn.execute("SELECT proto, port, result FROM credential_access "
                          "WHERE credential_id=?", (cid,)).fetchone()
        assert (acc["proto"], acc["port"], acc["result"]) == ("smb", 445, "admin")
