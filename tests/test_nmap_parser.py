"""Tests for the nmap XML parser and its DB insertion."""
from __future__ import annotations

from pathlib import Path

from yhwach import db as yhdb
from yhwach.parsers.nmap import insert_hosts, parse_nmap_xml


def test_parse_extracts_hosts_and_services(sample_nmap_xml: Path) -> None:
    hosts = parse_nmap_xml(sample_nmap_xml)
    assert len(hosts) == 2

    by_ip = {h.ip: h for h in hosts}
    assert set(by_ip) == {"10.10.10.15", "10.10.10.20"}

    ai = by_ip["10.10.10.15"]
    assert ai.hostname == "ai-host"
    ports = {(s.port, s.proto) for s in ai.services}
    assert (11434, "tcp") in ports
    assert (8000, "tcp") in ports
    # OS hint present and linux-classifiable
    assert ai.os_hint and "linux" in ai.os_hint.lower()

    win = by_ip["10.10.10.20"]
    assert win.os_hint and "windows" in win.os_hint.lower()
    win_ports = {(s.port, s.proto) for s in win.services}
    assert (445, "tcp") in win_ports


def test_parse_skips_down_hosts(tmp_path: Path) -> None:
    xml = tmp_path / "down.xml"
    xml.write_text(
        """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="down"/>
    <address addr="10.0.0.99" addrtype="ipv4"/>
  </host>
</nmaprun>""",
        encoding="utf-8",
    )
    assert parse_nmap_xml(xml) == []


def test_parse_skips_closed_ports(tmp_path: Path) -> None:
    xml = tmp_path / "closed.xml"
    xml.write_text(
        """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80"><state state="closed"/></port>
      <port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>
    </ports>
  </host>
</nmaprun>""",
        encoding="utf-8",
    )
    hosts = parse_nmap_xml(xml)
    assert len(hosts) == 1
    ports = {s.port for s in hosts[0].services}
    assert ports == {22}


def test_insert_advances_stage_to_scanned(tmp_db: Path, sample_nmap_xml: Path) -> None:
    hosts = parse_nmap_xml(sample_nmap_xml)
    with yhdb.transaction(tmp_db) as conn:
        eng_id = yhdb.upsert_engagement(conn, lab="fixture", scope="10.10.10.0/24")
        insert_hosts(conn, eng_id, hosts)
        rows = conn.execute(
            "SELECT ip, stage FROM host WHERE engagement_id = ? ORDER BY ip",
            (eng_id,),
        ).fetchall()
    assert {(r["ip"], r["stage"]) for r in rows} == {
        ("10.10.10.15", "scanned"),
        ("10.10.10.20", "scanned"),
    }


def test_insert_is_idempotent(tmp_db: Path, sample_nmap_xml: Path) -> None:
    hosts = parse_nmap_xml(sample_nmap_xml)
    with yhdb.transaction(tmp_db) as conn:
        eng_id = yhdb.upsert_engagement(conn, lab="fixture", scope="10.10.10.0/24")
        h1, s1 = insert_hosts(conn, eng_id, hosts)
        h2, s2 = insert_hosts(conn, eng_id, hosts)  # second time — no dupes
        host_count = conn.execute("SELECT COUNT(*) AS n FROM host").fetchone()["n"]
        svc_count = conn.execute("SELECT COUNT(*) AS n FROM service").fetchone()["n"]

    assert h1 == h2 == 2
    # Second call counts services touched too, but the underlying row set is stable.
    assert host_count == 2
    assert svc_count == 3  # 2 on ai-host + 1 on dc01


def test_os_class_windows_and_linux(sample_nmap_xml: Path, tmp_db: Path) -> None:
    hosts = parse_nmap_xml(sample_nmap_xml)
    with yhdb.transaction(tmp_db) as conn:
        eng_id = yhdb.upsert_engagement(conn, lab="fixture", scope="10.10.10.0/24")
        insert_hosts(conn, eng_id, hosts)
        rows = conn.execute(
            "SELECT ip, os FROM host WHERE engagement_id = ? ORDER BY ip",
            (eng_id,),
        ).fetchall()
    m = {r["ip"]: r["os"] for r in rows}
    assert m["10.10.10.15"] == "linux"
    assert m["10.10.10.20"] == "windows"


# --- normal (-oN) output + auto-detect --------------------------------------

_NORMAL = """\
Nmap scan report for dc02.corp.local (10.1.239.15)
Host is up (0.0011s latency).
PORT     STATE SERVICE       VERSION
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP
445/tcp  open  microsoft-ds?
Running: Microsoft Windows Server 2022

Nmap scan report for 10.1.239.27
Host is up.
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1
"""


def test_parse_nmap_normal() -> None:
    from yhwach.parsers.nmap import parse_nmap_normal
    hosts = {h.ip: h for h in parse_nmap_normal(_NORMAL)}
    assert set(hosts) == {"10.1.239.15", "10.1.239.27"}
    dc = hosts["10.1.239.15"]
    assert dc.hostname == "dc02.corp.local"
    assert {s.port for s in dc.services} == {88, 389, 445}
    assert dc.os_hint and "Windows Server 2022" in dc.os_hint
    assert hosts["10.1.239.27"].services[0].version == "OpenSSH 8.9p1"


def test_parse_nmap_autodetect(sample_nmap_xml: Path) -> None:
    from yhwach.parsers.nmap import parse_nmap
    xml_hosts = {h.ip for h in parse_nmap(sample_nmap_xml.read_text(encoding="utf-8"))}
    assert xml_hosts == {"10.10.10.15", "10.10.10.20"}          # XML path
    norm_hosts = {h.ip for h in parse_nmap(_NORMAL)}
    assert norm_hosts == {"10.1.239.15", "10.1.239.27"}         # normal path
