"""schema v1 — attack-surface enrichment: tables, helpers, parsers, ingest."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from yhwach import db as yhdb
from yhwach import ingest

V1_TABLES = {
    "software", "vulnerability", "principal", "membership", "privilege", "edge",
    "web_app", "web_path", "domain", "host_interface", "loot", "password_policy",
    "objective", "share",
}


@pytest.fixture()
def eng(tmp_db: Path):
    """(db_path, engagement_id, host_id) with one host to hang facts off."""
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.upsert_engagement(conn, "demo", "10.0.0.0/24", domain="corp.local")
        conn.execute(
            "INSERT INTO host (engagement_id, ip, hostname, first_seen) "
            "VALUES (?, ?, ?, '2026-01-01T00:00:00Z')",
            (eid, "10.0.0.5", "DC01"),
        )
        hid = conn.execute("SELECT id FROM host").fetchone()["id"]
    return tmp_db, eid, hid


def test_v1_tables_present(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        names = {r["name"] for r in
                 conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert names >= V1_TABLES


def test_service_cpe_and_credential_principal_columns(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        scols = {r["name"] for r in conn.execute("PRAGMA table_info(service)")}
        ccols = {r["name"] for r in conn.execute("PRAGMA table_info(credential)")}
    assert "cpe" in scols
    assert "principal_id" in ccols


def test_migrate_old_db_selfheals(tmp_path: Path) -> None:
    import sqlite3
    p = tmp_path / "old.db"
    c = sqlite3.connect(p)
    c.executescript(
        "CREATE TABLE engagement (id INTEGER PRIMARY KEY, lab TEXT UNIQUE, scope TEXT, "
        "started_at TEXT NOT NULL);"
        "CREATE TABLE service (id INTEGER PRIMARY KEY, host_id INTEGER, port INTEGER, "
        "proto TEXT, product TEXT, version TEXT, banner TEXT, discovered_at TEXT);"
    )
    c.commit()
    c.close()
    conn = yhdb.connect(p)  # triggers _migrate
    names = {r["name"] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert names >= V1_TABLES
    assert "cpe" in {r["name"] for r in conn.execute("PRAGMA table_info(service)")}
    conn.close()


def test_software_and_vuln_dedupe(eng) -> None:
    db, eid, hid = eng
    with yhdb.transaction(db) as conn:
        sid, c1 = yhdb.add_software(conn, hid, "Apache ActiveMQ", "5.17.4", source="nmap")
        sid2, c2 = yhdb.add_software(conn, hid, "Apache ActiveMQ", "5.17.4", cpe="cpe:x")
        assert sid == sid2 and c1 and not c2
        _, vc = yhdb.add_vulnerability(conn, eid, hid, "CVE-2023-46604", software_id=sid,
                                       cvss=10.0, exploit_available=True)
        assert vc
        cpe = conn.execute("SELECT cpe FROM software WHERE id=?", (sid,)).fetchone()["cpe"]
        assert cpe == "cpe:x"  # update filled the cpe


def test_principal_flags_union_merge(eng) -> None:
    db, eid, hid = eng
    with yhdb.transaction(db) as conn:
        pid, _ = yhdb.add_principal(conn, eid, "svc_sql", domain="corp.local", flags="spn")
        yhdb.add_principal(conn, eid, "svc_sql", domain="corp.local", flags="dont_require_preauth")
        flags = conn.execute("SELECT flags FROM principal WHERE id=?", (pid,)).fetchone()["flags"]
        assert set(flags.split(",")) == {"spn", "dont_require_preauth"}


def test_attack_graph_shortest_path(eng) -> None:
    db, eid, hid = eng
    with yhdb.transaction(db) as conn:
        pu, _ = yhdb.add_principal(conn, eid, "svc_sql", type="user")
        pg, _ = yhdb.add_principal(conn, eid, "Domain Admins", type="group")
        yhdb.add_edge(conn, eid, f"host:{hid}", f"principal:{pu}", "HasSession")
        yhdb.add_edge(conn, eid, f"principal:{pu}", f"principal:{pg}", "MemberOf")
        path = yhdb.shortest_path(conn, eid, f"host:{hid}", f"principal:{pg}")
    assert path == [f"host:{hid}", f"principal:{pu}", f"principal:{pg}"]
    with yhdb.transaction(db) as conn:
        assert yhdb.shortest_path(conn, eid, f"host:{hid}", "principal:999") is None


def test_share_helper(eng) -> None:
    db, eid, hid = eng
    with yhdb.transaction(db) as conn:
        yhdb.add_share(conn, hid, "C$", access="READ", remark="Default", source="netexec")
        # access legitimately upgrades as we gain creds; remark is preserved
        yhdb.add_share(conn, hid, "C$", access="READ,WRITE")
        row = conn.execute("SELECT access, remark FROM share WHERE name='C$'").fetchone()
    assert row["access"] == "READ,WRITE"
    assert row["remark"] == "Default"


# --- parsers -------------------------------------------------------------

def test_nmap_cpe_and_software(eng) -> None:
    from yhwach.parsers.nmap import insert_hosts, parse_nmap
    xml = (
        '<?xml version="1.0"?><nmaprun><host><status state="up"/>'
        '<address addr="10.0.0.9" addrtype="ipv4"/><ports><port protocol="tcp" portid="61616">'
        '<state state="open"/><service name="activemq" product="Apache ActiveMQ" version="5.17.4">'
        '<cpe>cpe:2.3:a:apache:activemq:5.17.4</cpe></service></port></ports></host></nmaprun>'
    )
    db, eid, _ = eng
    hosts = parse_nmap(xml)
    assert hosts[0].services[0].cpe == "cpe:2.3:a:apache:activemq:5.17.4"
    with yhdb.transaction(db) as conn:
        insert_hosts(conn, eid, hosts)
        svc = conn.execute("SELECT cpe FROM service WHERE port=61616").fetchone()
        sw = conn.execute("SELECT name, version, source FROM software WHERE name LIKE '%ActiveMQ%'").fetchone()
    assert svc["cpe"] == "cpe:2.3:a:apache:activemq:5.17.4"
    assert sw["version"] == "5.17.4" and sw["source"] == "nmap"


def test_web_parser_classifies_kinds() -> None:
    from yhwach.parsers.web import parse_web
    text = (
        "/admin (Status: 301) [Size: 178] [--> /admin/]\n"
        "/login.php (Status: 200) [Size: 900]\n"
        "/.git/HEAD (Status: 200) [Size: 23]\n"
        "/backup.zip (Status: 200) [Size: 90000]\n"
        "/api/v1/users (Status: 200) [Size: 50]\n"
    )
    kinds = {p.path: p.kind for p in parse_web(text)}
    assert kinds["/admin"] == "admin"
    assert kinds["/login.php"] == "login"
    assert kinds["/.git/HEAD"] == "source"
    assert kinds["/backup.zip"] == "backup"
    assert kinds["/api/v1/users"] == "api"


def test_web_parser_feroxbuster_full_urls() -> None:
    from yhwach.parsers.web import parse_web
    text = "200      GET       10l       20w      512c http://10.0.0.5/index.php\n"
    paths = parse_web(text, base_url="http://10.0.0.5")
    assert paths[0].path == "/index.php" and paths[0].status == 200


def test_netexec_parser() -> None:
    from yhwach.parsers.netexec import parse_netexec
    text = (
        "SMB 10.0.0.5 445 DC01 [*] Windows Server 2022 Build 20348 (name:DC01) "
        "(domain:corp.local) (signing:False) (SMBv1:False)\n"
        "SMB 10.0.0.5 445 DC01 [+] corp.local\\svc_sql:P@ss (Pwn3d!)\n"
        "SMB 10.0.0.5 445 DC01 [*] Enumerated shares\n"
        "SMB 10.0.0.5 445 DC01 Share Permissions Remark\n"
        "SMB 10.0.0.5 445 DC01 ----- ----------- ------\n"
        "SMB 10.0.0.5 445 DC01 C$ READ,WRITE Default share\n"
        "SMB 10.0.0.5 445 DC01 backups READ Backup\n"
        "SMB 10.0.0.5 445 DC01 [+] Enumerated domain user(s)\n"
        "SMB 10.0.0.5 445 DC01 corp.local\\Administrator badpwdcount: 0 desc: Built-in\n"
        "SMB 10.0.0.5 445 DC01 [+] Dumping password info for domain: CORP\n"
        "SMB 10.0.0.5 445 DC01 Minimum password length: 7\n"
        "SMB 10.0.0.5 445 DC01 Account Lockout Threshold: 5\n"
    )
    res = parse_netexec(text)
    assert res.signing is False
    assert res.domain == "corp.local"
    assert {s.name for s in res.shares} == {"C$", "backups"}
    assert any(s.name == "C$" and s.access == "READ,WRITE" for s in res.shares)
    assert res.admin_users == ["svc_sql"]
    assert res.password_policy["lockout_threshold"] == 5
    tags = {f.tag for f in res.findings}
    assert {"smb_signing_off", "domain_users", "admin_access", "writable_share"} <= tags


def test_ingest_netexec_creates_rows(eng) -> None:
    db, eid, hid = eng
    text = (
        "SMB 10.0.0.5 445 DC01 [*] Windows Server 2022 (name:DC01) (domain:corp.local) "
        "(signing:False) (SMBv1:False)\n"
        "SMB 10.0.0.5 445 DC01 [+] corp.local\\svc_sql:P@ss (Pwn3d!)\n"
        "SMB 10.0.0.5 445 DC01 [*] Enumerated shares\n"
        "SMB 10.0.0.5 445 DC01 C$ READ,WRITE Default\n"
        "SMB 10.0.0.5 445 DC01 [+] Dumping password info for domain: CORP\n"
        "SMB 10.0.0.5 445 DC01 Account Lockout Threshold: 5\n"
    )
    with yhdb.transaction(db) as conn:
        summ = ingest.ingest_netexec(conn, eid, hid, text)
        assert summ["shares"] == 1 and summ["admin"] == 1
        # admin cred -> local_admin privilege + AdminTo edge
        assert conn.execute("SELECT COUNT(*) c FROM privilege WHERE right='local_admin'").fetchone()["c"] == 1
        assert conn.execute("SELECT COUNT(*) c FROM edge WHERE kind='AdminTo'").fetchone()["c"] == 1
        assert conn.execute("SELECT COUNT(*) c FROM password_policy").fetchone()["c"] == 1


def test_ingest_bloodhound_graph_and_path(eng) -> None:
    db, eid, hid = eng
    facts = [
        {"kind": "kerberoastable", "principal": "svc_sql@corp.local", "detail": "MSSQLSvc/db"},
        {"kind": "dcsync", "principal": "corp\\svc_backup"},
        {"kind": "da_path", "principal": "svc_sql@corp.local"},
    ]
    with yhdb.transaction(db) as conn:
        summ = ingest.ingest_bloodhound_graph(conn, eid, json.dumps(facts))
        assert summ["principals"] >= 2 and summ["edges"] == 1
        spn = conn.execute("SELECT spn, flags FROM principal WHERE name='svc_sql'").fetchone()
        assert spn["flags"] == "spn" and spn["spn"] == "MSSQLSvc/db"
        assert conn.execute("SELECT COUNT(*) c FROM privilege WHERE right='DCSync'").fetchone()["c"] == 1
        sq = conn.execute("SELECT id FROM principal WHERE name='svc_sql'").fetchone()["id"]
        da = conn.execute("SELECT id FROM principal WHERE name='Domain Admins'").fetchone()["id"]
        assert yhdb.shortest_path(conn, eid, f"principal:{sq}", f"principal:{da}") is not None


def test_ingest_peas_software(eng) -> None:
    db, eid, hid = eng
    text = "Linux version 5.4.0-42-generic\nSudo version 1.8.31\n"
    with yhdb.transaction(db) as conn:
        n = ingest.ingest_peas_software(conn, hid, text, "linpeas")
        names = {r["name"]: r["version"] for r in conn.execute("SELECT name, version FROM software")}
    assert n == 2
    assert names["Linux kernel"] == "5.4.0-42-generic"
    assert names["sudo"] == "1.8.31"


# --- spray lockout gate -----------------------------------------------------

def test_cve_version_matcher() -> None:
    from yhwach.vulns import version_matches as vm
    assert vm("5.17.4", "<5.18.3") and not vm("5.19.0", "<5.18.3")
    assert vm("2.14.1", ">=2.0,<2.17.1") and not vm("2.17.1", ">=2.0,<2.17.1")
    assert vm("2.3.4", "==2.3.4") and not vm("2.3.5", "==2.3.4")
    assert vm("anything", "*")


def test_cve_enrich_matches_and_tags(eng) -> None:
    db, eid, hid = eng
    with yhdb.transaction(db) as conn:
        yhdb.add_software(conn, hid, "Apache ActiveMQ", "5.17.4", source="nmap",
                          cpe="cpe:2.3:a:apache:activemq:5.17.4")
        yhdb.add_software(conn, hid, "sudo", "1.8.31", kind="package", source="linpeas")
        yhdb.add_software(conn, hid, "sudo", "1.9.15", kind="package", source="linpeas")  # patched
        from yhwach.vulns import enrich
        summ = enrich(conn, eid)
        assert summ["matched"] >= 2 and summ["exploitable"] >= 2
        cves = {r["cve"] for r in conn.execute("SELECT cve FROM vulnerability")}
        assert "CVE-2023-46604" in cves and "CVE-2021-3156" in cves
        # patched sudo 1.9.15 must NOT match Baron Samedit (<1.9.5p2)
        assert conn.execute("SELECT COUNT(*) c FROM vulnerability WHERE cve='CVE-2021-3156'"
                            ).fetchone()["c"] == 1
        # exploitable_cve finding present -> the exploit_known_cve rule can chain
        assert conn.execute("SELECT COUNT(*) c FROM finding WHERE tag='exploitable_cve'"
                            ).fetchone()["c"] >= 1


def test_reference_packs_render() -> None:
    from yhwach.reference import render_pack
    assert "tomcat" in render_pack("default-creds", "tomcat").lower()
    assert "ESC1" in render_pack("esc", "esc1")
    assert "find" in render_pack("gtfobins", "find")
    assert render_pack("default-creds", "no-such-product-xyz") == ""


def test_web_ingest_emits_chaining_findings(eng) -> None:
    db, eid, hid = eng
    text = "/upload (Status: 200) [Size: 5]\n/.git/HEAD (Status: 200) [Size: 5]\n"
    with yhdb.transaction(db) as conn:
        summ = ingest.ingest_web(conn, hid, "http://10.0.0.5", text)
        tags = {r["tag"] for r in conn.execute("SELECT tag FROM finding WHERE host_id=?", (hid,))}
    assert summ["findings"] >= 2
    assert {"web_upload", "web_git"} <= tags


def test_export_notes_writes_tree(eng, tmp_path) -> None:
    from yhwach import notes
    db, eid, hid = eng
    with yhdb.transaction(db) as conn:
        yhdb.add_software(conn, hid, "sudo", "1.8.31", kind="package", source="linpeas")
        yhdb.add_share(conn, hid, "C$", access="READ,WRITE", source="netexec")
        pu, _ = yhdb.add_principal(conn, eid, "svc_sql", domain="corp.local", flags="spn")
        written = notes.export_notes(conn, eid, tmp_path / "notes")
    assert "Users & Groups.md" in written
    assert any(w.startswith("hosts/") for w in written)
    host_note = (tmp_path / "notes" / "hosts" / "DC01.md").read_text(encoding="utf-8")
    assert "yhwach:auto:software" in host_note  # fenced auto-block present
    assert "sudo" in host_note and "C$" in host_note
    ug = (tmp_path / "notes" / "Users & Groups.md").read_text(encoding="utf-8")
    assert "svc_sql" in ug
