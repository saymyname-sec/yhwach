"""I45 — domain facts + module-aware NetExec parsing + roastable hashes.

NetExec module output (MAQ, LDAP signing/channel binding, LAPS) becomes typed
domain_fact rows that gate real moves, and kerberoast/AS-REP hashes become
crackable credentials flagged spray_policy='manual' — offline-crack material, so
they are NEVER sprayed.
"""
from __future__ import annotations

from pathlib import Path

from yhwach import db as yhdb
from yhwach import sprayer
from yhwach.ingest import ingest_netexec
from yhwach.mcp_tools import tool_query
from yhwach.parsers.netexec import parse_netexec

_OUT = (
    "LDAP 10.0.0.10 389 DC01 [*] Windows Server 2022 (name:DC01) "
    "(domain:corp.local) (signing:True) (SMBv1:False)\n"
    "MAQ 10.0.0.10 389 DC01 MachineAccountQuota: 10\n"
    "LDAP 10.0.0.10 389 DC01 LDAP signing NOT enforced\n"
    "LDAP 10.0.0.10 389 DC01 LDAP channel binding is set to : Never\n"
    "LDAP 10.0.0.10 389 DC01 $krb5tgs$23$*svc_sql$CORP.LOCAL$MSSQLSvc/db*$abcd1234\n"
    "LDAP 10.0.0.10 389 DC01 $krb5asrep$23$jdoe@CORP.LOCAL:aabbccdd11223344\n"
)


# --- parser -----------------------------------------------------------------


def test_parse_extracts_domain_facts() -> None:
    r = parse_netexec(_OUT)
    assert r.domain_facts["machine_account_quota"] == "10"
    assert r.domain_facts["ldap_signing"] == "not_enforced"
    assert r.domain_facts["channel_binding"] == "never"


def test_parse_extracts_roast_hashes_with_users() -> None:
    r = parse_netexec(_OUT)
    kinds = {k["kind"]: k["user"] for k in r.kerberos_hashes}
    assert kinds == {"krb5tgs": "svc_sql", "krb5asrep": "jdoe"}


def test_parse_emits_chaining_findings() -> None:
    tags = {f.tag for f in parse_netexec(_OUT).findings}
    assert {"maq_abuse", "ldap_relay", "kerberoastable", "asreproastable"} <= tags


def test_maq_zero_is_not_flagged() -> None:
    r = parse_netexec("MAQ 10.0.0.10 389 DC01 MachineAccountQuota: 0")
    assert r.domain_facts["machine_account_quota"] == "0"
    assert not any(f.tag == "maq_abuse" for f in r.findings)


def test_enforced_ldap_signing_not_flagged() -> None:
    r = parse_netexec("LDAP 10.0.0.10 389 DC01 LDAP signing is enforced")
    assert r.domain_facts["ldap_signing"] == "enforced"
    assert not any(f.tag == "ldap_relay" for f in r.findings)


# --- ingest -----------------------------------------------------------------


def _eng_host(path: Path) -> tuple[int, int]:
    with yhdb.transaction(path) as conn:
        eid = yhdb.upsert_engagement(conn, lab="L", scope="10.0.0.0/24")
        hid = conn.execute(
            "INSERT INTO host (engagement_id, ip, stage, first_seen) "
            "VALUES (?, '10.0.0.10', 'scanned', 't')", (eid,)).lastrowid
        return eid, int(hid)


def test_ingest_writes_domain_facts(tmp_db: Path) -> None:
    eid, hid = _eng_host(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        summ = ingest_netexec(conn, eid, hid, _OUT)
        facts = {r["key"]: r["value"] for r in yhdb.list_domain_facts(conn, eid)}
    assert summ["domain_facts"] == 3
    assert facts["machine_account_quota"] == "10"
    assert facts["ldap_signing"] == "not_enforced"


def test_domain_fact_upsert_last_wins(tmp_db: Path) -> None:
    eid, hid = _eng_host(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        yhdb.add_domain_fact(conn, eid, "machine_account_quota", "10", domain="corp.local")
        yhdb.add_domain_fact(conn, eid, "machine_account_quota", "0", domain="corp.local")
        facts = yhdb.list_domain_facts(conn, eid)
    assert len(facts) == 1
    assert facts[0]["value"] == "0"


def test_roast_hashes_become_manual_creds_never_sprayed(tmp_db: Path) -> None:
    eid, hid = _eng_host(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        summ = ingest_netexec(conn, eid, hid, _OUT)
        rows = conn.execute(
            "SELECT identifier, kind, spray_policy FROM credential WHERE kind='kerberos' "
            "ORDER BY identifier").fetchall()
        sweep = sprayer._candidate_creds(conn, eid)
    assert summ["kerberos"] == 2
    assert [r["identifier"] for r in rows] == ["jdoe", "svc_sql"]
    assert all(r["spray_policy"] == "manual" for r in rows)
    assert not any(r["kind"] == "kerberos" for r in sweep)


def test_domain_facts_view_queryable(tmp_db: Path) -> None:
    eid, hid = _eng_host(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        ingest_netexec(conn, eid, hid, _OUT)
    out = tool_query(tmp_db, "L", "domain_facts")
    assert "machine_account_quota" in out
    assert "corp.local" in out
