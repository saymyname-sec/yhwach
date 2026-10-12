"""I35 — methodology matrix + host_fact negative evidence.

Each checklist item is PRESENT / CHECKED / UNKNOWN, DERIVED from host_fact and
domain_fact — never operator-typed. An item leaves UNKNOWN only once enumeration
has written the evidence; without the host_fact primitive it would sit at
UNKNOWN forever.
"""
from __future__ import annotations

from pathlib import Path

from yhwach import db as yhdb
from yhwach import methodology as meth
from yhwach.ingest import ingest_netexec
from yhwach.mcp_tools import tool_methodology, tool_query


def _eng_host(path: Path) -> tuple[int, int]:
    with yhdb.transaction(path) as conn:
        eid = yhdb.upsert_engagement(conn, lab="L", scope="10.0.0.0/24")
        hid = conn.execute("INSERT INTO host (engagement_id, ip, stage, first_seen) "
                           "VALUES (?, '10.0.0.10', 'scanned', 't')", (eid,)).lastrowid
        return eid, int(hid)


def test_unknown_until_enumerated(tmp_db: Path) -> None:
    eid, hid = _eng_host(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        matrix = meth.methodology_for_host(conn, eid, hid)
    # nothing enumerated -> every item UNKNOWN
    assert all(r["state"] == "UNKNOWN" for r in matrix)


def test_host_fact_moves_item_off_unknown(tmp_db: Path) -> None:
    eid, hid = _eng_host(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        yhdb.add_host_fact(conn, hid, "smb_signing", "false", source="netexec")
        yhdb.add_host_fact(conn, hid, "smbv1", "false", source="netexec")
        matrix = {r["key"]: r["state"] for r in meth.methodology_for_host(conn, eid, hid)}
    assert matrix["smb_signing"] == "PRESENT"   # false = weakness present
    assert matrix["smbv1"] == "CHECKED"          # false = checked, not vulnerable


def test_domain_fact_drives_domain_items(tmp_db: Path) -> None:
    eid, hid = _eng_host(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        yhdb.add_domain_fact(conn, eid, "ldap_signing", "not_enforced")
        yhdb.add_domain_fact(conn, eid, "machine_account_quota", "10")
        matrix = {r["key"]: r["state"] for r in meth.methodology_for_host(conn, eid, hid)}
    assert matrix["ldap_signing"] == "PRESENT"
    assert matrix["machine_account_quota"] == "PRESENT"


def test_maq_zero_is_checked_not_present(tmp_db: Path) -> None:
    eid, hid = _eng_host(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        yhdb.add_domain_fact(conn, eid, "machine_account_quota", "0")
        matrix = {r["key"]: r["state"] for r in meth.methodology_for_host(conn, eid, hid)}
    assert matrix["machine_account_quota"] == "CHECKED"


def test_netexec_ingest_writes_host_facts(tmp_db: Path) -> None:
    eid, hid = _eng_host(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        ingest_netexec(conn, eid, hid,
                       "SMB 10.0.0.10 445 DC01 [*] Win (name:DC01) (domain:corp) "
                       "(signing:False) (SMBv1:True)")
        facts = yhdb.list_host_facts(conn, hid)
    assert facts["smb_signing"] == "false"
    assert facts["smbv1"] == "true"


def test_tool_reports_counts(tmp_db: Path) -> None:
    eid, hid = _eng_host(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        yhdb.add_host_fact(conn, hid, "smb_signing", "false")
    out = tool_methodology(tmp_db, "L", "10.0.0.10")
    assert "1 present" in out
    assert "PRESENT" in out and "UNKNOWN" in out


def test_host_facts_view(tmp_db: Path) -> None:
    eid, hid = _eng_host(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        yhdb.add_host_fact(conn, hid, "spooler", "running", source="netexec")
    out = tool_query(tmp_db, "L", "host_facts", fields=["key", "value"])
    assert "spooler" in out and "running" in out
