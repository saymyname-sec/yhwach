"""I44 follow-up — masscan and nmap -oG (greppable) ingestion.

Both add hosts + services but, like a ping sweep, claim NO port coverage (they
do not carry a -p spec), so a host they discover still owes a real -sV scan.
"""
from __future__ import annotations

from pathlib import Path

from yhwach import db as yhdb
from yhwach.parsers.nmap import parse_nmap, parse_scan_meta

_GREP = ("Host: 10.0.0.5 (dc01)\tPorts: 22/open/tcp//ssh//OpenSSH 8.2//, "
         "445/open/tcp//microsoft-ds///\tIgnored State: closed (998)")
_MASS = "Discovered open port 445/tcp on 10.0.0.9\nDiscovered open port 3389/tcp on 10.0.0.9"
_MASS_LIST = "open tcp 80 10.0.0.10 1620000000\nopen tcp 443 10.0.0.10 1620000000"


def test_parse_greppable() -> None:
    h = parse_nmap(_GREP)[0]
    assert h.ip == "10.0.0.5"
    assert h.hostname == "dc01"
    ports = {s.port for s in h.services}
    assert ports == {22, 445}


def test_parse_masscan_discovered() -> None:
    h = parse_nmap(_MASS)[0]
    assert h.ip == "10.0.0.9"
    assert {s.port for s in h.services} == {445, 3389}


def test_parse_masscan_list() -> None:
    h = parse_nmap(_MASS_LIST)[0]
    assert {s.port for s in h.services} == {80, 443}


def test_these_formats_claim_no_coverage() -> None:
    # No -p spec in the output -> no coverage fabricated (the I44 honesty rule).
    assert parse_scan_meta(_GREP).coverage == []
    assert parse_scan_meta(_MASS).coverage == []


def test_ingest_records_services_but_leaves_scan_owed(tmp_db: Path) -> None:
    from yhwach.parsers.nmap import insert_hosts

    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.upsert_engagement(conn, lab="L", scope="10.0.0.0/24")
        insert_hosts(conn, eid, parse_nmap(_GREP), parse_scan_meta(_GREP))
        row = conn.execute("SELECT alive, scan_needed FROM host WHERE ip='10.0.0.5'").fetchone()
        svc = conn.execute("SELECT COUNT(*) n FROM service").fetchone()["n"]
        cov = conn.execute("SELECT COUNT(*) n FROM scan_coverage").fetchone()["n"]
    assert svc == 2
    assert row["alive"] == "alive"
    assert row["scan_needed"] == 1   # still owes a -sV pass
    assert cov == 0                  # no coverage claimed
