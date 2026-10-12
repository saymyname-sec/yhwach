"""G2c — secretsdump / potfile ingestion into the vault.

Dumped NT hashes and cracked passwords become credential rows so the reuse
graph can see them, but they are flagged spray_policy='manual' and NEVER enter
the autospray sweep — spraying a dumped domain hash estate-wide is the loud,
lockout-risking move this guard exists to prevent. An explicitly named cred may
still be sprayed. These tests lock the parsers, the manual flag, the sweep
exclusion, the potfile promotion, and the sniff detection.
"""
from __future__ import annotations

from pathlib import Path

from yhwach import db as yhdb
from yhwach import sniff, sprayer
from yhwach.mcp_tools import tool_interpret, tool_query
from yhwach.parsers.secrets import parse_potfile, parse_secretsdump

_DUMP = (
    "CONTOSO\\Administrator:500:aad3b435b51404eeaad3b435b51404ee:"
    "8846f7eaee8fb117ad06bdd830b7586c:::\n"
    "CONTOSO\\jdoe:1104:aad3b435b51404eeaad3b435b51404ee:"
    "5835048ce94ad0564e29a924a03510ef:::\n"
    "DC01$:1000:aad3b435b51404eeaad3b435b51404ee:"
    "31d6cfe0d16ae931b73c59d7e0c089c0:::\n"
    "someuser:aes256-cts-hmac-sha1-96:0011223344556677\n"  # kerberos key — ignored
)


# --- parsers ----------------------------------------------------------------


def test_parse_secretsdump_only_hash_lines() -> None:
    creds = parse_secretsdump(_DUMP)
    by = {c.identifier: c for c in creds}
    assert set(by) == {"Administrator", "jdoe", "DC01$"}  # kerberos key skipped
    assert by["jdoe"].domain == "CONTOSO"
    assert by["jdoe"].nt_hash == "5835048ce94ad0564e29a924a03510ef"
    assert by["DC01$"].is_machine is True
    assert by["DC01$"].empty_password is True
    assert by["Administrator"].empty_password is False


def test_parse_secretsdump_dedupes() -> None:
    assert len(parse_secretsdump(_DUMP + _DUMP)) == 3


def test_parse_potfile_handles_hashcat_and_john() -> None:
    pot = ("5835048ce94ad0564e29a924a03510ef:Summer2026!\n"
           "$NT$8846f7eaee8fb117ad06bdd830b7586c:password\n"
           "garbage line\n")
    out = {c.nt_hash: c.plaintext for c in parse_potfile(pot)}
    assert out["5835048ce94ad0564e29a924a03510ef"] == "Summer2026!"
    assert out["8846f7eaee8fb117ad06bdd830b7586c"] == "password"
    assert len(out) == 2


# --- sniff ------------------------------------------------------------------


def test_sniff_detects_dump_and_potfile() -> None:
    assert sniff.detect(_DUMP) == "secretsdump"
    assert sniff.detect("5835048ce94ad0564e29a924a03510ef:Summer2026!") == "potfile"


# --- ingest + the manual spray guard ----------------------------------------


def _eng(path: Path) -> int:
    with yhdb.transaction(path) as conn:
        return yhdb.upsert_engagement(conn, lab="L", scope="10.0.0.0/24")


def test_secretsdump_ingest_flags_manual(tmp_db: Path) -> None:
    eid = _eng(tmp_db)
    out = tool_interpret(tmp_db, "L", _DUMP)
    assert "3 NT hash" in out
    assert "manual" in out
    with yhdb.transaction(tmp_db) as conn:
        rows = yhdb.list_credentials(conn, eid, kind="ntlm")
        assert len(rows) == 3
        for r in conn.execute("SELECT spray_policy FROM credential WHERE engagement_id=?", (eid,)):
            assert r["spray_policy"] == "manual"


def test_dumped_hash_excluded_from_sweep_but_sprayable_when_named(tmp_db: Path) -> None:
    eid = _eng(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        cur = conn.execute(
            "INSERT INTO host (engagement_id, ip, stage, first_seen) "
            "VALUES (?, '10.0.0.10', 'scanned', '2026-01-01T00:00:00Z')", (eid,))
        conn.execute("INSERT INTO service (host_id, port, proto, product, discovered_at) "
                     "VALUES (?, 445, 'tcp', 'smb', '2026-01-01T00:00:00Z')", (cur.lastrowid,))
    tool_interpret(tmp_db, "L", _DUMP)
    with yhdb.transaction(tmp_db) as conn:
        sweep = sprayer._candidate_creds(conn, eid)
        assert not any(r["identifier"] == "jdoe" for r in sweep)
        cid = conn.execute("SELECT id FROM credential WHERE identifier='jdoe'").fetchone()[0]
        named = sprayer._candidate_creds(conn, eid, cred_id=cid)
        assert any(r["identifier"] == "jdoe" for r in named)


def test_potfile_promotes_matching_hash_to_plaintext(tmp_db: Path) -> None:
    eid = _eng(tmp_db)
    tool_interpret(tmp_db, "L", _DUMP)
    out = tool_interpret(tmp_db, "L", "5835048ce94ad0564e29a924a03510ef:Summer2026!")
    assert "1 promoted" in out
    with yhdb.transaction(tmp_db) as conn:
        pw = conn.execute(
            "SELECT secret, spray_policy, source FROM credential "
            "WHERE engagement_id=? AND identifier='jdoe' AND kind='password'", (eid,)).fetchone()
    assert pw["secret"] == "Summer2026!"
    assert pw["spray_policy"] == "manual"   # cracked plaintext never auto-sprays
    assert "cracked" in pw["source"]


def test_potfile_reports_unmatched(tmp_db: Path) -> None:
    _eng(tmp_db)
    tool_interpret(tmp_db, "L", _DUMP)
    out = tool_interpret(tmp_db, "L", "ffffffffffffffffffffffffffffffff:nope")
    assert "1 not matching" in out


def test_creds_view_exposes_spray_policy(tmp_db: Path) -> None:
    _eng(tmp_db)
    tool_interpret(tmp_db, "L", _DUMP)
    out = tool_query(tmp_db, "L", "creds", fields=["identifier", "spray_policy"])
    assert "spray_policy" in out
    assert "manual" in out
