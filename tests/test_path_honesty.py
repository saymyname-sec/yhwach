"""I46 — path honesty: ownership only from proven access.

A principal is owned only when its credential is validated against a host or was
client-provided (assumed breach) — never merely held as an unproven guess.
yhwach_own lets the operator assert access won out-of-band. Pathfind starts
only from genuinely-owned nodes.
"""
from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from yhwach import db as yhdb
from yhwach import pathfind
from yhwach.cli import main
from yhwach.mcp_tools import tool_own


def _eng_principal(path: Path, name: str = "svc"):
    with yhdb.transaction(path) as conn:
        eid = yhdb.upsert_engagement(conn, lab="L", scope="10.0.0.0/24")
        pid = yhdb.add_principal(conn, eid, name)[0]
        hid = conn.execute(
            "INSERT INTO host (engagement_id, ip, stage, first_seen) "
            "VALUES (?, '10.0.0.5', 'scanned', 't')", (eid,)).lastrowid
        return eid, pid, int(hid)


def test_unvalidated_cred_is_not_ownership(tmp_db: Path) -> None:
    eid, pid, _ = _eng_principal(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        yhdb.add_credential(conn, eid, "svc", "P@ss", "password", "dump")  # held, unproven
        owned = pathfind.owned_nodes(conn, eid)
    assert f"principal:{pid}" not in owned


def test_guess_cred_is_never_ownership(tmp_db: Path) -> None:
    eid, pid, _ = _eng_principal(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        yhdb.add_credential(conn, eid, "svc", "Summer2026", "password", "derive",
                            provenance="guess")
        owned = pathfind.owned_nodes(conn, eid)
    assert f"principal:{pid}" not in owned


def test_validated_cred_confers_ownership(tmp_db: Path) -> None:
    eid, pid, hid = _eng_principal(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        cid, _ = yhdb.add_credential(conn, eid, "svc", "P@ss", "password", "dump")
        yhdb.mark_credential_validated(conn, eid, cid, hid, port=445, proto="smb",
                                       service_kind="smb", result="success", source="spray")
        owned = pathfind.owned_nodes(conn, eid)
    assert f"principal:{pid}" in owned


def test_provided_cred_is_ownership_even_unvalidated(tmp_db: Path) -> None:
    eid, pid, _ = _eng_principal(tmp_db, "breachuser")
    with yhdb.transaction(tmp_db) as conn:
        yhdb.add_credential(conn, eid, "breachuser", "x", "password", "client",
                            provenance="provided")
        owned = pathfind.owned_nodes(conn, eid)
    assert f"principal:{pid}" in owned


def test_own_principal_marks_it_owned(tmp_db: Path) -> None:
    eid, pid, _ = _eng_principal(tmp_db)
    out = tool_own(tmp_db, "L", principal="svc")
    assert "marked owned" in out
    with yhdb.transaction(tmp_db) as conn:
        assert f"principal:{pid}" in pathfind.owned_nodes(conn, eid)


def test_own_creates_unknown_principal(tmp_db: Path) -> None:
    _eng_principal(tmp_db)
    tool_own(tmp_db, "L", principal="ghost")  # not previously known
    with yhdb.transaction(tmp_db) as conn:
        row = conn.execute("SELECT owned FROM principal WHERE name='ghost'").fetchone()
    assert row is not None and row["owned"] == 1


def test_own_host_advances_to_foothold(tmp_db: Path) -> None:
    eid, _, _ = _eng_principal(tmp_db)
    tool_own(tmp_db, "L", host="10.0.0.5")
    with yhdb.transaction(tmp_db) as conn:
        stage = conn.execute("SELECT stage FROM host WHERE ip='10.0.0.5'").fetchone()["stage"]
        assert "host:" in " ".join(pathfind.owned_nodes(conn, eid))
    assert stage == "foothold"


def test_own_requires_a_target(tmp_db: Path) -> None:
    _eng_principal(tmp_db)
    assert "pass host=" in tool_own(tmp_db, "L")


def test_cli_own(tmp_db: Path) -> None:
    _eng_principal(tmp_db)
    r = CliRunner().invoke(main, ["own", "--lab", "L", "--principal", "svc", "--db", str(tmp_db)])
    assert r.exit_code == 0
    assert "marked owned" in r.output
