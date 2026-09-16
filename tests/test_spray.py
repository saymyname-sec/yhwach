"""Tests for the credential spray planner."""
from __future__ import annotations

from pathlib import Path

from yhwach import db as yhdb
from yhwach.spray import build_spray_plan


def _seed(tmp_db: Path) -> int:
    with yhdb.transaction(tmp_db) as conn:
        eng = yhdb.upsert_engagement(conn, lab="s", scope="10.0.0.0/24")
        for ip, kind in [("10.0.0.1", "smb"), ("10.0.0.2", "smb"), ("10.0.0.3", "winrm")]:
            cur = conn.execute(
                "INSERT INTO host (engagement_id, ip, stage, first_seen) VALUES (?, ?, 'scanned', ?)",
                (eng, ip, "2026-01-01T00:00:00Z"))
            hid = int(cur.lastrowid)
            cur = conn.execute(
                "INSERT INTO service (host_id, port, proto, discovered_at) VALUES (?, 445, 'tcp', ?)",
                (hid, "2026-01-01T00:00:00Z"))
            yhdb.upsert_surface(conn, hid, int(cur.lastrowid), kind, "unknown", "{}")
    return eng


def test_empty_vault_no_spray(tmp_db: Path) -> None:
    eng = _seed(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        assert build_spray_plan(conn, eng) == []


def test_spray_pairs_creds_with_protocols(tmp_db: Path) -> None:
    eng = _seed(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        yhdb.add_credential(conn, eng, "admin", "P@ss", "password", "dump")
        cmds = build_spray_plan(conn, eng)
    # one smb command (both smb ips together) + one winrm command
    smb = [c for c in cmds if c.startswith("nxc smb")]
    winrm = [c for c in cmds if c.startswith("nxc winrm")]
    assert len(smb) == 1 and len(winrm) == 1
    assert "10.0.0.1 10.0.0.2" in smb[0]
    assert "-u admin -p 'P@ss'" in smb[0]
    assert "--continue-on-success" in smb[0]


def test_spray_ntlm_uses_hash_flag(tmp_db: Path) -> None:
    eng = _seed(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        yhdb.add_credential(conn, eng, "admin", "aad3b435:31d6cfe0", "ntlm", "secretsdump")
        cmds = build_spray_plan(conn, eng, proto_filter="smb")
    assert cmds and "-H aad3b435:31d6cfe0" in cmds[0]


def test_spray_proto_filter(tmp_db: Path) -> None:
    eng = _seed(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        yhdb.add_credential(conn, eng, "admin", "x", "password", "dump")
        cmds = build_spray_plan(conn, eng, proto_filter="winrm")
    assert all(c.startswith("nxc winrm") for c in cmds)
    assert len(cmds) == 1


def test_spray_multiple_creds(tmp_db: Path) -> None:
    eng = _seed(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        yhdb.add_credential(conn, eng, "admin", "a", "password", "dump")
        yhdb.add_credential(conn, eng, "svc", "b", "password", "dump")
        cmds = build_spray_plan(conn, eng, proto_filter="smb")
    assert len(cmds) == 2  # two creds x one smb target-group
