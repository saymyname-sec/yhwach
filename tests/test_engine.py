"""engine.execute_task + run_action HexStrike-delegated execution."""
from __future__ import annotations

from pathlib import Path

from yhwach import db as yhdb
from yhwach import engine
from yhwach.actions import Action, run_action


class _FakeHS:
    """Minimal HexStrike client double: returns canned command output."""

    def __init__(self, out: str, rc: int = 0) -> None:
        self.out = out
        self.rc = rc
        self.calls: list[str] = []

    def run_command(self, cmd: str, timeout=None) -> dict:
        self.calls.append(cmd)
        return {"stdout": self.out, "stderr": "", "return_code": self.rc, "success": True}


def test_run_action_via_hexstrike(tmp_path: Path) -> None:
    a = Action(id="probe", commands=["nxc smb 10.0.0.1"], risk="read_only", runnable=True)
    hs = _FakeHS("SMB  10.0.0.1  445  DC01  (signing:False)")
    res = run_action(a, {"IP": "10.0.0.1"}, loot_dir=tmp_path, hexstrike=hs)
    assert res[0]["via"] == "hexstrike"
    assert "signing:False" in res[0]["output"]
    assert hs.calls == ["nxc smb 10.0.0.1"]        # ran through HexStrike, not a subprocess
    assert Path(res[0]["loot_file"]).exists()


def test_run_action_hexstrike_error_is_captured(tmp_path: Path) -> None:
    class _Boom:
        def run_command(self, cmd, timeout=None):
            raise RuntimeError("connection refused")

    a = Action(id="probe", commands=["nxc smb 10.0.0.1"], risk="read_only", runnable=True)
    res = run_action(a, {"IP": "10.0.0.1"}, hexstrike=_Boom())
    assert res[0]["returncode"] is None
    assert "hexstrike error" in res[0]["output"]


def _seed_smb_task(tmp_db: Path) -> int:
    from yhwach.planner import match_rules
    from yhwach.playbooks import default_playbook_dir, load_rules
    with yhdb.transaction(tmp_db) as conn:
        eng = yhdb.upsert_engagement(conn, lab="e", scope="10.0.0.0/24")
        hid = conn.execute("INSERT INTO host (engagement_id, ip, os, stage, first_seen) "
                           "VALUES (?, '10.0.0.1', 'windows', 'scanned', 't')", (eng,)).lastrowid
        sid = conn.execute("INSERT INTO service (host_id, port, proto, discovered_at) "
                           "VALUES (?, 445, 'tcp', 't')", (hid,)).lastrowid
        yhdb.upsert_surface(conn, int(hid), int(sid), "smb", "none", "{}")
        match_rules(conn, eng, load_rules(default_playbook_dir()))
    return eng


def test_execute_task_via_hexstrike_extracts_tags(tmp_db: Path, monkeypatch) -> None:
    eng = _seed_smb_task(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        tid = conn.execute(
            "SELECT id FROM task WHERE playbook_rule_id='smb_enumeration'").fetchone()["id"]

    fake = _FakeHS("SMB  10.0.0.1  445  DC01  (signing:False)")
    monkeypatch.setattr("yhwach.hexstrike.HexStrikeClient", lambda url: fake)

    lines, ok = engine.execute_task(tmp_db, eng, tid, go=True,
                                    hexstrike_url="http://127.0.0.1:8888")
    assert ok
    assert any("via HexStrike" in ln for ln in lines)
    assert fake.calls  # something ran through HexStrike
    with yhdb.transaction(tmp_db) as conn:
        tags = {r["tag"] for r in conn.execute(
            "SELECT tag FROM finding WHERE tag IS NOT NULL").fetchall()}
    assert "smb_signing_off" in tags


def test_domain_var_fills_ad_commands() -> None:
    from yhwach.actions import context_from_surface, get_action, render_action
    ctx = context_from_surface("10.0.0.1", 445, {})
    assert ctx["DOMAIN"] == "<DOMAIN>"                 # placeholder until known
    ctx["DOMAIN"] = "corp.local"
    cmd = render_action(get_action("kerberoast_getuserspns"), ctx)[0]
    assert "corp.local/" in cmd and "-dc-ip 10.0.0.1" in cmd
