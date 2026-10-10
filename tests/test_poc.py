"""Tests for the reproducible PoC-chain recorder."""
from __future__ import annotations

from pathlib import Path

from yhwach import db as yhdb
from yhwach import poc as pocmod
from yhwach.mcp_tools import tool_poc, tool_poc_step


def _eng(tmp_db: Path) -> int:
    with yhdb.transaction(tmp_db) as conn:
        return yhdb.upsert_engagement(conn, lab="m", scope="10.0.0.0/24")


def test_slug():
    assert pocmod.slug("n8n Intake RCE!") == "n8n-intake-rce"
    assert pocmod.slug("") == "objective"


def test_add_and_render_chain(tmp_db: Path):
    _eng(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.engagement_id_for(conn, "m")
        s1 = pocmod.add_step(conn, eid, "n8n-intake-rce", title="probe form",
                             command="curl -sk https://t/form/x", output="200 OK",
                             host="10.0.0.5")
        s2 = pocmod.add_step(conn, eid, "n8n-intake-rce", title="fire CVE",
                             command="python exploit.py", output="uid=1000",
                             cve="CVE-2023-2255", source="https://ex/poc")
        assert (s1, s2) == (1, 2)
        md = pocmod.render_poc(conn, eid, "n8n-intake-rce", lab="m", write=True, db_path=tmp_db)
    assert "# PoC — n8n-intake-rce" in md
    assert "CVE-2023-2255" in md and "curl -sk https://t/form/x" in md
    assert "1. probe form" in md and "2. fire CVE" in md
    # written to chains/<slug>.md
    from yhwach.engine import artifact_dir
    assert (artifact_dir(tmp_db, "chains") / "n8n-intake-rce.md").exists()


def test_save_script_and_inline(tmp_db: Path):
    _eng(tmp_db)
    p = pocmod.save_script(tmp_db, "n8n-intake-rce", "gen.py", "print('payload')\n")
    assert Path(p).read_text() == "print('payload')\n"
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.engagement_id_for(conn, "m")
        pocmod.add_step(conn, eid, "n8n-intake-rce", title="build payload",
                        command="python gen.py", script_path=str(p))
        md = pocmod.render_poc(conn, eid, "n8n-intake-rce", db_path=tmp_db)
    assert "gen.py" in md and "print('payload')" in md   # small script inlined


def test_list_objectives(tmp_db: Path):
    _eng(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.engagement_id_for(conn, "m")
        pocmod.add_step(conn, eid, "obj-a", title="x")
        pocmod.add_step(conn, eid, "obj-b", title="y")
        pocmod.add_step(conn, eid, "obj-a", title="z")
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.engagement_id_for(conn, "m")
        objs = dict(pocmod.list_objectives(conn, eid))
    assert objs == {"obj-a": 2, "obj-b": 1}


def test_output_capped(tmp_db: Path):
    _eng(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.engagement_id_for(conn, "m")
        pocmod.add_step(conn, eid, "big", title="huge", output="A" * 10000)
        s = pocmod.steps_for(conn, eid, "big")[0]
    assert len(s["output"]) < 10000 and "truncated" in s["output"]


def test_mcp_poc_roundtrip(tmp_db: Path):
    _eng(tmp_db)
    out = tool_poc_step(tmp_db, "m", "web-rce", "step one",
                        command="curl x", output="pwned",
                        script_content="#!/bin/sh\nid\n", script_name="p.sh",
                        cve="CVE-2023-2255", source="url", host="10.0.0.5")
    assert "step #1 recorded" in out
    listing = tool_poc(tmp_db, "m")
    assert "web-rce" in listing
    chain = tool_poc(tmp_db, "m", "web-rce")
    assert "curl x" in chain and "CVE-2023-2255" in chain and "id" in chain


def test_scaffold_from_attempts_seeds_and_is_idempotent(tmp_db: Path):
    _eng(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.engagement_id_for(conn, "m")
        hid = conn.execute(
            "INSERT INTO host (engagement_id, ip, os, stage, first_seen) "
            "VALUES (?, '10.0.0.5', 'linux', 'foothold', 't')", (eid,)).lastrowid
        yhdb.add_attempt(conn, eid, result="success", host_id=int(hid),
                         playbook_rule_id="n8n_ni8mare", technique_id="n8n_ni8mare",
                         reason="unauth file read", evidence="/etc/passwd -> root:x:0:0")
        yhdb.add_attempt(conn, eid, result="fail", host_id=int(hid),
                         playbook_rule_id="ssh_key_read", technique_id="ssh_key_read",
                         reason="perms")
        seeded = pocmod.scaffold_from_attempts(conn, eid)
        assert seeded == ["n8n_ni8mare"]              # only the SUCCESS is scaffolded
        again = pocmod.scaffold_from_attempts(conn, eid)
        assert again == []                            # idempotent
        objs = dict(pocmod.list_objectives(conn, eid))
    assert "n8n_ni8mare" in objs
