"""BloodHound parser + the ingest -> AD-attack chain."""
from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from yhwach import db as yhdb
from yhwach.cli import main
from yhwach.parsers.bloodhound import parse_bloodhound
from yhwach.planner import match_rules, top_tasks
from yhwach.playbooks import default_playbook_dir, load_rules


def test_parse_normalized_facts() -> None:
    facts = json.dumps([
        {"kind": "kerberoastable", "principal": "svc_sql@CORP", "detail": "MSSQLSvc/db"},
        {"kind": "dcsync", "principal": "svc_bkp@CORP"},
        {"kind": "unconstrained_delegation", "principal": "WEB01"},
    ])
    fs = parse_bloodhound(facts)
    assert {f.tag for f in fs} == {"kerberoastable", "dcsync", "unconstrained_delegation"}
    assert any(f.severity == "critical" for f in fs)          # dcsync is critical
    assert any("svc_sql@CORP" in f.evidence for f in fs)


def test_parse_facts_wrapper_and_unknown_kind_is_forward_compatible() -> None:
    fs = parse_bloodhound(json.dumps({"facts": [{"kind": "weird_new_edge", "principal": "x"}]}))
    assert len(fs) == 1 and fs[0].tag == "weird_new_edge"


def test_parse_sharphound_collection() -> None:
    data = json.dumps({"meta": {"type": "users"}, "data": [
        {"Properties": {"name": "svc@CORP", "hasspn": True}},
        {"Properties": {"name": "joe@CORP", "dontreqpreauth": True}},
    ]})
    assert {f.tag for f in parse_bloodhound(data)} == {"kerberoastable", "asreproastable"}


def test_parse_garbage_is_empty() -> None:
    assert parse_bloodhound("not json") == []
    assert parse_bloodhound("{}") == []


def _seed_dc(tmp_db: Path) -> int:
    with yhdb.transaction(tmp_db) as conn:
        eng = yhdb.upsert_engagement(conn, lab="bh", scope="10.0.0.0/24")
        conn.execute("INSERT INTO host (engagement_id, ip, os, stage, first_seen) "
                     "VALUES (?, '10.0.0.10', 'windows', 'looted', 't')", (eng,))
    return eng


def test_bloodhound_ingest_chains_to_attacks(tmp_db: Path, tmp_path: Path) -> None:
    eng = _seed_dc(tmp_db)
    bh = tmp_path / "bh.json"
    bh.write_text(json.dumps([
        {"kind": "kerberoastable", "principal": "svc_sql"},
        {"kind": "dcsync", "principal": "svc_bkp"},
    ]))
    r = CliRunner().invoke(main, ["ingest", str(bh), "--lab", "bh", "--kind", "bloodhound",
                                  "--host", "10.0.0.10", "--db", str(tmp_db)])
    assert r.exit_code == 0 and "kerberoastable" in r.output

    rules = load_rules(default_playbook_dir())
    with yhdb.transaction(tmp_db) as conn:
        match_rules(conn, eng, rules)
        ids = [t["playbook_rule_id"] for t in top_tasks(conn, eng, 50)]
    assert "kerberoast" in ids and "dcsync" in ids
