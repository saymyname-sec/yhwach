"""BloodHound parser + the ingest -> AD-attack chain."""
from __future__ import annotations

import json
from pathlib import Path

from yhwach import db as yhdb
from yhwach.parsers.bloodhound import parse_bloodhound


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


