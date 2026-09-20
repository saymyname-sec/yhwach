"""certipy/ADCS parser + the ingest -> adcs_esc_abuse chain."""
from __future__ import annotations

import json
from pathlib import Path

from yhwach import db as yhdb
from yhwach.parsers.adcs import parse_certipy

_VULN = json.dumps({"Certificate Templates": {"0": {
    "Template Name": "VulnUser", "Enabled": True,
    "[!] Vulnerabilities": {"ESC1": "Enrollee supplies subject"}}}})


def test_parse_certipy_vulnerable() -> None:
    fs = parse_certipy(_VULN)
    assert len(fs) == 1
    assert fs[0].tag == "adcs_vuln" and fs[0].severity == "critical"
    assert "ESC1" in fs[0].title and "VulnUser" in fs[0].title


def test_parse_certipy_no_vulns() -> None:
    data = json.dumps({"Certificate Templates": {"0": {"Template Name": "Safe", "Enabled": True}}})
    assert parse_certipy(data) == []


def test_parse_certipy_garbage() -> None:
    assert parse_certipy("nope") == []
    assert parse_certipy("[]") == []


def _seed_ca(tmp_db: Path) -> int:
    with yhdb.transaction(tmp_db) as conn:
        eng = yhdb.upsert_engagement(conn, lab="adcs", scope="10.0.0.0/24")
        conn.execute("INSERT INTO host (engagement_id, ip, os, stage, first_seen) "
                     "VALUES (?, '10.0.0.10', 'windows', 'looted', 't')", (eng,))
    return eng


