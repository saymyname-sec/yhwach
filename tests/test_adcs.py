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
    # Aggregate adcs_vuln finding (catch-all rule) + the per-ESC adcs_esc1 finding.
    tags = {f.tag for f in fs}
    assert "adcs_vuln" in tags and "adcs_esc1" in tags
    agg = next(f for f in fs if f.tag == "adcs_vuln")
    assert agg.severity == "critical"
    assert "ESC1" in agg.title and "VulnUser" in agg.title


def test_parse_certipy_emits_per_esc_tags() -> None:
    data = json.dumps({"Certificate Templates": {"0": {
        "Template Name": "T", "Enabled": True,
        "[!] Vulnerabilities": {"ESC9": "No security extension", "ESC13": "issuance policy"}}}})
    fs = parse_certipy(data)
    tags = {f.tag for f in fs}
    assert {"adcs_vuln", "adcs_esc9", "adcs_esc13"} <= tags
    # ESC9 is high-impact -> critical; ESC13 is not in _HIGH_IMPACT -> high.
    esc9 = next(f for f in fs if f.tag == "adcs_esc9")
    esc13 = next(f for f in fs if f.tag == "adcs_esc13")
    assert esc9.severity == "critical" and esc13.severity == "high"


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


