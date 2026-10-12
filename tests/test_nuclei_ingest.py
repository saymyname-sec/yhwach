"""I50 — nuclei JSONL -> potential vulnerability rows.

Keyed on the template id (not the CVE), so distinct templates never collapse
into one host row. Known templates/CVEs promote to a chaining tag; a
credential-category template's extracts are loot, never sprayable creds.
"""
from __future__ import annotations

from pathlib import Path

from yhwach import db as yhdb
from yhwach import sniff
from yhwach.mcp_tools import tool_interpret, tool_query
from yhwach.parsers.nuclei import parse_nuclei

_JSONL = "\n".join([
    '{"template-id":"CVE-2021-44228","info":{"name":"Log4j RCE","severity":"critical",'
    '"tags":["rce","cve"],"classification":{"cve-id":["CVE-2021-44228"],"cvss-score":10.0}},'
    '"matched-at":"http://10.0.0.5:8080/api"}',
    '{"template-id":"git-config","info":{"name":"Git Config Exposure","severity":"medium",'
    '"tags":["exposure"]},"matched-at":"http://10.0.0.5:8080/.git/config"}',
    '{"template-id":"grafana-default","info":{"name":"Grafana default login",'
    '"severity":"high","tags":["default-login"]},"matched-at":"http://10.0.0.5:3000/login",'
    '"extracted-results":["admin:admin"]}',
])


def test_parse_fields_and_host_port() -> None:
    fs = {f.template_id: f for f in parse_nuclei(_JSONL)}
    assert set(fs) == {"CVE-2021-44228", "git-config", "grafana-default"}
    log4j = fs["CVE-2021-44228"]
    assert log4j.host_ip == "10.0.0.5"
    assert log4j.port == 8080
    assert log4j.cves == ["CVE-2021-44228"]
    assert log4j.cvss == 10.0
    assert log4j.severity == "critical"


def test_promote_and_credential_flags() -> None:
    fs = {f.template_id: f for f in parse_nuclei(_JSONL)}
    assert fs["CVE-2021-44228"].promote_tag == "exploitable_cve"
    assert fs["grafana-default"].promote_tag == "default_creds"
    assert fs["grafana-default"].is_credential is True
    assert fs["git-config"].is_credential is False


def test_malformed_lines_skipped() -> None:
    out = parse_nuclei('not json\n{"template-id":"x","info":{"name":"n"},"matched-at":"http://h"}\n')
    assert len(out) == 1
    assert out[0].template_id == "x"


def test_sniff_detects_nuclei() -> None:
    assert sniff.detect(_JSONL) == "nuclei"


def _eng(path: Path) -> int:
    with yhdb.transaction(path) as conn:
        return yhdb.upsert_engagement(conn, lab="L", scope="10.0.0.0/24")


def test_distinct_templates_do_not_collapse(tmp_db: Path) -> None:
    _eng(tmp_db)
    out = tool_interpret(tmp_db, "L", _JSONL)
    assert "3 potential vuln" in out
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.engagement_id_for(conn, "L")
        n = conn.execute("SELECT COUNT(*) n FROM vulnerability WHERE engagement_id=?",
                         (eid,)).fetchone()["n"]
    assert n == 3   # the dedupe-collapse bug would have made this 1


def test_credential_extract_goes_to_loot_not_vault(tmp_db: Path) -> None:
    _eng(tmp_db)
    tool_interpret(tmp_db, "L", _JSONL)
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.engagement_id_for(conn, "L")
        loot = conn.execute("SELECT type, summary FROM loot WHERE engagement_id=?",
                            (eid,)).fetchall()
        creds = conn.execute("SELECT COUNT(*) n FROM credential WHERE engagement_id=?",
                            (eid,)).fetchone()["n"]
    assert len(loot) == 1
    assert "admin:admin" in loot[0]["summary"]
    assert creds == 0   # extracted creds are loot, never sprayable vault entries


def test_promotes_known_templates(tmp_db: Path) -> None:
    _eng(tmp_db)
    tool_interpret(tmp_db, "L", _JSONL)
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.engagement_id_for(conn, "L")
        tags = sorted(r[0] for r in conn.execute(
            "SELECT tag FROM finding WHERE engagement_id=? AND tag IS NOT NULL", (eid,)))
    assert tags == ["default_creds", "exploitable_cve"]


def test_reingest_is_idempotent(tmp_db: Path) -> None:
    _eng(tmp_db)
    tool_interpret(tmp_db, "L", _JSONL)
    tool_interpret(tmp_db, "L", _JSONL)
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.engagement_id_for(conn, "L")
        vulns = conn.execute("SELECT COUNT(*) n FROM vulnerability WHERE engagement_id=?",
                            (eid,)).fetchone()["n"]
        loot = conn.execute("SELECT COUNT(*) n FROM loot WHERE engagement_id=?",
                           (eid,)).fetchone()["n"]
    assert vulns == 3
    assert loot == 1   # loot only on first ingest (created rows)


def test_vulns_view_shows_nuclei(tmp_db: Path) -> None:
    _eng(tmp_db)
    tool_interpret(tmp_db, "L", _JSONL)
    out = tool_query(tmp_db, "L", "vulns", fields=["plugin_id", "source", "state"])
    assert "git-config" in out
    assert "nuclei" in out
    assert "potential" in out
