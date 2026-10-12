"""I34 — CI/CD scanner ingestion (zizmor SARIF, poutine).

Parses the tools' output into findings on the gha_* chaining tags; yhwach does
not hand-roll a GitHub Actions analyzer.
"""
from __future__ import annotations

from pathlib import Path

from yhwach import db as yhdb
from yhwach import knowledge as kn
from yhwach import sniff
from yhwach.mcp_tools import tool_interpret
from yhwach.parsers.cicd import parse_poutine, parse_sarif

_SARIF = (
    '{"$schema":"https://json.schemastore.org/sarif-2.1.0.json","version":"2.1.0",'
    '"runs":[{"tool":{"driver":{"name":"zizmor"}},"results":['
    '{"ruleId":"template-injection","level":"error","message":{"text":"expression injection"},'
    '"locations":[{"physicalLocation":{"artifactLocation":{"uri":".github/workflows/ci.yml"}}}]},'
    '{"ruleId":"dangerous-checkout","level":"error","message":{"text":"pwn request checkout"}}]}]}'
)
_POUTINE = ('{"findings":[{"rule_id":"injection","title":"Expression injection",'
            '"level":"error","meta":{"path":".github/workflows/deploy.yml"}}]}')


# --- parsers ----------------------------------------------------------------


def test_parse_sarif_tags_and_path() -> None:
    fs = {f.rule: f for f in parse_sarif(_SARIF)}
    assert fs["template-injection"].tag == "gha_injection"
    assert fs["template-injection"].path == ".github/workflows/ci.yml"
    assert fs["template-injection"].severity == "high"
    assert fs["dangerous-checkout"].tag == "gha_pwn_request"
    assert fs["template-injection"].tool == "zizmor"


def test_parse_poutine() -> None:
    f = parse_poutine(_POUTINE)[0]
    assert f.tag == "gha_injection"
    assert f.path == ".github/workflows/deploy.yml"
    assert f.tool == "poutine"


def test_bad_json_empty() -> None:
    assert parse_sarif("nope") == []
    assert parse_poutine("{bad") == []


def test_sniff_detects_sarif() -> None:
    assert sniff.detect(_SARIF) == "sarif"


# --- ingest + rules ---------------------------------------------------------


def _eng(path: Path) -> int:
    with yhdb.transaction(path) as conn:
        return yhdb.upsert_engagement(conn, lab="L", scope="10.0.0.0/8", kind="redteam")


def test_ingest_sarif_records_tagged_findings(tmp_db: Path) -> None:
    eid = _eng(tmp_db)
    out = tool_interpret(tmp_db, "L", _SARIF, kind="sarif")
    assert "2 CI/CD finding" in out
    with yhdb.transaction(tmp_db) as conn:
        tags = sorted({r[0] for r in conn.execute(
            "SELECT tag FROM finding WHERE engagement_id=? AND tag LIKE 'gha_%'", (eid,))})
    assert tags == ["gha_injection", "gha_pwn_request"]


def test_gha_tags_fire_recall_when_attached_to_a_host(tmp_db: Path) -> None:
    # Recall is host-scoped. A gha finding attached to a host (e.g. a self-hosted
    # runner) lights up its consumer rule; an engagement-level one is recorded
    # and queryable but does not drive the per-host menu.
    eid = _eng(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        hid = conn.execute("INSERT INTO host (engagement_id, ip, stage, first_seen) "
                           "VALUES (?, '10.0.0.5', 'scanned', 't')", (eid,)).lastrowid
        yhdb.add_finding(conn, int(hid), None, "cicd", "runner injection", "high",
                         "evidence", tag="gha_injection", engagement_id=eid)
        cands = {c.technique_id for c in kn.candidates_for(conn, eid)}
    assert "gha_expression_injection" in cands


def test_consumer_rules_load_and_are_gated() -> None:
    techs = {t.id: t for t in kn.load_techniques()}
    assert "gha_expression_injection" in techs and "gha_pwn_request" in techs
    # CI/CD exploitation is active -> gated, not auto.
    assert techs["gha_expression_injection"].autonomy != "proceed"
