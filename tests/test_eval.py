"""End-to-end eval: seed a fixture lab with known flaws and assert the full agent
loop discovers them. Only HexStrike is stubbed — knowledge -> orchestrator ->
executor -> runner -> interpret -> memory all run for real (no LLM, no network).

This is the measurable "does the agent find the planted flaws" harness the audit
called for: add a host+surface+canned-output here and assert the tag it should
yield.
"""

from __future__ import annotations

import json
from pathlib import Path

from yhwach import db as yhdb
from yhwach import dryrun, runners, workers


class StubHex:
    """A fixture HexStrike: canned tool output keyed by command substring."""

    def __init__(self, responses: dict[str, str]):
        self.responses = responses

    def run_command(self, command: str, *, timeout=None) -> dict:
        for needle, stdout in self.responses.items():
            if needle in command:
                return {"stdout": stdout, "success": True, "return_code": 0}
        return {"stdout": "", "success": True, "return_code": 0}


# The planted lab: two hosts, each with a flaw the agent should surface.
LAB_RESPONSES = {
    "/api/tags": json.dumps({"models": [{"name": "llama3"}, {"name": "mistral"}]}),
    "/api/version": json.dumps({"version": "0.1.20"}),  # < 0.1.34 -> probllama
    "nxc ldap": "LDAP 10.0.0.6 389 dc01 [+] corp.local\\: (anonymous bind allowed)",
    "ldapsearch": "namingContexts: DC=corp,DC=local",
}
EXPECTED_TAGS = {"ollama_probllama", "ldap_anon"}


def _seed_lab(conn) -> int:
    eid = yhdb.upsert_engagement(conn, lab="eval", scope="10.0.0.0/24")
    o = conn.execute(
        "INSERT INTO host (engagement_id, ip, os, stage, first_seen) "
        "VALUES (?, '10.0.0.5', 'linux', 'scanned', 't')",
        (eid,),
    ).lastrowid
    yhdb.upsert_surface(conn, int(o), None, "ollama", "none", "{}")
    d = conn.execute(
        "INSERT INTO host (engagement_id, ip, os, stage, first_seen) "
        "VALUES (?, '10.0.0.6', 'linux', 'scanned', 't')",
        (eid,),
    ).lastrowid
    yhdb.upsert_surface(conn, int(d), None, "ldap", "none", "{}")
    return eid


def test_agent_finds_planted_flaws_end_to_end(tmp_db: Path) -> None:
    stub = StubHex(LAB_RESPONSES)
    with yhdb.transaction(tmp_db) as conn:
        eid = _seed_lab(conn)
        runner = runners.HexStrikeRunner(stub, conn, eid)
        report = workers.run_workers(
            conn,
            eid,
            doer_for=lambda ip: dryrun.DeterministicDoer(conn, eid, host_ip=ip),
            judge_brain=dryrun.DeterministicJudge(conn, eid),
            runner=runner,
        )
        tags = {
            r["tag"]
            for r in conn.execute(
                "SELECT DISTINCT tag FROM finding WHERE engagement_id=? AND tag IS NOT NULL",
                (eid,),
            ).fetchall()
        }
        stages = {
            r["ip"]: r["stage"]
            for r in conn.execute(
                "SELECT ip, stage FROM host WHERE engagement_id=?", (eid,)
            ).fetchall()
        }

    # the measurable result: every planted flaw was discovered
    assert tags >= EXPECTED_TAGS, f"missed: {EXPECTED_TAGS - tags}"
    # both hosts were worked and advanced out of 'scanned'
    assert stages == {"10.0.0.5": "enumerated", "10.0.0.6": "enumerated"}
    # each host worker executed at least one technique
    assert report.total_executed >= 2


def test_eval_reports_findings_in_synthesis(tmp_db: Path) -> None:
    from yhwach import synthesis

    stub = StubHex(LAB_RESPONSES)
    with yhdb.transaction(tmp_db) as conn:
        eid = _seed_lab(conn)
        runner = runners.HexStrikeRunner(stub, conn, eid)
        workers.run_workers(
            conn,
            eid,
            doer_for=lambda ip: dryrun.DeterministicDoer(conn, eid, host_ip=ip),
            judge_brain=dryrun.DeterministicJudge(conn, eid),
            runner=runner,
        )
        report = synthesis.phase_report(conn, eid)

    # the planted critical flaw shows up as a confirmed lead in the report
    assert "ollama_probllama" in report
    assert "Confirmed leads" in report
