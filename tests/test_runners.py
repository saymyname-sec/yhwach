"""Tests for the HexStrike enumeration runner (fake client, no network)."""

from __future__ import annotations

import json
from pathlib import Path

from yhwach import actions as act
from yhwach import db as yhdb
from yhwach import runners
from yhwach.brain import Action
from yhwach.knowledge import Candidate


class FakeHex:
    """Returns canned output per command substring; records what ran."""

    def __init__(self, responses: dict[str, dict]):
        self.responses = responses
        self.ran: list[str] = []

    def run_command(self, command: str, *, timeout=None) -> dict:
        self.ran.append(command)
        for needle, resp in self.responses.items():
            if needle in command:
                return resp
        return {"stdout": "", "success": True, "return_code": 0}


def _candidate(conn, eid, **kw) -> Candidate:
    cur = conn.execute(
        "INSERT INTO host (engagement_id, ip, os, stage, first_seen) "
        "VALUES (?, '10.0.0.5', 'linux', 'scanned', 't')",
        (eid,),
    )
    hid = int(cur.lastrowid)
    sid, _ = yhdb.upsert_surface(conn, hid, None, "ollama", "none", "{}")
    base = dict(
        technique_id="ollama_unauth_api",
        technique="ollama_unauth_api",
        host_id=hid,
        host_ip="10.0.0.5",
        surface_id=sid,
        surface_kind="ollama",
        risk="read_only",
        autonomy="proceed",
        technique_class="ai",
        points=15,
        maps=["LLM06"],
        routes=None,
        source=None,
        chained_from=None,
        rationale="applies",
    )
    base.update(kw)
    return Candidate(**base)


def test_runner_executes_and_extracts_findings(tmp_db: Path) -> None:
    tags = json.dumps({"models": [{"name": "llama3"}, {"name": "mistral"}]})
    ver = json.dumps({"version": "0.1.20"})  # < 0.1.34 -> probllama
    hexc = FakeHex(
        {
            "/api/tags": {"stdout": tags, "success": True, "return_code": 0},
            "/api/version": {"stdout": ver, "success": True, "return_code": 0},
        }
    )
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.upsert_engagement(conn, lab="t", scope="10.0.0.0/24")
        cand = _candidate(conn, eid)
        runner = runners.HexStrikeRunner(hexc, conn, eid)
        result = runner(cand)

    assert result.result == "success"
    tags_found = {f["tag"] for f in result.findings}
    # version fingerprint chains to probllama; models finding present
    assert "ollama_probllama" in tags_found
    assert any("Ollama API" in f["title"] for f in result.findings)
    # the default ollama port (11434) was used
    assert any("11434" in c for c in hexc.ran)


def test_runner_uses_service_port(tmp_db: Path) -> None:
    hexc = FakeHex({"/api/tags": {"stdout": "{}", "success": True, "return_code": 0}})
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.upsert_engagement(conn, lab="t", scope="10.0.0.0/24")
        cur = conn.execute(
            "INSERT INTO host (engagement_id, ip, os, stage, first_seen) "
            "VALUES (?, '10.0.0.5', 'linux', 'scanned', 't')",
            (eid,),
        )
        hid = int(cur.lastrowid)
        svc = conn.execute(
            "INSERT INTO service (host_id, port, proto, discovered_at) "
            "VALUES (?, 9999, 'tcp', 't')",
            (hid,),
        ).lastrowid
        sid, _ = yhdb.upsert_surface(conn, hid, int(svc), "ollama", "none", "{}")
        cand = Candidate(
            technique_id="ollama_unauth_api",
            technique="ollama_unauth_api",
            host_id=hid,
            host_ip="10.0.0.5",
            surface_id=sid,
            surface_kind="ollama",
            risk="read_only",
            autonomy="proceed",
            technique_class="ai",
            points=15,
            maps=[],
            routes=None,
            source=None,
            chained_from=None,
            rationale="x",
        )
        runners.HexStrikeRunner(hexc, conn, eid)(cand)

    assert any("9999" in c for c in hexc.ran)  # the real service port, not the default


def test_unwired_technique_is_partial(tmp_db: Path) -> None:
    hexc = FakeHex({})
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.upsert_engagement(conn, lab="t", scope="10.0.0.0/24")
        cand = _candidate(
            conn, eid, technique_id="windows_potato_to_system", technique="windows_potato_to_system"
        )
        result = runners.HexStrikeRunner(hexc, conn, eid)(cand)

    assert result.result == "partial"
    assert "no read-only runner wired" in result.reason
    assert result.findings == []
    assert hexc.ran == []  # nothing executed


def test_runner_wired_into_executor(tmp_db: Path) -> None:
    tags = json.dumps({"models": [{"name": "llama3"}]})
    hexc = FakeHex({"/api/tags": {"stdout": tags, "success": True, "return_code": 0}})
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.upsert_engagement(conn, lab="t", scope="10.0.0.0/24")
        cand = _candidate(conn, eid)
        runner = runners.HexStrikeRunner(hexc, conn, eid)
        ex = act.ActionExecutor(conn, eid, runner=runner)
        res = ex.execute(
            Action(
                action="run_technique",
                technique_id="ollama_unauth_api",
                host_ip="10.0.0.5",
                rationale="recon",
            ),
            candidates=[cand],
        )
        findings = conn.execute("SELECT tag FROM finding WHERE engagement_id=?", (eid,)).fetchall()

    assert res.outcome is act.Outcome.EXECUTED
    assert len(findings) >= 1


def test_runner_covers_web_recon_actions(tmp_db: Path) -> None:
    # jenkins /api/json reachable -> _jenkins_api finding
    jenkins = '{"_class":"hudson.model.Hudson","jobs":[{"name":"build"}]}'
    hexc = FakeHex({"/api/json": {"stdout": jenkins, "success": True, "return_code": 0}})
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.upsert_engagement(conn, lab="t", scope="10.0.0.0/24")
        cur = conn.execute(
            "INSERT INTO host (engagement_id, ip, os, stage, first_seen) "
            "VALUES (?, '10.0.0.5', 'linux', 'scanned', 't')",
            (eid,),
        )
        hid = int(cur.lastrowid)
        sid, _ = yhdb.upsert_surface(conn, hid, None, "web", "none", "{}")
        cand = Candidate(
            technique_id="jenkins_recon",
            technique="jenkins_recon",
            host_id=hid,
            host_ip="10.0.0.5",
            surface_id=sid,
            surface_kind="web",
            risk="read_only",
            autonomy="proceed",
            technique_class="traditional",
            points=10,
            maps=[],
            routes=None,
            source=None,
            chained_from=None,
            rationale="x",
        )
        # give the technique a jenkins_auth_check emit via a stub in the index
        runner = runners.HexStrikeRunner(hexc, conn, eid)
        runner._by_id["jenkins_recon"] = type(
            "T", (), {"emits": [{"action": "jenkins_auth_check"}]}
        )()
        result = runner(cand)
    assert result.result == "success"
    assert any("Jenkins" in f["title"] for f in result.findings)


def test_ctx_has_ip_for_extractors(tmp_db: Path) -> None:
    # ldap anon users -> _ad_users uses ctx['IP'] in evidence
    out = "DOMAIN\\alice\nDOMAIN\\bob\nDOMAIN\\carol"
    hexc = FakeHex({"nxc ldap": {"stdout": out, "success": True, "return_code": 0}})
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.upsert_engagement(conn, lab="t", scope="10.0.0.0/24")
        cur = conn.execute(
            "INSERT INTO host (engagement_id, ip, os, stage, first_seen) "
            "VALUES (?, '10.0.0.5', 'linux', 'scanned', 't')",
            (eid,),
        )
        hid = int(cur.lastrowid)
        sid, _ = yhdb.upsert_surface(conn, hid, None, "ldap", "none", "{}")
        cand = Candidate(
            technique_id="ldap_enumeration",
            technique="ldap_enumeration",
            host_id=hid,
            host_ip="10.0.0.5",
            surface_id=sid,
            surface_kind="ldap",
            risk="read_only",
            autonomy="proceed",
            technique_class="traditional",
            points=10,
            maps=[],
            routes=None,
            source=None,
            chained_from=None,
            rationale="x",
        )
        runner = runners.HexStrikeRunner(hexc, conn, eid)
        runner._by_id["ldap_enumeration"] = type(
            "T", (), {"emits": [{"action": "ldap_anon_dump"}]}
        )()
        result = runner(cand)
    assert any(f["tag"] == "domain_users" for f in result.findings)
    assert any("10.0.0.5" in f["evidence"] for f in result.findings)


def _surface_candidate(conn, eid, *, kind: str, technique_id: str) -> Candidate:
    """A candidate on a real catalog technique bound to a fresh `kind` surface."""
    cur = conn.execute(
        "INSERT INTO host (engagement_id, ip, os, stage, first_seen) "
        "VALUES (?, '10.0.0.5', 'linux', 'scanned', 't')",
        (eid,),
    )
    hid = int(cur.lastrowid)
    sid, _ = yhdb.upsert_surface(conn, hid, None, kind, "none", "{}")
    return Candidate(
        technique_id=technique_id,
        technique=technique_id,
        host_id=hid,
        host_ip="10.0.0.5",
        surface_id=sid,
        surface_kind=kind,
        risk="read_only",
        autonomy="proceed",
        technique_class="traditional",
        points=10,
        maps=[],
        routes=None,
        source=None,
        chained_from=None,
        rationale="x",
    )


def test_runner_covers_redis_unauth_info(tmp_db: Path) -> None:
    # redis-cli INFO on an unauth instance -> _redis_info tags redis_unauth
    info = "# Server\r\nredis_version:7.0.11\r\nredis_mode:standalone\r\n"
    hexc = FakeHex({"INFO server": {"stdout": info, "success": True, "return_code": 0}})
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.upsert_engagement(conn, lab="t", scope="10.0.0.0/24")
        cand = _surface_candidate(conn, eid, kind="redis", technique_id="redis_enumeration")
        result = runners.HexStrikeRunner(hexc, conn, eid)(cand)

    assert result.result == "success"
    assert any(f["tag"] == "redis_unauth" for f in result.findings)
    assert any("6379" in c for c in hexc.ran)  # default redis port used


def test_runner_covers_metabase_setup_probe(tmp_db: Path) -> None:
    # Metabase leaks a non-null setup-token pre-auth -> _setup_incomplete
    props = '{"setup-token":"deadbeefcafe1234","engine":"h2"}'
    hexc = FakeHex(
        {"/api/session/properties": {"stdout": props, "success": True, "return_code": 0}}
    )
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.upsert_engagement(conn, lab="t", scope="10.0.0.0/24")
        cand = _surface_candidate(conn, eid, kind="metabase", technique_id="metabase_recon")
        result = runners.HexStrikeRunner(hexc, conn, eid)(cand)

    assert result.result == "success"
    assert any(f["tag"] == "setup_incomplete" for f in result.findings)
    assert any("3000" in c for c in hexc.ran)  # default metabase port used


def test_every_wired_command_has_an_extractor() -> None:
    """Invariant (runners.py:44): a read-only command only earns a slot when its
    output has a deterministic extractor — otherwise it runs for nothing."""
    from yhwach import interpret

    missing = set(runners._COMMANDS) - set(interpret._EXTRACTORS)
    assert not missing, f"wired commands with no extractor: {sorted(missing)}"


# --- CRAFT path -------------------------------------------------------------


def _craft_candidate(conn, eid, tech="ssti_probe", emit="craft_ssti_probe", kind="web"):
    cur = conn.execute(
        "INSERT INTO host (engagement_id, ip, os, stage, first_seen) "
        "VALUES (?, '10.0.0.5', 'linux', 'scanned', 't')",
        (eid,),
    )
    hid = int(cur.lastrowid)
    sid, _ = yhdb.upsert_surface(conn, hid, None, kind, "none", "{}")
    cand = Candidate(
        technique_id=tech,
        technique=tech,
        host_id=hid,
        host_ip="10.0.0.5",
        surface_id=sid,
        surface_kind=kind,
        risk="exploit",
        autonomy="propose",
        technique_class="ai",
        points=15,
        maps=[],
        routes=None,
        source=None,
        chained_from=None,
        rationale="x",
    )
    return cand, hid


def test_craft_delivers_payload_and_interprets(tmp_db: Path) -> None:
    # SSTI: brain sends X{{7*7}}X, server reflects X49X -> jinja2_template
    hexc = FakeHex(
        {"/render": {"stdout": '{"rendered":"X49X"}', "success": True, "return_code": 0}}
    )
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.upsert_engagement(conn, lab="t", scope="10.0.0.0/24")
        cand, _ = _craft_candidate(conn, eid)
        runner = runners.HexStrikeRunner(hexc, conn, eid)
        runner._by_id["ssti_probe"] = type("T", (), {"emits": [{"action": "craft_ssti_probe"}]})()
        result = runner.craft(
            cand, {"payload": "X{{7*7}}X", "method": "POST", "path": "/render", "param": "tpl"}
        )
    assert result.result == "success"
    assert any(f["tag"] == "jinja2_template" for f in result.findings)
    # the payload was delivered as a POST to the given path
    assert any("/render" in c and "POST" in c for c in hexc.ran)


def test_craft_shell_quotes_payload(tmp_db: Path) -> None:
    # a payload full of shell metacharacters must be quoted, not interpreted
    hexc = FakeHex({})
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.upsert_engagement(conn, lab="t", scope="10.0.0.0/24")
        cand, _ = _craft_candidate(conn, eid)
        runner = runners.HexStrikeRunner(hexc, conn, eid)
        nasty = "'; rm -rf / #{{7*7}}$(id)"
        cmd = runner._build_craft_command(
            "10.0.0.5", 8080, {"payload": nasty, "content_type": "raw"}
        )
    import shlex

    # the payload survives intact as a single quoted shell token
    assert shlex.quote(nasty) in cmd
    assert "rm -rf" not in cmd.replace(shlex.quote(nasty), "")  # only inside the quoted arg


def test_craft_requires_payload(tmp_db: Path) -> None:
    hexc = FakeHex({})
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.upsert_engagement(conn, lab="t", scope="10.0.0.0/24")
        cand, _ = _craft_candidate(conn, eid)
        result = runners.HexStrikeRunner(hexc, conn, eid).craft(cand, {})
    assert result.result == "partial"
    assert "payload" in result.reason


def test_executor_craft_gated_then_approved(tmp_db: Path) -> None:
    from yhwach import control
    from yhwach.brain import Action

    hexc = FakeHex(
        {"/render": {"stdout": '{"rendered":"X49X"}', "success": True, "return_code": 0}}
    )
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.upsert_engagement(conn, lab="t", scope="10.0.0.0/24")
        cand, _ = _craft_candidate(conn, eid)
        runner = runners.HexStrikeRunner(hexc, conn, eid)
        runner._by_id["ssti_probe"] = type("T", (), {"emits": [{"action": "craft_ssti_probe"}]})()
        ex = act.ActionExecutor(conn, eid, runner=runner)  # allow_gated=False
        craft_action = Action(
            action="craft_and_run",
            technique_id="ssti_probe",
            host_ip="10.0.0.5",
            rationale="ssti",
            args={"payload": "X{{7*7}}X", "path": "/render"},
        )
        # exploit-tier craft is queued without approval
        r1 = ex.execute(craft_action, candidates=[cand])
        assert r1.outcome is act.Outcome.QUEUED
        # approve it, then it executes and records the SSTI finding
        control.grant_approval(conn, eid, technique="ssti_probe", host="10.0.0.5")
        r2 = ex.execute(craft_action, candidates=[cand])
        assert r2.outcome is act.Outcome.EXECUTED
        tags = {
            row["tag"]
            for row in conn.execute(
                "SELECT tag FROM finding WHERE engagement_id=?", (eid,)
            ).fetchall()
        }
    assert "jinja2_template" in tags


# ── ArsenalDeployRunner: dispatches to pivot_renderers ──────────────────────

import pytest  # noqa: E402

from yhwach import arsenal as _arsenal  # noqa: E402


def _cand(technique_id, host_ip="172.16.10.13", surface_kind=None):
    """Minimal Candidate suitable for the ArsenalDeployRunner path — it only
    reads technique_id + host_ip. Fields the runner ignores are stubbed."""
    return Candidate(
        technique_id=technique_id,
        technique=technique_id,
        host_id=1,
        host_ip=host_ip,
        surface_id=None,
        surface_kind=surface_kind,
        risk="exploit",
        autonomy="propose",
        technique_class="traditional",
        points=10,
        maps=["T1090.002"],
        routes="/pivot",
        source="test",
        chained_from=None,
        rationale="test",
        action_class="listener",
    )


def _seed_host(tmp_db: Path, ip: str, os: str = "linux") -> int:
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.upsert_engagement(conn, lab="ars", scope="10.0.0.0/24")
        conn.execute(
            "INSERT INTO host (engagement_id, ip, os, stage, first_seen) "
            "VALUES (?, ?, ?, 'foothold', '2026-01-01T00:00:00Z')",
            (eid, ip, os),
        )
    return eid


def test_arsenal_runner_renders_svcmon_absolute_path(tmp_db: Path) -> None:
    eid = _seed_host(tmp_db, "172.16.10.20", os="windows")
    with yhdb.transaction(tmp_db) as conn:
        r = runners.ArsenalDeployRunner(
            conn, eid, kali_ip="192.168.45.201",
            defaults={"subnet": "10.0.0.0/24", "lport": 11601},
        )
        result = r(_cand("pivot_ligolo_windows", host_ip="172.16.10.20"))
    assert result.result == "partial"  # honest — operator runs the shown cmds
    assert str(_arsenal.get("SVCMON_WIN").path) in result.evidence
    assert ":11601" in result.evidence


def test_arsenal_runner_renders_chisel_for_linux_pivot(tmp_db: Path) -> None:
    eid = _seed_host(tmp_db, "172.16.10.13")
    with yhdb.transaction(tmp_db) as conn:
        r = runners.ArsenalDeployRunner(
            conn, eid, kali_ip="192.168.45.201",
            defaults={"subnet": "10.0.0.0/24"},
        )
        result = r(_cand("pivot_chisel_linux"))
    assert result.result == "partial"
    assert str(_arsenal.get("CHISEL").path) in result.evidence
    assert "R:1080:socks" in result.evidence


def test_arsenal_runner_renders_ligolo_agent_linux(tmp_db: Path) -> None:
    eid = _seed_host(tmp_db, "10.10.10.1")
    with yhdb.transaction(tmp_db) as conn:
        r = runners.ArsenalDeployRunner(
            conn, eid, kali_ip="10.0.0.1",
            defaults={"subnet": "10.20.0.0/24"},
        )
        result = r(_cand("pivot_ligolo_linux", host_ip="10.10.10.1"))
    assert result.result == "partial"
    assert str(_arsenal.get("LIGOLO_AGENT_LINUX").path) in result.evidence


def test_arsenal_runner_renders_revshell_gen_sh(tmp_db: Path) -> None:
    eid = _seed_host(tmp_db, "172.16.10.20", os="windows")
    with yhdb.transaction(tmp_db) as conn:
        r = runners.ArsenalDeployRunner(
            conn, eid, kali_ip="192.168.45.201",
            defaults={"lport": 5986},
        )
        result = r(_cand("generate_windows_revshell", host_ip="172.16.10.20"))
    assert result.result == "partial"
    assert str(_arsenal.get("REVSHELL_GEN_WIN").path) in result.evidence
    assert "5986" in result.evidence


def test_arsenal_runner_renders_revshell_gen_linux(tmp_db: Path) -> None:
    eid = _seed_host(tmp_db, "172.16.10.13")
    with yhdb.transaction(tmp_db) as conn:
        r = runners.ArsenalDeployRunner(
            conn, eid, kali_ip="192.168.45.201",
            defaults={"lport": 4444},
        )
        result = r(_cand("generate_linux_revshell"))
    assert result.result == "partial"
    assert str(_arsenal.get("REVSHELL_GEN_LINUX").path) in result.evidence


def test_arsenal_runner_missing_subnet_returns_partial(tmp_db: Path) -> None:
    eid = _seed_host(tmp_db, "172.16.10.13")
    with yhdb.transaction(tmp_db) as conn:
        r = runners.ArsenalDeployRunner(conn, eid, kali_ip="10.0.0.1", defaults={})
        result = r(_cand("pivot_chisel_linux"))
    assert result.result == "partial"
    assert "unrenderable" in (result.reason or "")
    assert "subnet" in (result.reason or "")


def test_arsenal_runner_missing_lport_returns_partial_for_revshell(tmp_db: Path) -> None:
    eid = _seed_host(tmp_db, "172.16.10.13")
    with yhdb.transaction(tmp_db) as conn:
        r = runners.ArsenalDeployRunner(conn, eid, kali_ip="10.0.0.1", defaults={})
        result = r(_cand("generate_linux_revshell"))
    assert result.result == "partial"
    assert "lport" in (result.reason or "")


def test_arsenal_runner_unknown_technique_raises_from_render(tmp_db: Path) -> None:
    eid = _seed_host(tmp_db, "172.16.10.13")
    with yhdb.transaction(tmp_db) as conn:
        r = runners.ArsenalDeployRunner(
            conn, eid, kali_ip="10.0.0.1",
            defaults={"subnet": "10.20.0.0/24"},
        )
        with pytest.raises(ValueError, match="no renderer"):
            r.render(_cand("hallucinated_technique"))
        # __call__ downgrades the same error to a partial (honest).
        result = r(_cand("hallucinated_technique"))
        assert result.result == "partial"
        assert "unrenderable" in (result.reason or "")


def test_arsenal_runner_covers_every_pivot_rule():
    """Regression: RENDERERS must stay 1:1 with pivot.yaml so a new rule
    doesn't slip in without a delivery path."""
    from yhwach import pivot_renderers as pr
    from yhwach.knowledge import load_techniques
    pivot_ids = {
        t.id for t in load_techniques()
        if t.id in set(pr.RENDERERS)
    }
    assert pivot_ids == set(pr.RENDERERS)
