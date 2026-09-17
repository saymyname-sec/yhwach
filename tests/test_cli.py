"""End-to-end CLI tests (Click CliRunner). Covers the command surface, the
error/exit paths, and the run/advance/proof wiring."""
from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from yhwach import db as yhdb
from yhwach.cli import main


def _run(args: list[str]):
    return CliRunner().invoke(main, args)


def _seed(tmp_db: Path, kind: str = "ollama", port: int = 11434) -> None:
    """Engagement 'L' + one scanned host with a surface of the given kind."""
    with yhdb.transaction(tmp_db) as conn:
        eng = yhdb.upsert_engagement(conn, lab="L", scope="10.0.0.0/24")
        hid = conn.execute(
            "INSERT INTO host (engagement_id, ip, os, stage, first_seen) "
            "VALUES (?, '10.0.0.5', 'linux', 'scanned', 't')", (eng,)).lastrowid
        sid = conn.execute(
            "INSERT INTO service (host_id, port, proto, discovered_at) "
            "VALUES (?, ?, 'tcp', 't')", (hid, port)).lastrowid
        yhdb.upsert_surface(conn, int(hid), int(sid), kind, "none", "{}")


def _task_id(tmp_db: Path) -> int:
    with yhdb.transaction(tmp_db) as conn:
        return conn.execute("SELECT id FROM task LIMIT 1").fetchone()["id"]


# --- setup / ingestion ------------------------------------------------------

def test_version() -> None:
    r = _run(["--version"])
    assert r.exit_code == 0 and "yhwach" in r.output


def test_engage_creates_db(tmp_path: Path) -> None:
    db = tmp_path / "e.db"
    r = _run(["engage", "--lab", "L", "--scope", "10.0.0.0/24", "--db", str(db)])
    assert r.exit_code == 0 and db.exists() and "ready" in r.output


def test_ingest_nmap(tmp_db: Path, sample_nmap_xml: Path) -> None:
    _run(["engage", "--lab", "L", "--scope", "10.0.0.0/24", "--db", str(tmp_db)])
    r = _run(["ingest", str(sample_nmap_xml), "--lab", "L", "--db", str(tmp_db)])
    assert r.exit_code == 0 and "Ingested nmap" in r.output


def test_status(tmp_db: Path) -> None:
    _seed(tmp_db)
    r = _run(["status", "--lab", "L", "--db", str(tmp_db)])
    assert r.exit_code == 0 and "scanned" in r.output


# --- planning / handoff -----------------------------------------------------

def test_plan_next_run(tmp_db: Path) -> None:
    _seed(tmp_db)
    assert _run(["plan", "--lab", "L", "--db", str(tmp_db)]).exit_code == 0
    nxt = _run(["next", "--lab", "L", "--db", str(tmp_db)])
    assert "ollama_unauth_api" in nxt.output
    contract = _run(["next", "--lab", "L", "--contract", "--db", str(tmp_db)])
    assert "## FRAME" in contract.output
    rr = _run(["run", "--lab", "L", "--task", str(_task_id(tmp_db)), "--db", str(tmp_db)])
    assert rr.exit_code == 0 and "$ curl" in rr.output   # rendered, not executed


def test_run_unknown_task_exits_2(tmp_db: Path) -> None:
    _seed(tmp_db)
    r = _run(["run", "--lab", "L", "--task", "999", "--db", str(tmp_db)])
    assert r.exit_code == 2 and "not found" in r.output


def test_actions_list() -> None:
    r = _run(["actions"])
    assert r.exit_code == 0 and "probe_ollama_models" in r.output


# --- post-foothold ----------------------------------------------------------

def test_advance_looted_gated_by_proof(tmp_db: Path, tmp_path: Path) -> None:
    _seed(tmp_db)
    assert _run(["advance", "--lab", "L", "--host", "10.0.0.5", "--to", "foothold",
                 "--db", str(tmp_db)]).exit_code == 0
    refused = _run(["advance", "--lab", "L", "--host", "10.0.0.5", "--to", "looted",
                    "--db", str(tmp_db)])
    assert refused.exit_code == 1 and "proof" in refused.output

    shot = tmp_path / "s.png"
    shot.write_bytes(b"x")
    p = _run(["proof", "--lab", "L", "--host", "10.0.0.5", "--screenshot", str(shot),
              "--db", str(tmp_db)])
    assert p.exit_code == 0 and "looted" in p.output


def test_proof_missing_screenshot_exits_2(tmp_db: Path, tmp_path: Path) -> None:
    _seed(tmp_db)
    r = _run(["proof", "--lab", "L", "--host", "10.0.0.5",
              "--screenshot", str(tmp_path / "nope.png"), "--db", str(tmp_db)])
    assert r.exit_code == 2 and "not found" in r.output


def test_cred_creds_and_consume(tmp_db: Path) -> None:
    _seed(tmp_db)
    assert _run(["cred", "--lab", "L", "--user", "admin", "--secret", "P@ss",
                 "--db", str(tmp_db)]).exit_code == 0
    creds = _run(["creds", "--lab", "L", "--db", str(tmp_db)])
    assert "admin" in creds.output
    _run(["plan", "--lab", "L", "--db", str(tmp_db)])
    c = _run(["consume", "ollama_unauth_api", "--lab", "L", "--db", str(tmp_db)])
    assert c.exit_code == 0 and "consumed" in c.output


def test_pivot_records_tunnel_and_advances(tmp_db: Path) -> None:
    _seed(tmp_db)  # host 10.0.0.5 (linux)
    r = _run(["pivot", "--lab", "L", "--via-host", "10.0.0.5", "--subnet", "10.1.0.0/24",
              "--db", str(tmp_db)])
    assert r.exit_code == 0
    assert "10.1.0.0/24" in r.output and "pivoted" in r.output
    assert "./agent -connect" in r.output          # linux pivot -> stock agent
    rep = _run(["report", "--lab", "L", "--db", str(tmp_db)])
    assert "Reachability" in rep.output and "10.1.0.0/24" in rep.output


def test_spray_no_sprayable_surface(tmp_db: Path) -> None:
    _seed(tmp_db)  # ollama isn't sprayable
    _run(["cred", "--lab", "L", "--user", "admin", "--secret", "P@ss", "--db", str(tmp_db)])
    r = _run(["spray", "--lab", "L", "--db", str(tmp_db)])
    assert r.exit_code == 0 and "Nothing to spray" in r.output


# --- reporting / introspection ---------------------------------------------

def test_findings_empty(tmp_db: Path) -> None:
    _seed(tmp_db)
    r = _run(["findings", "--lab", "L", "--db", str(tmp_db)])
    assert "No findings" in r.output


def test_report(tmp_db: Path) -> None:
    _seed(tmp_db)
    r = _run(["report", "--lab", "L", "--db", str(tmp_db)])
    assert r.exit_code == 0 and "# Yhwach Engagement Report" in r.output


def test_report_timeline(tmp_db: Path) -> None:
    _seed(tmp_db)
    _run(["advance", "--lab", "L", "--host", "10.0.0.5", "--to", "foothold", "--db", str(tmp_db)])
    r = _run(["report", "--lab", "L", "--db", str(tmp_db)])
    assert "## Timeline" in r.output and "stage" in r.output


def test_engage_rejects_invalid_scope(tmp_path: Path) -> None:
    db = tmp_path / "bad.db"
    r = _run(["engage", "--lab", "X", "--scope", "not-a-cidr", "--db", str(db)])
    assert r.exit_code == 2 and "Invalid scope" in r.output


def test_enum_rejects_out_of_scope_target(tmp_db: Path) -> None:
    _run(["engage", "--lab", "L", "--scope", "10.0.0.0/24", "--db", str(tmp_db)])
    r = _run(["enum", "--lab", "L", "--target", "10.9.9.9", "--db", str(tmp_db)])
    assert r.exit_code == 2 and "not in scope" in r.output   # refused before HexStrike


def test_snapshot_to_stdout(tmp_db: Path) -> None:
    _seed(tmp_db)
    r = _run(["snapshot", "--lab", "L", "--db", str(tmp_db)])
    assert r.exit_code == 0 and "world_model" in r.output


def test_persona_prints_hash() -> None:
    r = _run(["persona"])
    assert r.exit_code == 0 and "sha256" in r.output


# --- error paths ------------------------------------------------------------

def test_unknown_lab_exits_2(tmp_db: Path) -> None:
    r = _run(["status", "--lab", "nope", "--db", str(tmp_db)])
    assert r.exit_code == 2 and "Unknown lab" in r.output


def test_missing_db_exits_2(tmp_path: Path) -> None:
    r = _run(["status", "--lab", "L", "--db", str(tmp_path / "nope.db")])
    assert r.exit_code == 2 and "not found" in r.output


# --- operator memory + enumeration coverage ---------------------------------

def test_outcome_fail_drops_the_task_from_next(tmp_db: Path) -> None:
    _seed(tmp_db)
    _run(["plan", "--lab", "L", "--db", str(tmp_db)])
    tid = _task_id(tmp_db)
    r = _run(["outcome", "--lab", "L", "--result", "fail", "--task", str(tid),
              "--why", "endpoint 404s", "--db", str(tmp_db)])
    assert r.exit_code == 0 and "abandoned" in r.output
    nxt = _run(["next", "--lab", "L", "--db", str(tmp_db)])
    assert "No pending tasks" in nxt.output


def test_outcome_success_consumes_and_prompts_for_the_note(tmp_db: Path) -> None:
    _seed(tmp_db)
    _run(["plan", "--lab", "L", "--db", str(tmp_db)])
    r = _run(["outcome", "--lab", "L", "--result", "success", "--task",
              str(_task_id(tmp_db)), "--why", "leaked key", "--db", str(tmp_db)])
    assert r.exit_code == 0
    assert "consumed" in r.output and "Obsidian vault" in r.output


def test_outcome_needs_a_target(tmp_db: Path) -> None:
    _seed(tmp_db)
    r = _run(["outcome", "--lab", "L", "--result", "fail", "--db", str(tmp_db)])
    assert r.exit_code == 2 and "task id or a playbook rule id" in r.output


def test_outcome_rejects_an_unknown_result(tmp_db: Path) -> None:
    _seed(tmp_db)
    r = _run(["outcome", "--lab", "L", "--result", "sideways", "--task", "1",
              "--db", str(tmp_db)])
    assert r.exit_code == 2  # click rejects it against the choice list


def test_recall_renders_and_has_a_json_mode(tmp_db: Path) -> None:
    import json

    _seed(tmp_db)
    r = _run(["recall", "--lab", "L", "--db", str(tmp_db)])
    assert r.exit_code == 0 and "YHWACH RECALL" in r.output
    j = _run(["recall", "--lab", "L", "--json", "--db", str(tmp_db)])
    assert j.exit_code == 0 and json.loads(j.output)["lab"] == "L"


def test_gaps_lists_hosts_and_the_fix_command(tmp_db: Path) -> None:
    _seed(tmp_db)
    r = _run(["gaps", "--lab", "L", "--db", str(tmp_db)])
    assert r.exit_code == 0
    assert "10.0.0.5" in r.output and "nmap -p-" in r.output


def test_ingest_records_coverage_and_flags_gaps(tmp_db: Path, tmp_path: Path) -> None:
    _run(["engage", "--lab", "L", "--scope", "10.0.0.0/24", "--db", str(tmp_db)])
    xml = tmp_path / "s.xml"
    xml.write_text(
        '<?xml version="1.0"?><nmaprun args="nmap -p 1-1000 -oX - 10.0.0.5">'
        '<scaninfo type="syn" protocol="tcp" numservices="1000" services="1-1000"/>'
        '<host><status state="up"/><address addr="10.0.0.5" addrtype="ipv4"/>'
        '<ports><port protocol="tcp" portid="22"><state state="open"/>'
        '<service name="ssh"/></port></ports></host></nmaprun>', encoding="utf-8")
    r = _run(["ingest", str(xml), "--lab", "L", "--db", str(tmp_db)])
    assert r.exit_code == 0
    assert "coverage: tcp 1-1000" in r.output
    assert "under-enumerated" in r.output
    g = _run(["gaps", "--lab", "L", "--json", "--db", str(tmp_db)])
    assert "full_tcp" in g.output


def test_advance_to_enumerated_warns_but_still_advances(tmp_db: Path) -> None:
    _seed(tmp_db)
    r = _run(["advance", "--lab", "L", "--host", "10.0.0.5", "--to", "enumerated",
              "--db", str(tmp_db)])
    assert r.exit_code == 0
    assert "-> enumerated" in r.output
    assert "NOT fully enumerated" in r.output


def test_next_contract_no_persona_is_much_cheaper(tmp_db: Path) -> None:
    _seed(tmp_db)
    _run(["plan", "--lab", "L", "--db", str(tmp_db)])
    full = _run(["next", "--lab", "L", "--contract", "--db", str(tmp_db)]).output
    cheap = _run(["next", "--lab", "L", "--contract", "--no-persona",
                  "--db", str(tmp_db)]).output
    assert "sha256:" in cheap and len(cheap) < len(full) / 2
    assert "## RANKED CANDIDATES" in cheap


def test_next_json_emits_the_handoff_as_data(tmp_db: Path) -> None:
    import json

    _seed(tmp_db)
    _run(["plan", "--lab", "L", "--db", str(tmp_db)])
    r = _run(["next", "--lab", "L", "--json", "--db", str(tmp_db)])
    data = json.loads(r.output)
    assert data["engagement"]["lab"] == "L"
    assert data["candidates"] and data["candidates"][0]["task_id"]
