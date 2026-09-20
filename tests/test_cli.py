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

def test_pivot_records_tunnel_and_advances(tmp_db: Path) -> None:
    _seed(tmp_db)  # host 10.0.0.5 (linux)
    r = _run(["pivot", "--lab", "L", "--via-host", "10.0.0.5", "--subnet", "10.1.0.0/24",
              "--db", str(tmp_db)])
    assert r.exit_code == 0
    assert "10.1.0.0/24" in r.output and "pivoted" in r.output
    assert "./agent -connect" in r.output          # linux pivot -> stock agent
    rep = _run(["report", "--lab", "L", "--db", str(tmp_db)])
    assert "Reachability" in rep.output and "10.1.0.0/24" in rep.output


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

def test_outcome_rejects_an_unknown_result(tmp_db: Path) -> None:
    _seed(tmp_db)
    r = _run(["outcome", "--lab", "L", "--result", "sideways", "--task", "1",
              "--db", str(tmp_db)])
    assert r.exit_code == 2  # click rejects it against the choice list


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


