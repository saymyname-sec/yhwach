"""End-to-end CLI tests (Click CliRunner). Covers the command surface, the
error/exit paths, and the run/advance/proof wiring."""
from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from yhwach import arsenal
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


def test_ui_refuses_bind_all_interfaces() -> None:
    import pytest

    pytest.importorskip("uvicorn")
    r = _run(["ui", "--lab", "L", "--host", "0.0.0.0", "--port", "8799"])
    assert r.exit_code == 2
    assert "all interfaces" in r.output or "refusing" in r.output.lower()


def test_engage_creates_db(tmp_path: Path) -> None:
    db = tmp_path / "e.db"
    r = _run(["engage", "--lab", "L", "--scope", "10.0.0.0/24", "--db", str(db)])
    assert r.exit_code == 0 and db.exists() and "ready" in r.output


def test_ingest_raw_records_finding_and_saves_loot(tmp_db: Path, tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("YHWACH_HOME", str(tmp_path))  # isolate the workspace/loot dir
    _run(["engage", "--lab", "L", "--scope", "10.0.0.0/24", "--db", str(tmp_db)])
    out = tmp_path / "out.txt"
    out.write_text("uid=0(root) gid=0(root)\nsecret line two\n")
    r = _run(["ingest", str(out), "--lab", "L", "--kind", "raw",
              "--title", "id on box", "--severity", "high", "--db", str(tmp_db)])
    assert r.exit_code == 0 and "Recorded raw finding" in r.output
    loot = tmp_path / "loot" / "raw_id_on_box.txt"
    assert loot.exists() and "secret line two" in loot.read_text()
    with yhdb.transaction(tmp_db) as conn:
        row = conn.execute("SELECT title, severity, evidence FROM finding WHERE title='id on box'").fetchone()
    assert row["severity"] == "high" and "full:" in row["evidence"]


def test_ingest_raw_requires_title(tmp_db: Path, tmp_path: Path) -> None:
    _run(["engage", "--lab", "L", "--scope", "10.0.0.0/24", "--db", str(tmp_db)])
    out = tmp_path / "o.txt"
    out.write_text("x")
    r = _run(["ingest", str(out), "--lab", "L", "--kind", "raw", "--db", str(tmp_db)])
    assert r.exit_code == 2 and "--title is required" in r.output


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
    # Post-arsenal-wiring: linux pivot default is chisel reverse-SOCKS,
    # not the stock ligolo agent. The rendered command must name chisel's
    # absolute canonical path and the reverse-SOCKS shape.
    assert "chisel" in r.output
    assert "R:1080:socks" in r.output
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
    # A token that is neither an IP/CIDR, a hostname, nor a wildcard.
    r = _run(["engage", "--lab", "X", "--scope", "10.0.0.0/99", "--db", str(db)])
    assert r.exit_code == 2 and "Invalid scope" in r.output


def test_engage_accepts_hostname_and_wildcard_scope(tmp_path: Path) -> None:
    db = tmp_path / "bounty.db"
    r = _run(["engage", "--lab", "B", "--kind", "bounty",
              "--scope", "*.example.com,app.example.com", "--db", str(db)])
    assert r.exit_code == 0
    # Bounty engagements start disarmed.
    assert "record_only" in r.output


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




# --- agent run (dry-run) ----------------------------------------------------

def test_run_dry_run_executes_and_reports(tmp_db: Path) -> None:
    _seed(tmp_db)  # lab L, one scanned host with an ollama surface
    r = _run(["run", "--lab", "L", "--dry-run", "--db", str(tmp_db)])
    assert r.exit_code == 0
    assert "Running agent on 'L'" in r.output
    assert "ENGAGEMENT STATE" in r.output
    with yhdb.transaction(tmp_db) as conn:
        eng = yhdb.engagement_id_for(conn, "L")
        attempts = yhdb.list_attempts(conn, eng)
    assert any(a["playbook_rule_id"] == "ollama_unauth_api" for a in attempts)


def test_run_unknown_lab_errors(tmp_db: Path) -> None:
    r = _run(["run", "--lab", "nope", "--dry-run", "--db", str(tmp_db)])
    assert r.exit_code == 2


def test_run_fan_out_dry(tmp_db: Path) -> None:
    _seed(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        eng = yhdb.engagement_id_for(conn, "L")
        hid = conn.execute(
            "INSERT INTO host (engagement_id, ip, os, stage, first_seen) "
            "VALUES (?, '10.0.0.6', 'linux', 'scanned', 't')", (eng,)).lastrowid
        yhdb.upsert_surface(conn, int(hid), None, "ollama", "none", "{}")
    r = _run(["run", "--lab", "L", "--dry-run", "--fan-out", "--db", str(tmp_db)])
    assert r.exit_code == 0
    assert "fan-out" in r.output


# --- doctor preflight -------------------------------------------------------

def test_doctor_reports_ready(tmp_db: Path) -> None:
    _seed(tmp_db)
    r = _run(["doctor", "--lab", "L", "--db", str(tmp_db)])
    assert r.exit_code == 0
    assert "preflight" in r.output
    assert "technique catalog loads" in r.output
    assert "ready." in r.output


def test_doctor_flags_missing_engagement(tmp_db: Path) -> None:
    _seed(tmp_db)
    r = _run(["doctor", "--lab", "does-not-exist", "--db", str(tmp_db)])
    assert r.exit_code == 1  # hard check failed
    assert "engagement 'does-not-exist' exists" in r.output


def test_run_allow_unknown_class_warns(tmp_db: Path) -> None:
    _seed(tmp_db)
    r = _run(["run", "--lab", "L", "--dry-run", "--allow", "bogus", "--db", str(tmp_db)])
    assert r.exit_code == 0
    assert "named no known action class" in r.output


def test_run_allow_grant_is_echoed(tmp_db: Path) -> None:
    _seed(tmp_db)
    r = _run(["run", "--lab", "L", "--dry-run", "--allow", "listener,push", "--db", str(tmp_db)])
    assert r.exit_code == 0
    assert "high-consequence grants enabled" in r.output
    assert "listener" in r.output and "push" in r.output


# ── revshell + pivot arsenal wiring ────────────────────────────────────────

def test_revshell_windows_renders_gen_sh_absolute_path() -> None:
    r = _run(["revshell", "--lport", "5986", "--os", "win"])
    assert r.exit_code == 0
    # Canonical Windows revshell generator (yhwach.arsenal.REVSHELL_GEN_WIN),
    # resolved to the vendored copy (or a legacy fallback if that is absent).
    assert str(arsenal.REVSHELL_GEN_WIN.path) in r.output
    assert "gen_cs_shell.sh" in r.output or "gen.sh" in r.output
    # Compile hints for both target sides.
    assert "mcs" in r.output
    assert "csc.exe" in r.output


def test_revshell_linux_renders_gen_linux_shell_absolute_path() -> None:
    r = _run(["revshell", "--lport", "4444", "--os", "linux"])
    assert r.exit_code == 0
    assert str(arsenal.REVSHELL_GEN_LINUX.path) in r.output
    assert "gen_linux_shell.sh" in r.output
    # Names every payload the generator emits so the operator can pick.
    for payload in ("bash_devtcp", "python_pty", "socat", "nc_mkfifo", "perl", "elf_revshell"):
        assert payload in r.output


def test_revshell_writes_to_default_loot_revshells_dir() -> None:
    r = _run(["revshell", "--lport", "4444", "--os", "linux"])
    assert r.exit_code == 0
    assert "/loot/revshells" in r.output


def test_revshell_outdir_override(tmp_path: Path) -> None:
    r = _run(["revshell", "--lport", "4444", "--os", "linux", "--outdir", str(tmp_path)])
    assert r.exit_code == 0
    assert str(tmp_path) in r.output


def test_revshell_requires_os_choice() -> None:
    # Click must reject an unknown --os value.
    r = _run(["revshell", "--lport", "4444", "--os", "solaris"])
    assert r.exit_code != 0


def test_pivot_kind_flag_forces_ligolo_on_linux(tmp_db: Path) -> None:
    _seed(tmp_db)  # linux host, chisel by default
    r = _run(["pivot", "--lab", "L", "--via-host", "10.0.0.5", "--subnet", "10.1.0.0/24",
              "--kind", "ligolo", "--db", str(tmp_db)])
    assert r.exit_code == 0
    assert "kind=ligolo" in r.output
    assert "LIGOLO_AGENT_LINUX" in r.output
    assert str(arsenal.LIGOLO_AGENT_LINUX.path) in r.output
    assert "ligolo-agent-linux" in r.output


def test_pivot_records_agent_key_in_output(tmp_db: Path) -> None:
    _seed(tmp_db)
    r = _run(["pivot", "--lab", "L", "--via-host", "10.0.0.5", "--subnet", "10.1.0.0/24",
              "--db", str(tmp_db)])
    assert r.exit_code == 0
    assert "agent=CHISEL" in r.output  # linux default
    assert "canonical arsenal binary" in r.output
