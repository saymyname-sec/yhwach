"""Tests for the deterministic no-key dry-run brains + full loop integration."""

from __future__ import annotations

from pathlib import Path

from yhwach import db as yhdb
from yhwach import dryrun
from yhwach import orchestrator as orch


def _engagement(conn, ip="10.0.0.5"):
    eid = yhdb.upsert_engagement(conn, lab="t", scope="10.0.0.0/24")
    cur = conn.execute(
        "INSERT INTO host (engagement_id, ip, os, stage, first_seen) "
        "VALUES (?, ?, 'linux', 'scanned', '2026-01-01T00:00:00Z')",
        (eid, ip),
    )
    yhdb.upsert_surface(conn, int(cur.lastrowid), None, "ollama", "none", "{}")
    return eid


def test_doer_picks_read_only_candidate(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        eid = _engagement(conn)
        doer = dryrun.DeterministicDoer(conn, eid)
        action = doer.decide("ignored")
    assert action.action == "run_technique"
    assert action.technique_id == "ollama_unauth_api"
    assert action.host_ip == "10.0.0.5"


def test_doer_stops_when_all_emitted(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        eid = _engagement(conn)
        doer = dryrun.DeterministicDoer(conn, eid)
        # Post-arsenal-wiring: os=linux hosts also carry the os-only
        # generate_linux_revshell rule, so the doer emits both. Consume
        # every candidate before we assert the doer runs out.
        first = doer.decide("x")
        assert first.action == "run_technique"
        for _ in range(6):  # loose upper bound; catalog has ~2 for this host
            action = doer.decide("x")
            if action.action == "mark_phase_done":
                break
        assert action.action == "mark_phase_done"


def test_judge_not_done_when_hosts_unenumerated(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        eid = _engagement(conn)  # host is 'scanned' -> unenumerated
        verdict = dryrun.DeterministicJudge(conn, eid).decide("x")
    assert verdict.action == "note"


def test_judge_done_when_clean(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.upsert_engagement(conn, lab="t", scope="10.0.0.0/24")
        cur = conn.execute(
            "INSERT INTO host (engagement_id, ip, os, stage, first_seen) "
            "VALUES (?, '10.0.0.6', 'linux', 'enumerated', '2026-01-01T00:00:00Z')",
            (eid,),
        )
        yhdb.record_coverage(
            conn, int(cur.lastrowid), proto="tcp", ports="1-65535", full_range=True
        )
        verdict = dryrun.DeterministicJudge(conn, eid).decide("x")
    assert verdict.action == "mark_phase_done"


def test_full_dry_loop_runs_and_converges(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        eid = _engagement(conn)
        report = orch.Orchestrator(
            conn,
            eid,
            doer=dryrun.DeterministicDoer(conn, eid),
            judge_brain=dryrun.DeterministicJudge(conn, eid),
        ).run()
        attempts = yhdb.list_attempts(conn, eid)

    # Post-arsenal-wiring: an os=linux host has two applicable candidates —
    # the ollama read-only recon (auto-executed) AND generate_linux_revshell
    # (gated). The loop runs the read-only one and halts with
    # 'awaiting_approval' because the revshell rule is queued behind the
    # --allow-gated gate. The important invariants — 1 attempt actually
    # executed AND the loop converges — still hold.
    assert report.executed == 1
    assert report.halt_reason in ("no_candidates", "awaiting_approval")
    assert len(attempts) == 1
