"""Tests for per-host worker fan-out."""

from __future__ import annotations

from pathlib import Path

from yhwach import db as yhdb
from yhwach import workers as wk
from yhwach.brain import Action


class ScriptedBrain:
    def __init__(self, actions):
        self._actions = list(actions)

    def decide(self, context, *, history=None):
        if self._actions:
            return self._actions.pop(0)
        return Action(action="mark_phase_done", rationale="done")


def _host_with_ollama(conn, eid, ip):
    cur = conn.execute(
        "INSERT INTO host (engagement_id, ip, os, stage, first_seen) "
        "VALUES (?, ?, 'linux', 'scanned', '2026-01-01T00:00:00Z')",
        (eid, ip),
    )
    yhdb.upsert_surface(conn, int(cur.lastrowid), None, "ollama", "none", "{}")


def test_target_hosts_are_those_with_candidates(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.upsert_engagement(conn, lab="t", scope="10.0.0.0/24")
        _host_with_ollama(conn, eid, "10.0.0.5")
        _host_with_ollama(conn, eid, "10.0.0.6")
        # Post-arsenal-wiring: a bare linux host still gets candidates because
        # the os-only revshell rule (generate_linux_revshell) lights up for
        # every linux host. So all three are targets — the invariant this test
        # actually cares about is "hosts with NO os and NO surface are NOT
        # targets", which we now assert explicitly with 10.0.0.99 (os=NULL).
        conn.execute(
            "INSERT INTO host (engagement_id, ip, os, stage, first_seen) "
            "VALUES (?, '10.0.0.7', 'linux', 'scanned', '2026-01-01T00:00:00Z')",
            (eid,),
        )
        conn.execute(
            "INSERT INTO host (engagement_id, ip, os, stage, first_seen) "
            "VALUES (?, '10.0.0.99', NULL, 'scanned', '2026-01-01T00:00:00Z')",
            (eid,),
        )
        hosts = wk.target_hosts(conn, eid)
    assert hosts == ["10.0.0.5", "10.0.0.6", "10.0.0.7"]
    assert "10.0.0.99" not in hosts  # no os -> no os-only rule matches -> not a target


def test_fan_out_runs_a_worker_per_host_scoped(tmp_db: Path) -> None:
    seen_hosts: list[str] = []

    def doer_for(ip: str):
        seen_hosts.append(ip)
        # each worker runs its host's ollama technique then the menu empties
        return ScriptedBrain(
            [
                Action(
                    action="run_technique",
                    technique_id="ollama_unauth_api",
                    host_ip=ip,
                    rationale="recon",
                ),
            ]
        )

    judge = ScriptedBrain([Action(action="mark_phase_done", rationale="all done")])

    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.upsert_engagement(conn, lab="t", scope="10.0.0.0/24")
        _host_with_ollama(conn, eid, "10.0.0.5")
        _host_with_ollama(conn, eid, "10.0.0.6")
        report = wk.run_workers(conn, eid, doer_for=doer_for, judge_brain=judge)
        attempts = yhdb.list_attempts(conn, eid)

    assert set(report.hosts) == {"10.0.0.5", "10.0.0.6"}
    assert report.total_executed == 2  # one per host
    assert report.verdict.done is True
    # each worker only ever saw its own host's candidates
    assert {a["host_ip"] for a in attempts} == {"10.0.0.5", "10.0.0.6"}


def test_parallel_fan_out_isolated_connections(tmp_db: Path) -> None:
    # setup committed to disk so per-thread worker connections can see the hosts
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.upsert_engagement(conn, lab="t", scope="10.0.0.0/24")
        _host_with_ollama(conn, eid, "10.0.0.5")
        _host_with_ollama(conn, eid, "10.0.0.6")

    def doer_for_conn(ip: str, _c):
        return ScriptedBrain(
            [Action(action="run_technique", technique_id="ollama_unauth_api",
                    host_ip=ip, rationale="recon")]
        )

    judge = ScriptedBrain([Action(action="mark_phase_done", rationale="done")])
    with yhdb.transaction(tmp_db) as conn:
        report = wk.run_workers(
            conn, eid, doer_for=lambda ip: None, judge_brain=judge,
            max_parallel=2, conn_for=lambda ip: yhdb.connect(tmp_db),
            doer_for_conn=doer_for_conn,
        )
        attempts = yhdb.list_attempts(conn, eid)

    assert set(report.hosts) == {"10.0.0.5", "10.0.0.6"}
    assert report.total_executed == 2  # both workers ran, on their own connections
    assert {a["host_ip"] for a in attempts} == {"10.0.0.5", "10.0.0.6"}


def test_parallel_requires_factories(tmp_db: Path) -> None:
    import pytest

    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.upsert_engagement(conn, lab="t", scope="10.0.0.0/24")
        _host_with_ollama(conn, eid, "10.0.0.5")
        _host_with_ollama(conn, eid, "10.0.0.6")
        with pytest.raises(ValueError, match="conn_for and doer_for_conn"):
            wk.run_workers(conn, eid, doer_for=lambda ip: None,
                           judge_brain=ScriptedBrain([]), max_parallel=2)


def test_worker_scope_isolates_candidates(tmp_db: Path) -> None:
    # A worker scoped to .5 is handed only .5's candidates; an action targeting
    # .6 is rejected by the executor guard, so a worker cannot act cross-host.
    import pytest

    from yhwach import actions as act
    from yhwach import knowledge as kn

    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.upsert_engagement(conn, lab="t", scope="10.0.0.0/24")
        _host_with_ollama(conn, eid, "10.0.0.5")
        _host_with_ollama(conn, eid, "10.0.0.6")

        cands_5 = kn.candidates_for(conn, eid, host_ip="10.0.0.5")
        assert {c.host_ip for c in cands_5} == {"10.0.0.5"}

        ex = act.ActionExecutor(conn, eid)
        with pytest.raises(act.ActionError, match="not an applicable candidate"):
            ex.execute(
                Action(
                    action="run_technique",
                    technique_id="ollama_unauth_api",
                    host_ip="10.0.0.6",
                    rationale="cross-host",
                ),
                candidates=cands_5,
            )
