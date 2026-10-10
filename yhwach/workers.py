"""Workers: per-host fan-out over the loop.

Per AGENT.md § "Workers (fan-out)": the engagement fans out into per-host workers,
each scoped to its host's candidate slice, with results folded back. Credentials
are the exception — never scoped, always global (the credential_reuse primitive):
a cred one worker recovers is visible to all, because the world model is shared
and `candidates_for`'s `vault` clause is engagement-wide.

Each worker is a host-scoped `Orchestrator` that does not judge phase completeness
on its own (that is an engagement-level call); after all workers finish, the
engagement judges once.

By default workers run **sequentially** over one shared connection — simple,
deterministic, safe. Parallelism is **opt-in** via `max_parallel > 1` plus a
`conn_for` factory (a fresh connection per thread) and a `doer_for_conn` factory
(a doer bound to that thread's connection). Under WAL + `busy_timeout` (set in
`db.connect`) writers serialize and readers run concurrently, so per-host workers
are safe on their own connections. Credentials remain global (the world model is
shared), so a cred one worker recovers is visible to the rest on their next read.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from yhwach import db
from yhwach import judge as jg
from yhwach import knowledge as kn
from yhwach import policy as pol
from yhwach.judge import DecidingBrain, Verdict
from yhwach.orchestrator import Orchestrator, RunReport

# A factory yielding the doer brain for a given host (its memory slice lives in
# the host-scoped context the orchestrator builds).
DoerFor = Callable[[str], DecidingBrain]
BudgetFor = Callable[[str], pol.Budget]
# Parallel-mode factories: a fresh connection per host/thread, and a doer bound
# to *that* connection (so no connection is shared across threads).
ConnFor = Callable[[str], sqlite3.Connection]
DoerForConn = Callable[[str, sqlite3.Connection], DecidingBrain]


@dataclass(frozen=True)
class WorkerReport:
    engagement_id: int
    phase: str
    per_host: dict[str, RunReport]
    verdict: Verdict | None

    @property
    def hosts(self) -> list[str]:
        return list(self.per_host)

    @property
    def total_executed(self) -> int:
        return sum(r.executed for r in self.per_host.values())

    @property
    def total_queued(self) -> int:
        return sum(r.queued for r in self.per_host.values())


def target_hosts(conn: sqlite3.Connection, engagement_id: int) -> list[str]:
    """Hosts that currently have at least one applicable candidate — the ones
    worth dispatching a worker to. Order is stable (by IP)."""
    ips = {c.host_ip for c in kn.candidates_for(conn, engagement_id)}
    return sorted(ips)


def run_workers(
    conn: sqlite3.Connection,
    engagement_id: int,
    *,
    doer_for: DoerFor,
    judge_brain: DecidingBrain,
    hosts: list[str] | None = None,
    budget_for: BudgetFor | None = None,
    allow_gated: bool = False,
    allow_grants: frozenset[str] | set[str] | None = None,
    phase: str = "enumeration",
    runner=None,
    max_parallel: int = 1,
    conn_for: ConnFor | None = None,
    doer_for_conn: DoerForConn | None = None,
) -> WorkerReport:
    """Fan out one host-scoped worker per target host, fold the results, then
    judge phase completeness once at engagement scope.

    Sequential by default. Set `max_parallel > 1` with `conn_for` +
    `doer_for_conn` to run workers concurrently, each on its own connection.
    """
    if hosts is None:
        hosts = target_hosts(conn, engagement_id)

    parallel = max_parallel > 1 and len(hosts) > 1
    if parallel and (conn_for is None or doer_for_conn is None):
        raise ValueError("parallel workers (max_parallel>1) require conn_for and doer_for_conn")

    def _end_status(rep: RunReport) -> str:
        return "done" if getattr(rep, "executed", 0) else "idle"

    def _work_shared(ip: str) -> RunReport:
        db.heartbeat_worker(conn, engagement_id, ip, "watching", phase=phase)
        rep = Orchestrator(
            conn, engagement_id, doer=doer_for(ip), judge_brain=judge_brain,
            runner=runner, budget=budget_for(ip) if budget_for else None,
            allow_gated=allow_gated, allow_grants=allow_grants,
            phase=phase, host_ip=ip, judge_at_end=False,
        ).run()
        db.heartbeat_worker(conn, engagement_id, ip, _end_status(rep), phase=phase)
        return rep

    def _work_isolated(ip: str) -> RunReport:
        # Own connection per thread; commit its writes so the engagement judge
        # (on the shared conn) sees them, then always close. Heartbeats are
        # committed immediately so the UI gaze sees the worker go live.
        c = conn_for(ip)  # type: ignore[misc]
        try:
            db.heartbeat_worker(c, engagement_id, ip, "watching", phase=phase)
            c.commit()
            rep = Orchestrator(
                c, engagement_id, doer=doer_for_conn(ip, c), judge_brain=judge_brain,  # type: ignore[misc]
                runner=runner, budget=budget_for(ip) if budget_for else None,
                allow_gated=allow_gated, allow_grants=allow_grants,
                phase=phase, host_ip=ip, judge_at_end=False,
            ).run()
            db.heartbeat_worker(c, engagement_id, ip, _end_status(rep), phase=phase)
            c.commit()
            return rep
        finally:
            c.close()

    per_host: dict[str, RunReport] = {}
    if parallel:
        with ThreadPoolExecutor(max_workers=max_parallel) as pool:
            for ip, rep in zip(hosts, pool.map(_work_isolated, hosts), strict=True):
                per_host[ip] = rep
    else:
        for ip in hosts:
            per_host[ip] = _work_shared(ip)

    verdict = jg.judge_phase(conn, engagement_id, brain=judge_brain, phase=phase)
    return WorkerReport(
        engagement_id=engagement_id,
        phase=phase,
        per_host=per_host,
        verdict=verdict,
    )
