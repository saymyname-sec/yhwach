"""Operator memory — the attempt ledger and the recall brief.

Yhwach's world model always recorded what *succeeded* (`technique_state`:
consumed). It never recorded what was **tried and failed**, so a task the
operator burned an hour on stayed `pending` and came back to the top of the
next handoff — and a model whose context had been compacted would happily
re-propose its own dead end. This module is the missing half:

  * **`record_outcome`** — the operator reports how a move went
    (success | fail | blocked | partial) with a one-line reason. Success
    consumes the technique and closes the task; failure retires the task and
    decays that rule's EV on that host at the next `plan`; everything lands in
    the append-only `attempt` ledger.
  * **`dead_ends`** — the "do not re-propose" list, injected into the handoff.
  * **`build_recall`** — a compact, persona-free digest of the engagement for
    the moment the operator's context is lost (a new session, a `/compact`, a
    handover). It answers "where am I, what did I already try, what is next?"
    in a few hundred tokens instead of a full context block.

No model is called here; like the rest of the engine this is deterministic SQL.
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from datetime import UTC, datetime

from yhwach import db as yhdb
from yhwach.coverage import enum_gaps
from yhwach.planner import top_tasks
from yhwach.playbooks import default_playbook_dir, load_rules
from yhwach.primitives import mark_technique_consumed, p0_leads
from yhwach.report import event_summary

# Each failure halves the rule's EV on that host. Deterministic, re-derived at
# every `plan` (never persisted as a mutated score), so the decay is auditable.
FAILURE_DECAY = 0.5

# Result -> the task status the ledger drives it to. `partial` deliberately
# leaves the task pending: partial progress is still the best move available.
_RESULT_TASK_STATUS = {
    "success": "done",
    "fail": "abandoned",
    "blocked": "blocked",
    "partial": None,
}


@dataclass
class OutcomeReport:
    attempt_id: int
    result: str
    rule_id: str | None
    host_ip: str | None
    task_status: str | None = None
    consumed: bool = False
    notes: list[str] = field(default_factory=list)

    def render(self) -> str:
        head = (f"attempt #{self.attempt_id} recorded: {self.rule_id or '?'} "
                f"@ {self.host_ip or '-'} -> {self.result}")
        return "\n".join([head, *[f"  {n}" for n in self.notes]])


def record_outcome(
    conn: sqlite3.Connection,
    engagement_id: int,
    *,
    result: str,
    task_id: int | None = None,
    rule_id: str | None = None,
    host_ip: str | None = None,
    reason: str | None = None,
    evidence: str | None = None,
    rules: list | None = None,
) -> OutcomeReport:
    """Record how an attempt went and apply its consequences.

    Identify the move either by `task_id` (preferred — it carries host + rule)
    or by `rule_id` [+ `host_ip`] for something run outside the task queue.
    """
    if result not in yhdb.ATTEMPT_RESULTS:
        raise ValueError(
            f"unknown result '{result}' — use one of {', '.join(yhdb.ATTEMPT_RESULTS)}")
    if task_id is None and rule_id is None:
        raise ValueError("give a task id or a playbook rule id")

    host_id: int | None = None
    if task_id is not None:
        row = conn.execute(
            "SELECT t.playbook_rule_id AS rule_id, t.target_host_id AS host_id, h.ip AS ip "
            "FROM task t LEFT JOIN host h ON h.id = t.target_host_id "
            "WHERE t.id = ? AND t.engagement_id = ?",
            (task_id, engagement_id),
        ).fetchone()
        if row is None:
            raise ValueError(f"task {task_id} not found in this engagement")
        rule_id = rule_id or row["rule_id"]
        host_id = row["host_id"]
        host_ip = host_ip or row["ip"]
    elif host_ip is not None:
        row = conn.execute(
            "SELECT id FROM host WHERE engagement_id = ? AND ip = ?",
            (engagement_id, host_ip),
        ).fetchone()
        if row is None:
            raise ValueError(f"host {host_ip} not found in this engagement")
        host_id = int(row["id"])

    if rules is None:
        rules = load_rules(default_playbook_dir())
    rule = next((r for r in rules if r.id == rule_id), None)
    technique_id = rule.technique if rule is not None else rule_id

    attempt_id = yhdb.add_attempt(
        conn, engagement_id, result=result, task_id=task_id, host_id=host_id,
        playbook_rule_id=rule_id, technique_id=technique_id, reason=reason,
        evidence=evidence,
    )
    rep = OutcomeReport(attempt_id=attempt_id, result=result, rule_id=rule_id,
                        host_ip=host_ip)

    new_status = _RESULT_TASK_STATUS[result]
    if new_status is not None and task_id is not None:
        conn.execute(
            "UPDATE task SET status = ?, updated_at = ? WHERE id = ? AND engagement_id = ?",
            (new_status, _now(), task_id, engagement_id),
        )
        rep.task_status = new_status
        rep.notes.append(f"task {task_id} -> {new_status}")
    elif new_status is not None and rule_id is not None:
        # No task id: retire the matching pending task(s) for this rule/host.
        clause = "AND target_host_id = ?" if host_id is not None else ""
        params: list = [new_status, _now(), engagement_id, rule_id]
        if host_id is not None:
            params.append(host_id)
        cur = conn.execute(
            "UPDATE task SET status = ?, updated_at = ? WHERE engagement_id = ? "
            f"AND playbook_rule_id = ? {clause} AND status = 'pending'",
            params,
        )
        if cur.rowcount:
            rep.task_status = new_status
            rep.notes.append(f"{cur.rowcount} queued task(s) -> {new_status}")

    if result == "success" and technique_id:
        mark_technique_consumed(conn, engagement_id, technique_id, host_id)
        rep.consumed = True
        rep.notes.append(
            f"technique '{technique_id}' consumed — the planner will stop proposing it")
        rep.notes.append(
            "capture the evidence now: yhwach proof --host <ip> --screenshot <path>")
    elif result in ("fail", "blocked"):
        fails = failure_counts(conn, engagement_id).get((rule_id, host_id), 0)
        rep.notes.append(
            f"dead end #{fails} for this rule/host — EV x{FAILURE_DECAY ** fails:.2f} "
            "at the next plan; it is listed as a DEAD END in the handoff")

    yhdb.log_event(conn, engagement_id, "attempt", {
        "rule": rule_id, "host": host_ip, "result": result, "reason": reason,
    })
    return rep


def failure_counts(
    conn: sqlite3.Connection,
    engagement_id: int,
) -> dict[tuple[str | None, int | None], int]:
    """(rule_id, host_id) -> number of fail/blocked attempts. Drives EV decay."""
    rows = conn.execute(
        "SELECT playbook_rule_id AS rule_id, host_id, COUNT(*) AS n FROM attempt "
        "WHERE engagement_id = ? AND result IN ('fail', 'blocked') "
        "GROUP BY playbook_rule_id, host_id",
        (engagement_id,),
    ).fetchall()
    return {(r["rule_id"], r["host_id"]): int(r["n"]) for r in rows}


def decayed_ev(base_ev: float, fails: int) -> float:
    """EV after `fails` recorded failures. Never persisted — recomputed each plan."""
    if fails <= 0:
        return base_ev
    return round(base_ev * (FAILURE_DECAY ** fails), 4)


def dead_ends(
    conn: sqlite3.Connection,
    engagement_id: int,
    *,
    limit: int = 10,
) -> list[sqlite3.Row]:
    """Latest fail/blocked attempt per (rule, host) — the do-not-re-propose list."""
    return conn.execute(
        "SELECT a.playbook_rule_id AS rule_id, a.result, a.reason, a.attempted_at, "
        "h.ip AS host_ip, COUNT(*) AS tries "
        "FROM attempt a LEFT JOIN host h ON h.id = a.host_id "
        "WHERE a.engagement_id = ? AND a.result IN ('fail', 'blocked') "
        "GROUP BY a.playbook_rule_id, a.host_id "
        "ORDER BY MAX(a.id) DESC LIMIT ?",
        (engagement_id, limit),
    ).fetchall()


def wins(
    conn: sqlite3.Connection,
    engagement_id: int,
    *,
    limit: int = 10,
) -> list[sqlite3.Row]:
    """Successful attempts, newest first."""
    return conn.execute(
        "SELECT a.playbook_rule_id AS rule_id, a.reason, a.attempted_at, h.ip AS host_ip "
        "FROM attempt a LEFT JOIN host h ON h.id = a.host_id "
        "WHERE a.engagement_id = ? AND a.result = 'success' "
        "ORDER BY a.id DESC LIMIT ?",
        (engagement_id, limit),
    ).fetchall()


# ---------------------------------------------------------------------------
# Recall — "catch me up" after a context reset
# ---------------------------------------------------------------------------
def collect_recall(
    conn: sqlite3.Connection,
    engagement_id: int,
    *,
    events: int = 8,
    tasks: int = 3,
) -> dict:
    """The recall brief as data (also the `--json` payload)."""
    eng = conn.execute(
        "SELECT lab, scope, domain, dc_ip, started_at, points_target "
        "FROM engagement WHERE id = ?", (engagement_id,)).fetchone()
    if eng is None:
        raise ValueError("engagement not found")

    def _scalar(sql: str) -> int:
        return int(conn.execute(sql, (engagement_id,)).fetchone()["n"])

    stages = {r["stage"]: r["n"] for r in conn.execute(
        "SELECT stage, COUNT(*) AS n FROM host WHERE engagement_id = ? GROUP BY stage",
        (engagement_id,))}
    counts = {
        "services": _scalar("SELECT COUNT(*) n FROM service s JOIN host h ON h.id = s.host_id "
                            "WHERE h.engagement_id = ?"),
        "surfaces": _scalar("SELECT COUNT(*) n FROM surface s JOIN host h ON h.id = s.host_id "
                            "WHERE h.engagement_id = ?"),
        "findings": _scalar("SELECT COUNT(*) n FROM finding WHERE engagement_id = ? "
                            "AND status = 'open'"),
        "credentials": _scalar("SELECT COUNT(*) n FROM credential WHERE engagement_id = ?"),
        "tunnels": _scalar("SELECT COUNT(*) n FROM tunnel WHERE engagement_id = ?"),
        "proofs": _scalar("SELECT COUNT(*) n FROM proof p JOIN host h ON h.id = p.host_id "
                          "WHERE h.engagement_id = ?"),
        # schema v1 attack-surface — the enrichment the world model now carries
        "software": _scalar("SELECT COUNT(*) n FROM software s JOIN host h ON h.id = s.host_id "
                            "WHERE h.engagement_id = ?"),
        "vulns_exploitable": _scalar(
            "SELECT COUNT(*) n FROM vulnerability WHERE engagement_id = ? AND exploit_available = 1"),
        "principals": _scalar("SELECT COUNT(*) n FROM principal WHERE engagement_id = ?"),
        "shares_writable": _scalar(
            "SELECT COUNT(*) n FROM share sh JOIN host h ON h.id = sh.host_id "
            "WHERE h.engagement_id = ? AND sh.access LIKE '%WRITE%'"),
        "web_apps": _scalar("SELECT COUNT(*) n FROM web_app w JOIN host h ON h.id = w.host_id "
                            "WHERE h.engagement_id = ?"),
    }
    pending = _scalar("SELECT COUNT(*) n FROM task WHERE engagement_id = ? AND status = 'pending'")
    total_events = _scalar("SELECT COUNT(*) n FROM event WHERE engagement_id = ?")

    recent = conn.execute(
        "SELECT ts, kind, payload_json FROM event WHERE engagement_id = ? "
        "ORDER BY id DESC LIMIT ?", (engagement_id, events)).fetchall()

    return {
        "lab": eng["lab"],
        "scope": eng["scope"],
        "domain": eng["domain"],
        "started_at": eng["started_at"],
        "elapsed": _elapsed(eng["started_at"]),
        "stages": stages,
        "counts": counts,
        "pending_tasks": pending,
        "total_events": total_events,
        "wins": [dict(r) for r in wins(conn, engagement_id, limit=5)],
        "dead_ends": [dict(r) for r in dead_ends(conn, engagement_id, limit=6)],
        "p0_leads": [dict(r) for r in p0_leads(conn, engagement_id)],
        "blocked_hosts": [r["ip"] for r in conn.execute(
            "SELECT ip FROM host WHERE engagement_id = ? AND stage = 'blocked' ORDER BY ip",
            (engagement_id,))],
        "enum_gaps": [{"ip": c.ip, "stage": c.stage, "summary": c.summary,
                       "fixes": [g.fix for g in c.gaps]}
                      for c in enum_gaps(conn, engagement_id)],
        "recent_events": [
            {"ts": r["ts"], "kind": r["kind"],
             "summary": event_summary(r["kind"], r["payload_json"])}
            for r in recent],
        "next_tasks": [
            {"id": t["id"], "rule": t["playbook_rule_id"], "host": t["host_ip"],
             "ev": t["ev_score"], "autonomy": t["autonomy"],
             "surface": t["surface_kind"]}
            for t in top_tasks(conn, engagement_id, tasks)],
    }


def build_recall(
    conn: sqlite3.Connection,
    engagement_id: int,
    *,
    events: int = 8,
    tasks: int = 3,
) -> str:
    """Render the recall brief — persona-free, compact, safe to re-read often."""
    d = collect_recall(conn, engagement_id, events=events, tasks=tasks)
    stage_str = ", ".join(f"{k}:{v}" for k, v in sorted(d["stages"].items())) or "no hosts"
    c = d["counts"]

    out = [f"== YHWACH RECALL — '{d['lab']}' ==",
           f"Elapsed {d['elapsed']} since {d['started_at']}  |  scope {d['scope']}"
           + (f"  |  domain {d['domain']}" if d["domain"] else ""),
           f"Hosts: {stage_str}",
           f"services={c['services']} surfaces={c['surfaces']} findings={c['findings']} "
           f"vault={c['credentials']} proofs={c['proofs']} tunnels={c['tunnels']} "
           f"pending_tasks={d['pending_tasks']}",
           f"software={c['software']} exploitable_cves={c['vulns_exploitable']} "
           f"principals={c['principals']} writable_shares={c['shares_writable']} "
           f"web_apps={c['web_apps']}"]

    if d["wins"]:
        out.append(f"\n-- WINS ({len(d['wins'])}) --")
        out += [f"  + {w['host_ip'] or '-':<16} {w['rule_id']}"
                + (f" — {w['reason']}" if w["reason"] else "") for w in d["wins"]]
    if d["dead_ends"]:
        out.append(f"\n-- DEAD ENDS ({len(d['dead_ends'])}) — do NOT re-propose --")
        out += [f"  x {e['host_ip'] or '-':<16} {e['rule_id']} ({e['result']} x{e['tries']})"
                + (f" — {e['reason']}" if e["reason"] else "") for e in d["dead_ends"]]
    if d["p0_leads"]:
        out.append(f"\n-- P0 LEADS ({len(d['p0_leads'])}) — attack first --")
        out += [f"  ! [{p['severity'].upper()}] {p['ip'] or '-':<16} {p['tag']} — {p['title']}"
                for p in d["p0_leads"]]
    if d["enum_gaps"]:
        out.append(f"\n-- ENUM GAPS ({len(d['enum_gaps'])}) — under-enumeration costs points --")
        out += [f"  ! {g['ip']:<16} [{g['stage']}] {g['summary']}" for g in d["enum_gaps"][:5]]
    if d["blocked_hosts"]:
        out.append("\n-- BLOCKED HOSTS --")
        out.append("  " + ", ".join(d["blocked_hosts"]))
    if d["recent_events"]:
        out.append(f"\n-- RECENT ({len(d['recent_events'])} of {d['total_events']} events) --")
        out += [f"  {e['ts']}  {e['kind']:<10} {e['summary']}" for e in d["recent_events"]]

    out.append(f"\n-- NEXT ({len(d['next_tasks'])} of {d['pending_tasks']} pending) --")
    if d["next_tasks"]:
        out += [f"  {t['id']}. {t['rule']:<32} EV={t['ev']} @ {t['host'] or '-'} "
                f"[{t['autonomy']}]" for t in d["next_tasks"]]
    else:
        out.append("  (none — run `yhwach probe` then `yhwach plan`)")
    out.append("\n`yhwach next --contract` for the full handoff; "
               "`yhwach outcome` when a move resolves.")
    return "\n".join(out)


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _elapsed(started_at: str | None) -> str:
    """Human 'Xh Ym' since the engagement started; '?' when unparseable."""
    if not started_at:
        return "?"
    try:
        start = datetime.strptime(started_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except (ValueError, TypeError):
        return "?"
    delta = datetime.now(UTC) - start
    mins = int(delta.total_seconds() // 60)
    if mins < 0:
        return "0m"
    return f"{mins // 60}h{mins % 60:02d}m" if mins >= 60 else f"{mins}m"
