"""Control channel: kill + approvals, mediated entirely through the world model.

Per AGENT.md § "UI": the UI and the orchestrator communicate *only through the
DB*. This module is that channel. It uses the existing `event` table (no schema
change) so signals are durable, auditable, and visible cross-process — the UI
process writes a signal, and a running `yhwach run` reads it between iterations.

Two signals:
  * **kill** — stop the current run at the next iteration boundary. Scoped to the
    run via the run's start-event id, so a kill never leaks into a later run.
  * **approval** — a human granting a gated (exploit/destructive) move. The
    executor honors an approval as if the move were allowed to proceed. This is
    the human go/no-go at the phase-boundary checkpoint; approvals persist.
"""

from __future__ import annotations

import sqlite3

from yhwach import db as yhdb

KILL = "control_kill"
APPROVAL = "approval_granted"
RUN_STARTED = "run_started"


def mark_run_started(conn: sqlite3.Connection, engagement_id: int, *, phase: str) -> int:
    """Record a run boundary; returns the event id used to scope later kills."""
    return yhdb.log_event(conn, engagement_id, RUN_STARTED, {"phase": phase})


def request_kill(conn: sqlite3.Connection, engagement_id: int, *, why: str = "user") -> int:
    """Signal the current run to stop. Idempotent in effect."""
    return yhdb.log_event(conn, engagement_id, KILL, {"why": why})


def is_killed(conn: sqlite3.Connection, engagement_id: int, *, since_event_id: int = 0) -> bool:
    """True if a kill was signaled after `since_event_id` (the run's start)."""
    row = conn.execute(
        "SELECT 1 FROM event WHERE engagement_id=? AND kind=? AND id>? LIMIT 1",
        (engagement_id, KILL, since_event_id),
    ).fetchone()
    return row is not None


def grant_approval(
    conn: sqlite3.Connection, engagement_id: int, *, technique: str, host: str | None
) -> int:
    """Grant a human go-ahead for a gated (technique, host) move."""
    return yhdb.log_event(conn, engagement_id, APPROVAL, {"technique": technique, "host": host})


def is_approved(
    conn: sqlite3.Connection, engagement_id: int, *, technique: str, host: str | None
) -> bool:
    """True if (technique, host) has a standing approval. A host-agnostic grant
    (host=None) approves the technique on any host."""
    row = conn.execute(
        "SELECT 1 FROM event WHERE engagement_id=? AND kind=? "
        "AND json_extract(payload_json,'$.technique')=? "
        "AND (json_extract(payload_json,'$.host')=? "
        "     OR json_extract(payload_json,'$.host') IS NULL) LIMIT 1",
        (engagement_id, APPROVAL, technique, host),
    ).fetchone()
    return row is not None


def pending_approvals(conn: sqlite3.Connection, engagement_id: int) -> list[dict]:
    """Gated moves that requested approval and have not been granted yet — the
    UI's approval inbox. Deduped by (technique, host)."""
    requested = conn.execute(
        "SELECT DISTINCT json_extract(payload_json,'$.technique') technique, "
        "json_extract(payload_json,'$.host') host, "
        "json_extract(payload_json,'$.risk') risk "
        "FROM event WHERE engagement_id=? AND kind='approval_requested'",
        (engagement_id,),
    ).fetchall()
    out: list[dict] = []
    for r in requested:
        if r["technique"] and not is_approved(
            conn, engagement_id, technique=r["technique"], host=r["host"]
        ):
            out.append({"technique": r["technique"], "host": r["host"], "risk": r["risk"]})
    return out
