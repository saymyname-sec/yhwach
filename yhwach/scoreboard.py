"""Objective / flag scoreboard — the timed-engagement cockpit.

Engagements can be scored and timed, but the point-bearing `objective` table had
no operator write path (`db.add_objective` had zero callers) and the scoring
columns (`engagement.points_target/points_max/time_budget_h`,
`objective.points/captured`) were dormant — there was no way to record a flag,
its points, or the pace to a target.

This turns those rows into a live scoreboard: points scored vs target, flags
captured vs found, and hours elapsed vs the time budget. The point target / max /
budget are optional per-engagement fields (NULL = unscored): set them at
`yhwach engage` time to get the pace view; leave them unset and the board shows a
plain running count with no target. Pure reads; the score is DERIVED from captured
objectives (the single source of truth), never a stored counter that could drift.
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime


@dataclass
class Scoreboard:
    points_scored: int
    points_target: int | None
    points_max: int | None
    captured: int
    total: int
    elapsed_h: float | None
    budget_h: float | None

    @property
    def pct(self) -> int | None:
        """% of the point target, or None when no target is set (unscored engagement)."""
        return None if not self.points_target else round(100 * self.points_scored / self.points_target)

    @property
    def remaining_h(self) -> float | None:
        if self.budget_h is None or self.elapsed_h is None:
            return None
        return round(self.budget_h - self.elapsed_h, 1)


def _elapsed_hours(started_at: str | None) -> float | None:
    """Hours since the engagement started, or None if the timestamp is unparseable."""
    if not started_at:
        return None
    try:
        t0 = datetime.strptime(started_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except (ValueError, TypeError):
        return None
    return round((datetime.now(UTC) - t0).total_seconds() / 3600, 1)


def compute(conn: sqlite3.Connection, engagement_id: int) -> Scoreboard:
    e = conn.execute(
        "SELECT points_target pt, points_max pm, started_at, time_budget_h "
        "FROM engagement WHERE id=?",
        (engagement_id,),
    ).fetchone()
    o = conn.execute(
        "SELECT COALESCE(SUM(CASE WHEN captured=1 THEN COALESCE(points,0) ELSE 0 END),0) scored, "
        "COALESCE(SUM(CASE WHEN captured=1 THEN 1 ELSE 0 END),0) cap, COUNT(*) tot "
        "FROM objective WHERE engagement_id=?",
        (engagement_id,),
    ).fetchone()
    pt = e["pt"] if e else None
    pm = e["pm"] if e else None
    return Scoreboard(
        points_scored=int(o["scored"]),
        points_target=int(pt) if pt is not None else None,
        points_max=int(pm) if pm is not None else None,
        captured=int(o["cap"]),
        total=int(o["tot"]),
        elapsed_h=_elapsed_hours(e["started_at"] if e else None),
        budget_h=(e["time_budget_h"] if e else None),
    )


def objectives(conn: sqlite3.Connection, engagement_id: int) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT o.label, o.kind, COALESCE(o.points,0) points, COALESCE(o.captured,0) captured, "
        "COALESCE(h.ip,'-') ip FROM objective o LEFT JOIN host h ON h.id=o.host_id "
        "WHERE o.engagement_id=? ORDER BY o.captured, o.points DESC, o.id",
        (engagement_id,),
    ).fetchall()


def render(conn: sqlite3.Connection, engagement_id: int) -> list[str]:
    sb = compute(conn, engagement_id)
    if sb.points_target:
        maxpart = f"; max {sb.points_max}" if sb.points_max is not None else ""
        head = (f"Score: {sb.points_scored}/{sb.points_target} pts ({sb.pct}% of target"
                f"{maxpart}) · {sb.captured}/{sb.total} flags")
    else:
        head = f"Score: {sb.points_scored} pts · {sb.captured}/{sb.total} flags"
    if sb.elapsed_h is not None:
        if sb.budget_h:
            head += f" · {sb.elapsed_h}h / {sb.budget_h}h"
            rem = sb.remaining_h
            if rem is not None:
                head += f" ({rem}h left)"
        else:
            head += f" · {sb.elapsed_h}h elapsed"
    lines = [head]
    objs = objectives(conn, engagement_id)
    for o in objs:
        mark = "x" if o["captured"] else " "
        pts = f" · {o['points']}pts" if o["points"] else ""
        lines.append(f"  [{mark}] {o['label']} @ {o['ip']}{pts}")
    if not objs:
        lines.append("  (no objectives yet — add with `yhwach objective --add <label>`)")
    return lines


def as_dict(conn: sqlite3.Connection, engagement_id: int) -> dict:
    sb = compute(conn, engagement_id)
    return {
        "points_scored": sb.points_scored,
        "points_target": sb.points_target,
        "points_max": sb.points_max,
        "pct": sb.pct,
        "captured": sb.captured,
        "total": sb.total,
        "elapsed_h": sb.elapsed_h,
        "budget_h": sb.budget_h,
        "remaining_h": sb.remaining_h,
        "objectives": [
            {"label": o["label"], "kind": o["kind"], "points": o["points"],
             "captured": bool(o["captured"]), "ip": o["ip"]}
            for o in objectives(conn, engagement_id)
        ],
    }
