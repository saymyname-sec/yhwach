"""Attack-graph pathfinding — render the owned → objective path the engine can
already compute but never showed.

`db.shortest_path` (a deterministic BFS over the `edge` table) existed but was
only ever reachable through `yhwach path` for a hand-named pair. The high-value
question — *"from everything I already own, what is the shortest path to the
objective / Domain Admins?"* — was never asked automatically, and never rendered
on the board.

This module answers it: it derives the set of nodes we control (principals we
hold creds for, plus owned hosts), the set of objective targets (uncaptured
objective hosts + the Domain/Enterprise Admins groups), and returns the shortest
path to each target from any owned node. Pure reads; no scoring, no writes.

Nodes are addressed `principal:<id>` / `host:<id>`, exactly as the `edge` table
and `db.shortest_path` use them.
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from yhwach import db as yhdb

# Stages that mean "we control this host" — mirrors ui._OWNED / brief.REACHABLE.
OWNED_STAGES = ("foothold", "looted", "pivoted", "done")

# High-value group principals that are always worth a path even without an
# explicit objective row (the AD crown).
CROWN_GROUPS = ("domain admins", "enterprise admins")


@dataclass
class ObjectivePath:
    target_label: str
    target_node: str
    path: list[str] | None       # inclusive node path, or None if unreachable
    source_node: str | None      # the owned node the path starts from

    @property
    def reachable(self) -> bool:
        return self.path is not None

    @property
    def hops(self) -> int | None:
        return (len(self.path) - 1) if self.path else None


def owned_nodes(conn: sqlite3.Connection, engagement_id: int) -> list[str]:
    """Nodes we actually control — the BFS sources. Honest ownership (I46):

    A principal is owned only when its credential is PROVEN — validated against a
    host, OR client-provided (assumed breach) — never merely held as an unproven
    guess. Operator-asserted ownership (yhwach_own, principal.owned=1) also counts,
    for access won out-of-band that yhwach cannot observe. Hosts count at an owned
    FSM stage.
    """
    pids: set[int] = set()
    for r in conn.execute(
        "SELECT DISTINCT p.id FROM principal p JOIN credential c "
        "ON LOWER(c.identifier)=LOWER(p.name) "
        "WHERE p.engagement_id=? AND c.engagement_id=? "
        "AND (c.validated_on_host_id IS NOT NULL OR c.provenance='provided') "
        "AND COALESCE(c.provenance,'discovered') != 'guess' ORDER BY p.id",
        (engagement_id, engagement_id),
    ).fetchall():
        pids.add(int(r["id"]))
    for r in conn.execute(
        "SELECT id FROM principal WHERE engagement_id=? AND COALESCE(owned,0)=1",
        (engagement_id,),
    ).fetchall():
        pids.add(int(r["id"]))
    nodes = [f"principal:{pid}" for pid in sorted(pids)]
    placeholders = ",".join("?" * len(OWNED_STAGES))
    for r in conn.execute(
        f"SELECT id FROM host WHERE engagement_id=? AND stage IN ({placeholders}) ORDER BY id",
        (engagement_id, *OWNED_STAGES),
    ).fetchall():
        nodes.append(f"host:{r['id']}")
    return nodes


def objective_targets(conn: sqlite3.Connection, engagement_id: int) -> list[tuple[str, str]]:
    """(label, node) for every path target: uncaptured objective hosts + the
    Domain/Enterprise Admins group principals. Deduped by node (first label wins)."""
    seen: dict[str, str] = {}
    for r in conn.execute(
        "SELECT label, host_id FROM objective WHERE engagement_id=? AND COALESCE(captured,0)=0 "
        "AND host_id IS NOT NULL ORDER BY COALESCE(points,0) DESC, id",
        (engagement_id,),
    ).fetchall():
        seen.setdefault(f"host:{r['host_id']}", r["label"])
    placeholders = ",".join("?" * len(CROWN_GROUPS))
    for r in conn.execute(
        f"SELECT id, name FROM principal WHERE engagement_id=? "
        f"AND LOWER(name) IN ({placeholders}) ORDER BY id",
        (engagement_id, *CROWN_GROUPS),
    ).fetchall():
        seen.setdefault(f"principal:{r['id']}", r["name"])
    return list(seen.items())


def paths_to_objectives(
    conn: sqlite3.Connection,
    engagement_id: int,
    *,
    max_hops: int = 8,
) -> list[ObjectivePath]:
    """Shortest path from any owned node to each objective target, worst last
    (reachable first, then fewest hops). Unreachable targets are reported too —
    "no known path yet" is the signal to enumerate more edges."""
    sources = owned_nodes(conn, engagement_id)
    targets = objective_targets(conn, engagement_id)

    out: list[ObjectivePath] = []
    for node, label in targets:
        best: list[str] | None = None
        best_src: str | None = None
        for s in sources:
            if s == node:
                best, best_src = [s], s
                break
            p = yhdb.shortest_path(conn, engagement_id, s, node, max_hops=max_hops)
            if p is not None and (best is None or len(p) < len(best)):
                best, best_src = p, s
        out.append(ObjectivePath(target_label=label, target_node=node, path=best,
                                 source_node=best_src))
    out.sort(key=lambda r: (not r.reachable, r.hops if r.hops is not None else 10**6))
    return out


def label_node(conn: sqlite3.Connection, node: str) -> str:
    """A `principal:<id>` / `host:<id>` node as a readable name."""
    kind, _, nid = node.partition(":")
    if kind == "principal":
        r = conn.execute("SELECT name FROM principal WHERE id=?", (nid,)).fetchone()
        return r["name"] if r else node
    r = conn.execute("SELECT hostname, ip FROM host WHERE id=?", (nid,)).fetchone()
    return (r["hostname"] or r["ip"]) if r else node


def render_path(conn: sqlite3.Connection, nodes: list[str]) -> str:
    """A node path as `A --Kind--> B --Kind--> C` with readable labels."""
    if not nodes:
        return ""
    labels = [label_node(conn, n) for n in nodes]
    parts = [labels[0]]
    for i in range(1, len(nodes)):
        e = conn.execute(
            "SELECT kind FROM edge WHERE src=? AND dst=? LIMIT 1",
            (nodes[i - 1], nodes[i]),
        ).fetchone()
        parts.append(f" --{e['kind'] if e else '?'}--> {labels[i]}")
    return "".join(parts)


def render_objectives(conn: sqlite3.Connection, paths: list[ObjectivePath]) -> list[str]:
    """Operator-facing lines shared by the CLI and the MCP tool."""
    if not paths:
        return ["(no objective targets yet — add an objective, or ingest BloodHound "
                "for the Domain Admins crown)"]
    lines: list[str] = []
    for p in paths:
        if p.reachable:
            lines.append(f"  ✓ {p.target_label}  ({p.hops} hop(s))")
            lines.append(f"      {render_path(conn, p.path)}")
        else:
            lines.append(f"  ✗ {p.target_label}  — no known path yet "
                         "(enumerate more edges: bloodhound / netexec)")
    return lines
