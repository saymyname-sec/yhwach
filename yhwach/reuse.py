"""Credential-reuse attack-graph edges (G2e).

Turns dumped hashes and validated access into the lateral-movement edges
BloodHound cannot know, so pathfind sees the most common real path — the local
admin password reused across the fleet.

Three derivations, all idempotent (add_edge dedupes) and read-only except for
the edges they write:

  * CredValidOn — a credential proven on a host links its principal to that host
    (AdminTo when the access was admin). Only for creds already tied to a
    principal; we never invent identities.
  * LocalAdminReuse — hosts an identical admin-granting secret opens are mutually
    reachable. Written as a STAR (hub + spokes), never a clique, so a 50-host
    cluster is ~100 edges, not ~2500.
  * SameHash — principals sharing a secret are one pass-the-hash away from each
    other. Also a star, over principals that already exist.

The empty-password NT hash is excluded: it would cluster every password-less
account into one meaningless mega-star.
"""
from __future__ import annotations

import sqlite3

from yhwach.db import add_edge

_EMPTY_NT = "31d6cfe0d16ae931b73c59d7e0c089c0"  # NT hash of the empty password


def _star_pairs(members: list[int]) -> list[tuple[int, int]]:
    """Bidirectional hub<->spoke pairs for a reuse cluster (sorted, hub = first).

    A star gives any member a 2-hop route to any other through the hub, at
    2*(n-1) edges instead of a clique's n*(n-1)."""
    hub, spokes = members[0], members[1:]
    pairs: list[tuple[int, int]] = []
    for spoke in spokes:
        pairs.append((hub, spoke))
        pairs.append((spoke, hub))
    return pairs


def derive_reuse_edges(conn: sqlite3.Connection, engagement_id: int) -> dict[str, int]:
    """Derive the three reuse edge sets. Returns a count of NEW edges per kind."""
    counts = {"CredValidOn": 0, "LocalAdminReuse": 0, "SameHash": 0}

    # 1. CredValidOn / AdminTo — validated access for creds tied to a principal.
    for r in conn.execute(
        "SELECT DISTINCT ca.host_id, ca.result, c.principal_id "
        "FROM credential_access ca JOIN credential c ON c.id = ca.credential_id "
        "WHERE ca.engagement_id = ? AND ca.result IN ('success', 'admin') "
        "AND c.principal_id IS NOT NULL",
        (engagement_id,),
    ).fetchall():
        kind = "AdminTo" if r["result"] == "admin" else "CredValidOn"
        _id, created = add_edge(
            conn, engagement_id, f"principal:{r['principal_id']}",
            f"host:{r['host_id']}", kind, confidence="confirmed", source="validated_access")
        counts["CredValidOn"] += int(created)

    # 2. LocalAdminReuse — hosts an identical admin-granting secret opens.
    admin_hosts: dict[str, set[int]] = {}
    for r in conn.execute(
        "SELECT ca.host_id, c.secret FROM credential_access ca "
        "JOIN credential c ON c.id = ca.credential_id "
        "WHERE ca.engagement_id = ? AND ca.result = 'admin' "
        "AND c.secret IS NOT NULL AND lower(c.secret) != ?",
        (engagement_id, _EMPTY_NT),
    ).fetchall():
        admin_hosts.setdefault(r["secret"], set()).add(int(r["host_id"]))
    for hosts in admin_hosts.values():
        if len(hosts) < 2:
            continue
        for a, b in _star_pairs(sorted(hosts)):
            _id, created = add_edge(
                conn, engagement_id, f"host:{a}", f"host:{b}", "LocalAdminReuse",
                confidence="likely", source="cred_reuse")
            counts["LocalAdminReuse"] += int(created)

    # 3. SameHash — principals sharing a secret (pass-the-hash neighbours).
    secret_principals: dict[str, set[int]] = {}
    for r in conn.execute(
        "SELECT principal_id, secret FROM credential "
        "WHERE engagement_id = ? AND principal_id IS NOT NULL "
        "AND secret IS NOT NULL AND lower(secret) != ?",
        (engagement_id, _EMPTY_NT),
    ).fetchall():
        secret_principals.setdefault(r["secret"], set()).add(int(r["principal_id"]))
    for pids in secret_principals.values():
        if len(pids) < 2:
            continue
        for a, b in _star_pairs(sorted(pids)):
            _id, created = add_edge(
                conn, engagement_id, f"principal:{a}", f"principal:{b}", "SameHash",
                confidence="likely", source="cred_reuse")
            counts["SameHash"] += int(created)

    return counts
