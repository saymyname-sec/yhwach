"""G2e — credential-reuse attack-graph edges.

Dumped hashes and validated access become the lateral-movement edges BloodHound
cannot know, so pathfind sees the real path: the local admin secret reused
across the fleet. These tests lock the three derivations, the star (not clique)
topology, the empty-hash exclusion, idempotency, and that no identities are
invented.
"""
from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from yhwach import db as yhdb
from yhwach import reuse
from yhwach.cli import main
from yhwach.mcp_tools import tool_interpret, tool_reuse

_EMPTY_NT = "31d6cfe0d16ae931b73c59d7e0c089c0"


def _setup(path: Path):
    with yhdb.transaction(path) as conn:
        eid = yhdb.upsert_engagement(conn, lab="L", scope="10.0.0.0/24")
        hosts = [conn.execute(
            "INSERT INTO host (engagement_id, ip, stage, first_seen) "
            "VALUES (?, ?, 'scanned', 't')", (eid, f"10.0.0.{i}")).lastrowid
            for i in range(1, 6)]
    return eid, hosts


def _edges(path: Path, eid: int, kind: str) -> list[tuple[str, str]]:
    with yhdb.transaction(path) as conn:
        return [(r["src"], r["dst"]) for r in conn.execute(
            "SELECT src, dst FROM edge WHERE engagement_id=? AND kind=? ORDER BY id",
            (eid, kind))]


def test_cred_valid_on_links_principal_to_host(tmp_db: Path) -> None:
    eid, hosts = _setup(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        pid, _ = yhdb.add_principal(conn, eid, "alice")
        cid, _ = yhdb.add_credential(conn, eid, "alice", "H", "ntlm", "dump", principal_id=pid)
        yhdb.record_cred_access(conn, eid, cid, hosts[0], port=445, proto="smb",
                                service_kind="smb", result="admin", source="spray")
        reuse.derive_reuse_edges(conn, eid)
    assert (f"principal:{pid}", f"host:{hosts[0]}") in _edges(tmp_db, eid, "AdminTo")


def test_cred_without_principal_invents_no_node(tmp_db: Path) -> None:
    eid, hosts = _setup(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        cid, _ = yhdb.add_credential(conn, eid, "svc", "H", "password", "spray")
        yhdb.record_cred_access(conn, eid, cid, hosts[0], port=22, proto="ssh",
                                service_kind="ssh", result="success", source="spray")
        reuse.derive_reuse_edges(conn, eid)
    assert _edges(tmp_db, eid, "CredValidOn") == []
    assert _edges(tmp_db, eid, "AdminTo") == []


def test_local_admin_reuse_is_a_star_not_a_clique(tmp_db: Path) -> None:
    eid, hosts = _setup(tmp_db)  # 5 hosts
    with yhdb.transaction(tmp_db) as conn:
        cid, _ = yhdb.add_credential(conn, eid, "ladmin", "PW", "password", "spray")
        for h in hosts:
            yhdb.record_cred_access(conn, eid, cid, h, port=445, proto="smb",
                                    service_kind="smb", result="admin", source="spray")
        reuse.derive_reuse_edges(conn, eid)
    edges = _edges(tmp_db, eid, "LocalAdminReuse")
    # star over 5 nodes = 2*(5-1) = 8 directed edges; a clique would be 5*4 = 20
    assert len(edges) == 8
    hub = f"host:{min(hosts)}"
    assert all(hub in (s, d) for s, d in edges)


def test_same_hash_links_principals_sharing_a_secret(tmp_db: Path) -> None:
    eid, _ = _setup(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        pa, _ = yhdb.add_principal(conn, eid, "alice")
        pb, _ = yhdb.add_principal(conn, eid, "bob")
        yhdb.add_credential(conn, eid, "alice", "SHARED", "ntlm", "dump", principal_id=pa)
        yhdb.add_credential(conn, eid, "bob", "SHARED", "ntlm", "dump", principal_id=pb)
        reuse.derive_reuse_edges(conn, eid)
    edges = _edges(tmp_db, eid, "SameHash")
    assert (f"principal:{pa}", f"principal:{pb}") in edges
    assert (f"principal:{pb}", f"principal:{pa}") in edges


def test_empty_password_hash_is_excluded(tmp_db: Path) -> None:
    eid, hosts = _setup(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        for name in ("a", "b", "c"):
            pid, _ = yhdb.add_principal(conn, eid, name)
            yhdb.add_credential(conn, eid, name, _EMPTY_NT, "ntlm", "dump", principal_id=pid)
        reuse.derive_reuse_edges(conn, eid)
    assert _edges(tmp_db, eid, "SameHash") == []  # no mega-star from empty hashes


def test_reuse_feeds_pathfind_lateral_movement(tmp_db: Path) -> None:
    eid, hosts = _setup(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        pa, _ = yhdb.add_principal(conn, eid, "alice")
        ca, _ = yhdb.add_credential(conn, eid, "alice", "AH", "ntlm", "dump", principal_id=pa)
        cl, _ = yhdb.add_credential(conn, eid, "ladmin", "LP", "password", "spray")
        # alice is admin on host0; ladmin is admin on host0 AND host1
        yhdb.record_cred_access(conn, eid, ca, hosts[0], port=445, proto="smb",
                                service_kind="smb", result="admin", source="spray")
        for h in (hosts[0], hosts[1]):
            yhdb.record_cred_access(conn, eid, cl, h, port=445, proto="smb",
                                    service_kind="smb", result="admin", source="spray")
        reuse.derive_reuse_edges(conn, eid)
        path = yhdb.shortest_path(conn, eid, f"principal:{pa}", f"host:{hosts[1]}")
    assert path == [f"principal:{pa}", f"host:{hosts[0]}", f"host:{hosts[1]}"]


def test_derive_is_idempotent(tmp_db: Path) -> None:
    eid, hosts = _setup(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        cid, _ = yhdb.add_credential(conn, eid, "ladmin", "PW", "password", "spray")
        for h in hosts[:3]:
            yhdb.record_cred_access(conn, eid, cid, h, port=445, proto="smb",
                                    service_kind="smb", result="admin", source="spray")
        first = reuse.derive_reuse_edges(conn, eid)
        second = reuse.derive_reuse_edges(conn, eid)
    assert sum(first.values()) > 0
    assert sum(second.values()) == 0


def test_secretsdump_auto_derives_same_hash(tmp_db: Path) -> None:
    # Two accounts dumped with the same NT hash -> SameHash appears without a
    # separate reuse call (the ingest auto-derives).
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.upsert_engagement(conn, lab="L", scope="10.0.0.0/24")
        yhdb.add_principal(conn, eid, "u1")
        yhdb.add_principal(conn, eid, "u2")
    dump = ("u1:1001:aad3b435b51404eeaad3b435b51404ee:"
            "5835048ce94ad0564e29a924a03510ef:::\n"
            "u2:1002:aad3b435b51404eeaad3b435b51404ee:"
            "5835048ce94ad0564e29a924a03510ef:::\n")
    out = tool_interpret(tmp_db, "L", dump)
    assert "reuse edge" in out
    assert _edges(tmp_db, eid, "SameHash")


def test_tool_and_cli_reuse(tmp_db: Path) -> None:
    eid, hosts = _setup(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        cid, _ = yhdb.add_credential(conn, eid, "ladmin", "PW", "password", "spray")
        for h in hosts[:2]:
            yhdb.record_cred_access(conn, eid, cid, h, port=445, proto="smb",
                                    service_kind="smb", result="admin", source="spray")
    out = tool_reuse(tmp_db, "L")
    assert "LocalAdminReuse" in out
    # idempotent second call via CLI reports nothing new
    r = CliRunner().invoke(main, ["reuse", "--lab", "L", "--db", str(tmp_db)])
    assert r.exit_code == 0
    assert "no new reuse edges" in r.output
