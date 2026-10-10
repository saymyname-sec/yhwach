"""yhwach paths — render the owned → objective attack path.

db.shortest_path existed but was only reachable for a hand-named pair and was
never rendered on the board. These tests lock the automatic version: derive the
owned nodes + objective targets, find the shortest path to each, and report
unreachable targets honestly.
"""
from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from yhwach import db as yhdb
from yhwach import pathfind
from yhwach.cli import main


def _seed(tmp_db: Path) -> int:
    """svc (we hold its cred) --GenericAll--> helpdesk --MemberOf--> Domain Admins,
    and svc --AdminTo--> DC01 (an objective host). A second objective host has no
    inbound edge (unreachable). Returns engagement id."""
    with yhdb.transaction(tmp_db) as conn:
        eng = yhdb.upsert_engagement(conn, lab="pathtest", scope="10.0.0.0/24", domain="corp.local")
        svc = yhdb.add_principal(conn, eng, "svc", type="user")[0]
        helpdesk = yhdb.add_principal(conn, eng, "helpdesk", type="user")[0]
        da = yhdb.add_principal(conn, eng, "Domain Admins", type="group")[0]
        dc = int(conn.execute(
            "INSERT INTO host (engagement_id, ip, hostname, stage, first_seen) "
            "VALUES (?, '10.0.0.10', 'DC01', 'scanned', 't')", (eng,)).lastrowid)
        far = int(conn.execute(
            "INSERT INTO host (engagement_id, ip, hostname, stage, first_seen) "
            "VALUES (?, '10.0.0.20', 'SAFE01', 'scanned', 't')", (eng,)).lastrowid)
        # we own svc (hold its credential)
        yhdb.add_credential(conn, eng, "svc", "P@ss", "password", "dump")
        # the graph
        yhdb.add_edge(conn, eng, f"principal:{svc}", f"principal:{helpdesk}", "GenericAll")
        yhdb.add_edge(conn, eng, f"principal:{helpdesk}", f"principal:{da}", "MemberOf")
        yhdb.add_edge(conn, eng, f"principal:{svc}", f"host:{dc}", "AdminTo")
        # objectives: one reachable (DC01), one not (SAFE01)
        yhdb.add_objective(conn, eng, "proof.txt", host_id=dc, points=25)
        yhdb.add_objective(conn, eng, "flag2", host_id=far, points=5)
        return eng


def test_owned_nodes_and_targets(tmp_db: Path) -> None:
    eng = _seed(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        owned = pathfind.owned_nodes(conn, eng)
        targets = dict(pathfind.objective_targets(conn, eng))
    # svc is owned via its held credential
    assert any(n.startswith("principal:") for n in owned)
    # both objective hosts + the Domain Admins crown are targets
    labels = set(targets.values())
    assert "proof.txt" in labels and "flag2" in labels and "Domain Admins" in labels


def test_paths_reachable_and_unreachable(tmp_db: Path) -> None:
    eng = _seed(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        found = {p.target_label: p for p in pathfind.paths_to_objectives(conn, eng)}
    # Domain Admins: svc --GenericAll--> helpdesk --MemberOf--> Domain Admins = 2 hops
    da = found["Domain Admins"]
    assert da.reachable and da.hops == 2
    # DC01 objective: svc --AdminTo--> DC01 = 1 hop
    assert found["proof.txt"].reachable and found["proof.txt"].hops == 1
    # SAFE01: no inbound edge -> unreachable
    assert not found["flag2"].reachable and found["flag2"].hops is None


def test_render_path_and_objectives(tmp_db: Path) -> None:
    eng = _seed(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        found = pathfind.paths_to_objectives(conn, eng)
        text = "\n".join(pathfind.render_objectives(conn, found))
    assert "GenericAll" in text and "MemberOf" in text
    assert "Domain Admins" in text
    assert "no known path yet" in text  # the unreachable one


def test_reachable_sorted_before_unreachable(tmp_db: Path) -> None:
    eng = _seed(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        found = pathfind.paths_to_objectives(conn, eng)
    # every reachable target precedes every unreachable one
    reach_flags = [p.reachable for p in found]
    assert reach_flags == sorted(reach_flags, reverse=True)


def test_cli_paths(tmp_db: Path) -> None:
    _seed(tmp_db)
    res = CliRunner().invoke(main, ["paths", "--lab", "pathtest", "--db", str(tmp_db)])
    assert res.exit_code == 0, res.output
    assert "Paths to objectives for 'pathtest'" in res.output
    assert "Domain Admins" in res.output
    js = CliRunner().invoke(
        main, ["paths", "--lab", "pathtest", "--json", "--db", str(tmp_db)])
    assert js.exit_code == 0, js.output
    doc = json.loads(js.output)
    assert any(p["target"] == "Domain Admins" and p["reachable"] for p in doc)


def test_mcp_tool_paths(tmp_db: Path) -> None:
    from yhwach import mcp_tools

    _seed(tmp_db)
    out = mcp_tools.tool_paths(tmp_db, "pathtest")
    assert "Paths to objectives for 'pathtest'" in out
    assert "Domain Admins" in out
    names = {name for name, _fn, _desc in mcp_tools.TOOL_SPECS}
    assert "yhwach_paths" in names
