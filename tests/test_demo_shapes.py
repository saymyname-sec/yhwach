"""G6c-e — the demo seeds and a real-shape CI suite.

These assert product-level invariants against synthetic-but-realistic engagements:
  * brief size budget — the governor keeps a brief small even on a multi-host seed;
  * no "points" outside labs — client kinds carry no scoring target;
  * pathfind-from-provided-account — an assumed-breach account reaches the DC;
  * no-network disarmed proof — client kinds start record-only and a gated tool
    refuses before it could ever touch the network.
"""
from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from yhwach import brief, demo, pathfind, scoreboard
from yhwach import db as yhdb
from yhwach.cli import main
from yhwach.mcp_tools import tool_enum

BRIEF_BUDGET = 6000          # chars; a brief must fit an LLM preamble comfortably
_CLIENT_KINDS = ("internal", "web", "cloud", "bounty")


@pytest.fixture()
def seeded(tmp_db: Path) -> dict[str, int]:
    ids: dict[str, int] = {}
    for kind in demo.SEED_KINDS:
        with yhdb.transaction(tmp_db) as conn:
            ids[kind] = demo.build_demo(conn, kind)["engagement_id"]
    return ids


# --- all seeds build --------------------------------------------------------


def test_every_seed_builds(seeded: dict[str, int]) -> None:
    assert set(seeded) == set(demo.SEED_KINDS)
    assert len(demo.SEED_KINDS) == 5


def test_build_rejects_unknown_kind(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn, pytest.raises(ValueError):
        demo.build_demo(conn, "nope")


# --- 1. brief size budget ---------------------------------------------------


def test_brief_within_budget(tmp_db: Path, seeded: dict[str, int]) -> None:
    with yhdb.transaction(tmp_db) as conn:
        for kind, eid in seeded.items():
            b = brief.build_brief(conn, eid)
            assert b, kind
            assert len(b) < BRIEF_BUDGET, f"{kind} brief is {len(b)} chars (> {BRIEF_BUDGET})"


# --- 2. no "points" outside labs --------------------------------------------


def test_no_points_outside_labs(tmp_db: Path, seeded: dict[str, int]) -> None:
    with yhdb.transaction(tmp_db) as conn:
        for kind in _CLIENT_KINDS:
            sb = scoreboard.as_dict(conn, seeded[kind])
            assert sb["points_target"] is None, kind
            assert sb["points_max"] is None, kind
            assert sb["pct"] is None, kind
            assert all(o["points"] == 0 for o in sb["objectives"]), kind


def test_lab_may_be_scored(tmp_db: Path, seeded: dict[str, int]) -> None:
    with yhdb.transaction(tmp_db) as conn:
        sb = scoreboard.as_dict(conn, seeded["lab"])
    assert sb["points_target"] == 20 and sb["points_max"] == 40


# --- 3. pathfind-from-provided-account --------------------------------------


def test_internal_provided_account_reaches_dc(tmp_db: Path, seeded: dict[str, int]) -> None:
    with yhdb.transaction(tmp_db) as conn:
        eid = seeded["internal"]
        owned = pathfind.owned_nodes(conn, eid)
        paths = pathfind.paths_to_objectives(conn, eid)
    # the provided account is the only owned source
    assert owned and all(n.startswith("principal:") for n in owned)
    reachable = [p for p in paths if p.reachable]
    assert reachable, "the assumed-breach account should reach at least the DC"
    dc = next(p for p in reachable if "Domain Controller" in p.target_label)
    assert dc.source_node in owned and dc.hops == 1


# --- 4. no-network disarmed proof -------------------------------------------


def test_client_kinds_start_record_only(tmp_db: Path, seeded: dict[str, int]) -> None:
    with yhdb.transaction(tmp_db) as conn:
        for kind in _CLIENT_KINDS:
            assert yhdb.engagement_armed(conn, seeded[kind]) is False, kind
        assert yhdb.engagement_armed(conn, seeded["lab"]) is True


def test_gated_tool_refuses_before_network(tmp_db: Path, seeded: dict[str, int]) -> None:
    # tool_enum asserts armed BEFORE it opens any HexStrike connection, so on a
    # record-only engagement it raises without ever touching the network.
    with pytest.raises(ValueError, match="record_only"):
        tool_enum(tmp_db, "demo-internal", "10.10.0.1")


# --- CLI --------------------------------------------------------------------


def test_cli_demo_seeds_and_hints(tmp_db: Path) -> None:
    r = CliRunner().invoke(main, ["demo", "--kind", "internal", "--db", str(tmp_db)])
    assert r.exit_code == 0, r.output
    assert "record-only" in r.output
    assert "yhwach path" in r.output   # internal gets the pathfind hint


def test_cli_demo_refuses_duplicate(tmp_db: Path) -> None:
    runner = CliRunner()
    r1 = runner.invoke(main, ["demo", "--kind", "web", "--db", str(tmp_db)])
    assert r1.exit_code == 0, r1.output
    r2 = runner.invoke(main, ["demo", "--kind", "web", "--db", str(tmp_db)])
    assert r2.exit_code == 2 and "already exists" in r2.output


def test_cli_demo_all_kinds(tmp_db: Path) -> None:
    for kind in demo.SEED_KINDS:
        r = CliRunner().invoke(main, ["demo", "--kind", kind, "--lab", f"d-{kind}",
                                      "--db", str(tmp_db)])
        assert r.exit_code == 0, (kind, r.output)
