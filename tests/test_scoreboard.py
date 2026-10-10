"""Objective / flag scoreboard — the timed-engagement cockpit.

`db.add_objective` had no operator caller and the scoring columns were dormant.
These lock the write path (add / capture) and the derived scoreboard (points
scored vs target, flags captured vs found). The point target/max are optional,
engagement-specific fields — the engine assumes no numbers; the operator sets
them at engage time.
"""
from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from yhwach import db as yhdb
from yhwach import scoreboard
from yhwach.cli import main


def _seed(tmp_db: Path, *, points_target: int | None = 75,
          points_max: int | None = 100) -> tuple[int, int]:
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.upsert_engagement(conn, lab="sc", scope="10.0.0.0/24",
                                     points_target=points_target, points_max=points_max)
        hid = int(conn.execute(
            "INSERT INTO host (engagement_id, ip, stage, first_seen) "
            "VALUES (?, '10.0.0.5', 'foothold', 't')", (eid,)).lastrowid)
        return eid, hid


def test_scoreboard_with_target(tmp_db: Path) -> None:
    """A scored engagement (operator set a target) renders % of target."""
    eid, _ = _seed(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        sb = scoreboard.compute(conn, eid)
    assert sb.points_scored == 0 and sb.captured == 0 and sb.total == 0
    assert sb.points_target == 75 and sb.points_max == 100 and sb.pct == 0


def test_unscored_engagement_has_no_target(tmp_db: Path) -> None:
    """With no target set, the engine assumes no numbers: target/max/pct are None,
    and the board shows a plain running count with no denominator."""
    eid, _ = _seed(tmp_db, points_target=None, points_max=None)
    with yhdb.transaction(tmp_db) as conn:
        sb = scoreboard.compute(conn, eid)
        text = "\n".join(scoreboard.render(conn, eid))
    assert sb.points_target is None and sb.points_max is None and sb.pct is None
    assert "Score: 0 pts" in text and "% of target" not in text and "/" not in text.split("·")[0]


def test_score_derives_from_captured_objectives(tmp_db: Path) -> None:
    eid, hid = _seed(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        yhdb.add_objective(conn, eid, "local.txt", host_id=hid, points=10)
        yhdb.add_objective(conn, eid, "proof.txt", host_id=hid, points=25)
        n, msg = yhdb.capture_objective(conn, eid, "proof.txt")
        sb = scoreboard.compute(conn, eid)
    assert n == 1 and msg is None
    assert sb.points_scored == 25 and sb.captured == 1 and sb.total == 2
    assert sb.pct == round(100 * 25 / 75)


def test_capture_scoping_and_misses(tmp_db: Path) -> None:
    eid, hid = _seed(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        yhdb.add_objective(conn, eid, "flag", host_id=hid, points=5)
        # wrong host -> no match
        n0, msg0 = yhdb.capture_objective(conn, eid, "flag", host_ip="10.0.0.99")
        assert n0 == 0 and "no uncaptured" in msg0
        # right host -> captured
        n1, _ = yhdb.capture_objective(conn, eid, "flag", host_ip="10.0.0.5")
        assert n1 == 1
        # already captured -> no match second time
        n2, _ = yhdb.capture_objective(conn, eid, "flag")
        assert n2 == 0


def test_render_and_as_dict(tmp_db: Path) -> None:
    eid, hid = _seed(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        yhdb.add_objective(conn, eid, "proof.txt", host_id=hid, points=25)
        text = "\n".join(scoreboard.render(conn, eid))
        doc = scoreboard.as_dict(conn, eid)
    assert "Score:" in text and "proof.txt" in text
    for key in ("points_scored", "points_target", "captured", "total", "objectives"):
        assert key in doc
    assert json.loads(json.dumps(doc))  # serialisable end-to-end


def test_cli_objective_add_capture_list(tmp_db: Path) -> None:
    _seed(tmp_db)
    r = CliRunner()
    add = r.invoke(main, ["objective", "--lab", "sc", "--add", "proof.txt",
                          "--host", "10.0.0.5", "--points", "25", "--db", str(tmp_db)])
    assert add.exit_code == 0, add.output
    cap = r.invoke(main, ["objective", "--lab", "sc", "--capture", "proof.txt",
                          "--db", str(tmp_db)])
    assert cap.exit_code == 0 and "captured 1" in cap.output
    board = r.invoke(main, ["objective", "--lab", "sc", "--db", str(tmp_db)])
    assert "Scoreboard for 'sc'" in board.output and "25/75" in board.output
    js = r.invoke(main, ["objective", "--lab", "sc", "--json", "--db", str(tmp_db)])
    doc = json.loads(js.output)
    assert doc["points_scored"] == 25 and doc["captured"] == 1


def test_mcp_tool_objective(tmp_db: Path) -> None:
    from yhwach import mcp_tools

    _seed(tmp_db)
    mcp_tools.tool_objective(tmp_db, "sc", add="proof.txt", host="10.0.0.5", points=25)
    out = mcp_tools.tool_objective(tmp_db, "sc", capture="proof.txt")
    assert "Scoreboard for 'sc'" in out and "25/75" in out
    names = {name for name, _fn, _desc in mcp_tools.TOOL_SPECS}
    assert "yhwach_objective" in names
