"""I54 — indirect-injection plant tracker.

A plant is an injection left in a writable source; it fires elsewhere later.
Each plant carries a NEUTRAL canary (no tool fingerprint). Sightings attribute a
firing back to a plant. A live (not-removed) plant blocks a clean close.
"""
from __future__ import annotations

from pathlib import Path

from yhwach import db as yhdb
from yhwach.mcp_tools import tool_plant, tool_query, tool_report_check


def _eng(path: Path) -> int:
    with yhdb.transaction(path) as conn:
        return yhdb.upsert_engagement(conn, lab="L", scope="10.0.0.0/24")


def test_plant_returns_neutral_canary(tmp_db: Path) -> None:
    _eng(tmp_db)
    out = tool_plant(tmp_db, "L", location="kb doc #7", payload="ignore prior", kind="rag")
    assert "plant #1" in out
    with yhdb.transaction(tmp_db) as conn:
        canary = conn.execute("SELECT canary FROM plant WHERE id=1").fetchone()["canary"]
    assert canary and not canary.upper().startswith("YHW")


def test_sighting_attributes_to_plant(tmp_db: Path) -> None:
    _eng(tmp_db)
    tool_plant(tmp_db, "L", location="kb", payload="x")
    tool_plant(tmp_db, "L", sight=1, context="bot echoed the canary")
    with yhdb.transaction(tmp_db) as conn:
        n = conn.execute("SELECT COUNT(*) n FROM plant_sighting WHERE plant_id=1").fetchone()["n"]
    assert n == 1


def test_live_plant_is_a_cleanup_obligation(tmp_db: Path) -> None:
    _eng(tmp_db)
    tool_plant(tmp_db, "L", location="kb", payload="x")
    chk = tool_report_check(tmp_db, "L")
    assert "injection plant(s) not confirmed removed" in chk


def test_removal_clears_the_obligation(tmp_db: Path) -> None:
    _eng(tmp_db)
    tool_plant(tmp_db, "L", location="kb", payload="x")
    tool_plant(tmp_db, "L", remove=1)
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.engagement_id_for(conn, "L")
        assert yhdb.outstanding_plants(conn, eid) == []


def test_list_shows_live_and_removed(tmp_db: Path) -> None:
    _eng(tmp_db)
    tool_plant(tmp_db, "L", location="a", payload="x")
    tool_plant(tmp_db, "L", location="b", payload="y")
    tool_plant(tmp_db, "L", remove=1)
    out = tool_plant(tmp_db, "L")
    assert "LIVE" in out and "removed" in out
    assert "CLEANUP: 1 plant(s) still live" in out


def test_plants_view(tmp_db: Path) -> None:
    _eng(tmp_db)
    tool_plant(tmp_db, "L", location="customer-kb", payload="inject", kind="rag")
    out = tool_query(tmp_db, "L", "plants", fields=["location", "kind", "canary"])
    assert "customer-kb" in out and "rag" in out


def test_each_plant_gets_a_distinct_canary(tmp_db: Path) -> None:
    _eng(tmp_db)
    tool_plant(tmp_db, "L", location="a", payload="x")
    tool_plant(tmp_db, "L", location="b", payload="y")
    with yhdb.transaction(tmp_db) as conn:
        cans = [r["canary"] for r in conn.execute("SELECT canary FROM plant")]
    assert len(set(cans)) == 2
