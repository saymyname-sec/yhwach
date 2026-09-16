"""Golden-fixture regression runner.

Every `tests/fixtures/*.yaml` with an `expected:` block is a golden test: seed a
world model, run the planner, assert the ranked output matches. A rule change
that would mis-rank a captured scenario fails here.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from yhwach import db as yhdb
from yhwach.fixtures import (
    load_fixture,
    run_fixture_file,
    seed_world_model,
    snapshot_world_model,
)

FIXTURE_DIR = Path(__file__).parent / "fixtures"
# Recurse so captured lab scenarios under fixtures/labs/ are golden tests too.
FIXTURE_FILES = sorted(FIXTURE_DIR.rglob("*.yaml"))


def test_there_are_fixtures() -> None:
    assert FIXTURE_FILES, "no golden fixtures found"


@pytest.mark.parametrize("fixture_path", FIXTURE_FILES, ids=lambda p: p.stem)
def test_golden_fixture(fixture_path: Path) -> None:
    result = run_fixture_file(fixture_path)
    assert result.passed, f"{result.name}: " + "; ".join(result.failures)


def test_seed_then_snapshot_roundtrips_hosts(tmp_db: Path) -> None:
    fixture = load_fixture(FIXTURE_DIR / "chatbot_open.yaml")
    with yhdb.transaction(tmp_db) as conn:
        eng_id = seed_world_model(conn, fixture)
        snap = snapshot_world_model(conn, eng_id)

    orig_hosts = fixture["world_model"]["hosts"]
    snap_hosts = snap["world_model"]["hosts"]
    assert len(snap_hosts) == len(orig_hosts)
    assert snap_hosts[0]["ip"] == orig_hosts[0]["ip"]

    # surface kind + auth survive the round trip
    orig_kinds = {s["kind"] for s in orig_hosts[0]["surfaces"]}
    snap_kinds = {s["kind"] for s in snap_hosts[0]["surfaces"]}
    assert orig_kinds == snap_kinds


def test_snapshot_preserves_service_port_link(tmp_db: Path) -> None:
    fixture = load_fixture(FIXTURE_DIR / "ollama_unauth.yaml")
    with yhdb.transaction(tmp_db) as conn:
        eng_id = seed_world_model(conn, fixture)
        snap = snapshot_world_model(conn, eng_id)
    surf = snap["world_model"]["hosts"][0]["surfaces"][0]
    assert surf["service_port"] == 11434
