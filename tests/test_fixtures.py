"""World-model fixture helpers: seed a lab from YAML, snapshot it back.

Post-strip there is no ranker/golden runner — these just verify the seed/snapshot
round-trip that the lab fixtures and tests rely on.
"""
from __future__ import annotations

from pathlib import Path

from yhwach import db as yhdb
from yhwach.fixtures import load_fixture, seed_world_model, snapshot_world_model

FIXTURE_DIR = Path(__file__).parent / "fixtures"


def test_there_are_fixtures() -> None:
    assert sorted(FIXTURE_DIR.rglob("*.yaml")), "no fixtures found"


def test_seed_then_snapshot_roundtrips_hosts(tmp_db: Path) -> None:
    fixture = load_fixture(FIXTURE_DIR / "chatbot_open.yaml")
    with yhdb.transaction(tmp_db) as conn:
        eng_id = seed_world_model(conn, fixture)
        snap = snapshot_world_model(conn, eng_id)
    orig_hosts = fixture["world_model"]["hosts"]
    snap_hosts = snap["world_model"]["hosts"]
    assert len(snap_hosts) == len(orig_hosts)
    assert snap_hosts[0]["ip"] == orig_hosts[0]["ip"]
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
