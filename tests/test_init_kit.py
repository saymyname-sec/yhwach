"""G6b — `yhwach init --kind K`: MCP registration (absolute paths) + per-kind
instruction fragment."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from yhwach import db as yhdb
from yhwach import initkit
from yhwach.cli import main

# --- mcp_registration -------------------------------------------------------


def test_registration_uses_absolute_db_path(tmp_path: Path) -> None:
    rel = "state/y.db"
    reg = initkit.mcp_registration(rel)
    env = reg["config"]["mcpServers"]["yhwach"]["env"]["YHWACH_DB"]
    assert Path(env).is_absolute()
    assert env in reg["add_command"]
    assert reg["config"]["mcpServers"]["yhwach"]["args"] == ["mcp"]
    assert "claude mcp add yhwach" in reg["add_command"]


# --- instruction_fragment ---------------------------------------------------


def test_every_kind_renders() -> None:
    for k in yhdb.ENGAGEMENT_KINDS:
        frag = initkit.instruction_fragment(k)
        assert f"kind: {k}" in frag


def test_none_is_lab() -> None:
    assert "kind: lab" in initkit.instruction_fragment(None)


def test_armed_vs_record_only_posture() -> None:
    for k in ("lab", "ctf"):
        assert "armed" in initkit.instruction_fragment(k).lower()
        assert "record-only" not in initkit.instruction_fragment(k)
    for k in ("internal", "external", "web", "cloud", "redteam", "bounty", "retest"):
        frag = initkit.instruction_fragment(k)
        assert "record-only" in frag
        assert "yhwach arm" in frag
        assert "cannot arm" in frag


def test_kind_specific_guidance() -> None:
    assert "yhwach_submission" in initkit.instruction_fragment("bounty")
    assert "yhwach_reuse" in initkit.instruction_fragment("internal")
    assert "metadata only" in initkit.instruction_fragment("web")
    assert "cloud_tenant_in_scope" in initkit.instruction_fragment("cloud")
    assert "cleanup" in initkit.instruction_fragment("redteam").lower()


def test_invariants_always_present() -> None:
    for k in yhdb.ENGAGEMENT_KINDS:
        frag = initkit.instruction_fragment(k)
        assert "never swept" in frag          # manual spray policy
        assert "metadata only" in frag        # no body capture
        assert "0.0.0.0" in frag              # board bind guard


def test_unknown_kind_raises() -> None:
    with pytest.raises(ValueError):
        initkit.instruction_fragment("nope")


def test_render_filename_switch(tmp_path: Path) -> None:
    assert initkit.render("lab", tmp_path / "y.db")["filename"] == "CLAUDE.md"
    assert initkit.render("lab", tmp_path / "y.db", agents=True)["filename"] == "AGENTS.md"
    out = initkit.render("web", tmp_path / "y.db")
    assert json.loads(out["config_json"])["mcpServers"]["yhwach"]["args"] == ["mcp"]


# --- CLI --------------------------------------------------------------------


def test_cli_init_prints_both(tmp_path: Path) -> None:
    db = tmp_path / "state" / "y.db"
    r = CliRunner().invoke(main, ["init", "--kind", "bounty", "--db", str(db)])
    assert r.exit_code == 0, r.output
    assert "claude mcp add yhwach" in r.output
    assert "kind: bounty" in r.output
    assert "yhwach_submission" in r.output


def test_cli_init_write_and_force(tmp_path: Path) -> None:
    db = tmp_path / "y.db"
    out = tmp_path / "frag"
    r = CliRunner().invoke(main, ["init", "--kind", "internal", "--db", str(db),
                                  "--write", "--dir", str(out)])
    assert r.exit_code == 0, r.output
    f = out / "CLAUDE.md"
    assert f.exists() and "kind: internal" in f.read_text(encoding="utf-8")
    # second write without --force refuses
    r2 = CliRunner().invoke(main, ["init", "--kind", "internal", "--db", str(db),
                                   "--write", "--dir", str(out)])
    assert r2.exit_code == 2 and "exists" in r2.output
    # --force overwrites, and --agents names it AGENTS.md
    r3 = CliRunner().invoke(main, ["init", "--kind", "web", "--db", str(db),
                                   "--write", "--dir", str(out), "--agents"])
    assert r3.exit_code == 0 and (out / "AGENTS.md").exists()


def test_cli_init_accepts_all_kinds(tmp_path: Path) -> None:
    for k in yhdb.ENGAGEMENT_KINDS:
        r = CliRunner().invoke(main, ["init", "--kind", k, "--db", str(tmp_path / "y.db")])
        assert r.exit_code == 0, (k, r.output)


def test_engage_choice_matches_canonical_kinds() -> None:
    # guard against the engage --kind list drifting from the canonical enum
    opt = next(p for p in main.commands["engage"].params if p.name == "kind")
    assert tuple(opt.type.choices) == yhdb.ENGAGEMENT_KINDS


def test_init_choice_matches_canonical_kinds() -> None:
    opt = next(p for p in main.commands["init"].params if p.name == "kind")
    assert tuple(opt.type.choices) == yhdb.ENGAGEMENT_KINDS
