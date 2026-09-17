"""Tests for the action layer: registry coverage, rendering, execution policy."""
from __future__ import annotations

from pathlib import Path

import pytest

from yhwach.actions import (
    ACTION_REGISTRY,
    context_from_surface,
    get_action,
    render_action,
    run_action,
)
from yhwach.playbooks import default_playbook_dir, load_rules


def test_every_playbook_emit_has_an_action() -> None:
    """Coverage guard: every action referenced by a rule exists in the registry."""
    rules = load_rules(default_playbook_dir())
    referenced = {e.get("action") for r in rules for e in r.emits}
    missing = {a for a in referenced if a not in ACTION_REGISTRY}
    assert not missing, f"playbook emits with no registered action: {sorted(missing)}"


def test_context_from_surface_builds_url() -> None:
    ctx = context_from_surface("10.0.0.5", 11434, {"models": ["llama3.2"]})
    assert ctx["URL"] == "http://10.0.0.5:11434"
    assert ctx["IP"] == "10.0.0.5"
    assert ctx["MODEL"] == "llama3.2"


def test_render_fills_placeholders() -> None:
    action = get_action("probe_ollama_models")
    ctx = context_from_surface("10.0.0.5", 11434, {})
    rendered = render_action(action, ctx)
    assert rendered == ["curl -sk http://10.0.0.5:11434/api/tags"]


def test_render_keeps_json_braces_intact() -> None:
    action = get_action("mcp_tools_list")
    ctx = context_from_surface("10.0.0.9", 8080, {})
    rendered = render_action(action, ctx)[0]
    assert '"jsonrpc":"2.0"' in rendered
    assert "http://10.0.0.9:8080/mcp" in rendered


def test_render_substitutes_endpoint_from_meta() -> None:
    action = get_action("craft_system_prompt_leak")
    ctx = context_from_surface("10.0.0.7", 8000, {"endpoint": "/v2/message"})
    rendered = render_action(action, ctx)[0]
    assert "http://10.0.0.7:8000/v2/message" in rendered


def test_text_to_sql_bypass_renders_hex_projection() -> None:
    action = get_action("craft_text_to_sql_bypass")
    assert action.risk == "propose" and action.runnable is False
    rendered = "\n".join(render_action(action, context_from_surface("10.0.0.20", 80, {})))
    assert "hex(value)" in rendered
    assert "http://10.0.0.20:80" in rendered


def test_run_action_refuses_propose() -> None:
    action = get_action("jenkins_script_console")
    assert action.risk == "propose"
    with pytest.raises(PermissionError):
        run_action(action, context_from_surface("10.0.0.1", 8080, {}))


def test_run_action_refuses_render_only_readonly() -> None:
    # nuclei_scan is read_only but runnable=False (heavy / external) -> refuse.
    action = get_action("nuclei_scan")
    assert action.risk == "read_only" and action.runnable is False
    with pytest.raises(PermissionError):
        run_action(action, context_from_surface("10.0.0.1", 80, {}))


def test_run_action_executes_readonly(tmp_path: Path) -> None:
    # Use a harmless read_only action but override its command to a portable echo,
    # to avoid depending on curl/network in CI.
    from yhwach.actions import Action

    action = Action(id="echo_probe", commands=["echo yhwach-$IP-$PORT"], risk="read_only")
    ctx = context_from_surface("10.0.0.5", 1234, {})
    results = run_action(action, ctx, loot_dir=tmp_path)
    assert results[0]["returncode"] == 0
    assert "yhwach-10.0.0.5-1234" in results[0]["output"]
    assert Path(results[0]["loot_file"]).exists()


def test_registry_risk_values_are_valid() -> None:
    for a in ACTION_REGISTRY.values():
        assert a.risk in {"read_only", "propose", "destructive"}
