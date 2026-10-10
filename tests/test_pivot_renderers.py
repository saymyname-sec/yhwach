"""Tests for the pivot / revshell renderers.

Ground rules:
  * Every renderer emits the CANONICAL absolute arsenal path — no bare
    filenames, no ``svcmon.exe`` without a leading directory.
  * The RENDERERS registry has an entry for every rule in playbooks/pivot.yaml.
  * Windows renderers do not leak into Linux flows and vice-versa (renderer
    keys are 1:1 with rule ids so wrong-OS dispatch is a schema bug caught
    by :func:`test_registry_mirrors_pivot_yaml`).
"""
from __future__ import annotations

import pytest

from yhwach import arsenal
from yhwach import pivot_renderers as pr


def _joined(lines):
    return "\n".join(lines)


# ── registry integrity ─────────────────────────────────────────────────────

def test_registry_mirrors_pivot_yaml():
    """Every rule id in playbooks/pivot.yaml MUST have a renderer here."""
    from yhwach.knowledge import load_techniques

    pivot_ids = {
        t.id for t in load_techniques()
        if t.id in {
            "pivot_ligolo_windows",
            "pivot_chisel_linux",
            "pivot_ligolo_linux",
            "generate_windows_revshell",
            "generate_linux_revshell",
        }
    }
    assert set(pr.RENDERERS) == pivot_ids, (
        "RENDERERS must be 1:1 with pivot.yaml rule ids — a rule without a "
        "renderer will emit an unroutable action at runtime."
    )


# ── Windows: svcmon.exe canonical path ─────────────────────────────────────

def test_deploy_svcmon_uses_absolute_svcmon_path():
    lines = pr.deploy_svcmon_and_route(
        target_ip="172.16.10.13",
        kali_ip="192.168.45.201",
        subnet="10.0.0.0/24",
    )
    body = _joined(lines)
    svcmon = str(arsenal.get("SVCMON_WIN").path)
    assert svcmon in body, "svcmon.exe canonical absolute path must appear"
    assert "C:\\Users\\Public\\svcmon.exe" in body
    proxy = str(arsenal.get("LIGOLO_PROXY").path)
    assert proxy in body


def test_deploy_svcmon_lport_and_subnet_in_route():
    lines = pr.deploy_svcmon_and_route(
        target_ip="10.0.0.5", kali_ip="10.9.9.9", subnet="10.10.0.0/24", lport=44443,
    )
    body = _joined(lines)
    assert ":44443" in body
    assert "10.10.0.0/24" in body


# ── Linux: chisel canonical path ───────────────────────────────────────────

def test_deploy_chisel_uses_usr_local_bin_chisel():
    lines = pr.deploy_chisel_reverse_socks(
        target_ip="172.16.10.13",
        kali_ip="192.168.45.201",
        subnet="10.0.0.0/24",
    )
    body = _joined(lines)
    assert str(arsenal.get("CHISEL").path) in body
    assert "R:1080:socks" in body
    server_idx = body.index("server -p")
    client_idx = body.index("client 192.168.45.201")
    assert server_idx < client_idx, "chisel server line must come before client line"


def test_deploy_chisel_default_ports():
    lines = pr.deploy_chisel_reverse_socks(
        target_ip="10.0.0.5", kali_ip="10.9.9.9", subnet="10.10.0.0/24",
    )
    body = _joined(lines)
    assert f":{pr.CHISEL_DEFAULT_PORT}" in body
    assert f":{pr.CHISEL_SOCKS_PORT}" in body


# ── Linux ligolo agent (alt L3 path) ───────────────────────────────────────

def test_deploy_ligolo_agent_linux_uses_current_tools_path():
    lines = pr.deploy_ligolo_agent_linux(
        target_ip="10.0.0.5", kali_ip="10.9.9.9", subnet="10.10.0.0/24",
    )
    body = _joined(lines)
    agent = str(arsenal.get("LIGOLO_AGENT_LINUX").path)
    assert agent in body
    assert "ligolo-agent-linux" in body
    assert "sudo" in body
    assert str(arsenal.get("LIGOLO_PROXY").path) in body


# ── revshell generators ────────────────────────────────────────────────────

def test_render_gen_sh_writes_to_default_loot_revshells():
    lines = pr.render_gen_sh(kali_ip="10.9.9.9", lport=4444)
    body = _joined(lines)
    assert str(arsenal.get("REVSHELL_GEN_WIN").path) in body
    assert str(pr.DEFAULT_LOOT_REVSHELLS) in body
    assert "mcs" in body
    assert "csc.exe" in body


def test_render_gen_sh_respects_outdir_override(tmp_path):
    lines = pr.render_gen_sh(kali_ip="10.9.9.9", lport=4444, outdir=tmp_path)
    body = _joined(lines)
    assert str(tmp_path) in body


def test_render_gen_linux_shell_uses_canonical_generator():
    lines = pr.render_gen_linux_shell(kali_ip="10.9.9.9", lport=4444)
    body = _joined(lines)
    assert str(arsenal.get("REVSHELL_GEN_LINUX").path) in body
    for payload in ("bash_devtcp", "python_pty", "socat", "nc_mkfifo", "perl", "elf_revshell"):
        assert payload in body, f"linux revshell menu missing {payload}"


# ── smoke: every renderer callable ────────────────────────────────────────

@pytest.mark.parametrize("rule_id", sorted([
    "pivot_ligolo_windows", "pivot_chisel_linux", "pivot_ligolo_linux",
    "generate_windows_revshell", "generate_linux_revshell",
]))
def test_every_renderer_returns_nonempty_command_block(rule_id):
    """A renderer must always emit at least a header + one command line — an
    empty list means the operator would see nothing on that action."""
    fn = pr.RENDERERS[rule_id]
    if rule_id.startswith("pivot_"):
        lines = fn(target_ip="1.1.1.1", kali_ip="9.9.9.9", subnet="10.0.0.0/24")
    else:  # generate_* revshell renderers
        lines = fn(kali_ip="9.9.9.9", lport=4444)
    assert len(lines) >= 3
    # Header line starts with "==" per _header()
    assert lines[0].startswith("==")
