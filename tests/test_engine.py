"""Tests for :mod:`yhwach.engine` — artifact_dir + render_pivot.

Focus on the pivot rendering: canonical arsenal paths must appear in the
rendered commands, and kind selection must respect an explicit override
before it falls back to the OS heuristic.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from yhwach import arsenal, engine

# ── artifact_dir ────────────────────────────────────────────────────────────

def test_artifact_dir_canonical_lab_layout(tmp_path: Path) -> None:
    lab = tmp_path / "lab" / "state" / "yhwach.db"
    lab.parent.mkdir(parents=True)
    lab.touch()
    assert engine.artifact_dir(lab, "loot") == lab.parent.parent / "loot"


def test_artifact_dir_flat_db_path(tmp_path: Path) -> None:
    flat = tmp_path / "y.db"
    flat.touch()
    assert engine.artifact_dir(flat, "recon") == tmp_path / "recon"


# ── render_pivot ────────────────────────────────────────────────────────────

def _joined(lines: list[str]) -> str:
    return "\n".join(lines)


def test_render_pivot_windows_uses_svcmon_absolute_path():
    lines = engine.render_pivot("172.16.10.13", "10.0.0.0/24", "Windows Server 2022")
    body = _joined(lines)
    svcmon = str(arsenal.get("SVCMON_WIN").path)
    assert svcmon in body, "Windows branch must emit svcmon.exe's ABSOLUTE canonical path"
    assert ".\\svcmon.exe -connect" in body
    assert "kind=ligolo" in body


def test_render_pivot_windows_names_ligolo_proxy_absolute_path():
    lines = engine.render_pivot("192.0.2.10", "10.0.0.0/24", "Windows 10")
    proxy = str(arsenal.get("LIGOLO_PROXY").path)
    assert proxy in _joined(lines)


def test_render_pivot_linux_default_is_chisel():
    lines = engine.render_pivot("172.16.10.13", "10.0.0.0/24", "Linux 5.15")
    body = _joined(lines)
    chisel = str(arsenal.get("CHISEL").path)
    assert "kind=chisel" in body
    assert chisel in body, "Linux default must emit chisel absolute path (canonical Linux pivot)"
    assert "server -p" in body and "--reverse" in body
    assert "R:1080:socks" in body


def test_render_pivot_linux_ligolo_when_forced():
    lines = engine.render_pivot(
        "10.10.10.10", "10.20.0.0/24", "linux",
        pivot_kind="ligolo",
    )
    body = _joined(lines)
    agent = str(arsenal.get("LIGOLO_AGENT_LINUX").path)
    assert "kind=ligolo" in body
    assert agent in body, "explicit pivot_kind=ligolo on Linux must use ligolo-agent-linux"
    assert "sudo" in body and "ligolo" in body


def test_render_pivot_unknown_os_defaults_to_chisel():
    lines = engine.render_pivot("172.16.0.5", "10.0.0.0/24", None)
    assert "kind=chisel" in _joined(lines)


def test_render_pivot_lport_override_wins():
    lines = engine.render_pivot(
        "172.16.0.5", "10.0.0.0/24", "windows",
        lport=44443,
    )
    assert ":44443" in _joined(lines)


def test_render_pivot_chisel_default_port_is_9055():
    # ligolo default (11601) and chisel default (9055) MUST differ so a single
    # operator box can hold both without a port clash.
    lines = engine.render_pivot("172.16.0.5", "10.0.0.0/24", "linux")
    assert ":9055" in _joined(lines)


def test_render_pivot_windows_default_port_is_11601():
    lines = engine.render_pivot("172.16.0.5", "10.0.0.0/24", "windows")
    assert ":11601" in _joined(lines)


def test_render_pivot_unknown_kind_does_not_invent_commands():
    lines = engine.render_pivot(
        "10.0.0.5", "10.0.1.0/24", "linux",
        pivot_kind="wireguard",
    )
    body = _joined(lines)
    assert "unknown pivot kind" in body
    # Anti-fabrication: no fake command lines
    assert "wireguard" in body
    assert "$ " not in body.replace("$ARG", "")


@pytest.mark.parametrize("os_hint,expected_kind", [
    ("Windows Server 2019", "ligolo"),
    ("Windows 10", "ligolo"),
    ("Linux 6.1", "chisel"),
    ("ubuntu 22.04", "chisel"),
    (None, "chisel"),
    ("", "chisel"),
])
def test_render_pivot_kind_heuristic(os_hint, expected_kind):
    lines = engine.render_pivot("10.0.0.5", "10.0.1.0/24", os_hint)
    assert f"kind={expected_kind}" in _joined(lines)
