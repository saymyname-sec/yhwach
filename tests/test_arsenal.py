"""Tests for the canonical arsenal registry.

Ground rules:
  * Every canonical key resolves to an absolute Path.
  * The path may or may not exist on CI (arsenal is a Kali box artifact);
    existence checks are gated on ARSENAL_PRESENT=1 so this file stays green
    everywhere.
  * The (os, kind) → item mapping is unambiguous: exactly one canonical entry
    per pair we care about.
  * for_os returns None (never raises) on "no such tool" so callers can
    branch cleanly.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from yhwach import arsenal

_ALL_KEYS = {
    "SVCMON_WIN",
    "LIGOLO_AGENT_LINUX",
    "LIGOLO_PROXY",
    "CHISEL",
    "REVSHELL_GEN_WIN",
    "REVSHELL_GEN_LINUX",
}


def test_registry_covers_expected_keys():
    got = {item.key for item in arsenal.all_items()}
    assert got == _ALL_KEYS


@pytest.mark.parametrize("key", sorted(_ALL_KEYS))
def test_get_returns_absolute_path(key):
    item = arsenal.get(key)
    assert isinstance(item.path, Path)
    assert item.path.is_absolute(), f"{key} path {item.path} is not absolute"


def test_get_unknown_key_raises():
    with pytest.raises(KeyError):
        arsenal.get("NOPE")


def _swap_registry_path(monkeypatch, key: str, new_path: Path) -> None:
    """Substitute a REGISTRY entry with a copy pointing at ``new_path``.

    ArsenalItem is frozen (immutable) so we swap the whole record rather than
    mutating a field — matches how a real path-drift would be corrected.
    """
    original = arsenal._REGISTRY[key]
    swapped = arsenal.ArsenalItem(
        key=original.key,
        path=new_path,
        kind=original.kind,
        os=original.os,
        sha256=original.sha256,
        notes=original.notes,
    )
    patched = dict(arsenal._REGISTRY)
    patched[key] = swapped
    monkeypatch.setattr(arsenal, "_REGISTRY", patched)


def test_resolve_missing_raises_arsenal_missing(tmp_path, monkeypatch):
    ghost = tmp_path / "not-there.bin"
    _swap_registry_path(monkeypatch, "SVCMON_WIN", ghost)
    with pytest.raises(arsenal.ArsenalMissing):
        arsenal.resolve("SVCMON_WIN")


def test_resolve_no_require_returns_path_even_if_missing(tmp_path, monkeypatch):
    ghost = tmp_path / "not-there.bin"
    _swap_registry_path(monkeypatch, "SVCMON_WIN", ghost)
    p = arsenal.resolve("SVCMON_WIN", require_exists=False)
    assert p == ghost


def test_for_os_windows_ligolo_is_svcmon():
    item = arsenal.for_os("windows", "ligolo_agent")
    assert item is not None
    assert item.key == "SVCMON_WIN"


def test_for_os_linux_ligolo_is_linux_agent():
    item = arsenal.for_os("linux", "ligolo_agent")
    assert item is not None
    assert item.key == "LIGOLO_AGENT_LINUX"


def test_for_os_windows_revshell_is_gen_sh():
    item = arsenal.for_os("windows", "revshell_gen")
    assert item is not None
    assert item.key == "REVSHELL_GEN_WIN"


def test_for_os_linux_revshell_is_linux_gen():
    item = arsenal.for_os("linux", "revshell_gen")
    assert item is not None
    assert item.key == "REVSHELL_GEN_LINUX"


def test_for_os_chisel_matches_any_os():
    # kind=chisel_client is os='any' — Windows or Linux both resolve.
    win = arsenal.for_os("windows", "chisel_client")
    lin = arsenal.for_os("linux", "chisel_client")
    assert win is not None and win.key == "CHISEL"
    assert lin is not None and lin.key == "CHISEL"


def test_for_os_no_such_pair_returns_none():
    # There is no ligolo_proxy for windows (we ship the Linux one only).
    assert arsenal.for_os("windows", "ligolo_proxy") is None


def test_windows_ligolo_has_sha256_pin():
    # svcmon.exe is the security-relevant obfuscated build; its sha256 MUST
    # be pinned so an accidental swap is caught by verify_sha256.
    assert arsenal.SVCMON_WIN.sha256 is not None
    assert len(arsenal.SVCMON_WIN.sha256) == 64


def test_chisel_no_sha256_pin():
    # /usr/local/bin/chisel is a system tool; pinning would break on `apt`
    # upgrades — kind='chisel_client' intentionally leaves sha256=None.
    assert arsenal.CHISEL.sha256 is None


@pytest.mark.skipif(
    os.environ.get("ARSENAL_PRESENT") != "1",
    reason="arsenal existence check only runs on the Kali engagement box",
)
def test_all_canonical_paths_exist_when_arsenal_present():
    missing = [i.key for i in arsenal.all_items() if not i.exists()]
    assert not missing, f"arsenal binaries missing on this box: {missing}"


@pytest.mark.skipif(
    os.environ.get("ARSENAL_PRESENT") != "1",
    reason="sha256 verification only runs on the Kali engagement box",
)
def test_pinned_sha256s_verify_on_disk():
    bad = [i.key for i in arsenal.all_items() if i.sha256 and not i.verify_sha256()]
    assert not bad, f"pinned sha256 mismatch: {bad}"
