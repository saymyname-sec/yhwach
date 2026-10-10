"""Scope validation / containment helpers."""
from __future__ import annotations

from yhwach.scope import in_scope, is_ip_or_cidr, validate_scope


def test_is_ip_or_cidr() -> None:
    assert is_ip_or_cidr("10.0.0.5")
    assert is_ip_or_cidr("10.0.0.0/24")
    assert not is_ip_or_cidr("dc01.corp.local")
    assert not is_ip_or_cidr("not-a-cidr")


def test_validate_scope() -> None:
    assert validate_scope("10.0.0.0/24, 192.168.1.5") == []
    assert validate_scope("10.0.0.0/24, bogus, 999.1.1.1") == ["bogus", "999.1.1.1"]


def test_in_scope_ip_and_cidr() -> None:
    scope = "10.0.0.0/24,172.16.5.0/24"
    assert in_scope("10.0.0.42", scope)          # IP inside a scope CIDR
    assert in_scope("172.16.5.0/25", scope)      # sub-CIDR inside scope
    assert not in_scope("10.9.9.9", scope)       # outside every scope net


def test_in_scope_empty_scope_allows() -> None:
    assert in_scope("10.0.0.1", "")              # unknown scope -> don't block


def test_in_scope_hostname_is_false() -> None:
    assert not in_scope("dc01.corp.local", "10.0.0.0/24")
