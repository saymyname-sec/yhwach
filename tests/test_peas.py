"""Tests for linPEAS / winPEAS privesc extraction."""
from __future__ import annotations

from yhwach.parsers.peas import parse_linpeas, parse_peas, parse_winpeas


def _titles(findings):
    return {f.title for f in findings}


def test_linpeas_sudo_nopasswd() -> None:
    text = "Checking sudo -l\nUser may run the following:\n    (root) NOPASSWD: /usr/bin/find"
    f = parse_linpeas(text)
    assert "sudo NOPASSWD entry" in _titles(f)
    assert any(x.severity == "high" for x in f)


def test_linpeas_suid_gtfobins() -> None:
    text = "-rwsr-xr-x 1 root root 100 Jan 1 /usr/bin/find\n-rwsr-xr-x 1 root root 5 x /usr/bin/vim"
    f = parse_linpeas(text)
    titles = _titles(f)
    assert "Exploitable SUID binary (GTFObins)" in titles
    ev = next(x.evidence for x in f if x.title.startswith("Exploitable SUID"))
    assert "find" in ev and "vim" in ev


def test_linpeas_capability() -> None:
    text = "Files with capabilities:\n/usr/bin/python3 = cap_setuid+ep"
    f = parse_linpeas(text)
    assert "Dangerous file capability" in _titles(f)


def test_linpeas_writable_passwd() -> None:
    text = "You have write privileges over /etc/passwd"
    f = parse_linpeas(text)
    crit = [x for x in f if x.title == "Writable /etc/passwd"]
    assert crit and crit[0].severity == "critical"


def test_linpeas_private_key() -> None:
    text = "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA..."
    assert "Private SSH key found on host" in _titles(parse_linpeas(text))


def test_linpeas_clean_output_no_findings() -> None:
    assert parse_linpeas("nothing juicy here, all patched") == []


def test_winpeas_seimpersonate() -> None:
    text = "SeImpersonatePrivilege             Enabled"
    assert "SeImpersonate/SeAssignPrimaryToken (Potato)" in _titles(parse_winpeas(text))


def test_winpeas_always_install_elevated() -> None:
    text = "AlwaysInstallElevated HKLM: 1\nAlwaysInstallElevated HKCU: 1"
    assert "AlwaysInstallElevated enabled" in _titles(parse_winpeas(text))


def test_winpeas_unquoted_service() -> None:
    text = "No quotes and Space detected in C:\\Program Files\\app\\svc.exe"
    assert "Unquoted service path" in _titles(parse_winpeas(text))


def test_winpeas_gpp_cpassword() -> None:
    text = "Found Groups.xml with cpassword=abcdef"
    assert "GPP cpassword recoverable" in _titles(parse_winpeas(text))


def test_parse_peas_dispatch() -> None:
    assert parse_peas("(root) NOPASSWD: /bin/sh", "linpeas")
    assert parse_peas("SeImpersonatePrivilege Enabled", "winpeas")


def test_parse_peas_unknown_kind() -> None:
    import pytest
    with pytest.raises(ValueError):
        parse_peas("x", "bogus")
