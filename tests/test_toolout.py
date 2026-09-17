"""Parser robustness against realistic captured tool output.

These fixtures (tests/fixtures/toolout/) are shaped like real netexec / kerbrute /
enum4linux-ng / ldapsearch / certipy / SharpHound output — the point is to catch
format drift the minimal synthetic strings in the other tests would miss. When a
real lab produces output a parser mishandles, drop it here and harden the parser.
"""
from __future__ import annotations

from pathlib import Path

from yhwach.interpret import interpret_all
from yhwach.parsers.adcs import parse_certipy
from yhwach.parsers.bloodhound import parse_bloodhound

_DIR = Path(__file__).parent / "fixtures" / "toolout"


def _read(name: str) -> str:
    return (_DIR / name).read_text(encoding="utf-8")


def test_nxc_smb_realistic_multi_signal() -> None:
    fs = interpret_all("netexec_smb_null", _read("nxc_smb.txt"), {"IP": "10.10.10.20"})
    tags = {f.tag for f in fs}
    assert "smb_signing_off" in tags       # (signing:False)
    assert "null_session" in tags          # READ,WRITE shares + domain\user
    assert any(f.severity == "critical" for f in fs)   # (Pwn3d!)


def test_kerbrute_userlist() -> None:
    fs = interpret_all("kerbrute_userenum", _read("kerbrute_users.txt"), {"IP": "10.10.10.20"})
    assert any(f.tag == "domain_users" for f in fs)


def test_enum4linux_users_and_smb() -> None:
    fs = interpret_all("enum4linux_ng", _read("enum4linux_users.txt"), {"IP": "10.10.10.20"})
    assert any(f.tag == "domain_users" for f in fs)   # 'username:' lines


def test_ldapsearch_anon_naming_context() -> None:
    fs = interpret_all("ldapsearch_anon", _read("ldapsearch_anon.txt"), {"IP": "10.10.10.20"})
    assert fs and fs[0].tag == "ldap_anon" and "corp.local" in fs[0].evidence


def test_certipy_real_json() -> None:
    fs = parse_certipy(_read("certipy_find.json"))
    assert len(fs) == 1                    # SafeUser skipped, VulnUserESC1 kept
    assert fs[0].tag == "adcs_vuln" and "ESC1" in fs[0].title and fs[0].severity == "critical"


def test_sharphound_users_collection() -> None:
    tags = {f.tag for f in parse_bloodhound(_read("sharphound_users.json"))}
    assert tags == {"kerberoastable", "asreproastable"}   # SPN user + no-preauth user


def test_bloodhound_facts_incl_unknown_edge() -> None:
    tags = {f.tag for f in parse_bloodhound(_read("bloodhound_facts.json"))}
    assert {"kerberoastable", "dcsync", "unconstrained_delegation"}.issubset(tags)
    assert "some_new_edge_type" in tags   # forward-compatible
