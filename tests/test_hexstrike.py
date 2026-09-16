"""Tests for the HexStrike client and nmap-from-string parsing (mocked HTTP)."""
from __future__ import annotations

import pytest
import requests

from yhwach.hexstrike import DEFAULT_URL, HexStrikeClient, HexStrikeError, is_loopback
from yhwach.parsers.nmap import parse_nmap_xml_text

_NMAP_XML = """<?xml version="1.0"?><nmaprun><host><status state="up"/>
<address addr="10.10.10.9" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="22"><state state="open"/>
<service name="ssh" product="OpenSSH" version="9.2"/></port></ports></host></nmaprun>"""


class FakeResp:
    def __init__(self, status=200, json_data=None):
        self.status_code = status
        self._json = json_data or {}

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"HTTP {self.status_code}")

    def json(self):
        return self._json


class FakeSession:
    def __init__(self, get_resp=None, post_resp=None):
        self._get = get_resp
        self._post = post_resp
        self.posted = None

    def get(self, url, **_kw):
        return self._get

    def post(self, url, json=None, **_kw):
        self.posted = json
        return self._post


def test_is_loopback() -> None:
    assert is_loopback("http://127.0.0.1:8888")
    assert is_loopback("http://localhost:8888")
    assert not is_loopback("http://10.1.1.1:8888")


def test_health() -> None:
    sess = FakeSession(get_resp=FakeResp(200, {"all_essential_tools_available": True}))
    c = HexStrikeClient(session=sess)
    assert c.health()["all_essential_tools_available"] is True


def test_run_command_returns_structured() -> None:
    sess = FakeSession(post_resp=FakeResp(200, {
        "stdout": "uid=1000(kali)", "stderr": "", "return_code": 0, "success": True}))
    c = HexStrikeClient(session=sess)
    out = c.run_command("id")
    assert out["success"] is True
    assert sess.posted == {"command": "id"}


def test_nmap_xml_builds_command_and_returns_stdout() -> None:
    sess = FakeSession(post_resp=FakeResp(200, {"stdout": _NMAP_XML, "success": True, "return_code": 0}))
    c = HexStrikeClient(session=sess)
    xml = c.nmap_xml("10.10.10.9", ports="22,80")
    assert "<nmaprun>" in xml
    assert "-oX -" in sess.posted["command"]
    assert "-p 22,80" in sess.posted["command"]
    assert sess.posted["command"].endswith("10.10.10.9")


def test_nmap_xml_raises_on_failure() -> None:
    sess = FakeSession(post_resp=FakeResp(200, {"stdout": "", "success": False, "stderr": "boom"}))
    c = HexStrikeClient(session=sess)
    with pytest.raises(HexStrikeError):
        c.nmap_xml("10.10.10.9")


def test_parse_nmap_xml_text_roundtrip() -> None:
    hosts = parse_nmap_xml_text(_NMAP_XML)
    assert len(hosts) == 1
    assert hosts[0].ip == "10.10.10.9"
    assert hosts[0].services[0].port == 22


def test_default_url_is_loopback() -> None:
    assert is_loopback(DEFAULT_URL)
