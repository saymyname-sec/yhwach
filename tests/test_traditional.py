"""Tests for traditional (non-AI) surface detection."""
from __future__ import annotations

from urllib.parse import urlparse

import requests

from yhwach.probes.traditional import (
    classify_service,
    detect_traditional,
    probe_gitlab,
    probe_jenkins,
    probe_web_app,
)


class FakeResponse:
    def __init__(self, status_code=200, headers=None, text=""):
        self.status_code = status_code
        self.headers = headers or {}
        self.text = text


class FakeSession:
    def __init__(self, mapping):
        self.mapping = mapping

    def get(self, url, **_kw):
        path = urlparse(url).path
        if ("GET", path) in self.mapping:
            return self.mapping[("GET", path)]
        raise requests.exceptions.ConnectionError(f"no mock for GET {path}")


def test_classify_service_known_ports() -> None:
    assert classify_service(None, 445) == "smb"
    assert classify_service(None, 389) == "ldap"
    assert classify_service(None, 22) == "ssh"
    assert classify_service(None, 3389) == "rdp"
    assert classify_service(None, 5985) == "winrm"
    assert classify_service(None, 1433) == "mssql"


def test_classify_service_unknown_port() -> None:
    assert classify_service("weird", 24601) is None


def test_probe_jenkins_via_header() -> None:
    session = FakeSession({("GET", "/"): FakeResponse(200, headers={"X-Jenkins": "2.555.1"})})
    res = probe_jenkins(session, "10.0.0.1", 8080)
    assert res is not None
    assert res.kind == "jenkins"
    assert res.meta["version"] == "2.555.1"


def test_probe_jenkins_none_without_header() -> None:
    session = FakeSession({("GET", "/"): FakeResponse(200, headers={"Server": "nginx"})})
    assert probe_jenkins(session, "10.0.0.1", 8080) is None


def test_probe_gitlab_via_header() -> None:
    session = FakeSession({("GET", "/"): FakeResponse(200, headers={"X-Gitlab-Feature-Category": "x"})})
    res = probe_gitlab(session, "10.0.0.1", 80)
    assert res is not None
    assert res.kind == "gitlab"


def test_probe_web_app_html_with_title() -> None:
    session = FakeSession({
        ("GET", "/"): FakeResponse(200, headers={"Content-Type": "text/html; charset=UTF-8"},
                                   text="<html><head><title>Aldinervaide Corp Portal</title></head></html>")
    })
    res = probe_web_app(session, "10.0.0.1", 80)
    assert res is not None
    assert res.kind == "web"
    assert res.meta["title"] == "Aldinervaide Corp Portal"


def test_probe_web_app_skips_404() -> None:
    session = FakeSession({("GET", "/"): FakeResponse(404, headers={"Content-Type": "text/html"})})
    assert probe_web_app(session, "10.0.0.1", 80) is None


def test_detect_traditional_port_match_wins() -> None:
    # Port 445 is classified deterministically; no network call needed.
    assert detect_traditional(FakeSession({}), "10.0.0.1", 445, "microsoft-ds").kind == "smb"


def test_detect_traditional_web_fingerprint_jenkins() -> None:
    session = FakeSession({("GET", "/"): FakeResponse(200, headers={"X-Jenkins": "2.555.1"})})
    res = detect_traditional(session, "10.0.0.1", 8080, "Jetty")
    assert res is not None
    assert res.kind == "jenkins"


def test_detect_traditional_none_for_unknown_nonweb_port() -> None:
    assert detect_traditional(FakeSession({}), "10.0.0.1", 24601, "weird") is None


# --- document-intake detection (self-learning from Iron Crown 8081 careers site) ---

def test_web_app_detects_careers_upload_as_web_upload() -> None:
    body = ("<html><head><title>Open Roles · Aldinervaide Careers</title></head>"
            "<body><h1>Careers</h1><form enctype='multipart/form-data'>"
            "<input type='file' name='cv'></form></body></html>")
    session = FakeSession({("GET", "/"): FakeResponse(
        200, headers={"Content-Type": "text/html; charset=utf-8"}, text=body)})
    res = probe_web_app(session, "10.0.0.1", 8081)
    assert res is not None
    assert res.kind == "web_upload"


def test_web_app_plain_html_stays_web() -> None:
    session = FakeSession({("GET", "/"): FakeResponse(
        200, headers={"Content-Type": "text/html"}, text="<html><title>Home</title></html>")})
    res = probe_web_app(session, "10.0.0.1", 80)
    assert res is not None and res.kind == "web"


# --- message-broker detection (self-learned from Iron Crown BROKER01) ---

def test_classify_broker_ports() -> None:
    assert classify_service(None, 1883) == "mqtt"
    assert classify_service(None, 5672) == "amqp"
    assert classify_service(None, 8161) == "activemq"
    assert classify_service(None, 61616) == "activemq_openwire"


