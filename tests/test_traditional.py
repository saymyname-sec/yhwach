"""Tests for traditional (non-AI) surface detection."""
from __future__ import annotations

from urllib.parse import urlparse

import requests

from yhwach.probes.traditional import (
    classify_service,
    detect_traditional,
    probe_gitea,
    probe_gitlab,
    probe_jenkins,
    probe_web_app,
    probe_webapp_products,
)


class FakeResponse:
    def __init__(self, status_code=200, headers=None, text="", json_data=None):
        self.status_code = status_code
        self.headers = headers or {}
        self.text = text
        self._json = json_data

    def json(self):
        if self._json is None:
            raise ValueError("no json")
        return self._json


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
                                   text="<html><head><title>Acme Corp Portal</title></head></html>")
    })
    res = probe_web_app(session, "10.0.0.1", 80)
    assert res is not None
    assert res.kind == "web"
    assert res.meta["title"] == "Acme Corp Portal"


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


# --- document-intake detection (self-learning from a careers site) ---

def test_web_app_detects_careers_upload_as_web_upload() -> None:
    body = ("<html><head><title>Open Roles · Acme Careers</title></head>"
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


# --- message-broker detection (self-learned from a message broker) ---

def test_classify_broker_ports() -> None:
    assert classify_service(None, 1883) == "mqtt"
    assert classify_service(None, 5672) == "amqp"
    assert classify_service(None, 8161) == "activemq"
    assert classify_service(None, 61616) == "activemq_openwire"


# --- datastore / cloud-native classification (P0 wiring: PORT_KIND additions) ---

def test_classify_datastore_and_control_plane_ports() -> None:
    assert classify_service(None, 6379) == "redis"
    assert classify_service(None, 11211) == "memcached"
    assert classify_service(None, 27017) == "mongodb"
    assert classify_service(None, 9200) == "elasticsearch"
    assert classify_service(None, 2379) == "etcd"
    assert classify_service(None, 2375) == "docker_api"
    assert classify_service(None, 8500) == "consul"
    assert classify_service(None, 10255) == "kubelet_ro"


def test_apiserver_renamed_from_kubernetes() -> None:
    # G1: 6443 is now "apiserver" (a rule keys on `surface: apiserver`).
    assert classify_service(None, 6443) == "apiserver"


# --- G2: classify_service falls through to the -sV product on a non-standard port ---

def test_classify_service_product_fallthrough_nonstandard_port() -> None:
    # Redis on a non-default port used to be invisible (product was dropped).
    assert classify_service("Redis key-value store 7.0.5", 63790) == "redis"
    assert classify_service("MongoDB 6.0", 55555) == "mongodb"
    assert classify_service("Microsoft SQL Server 2019", 14330) == "mssql"
    assert classify_service("PostgreSQL DB 14.2", 6000) == "postgres"
    assert classify_service("Elasticsearch REST API", 9999) == "elasticsearch"


def test_classify_service_port_wins_over_product() -> None:
    # Port is the reliable signal; product only fills the gap.
    assert classify_service("Redis", 445) == "smb"


def test_classify_service_still_none_for_truly_unknown() -> None:
    assert classify_service("some bespoke daemon", 24601) is None




# ---------------------------------------------------------------------------
# probe_gitea — Gitea must not be mislabelled GitLab, and must carry a version
# ---------------------------------------------------------------------------

def test_probe_gitea_via_cookie_and_version() -> None:
    session = FakeSession({
        ("GET", "/"): FakeResponse(
            200,
            headers={"Set-Cookie": "i_like_gitea=abc; Path=/; HttpOnly"},
            text="<html><title>Corp Git</title></html>",
        ),
        ("GET", "/api/v1/version"): FakeResponse(200, json_data={"version": "1.22.6"}),
    })
    res = probe_gitea(session, "10.0.0.1", 3000)
    assert res is not None
    assert res.kind == "gitea"
    assert res.meta["version"] == "1.22.6"


def test_probe_gitea_via_body_reference() -> None:
    session = FakeSession({
        ("GET", "/"): FakeResponse(200, text='<meta name="author" content="Gitea">'),
        ("GET", "/api/v1/version"): FakeResponse(404),
    })
    res = probe_gitea(session, "10.0.0.1", 3000)
    assert res is not None
    assert res.kind == "gitea"
    assert res.meta["version"] is None


def test_probe_gitea_none_on_plain_page() -> None:
    session = FakeSession({("GET", "/"): FakeResponse(200, text="<html>nothing here</html>")})
    assert probe_gitea(session, "10.0.0.1", 3000) is None


def test_detect_traditional_prefers_gitea_over_gitlab() -> None:
    # A Gitea instance whose page happens to mention neither product's rival:
    # detect_traditional must return gitea (checked before gitlab in the chain).
    session = FakeSession({
        ("GET", "/"): FakeResponse(
            200,
            headers={"Set-Cookie": "i_like_gitea=abc"},
            text="<title>Corp Git</title>",
        ),
        ("GET", "/api/v1/version"): FakeResponse(200, json_data={"version": "1.22.6"}),
    })
    res = detect_traditional(session, "10.0.0.1", 3000, product="Golang net/http server")
    assert res is not None
    assert res.kind == "gitea"


# --- P1: data-driven web-app product fingerprints ---

def test_webapp_grafana_with_version() -> None:
    session = FakeSession({
        ("GET", "/"): FakeResponse(200, headers={"Content-Type": "text/html"},
                                   text="<html><title>Grafana</title></html>"),
        ("GET", "/api/health"): FakeResponse(200, json_data={"version": "10.2.0"}),
    })
    res = probe_webapp_products(session, "10.0.0.1", 3000)
    assert res is not None and res.kind == "grafana"
    assert res.meta["version"] == "10.2.0"


def test_webapp_minio_no_version_endpoint() -> None:
    session = FakeSession({("GET", "/"): FakeResponse(
        200, headers={"Server": "MinIO"}, text="minio console")})
    res = probe_webapp_products(session, "10.0.0.1", 9001)
    assert res is not None and res.kind == "minio" and res.meta["version"] is None


def test_webapp_confluence_via_header_name() -> None:
    # Header NAME (not value) carries the signal -> the haystack must include names.
    session = FakeSession({("GET", "/"): FakeResponse(
        200, headers={"X-Confluence-Request-Time": "1"}, text="<html></html>")})
    res = probe_webapp_products(session, "10.0.0.1", 8090)
    assert res is not None and res.kind == "confluence"


def test_webapp_none_on_unrecognised_page() -> None:
    session = FakeSession({("GET", "/"): FakeResponse(200, text="<html>nothing</html>")})
    assert probe_webapp_products(session, "10.0.0.1", 8080) is None


def test_detect_traditional_routes_to_webapp_then_generic() -> None:
    # A recognised product on a WEB_PORT -> product surface (not generic web).
    session = FakeSession({("GET", "/"): FakeResponse(
        200, headers={"Content-Type": "text/html"}, text="Welcome to Keycloak")})
    res = detect_traditional(session, "10.0.0.1", 8080, "Jetty")
    assert res is not None and res.kind == "keycloak"
