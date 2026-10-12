"""I47 — ProjectDiscovery (httpx/subfinder) + bbot external asset ingestion.

Produces scope-gated subdomain (domain) rows and, for a non-CDN host that
resolves, a web_app. Two corrections: no host row for a CDN IP, and no spray
hook from a domain-keyed ingest.
"""
from __future__ import annotations

from pathlib import Path

from yhwach import db as yhdb
from yhwach import sniff
from yhwach.mcp_tools import tool_interpret, tool_query
from yhwach.parsers.pd import parse_bbot, parse_httpx, parse_subfinder

_HTTPX = "\n".join([
    '{"url":"https://api.acme.test","input":"api.acme.test","status_code":200,'
    '"title":"API","webserver":"nginx","tech":["nginx"],"a":["10.9.9.9"],"cdn":false}',
    '{"url":"https://cdn.acme.test","input":"cdn.acme.test","a":["104.16.1.1"],'
    '"cdn":true,"cdn_name":"cloudflare"}',
    '{"url":"https://evil.other.test","input":"evil.other.test","a":["1.2.3.4"]}',
])


# --- parsers ----------------------------------------------------------------


def test_parse_httpx() -> None:
    a = {x.name: x for x in parse_httpx(_HTTPX)}
    assert a["api.acme.test"].ip == "10.9.9.9"
    assert a["api.acme.test"].cdn is False
    assert a["cdn.acme.test"].cdn is True
    assert a["cdn.acme.test"].cdn_name == "cloudflare"


def test_parse_subfinder() -> None:
    out = parse_subfinder('{"host":"a.acme.test","source":"crtsh"}\n{"host":"b.acme.test"}\n')
    assert {x.name for x in out} == {"a.acme.test", "b.acme.test"}


def test_parse_bbot() -> None:
    nd = ('{"type":"DNS_NAME","data":"dev.acme.test","tags":["subdomain"]}\n'
          '{"type":"URL","data":"https://dev.acme.test/","tags":["cdn-cloudflare"]}\n'
          '{"type":"OPEN_TCP_PORT","data":"1.2.3.4:443"}\n')
    out = parse_bbot(nd)
    names = {x.name for x in out}
    assert "dev.acme.test" in names
    url_asset = next(x for x in out if x.url)
    assert url_asset.cdn is True   # cdn-cloudflare tag


def test_sniff_detects_formats() -> None:
    assert sniff.detect(_HTTPX) == "httpx"
    assert sniff.detect('{"type":"DNS_NAME","data":"x.acme.test"}') == "bbot"


# --- ingest: scope gate + CDN handling --------------------------------------


def _eng(path: Path) -> int:
    with yhdb.transaction(path) as conn:
        return yhdb.upsert_engagement(conn, lab="L", scope="*.acme.test", kind="bounty")


def test_ingest_scopes_cdn_and_hosts(tmp_db: Path) -> None:
    eid = _eng(tmp_db)
    out = tool_interpret(tmp_db, "L", _HTTPX)
    assert "2 in-scope domain" in out
    assert "1 web_app" in out
    assert "1 CDN-fronted" in out
    assert "1 out-of-scope skipped" in out
    with yhdb.transaction(tmp_db) as conn:
        ips = [r["ip"] for r in conn.execute("SELECT ip FROM host WHERE engagement_id=?", (eid,))]
        domains = {r["name"] for r in conn.execute(
            "SELECT name FROM domain WHERE engagement_id=?", (eid,))}
    assert ips == ["10.9.9.9"]           # only the non-CDN in-scope resolved host
    assert "104.16.1.1" not in ips       # the CDN IP is never a host
    assert domains == {"api.acme.test", "cdn.acme.test"}   # out-of-scope excluded


def test_out_of_scope_assets_skipped(tmp_db: Path) -> None:
    _eng(tmp_db)
    tool_interpret(tmp_db, "L", _HTTPX)
    with yhdb.transaction(tmp_db) as conn:
        assert conn.execute(
            "SELECT COUNT(*) n FROM domain WHERE name='evil.other.test'").fetchone()["n"] == 0


def test_domain_ingest_does_not_create_credentials_or_spray(tmp_db: Path) -> None:
    # Domain-keyed ingests must never touch the vault / spray.
    eid = _eng(tmp_db)
    tool_interpret(tmp_db, "L", _HTTPX)
    with yhdb.transaction(tmp_db) as conn:
        creds = conn.execute("SELECT COUNT(*) n FROM credential WHERE engagement_id=?",
                            (eid,)).fetchone()["n"]
        access = conn.execute("SELECT COUNT(*) n FROM credential_access WHERE engagement_id=?",
                            (eid,)).fetchone()["n"]
    assert creds == 0
    assert access == 0


def test_reingest_idempotent(tmp_db: Path) -> None:
    eid = _eng(tmp_db)
    tool_interpret(tmp_db, "L", _HTTPX)
    tool_interpret(tmp_db, "L", _HTTPX)
    with yhdb.transaction(tmp_db) as conn:
        d = conn.execute("SELECT COUNT(*) n FROM domain WHERE engagement_id=?", (eid,)).fetchone()["n"]
        h = conn.execute("SELECT COUNT(*) n FROM host WHERE engagement_id=?", (eid,)).fetchone()["n"]
    assert d == 2
    assert h == 1


def test_domains_view(tmp_db: Path) -> None:
    _eng(tmp_db)
    tool_interpret(tmp_db, "L", _HTTPX)
    out = tool_query(tmp_db, "L", "domains", fields=["name", "source"])
    assert "api.acme.test" in out
    assert "cloudflare" in out   # cdn name recorded in source
