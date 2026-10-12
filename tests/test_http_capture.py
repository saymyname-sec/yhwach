"""I49 — Burp / HAR capture -> web_path METADATA only.

Method, path, parameter NAMES, auth requirement, status — never bodies, never
values. Requests to hosts yhwach does not already track are skipped (no host
invention from a proxy log full of third-party traffic).
"""
from __future__ import annotations

import base64
from pathlib import Path

from yhwach import db as yhdb
from yhwach import sniff
from yhwach.mcp_tools import tool_interpret, tool_query
from yhwach.parsers.httpcap import parse_burp, parse_har


def _burp_item(body: bytes) -> str:
    req = base64.b64encode(body).decode()
    return (f'<items><item><url>http://app.acme.test/api/login?debug=1</url>'
            f'<host ip="10.9.9.9">app.acme.test</host><port>80</port>'
            f'<method>POST</method><status>200</status>'
            f'<request base64="true">{req}</request></item></items>')


_BODY = (b"POST /api/login?debug=1 HTTP/1.1\r\nHost: app.acme.test\r\n"
         b"Authorization: Bearer secrettoken\r\n"
         b"Content-Type: application/x-www-form-urlencoded\r\n\r\nuser=alice&pass=hunter2")
_HAR = ('{"log":{"entries":[{"request":{"method":"GET",'
        '"url":"https://app.acme.test/users?id=5","headers":[{"name":"Cookie","value":"s=1"}]},'
        '"response":{"status":200},"serverIPAddress":"10.9.9.9"}]}}')


# --- parsers ----------------------------------------------------------------


def test_parse_burp_metadata_only() -> None:
    m = parse_burp(_burp_item(_BODY))[0]
    assert m.method == "POST"
    assert m.path == "/api/login"
    assert m.params == ["debug", "user", "pass"]   # names: query + form
    assert m.auth_required is True
    assert m.ip == "10.9.9.9"


def test_parse_burp_stores_no_values() -> None:
    m = parse_burp(_burp_item(_BODY))[0]
    blob = repr(m)
    assert "alice" not in blob and "hunter2" not in blob and "secrettoken" not in blob


def test_parse_har() -> None:
    m = parse_har(_HAR)[0]
    assert m.path == "/users"
    assert m.params == ["id"]
    assert m.auth_required is True
    assert m.ip == "10.9.9.9"


def test_bad_input_is_empty() -> None:
    assert parse_burp("not xml") == []
    assert parse_har("{not json") == []


def test_sniff_detects_burp_and_har() -> None:
    assert sniff.detect(_burp_item(_BODY)) == "burp"
    assert sniff.detect(_HAR) == "har"


# --- ingest -----------------------------------------------------------------


def _eng_host(path: Path) -> int:
    with yhdb.transaction(path) as conn:
        eid = yhdb.upsert_engagement(conn, lab="L", scope="10.0.0.0/8", kind="web")
        conn.execute("INSERT INTO host (engagement_id, ip, hostname, stage, first_seen) "
                     "VALUES (?, '10.9.9.9', 'app.acme.test', 'scanned', 't')", (eid,))
        return eid


def test_ingest_records_web_path_metadata(tmp_db: Path) -> None:
    _eng_host(tmp_db)
    out = tool_interpret(tmp_db, "L", _burp_item(_BODY))
    assert "1 web_path" in out
    assert "metadata only" in out
    view = tool_query(tmp_db, "L", "web_paths", fields=["path", "method", "params", "auth_required"])
    assert "/api/login" in view
    assert "debug,user,pass" in view
    # no secret value ever lands in the DB
    assert "hunter2" not in view


def test_request_to_untracked_host_is_skipped(tmp_db: Path) -> None:
    _eng_host(tmp_db)
    other = _burp_item(_BODY).replace("app.acme.test", "cdn.thirdparty.test").replace(
        '"10.9.9.9"', '"8.8.8.8"')
    out = tool_interpret(tmp_db, "L", other)
    assert "1 request(s) to untracked hosts skipped" in out
    with yhdb.transaction(tmp_db) as conn:
        n = conn.execute("SELECT COUNT(*) n FROM web_path").fetchone()["n"]
    assert n == 0


def test_reingest_idempotent(tmp_db: Path) -> None:
    _eng_host(tmp_db)
    tool_interpret(tmp_db, "L", _burp_item(_BODY))
    tool_interpret(tmp_db, "L", _burp_item(_BODY))
    with yhdb.transaction(tmp_db) as conn:
        n = conn.execute("SELECT COUNT(*) n FROM web_path").fetchone()["n"]
    assert n == 1
