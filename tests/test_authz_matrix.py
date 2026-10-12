"""I24 — role-by-endpoint authorization matrix from captured traffic.

Sessions are fingerprinted by a NON-secret identity (JWT sub, or cookie/header
NAME + value-hash), never a hash of the whole header. Path ids template to {id}.
An unobserved cell is distinct from a denial; requests with no session go to the
'unassigned' bucket.
"""
from __future__ import annotations

import base64
import json
from pathlib import Path

from yhwach import db as yhdb
from yhwach.mcp_tools import tool_authz, tool_interpret
from yhwach.parsers.httpcap import session_id, template_path

# --- fingerprint + templating -----------------------------------------------


def test_jwt_sub_fingerprint() -> None:
    jwt = "x." + base64.urlsafe_b64encode(json.dumps({"sub": "alice"}).encode()).decode().rstrip("=") + ".y"
    assert session_id({"authorization": f"Bearer {jwt}"}) == "jwt:alice"


def test_cookie_fingerprint_is_name_plus_value_hash() -> None:
    s = session_id({"cookie": "session=abc123; theme=dark"})
    assert s.startswith("session:")
    # same cookie value -> same fingerprint; different value -> different
    assert s == session_id({"cookie": "session=abc123"})
    assert s != session_id({"cookie": "session=zzz999"})


def test_no_auth_is_none() -> None:
    assert session_id({}) is None
    assert session_id({"content-type": "application/json"}) is None


def test_template_path() -> None:
    assert template_path("/api/users/1001/orders/9") == "/api/users/{id}/orders/{id}"
    uuid = "550e8400-e29b-41d4-a716-446655440000"
    assert template_path(f"/u/{uuid}") == "/u/{id}"
    assert template_path("/about/team") == "/about/team"


# --- matrix -----------------------------------------------------------------


def _har(sub: str | None, path: str, status: int) -> str:
    headers = [{"name": "Cookie", "value": f"session={sub}"}] if sub else []
    return json.dumps({"log": {"entries": [{
        "request": {"method": "GET", "url": f"https://app/{path}", "headers": headers},
        "response": {"status": status}, "serverIPAddress": "10.0.0.5"}]}})


def _eng_host(path: Path) -> int:
    with yhdb.transaction(path) as conn:
        eid = yhdb.upsert_engagement(conn, lab="L", scope="10.0.0.0/8")
        conn.execute("INSERT INTO host (engagement_id, ip, hostname, stage, first_seen) "
                     "VALUES (?, '10.0.0.5', 'app', 'scanned', 't')", (eid,))
        return eid


def test_matrix_allowed_denied_unobserved(tmp_db: Path) -> None:
    eid = _eng_host(tmp_db)
    tool_interpret(tmp_db, "L", _har("ADMIN", "admin/panel", 200), kind="har")
    tool_interpret(tmp_db, "L", _har("USER", "admin/panel", 403), kind="har")
    tool_interpret(tmp_db, "L", _har("USER", "me", 200), kind="har")
    with yhdb.transaction(tmp_db) as conn:
        m = yhdb.authz_matrix(conn, eid)
    admin = next(s for s in m["sessions"] if s != "unassigned"
                 and m["cells"].get(("GET /admin/panel", s)) == 200)
    user = next(s for s in m["sessions"] if m["cells"].get(("GET /admin/panel", s)) == 403)
    assert m["cells"][("GET /admin/panel", admin)] == 200       # allowed
    assert m["cells"][("GET /admin/panel", user)] == 403        # denied
    assert ("GET /me", admin) not in m["cells"]                 # UNOBSERVED != denied


def test_two_hits_keep_the_2xx(tmp_db: Path) -> None:
    eid = _eng_host(tmp_db)
    tool_interpret(tmp_db, "L", _har("USER", "x/1", 403), kind="har")
    tool_interpret(tmp_db, "L", _har("USER", "x/2", 200), kind="har")   # templates to x/{id}
    with yhdb.transaction(tmp_db) as conn:
        m = yhdb.authz_matrix(conn, eid)
        sess = m["sessions"][0]
    assert m["cells"][("GET /x/{id}", sess)] == 200   # a 2xx ever seen wins


def test_no_session_goes_to_unassigned(tmp_db: Path) -> None:
    eid = _eng_host(tmp_db)
    tool_interpret(tmp_db, "L", _har(None, "public", 200), kind="har")
    with yhdb.transaction(tmp_db) as conn:
        m = yhdb.authz_matrix(conn, eid)
    assert "unassigned" in m["sessions"]


def test_tool_renders_matrix(tmp_db: Path) -> None:
    _eng_host(tmp_db)
    tool_interpret(tmp_db, "L", _har("ADMIN", "admin", 200), kind="har")
    out = tool_authz(tmp_db, "L")
    assert "authz matrix" in out
    assert "GET /admin" in out
    assert "·" in out or "200" in out


def test_tool_empty(tmp_db: Path) -> None:
    _eng_host(tmp_db)
    assert "no captured traffic" in tool_authz(tmp_db, "L")
