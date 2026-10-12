"""I23 — web chaining tags from content discovery.

Finer surfaces split out of the generic 'api' kind (graphql / api_spec /
debug_page) plus param-driven LEADs (idor_candidate, redirect_param). Each tag
lights up a consumer rule; the param LEADs are info-severity (a reference worth
testing), not asserted vulns.
"""
from __future__ import annotations

from pathlib import Path

from yhwach import db as yhdb
from yhwach import knowledge as kn
from yhwach.ingest import ingest_web
from yhwach.parsers.web import ParsedWebPath, chaining_tags

_DISCO = "\n".join([
    "/graphql (Status: 200)",
    "/swagger/openapi.json (Status: 200)",
    "/actuator/env (Status: 200)",
    "/users?id=42 (Status: 200)",
    "/go?redirect=http://evil (Status: 302)",
])


# --- classification ---------------------------------------------------------


def test_path_kinds_split_out_of_api() -> None:
    assert ParsedWebPath("/graphql").kind == "graphql"
    assert ParsedWebPath("/swagger/openapi.json").kind == "api_spec"
    assert ParsedWebPath("/actuator/env").kind == "debug_page"
    assert ParsedWebPath("/api/v1/users").kind == "api"   # generic api still works


def test_chaining_tags_idor() -> None:
    assert chaining_tags("/users?id=42") == ["idor_candidate"]
    assert chaining_tags("/api/users/1001") == ["idor_candidate"]   # numeric segment
    assert chaining_tags("/doc?docid=7") == ["idor_candidate"]
    assert chaining_tags("/about") == []


def test_chaining_tags_redirect() -> None:
    assert "redirect_param" in chaining_tags("/go?next=/x&url=http://e")
    assert chaining_tags("/logout?returnurl=/home") == ["redirect_param"]


def test_tags_are_orthogonal() -> None:
    # a path can be an API endpoint AND an idor candidate AND carry a redirect.
    tags = chaining_tags("/api/orders/55?redirect=/done")
    assert set(tags) == {"idor_candidate", "redirect_param"}


# --- ingest emits the chaining findings -------------------------------------


def test_ingest_emits_all_chaining_tags(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.upsert_engagement(conn, lab="L", scope="10.0.0.0/24")
        hid = conn.execute(
            "INSERT INTO host (engagement_id, ip, stage, first_seen) "
            "VALUES (?, '10.0.0.5', 'scanned', 't')", (eid,)).lastrowid
        ingest_web(conn, int(hid), "http://10.0.0.5", _DISCO)
        tags = sorted(r[0] for r in conn.execute(
            "SELECT tag FROM finding WHERE host_id=? AND tag IS NOT NULL", (hid,)))
        sevs = {r["tag"]: r["severity"] for r in conn.execute(
            "SELECT tag, severity FROM finding WHERE host_id=?", (hid,))}
    assert set(tags) == {"graphql", "api_spec", "debug_page",
                         "idor_candidate", "redirect_param"}
    # param LEADs are info-severity, not asserted vulns
    assert sevs["idor_candidate"] == "info"
    assert sevs["redirect_param"] == "info"


# --- consumer rules load ----------------------------------------------------


def test_consumer_rules_fire_on_the_tags() -> None:
    techs = {t.id: t for t in kn.load_techniques()}
    for rid in ("web_graphql_recon", "web_api_spec_recon", "web_debug_page_review",
                "web_idor_probe", "web_open_redirect_probe"):
        assert rid in techs, rid
    # recon is auto; probing an IDOR / open-redirect is active -> gated
    assert techs["web_graphql_recon"].autonomy == "proceed"
    assert techs["web_idor_probe"].autonomy != "proceed"
    assert techs["web_open_redirect_probe"].autonomy != "proceed"


def test_idor_candidate_lights_up_its_rule(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.upsert_engagement(conn, lab="L", scope="10.0.0.0/24")
        hid = conn.execute(
            "INSERT INTO host (engagement_id, ip, stage, first_seen) "
            "VALUES (?, '10.0.0.5', 'scanned', 't')", (eid,)).lastrowid
        ingest_web(conn, int(hid), "http://10.0.0.5", "/users?id=42 (Status: 200)")
        cands = {c.technique_id for c in kn.candidates_for(conn, eid)}
    assert "web_idor_probe" in cands
