"""The per-host dossier: composed from the DB and the shipped YAML packs.

The contract these tests defend is that it needs NO model, NO network and no API
key — the project's primary mode is Claude Code over MCP with no key at all — and
that it informs rather than recommends.
"""
from __future__ import annotations

from pathlib import Path

from yhwach import db as yhdb
from yhwach import dossier


def _seed(tmp_db: Path, *, stage: str = "enumerated", kind: str = "ldap",
          port: int = 389) -> tuple[int, str]:
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.upsert_engagement(conn, lab="L", scope="10.0.0.0/24")
        hid = conn.execute(
            "INSERT INTO host (engagement_id, ip, hostname, os, role, stage, first_seen) "
            "VALUES (?, '10.0.0.5', 'dc01', 'windows', 'Domain Controller', ?, 't')",
            (eid, stage)).lastrowid
        sid = conn.execute(
            "INSERT INTO service (host_id, port, proto, product, discovered_at) "
            "VALUES (?, ?, 'tcp', 'Microsoft Windows LDAP', 't')", (int(hid), port)).lastrowid
        yhdb.upsert_surface(conn, int(hid), int(sid), kind, "unknown", "{}")
    return eid, "10.0.0.5"


def test_dossier_briefs_a_domain_controller(tmp_db: Path) -> None:
    """The case that briefed as NOTHING before service_matrix.yaml gained rows
    for smb/ldap/kerberos/winrm."""
    eid, ip = _seed(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        md = dossier.build(conn, eid, ip)
    assert "dc01" in md and "Domain Controller" in md
    assert "**ldap**" in md
    assert "anonymous bind" in md, "no triage context for the commonest AD surface"
    assert "T1087.002" in md


def test_dossier_needs_no_model_or_network(tmp_db: Path, monkeypatch) -> None:
    """Every line is a DB fact or a verbatim pack quote. If this ever starts
    importing a provider or opening a socket, it has stopped being offline."""
    import socket

    eid, ip = _seed(tmp_db)

    def _no_sockets(*a, **k):  # noqa: ANN002, ANN003
        raise AssertionError("the dossier opened a network connection")

    monkeypatch.setattr(socket, "socket", _no_sockets)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    with yhdb.transaction(tmp_db) as conn:
        assert dossier.build(conn, eid, ip)


def test_dossier_sections_follow_the_real_stage_fsm() -> None:
    """There is no 'triaged' stage; keying on one would silently brief nothing."""
    assert set(dossier._SECTIONS) == set(yhdb.STAGES), (
        set(dossier._SECTIONS) ^ set(yhdb.STAGES))


def test_dossier_section_set_changes_with_stage(tmp_db: Path) -> None:
    eid, ip = _seed(tmp_db, stage="scanned")
    with yhdb.transaction(tmp_db) as conn:
        scanned = dossier.build(conn, eid, ip)
        conn.execute("UPDATE host SET stage='looted' WHERE ip=?", (ip,))
        looted = dossier.build(conn, eid, ip)
    assert "What is still dark here" in scanned
    assert "What we hold here" not in scanned      # nothing is held at `scanned`
    assert "What we hold here" in looted


def test_dossier_names_a_kind_it_has_no_row_for(tmp_db: Path) -> None:
    """An unknown kind must say so, not render a blank heading."""
    eid, ip = _seed(tmp_db, kind="something_new", port=9999)
    with yhdb.transaction(tmp_db) as conn:
        md = dossier.build(conn, eid, ip)
    assert "no service-matrix row for this kind" in md


def test_dossier_quotes_the_ai_pack_for_an_ai_surface(tmp_db: Path) -> None:
    eid, ip = _seed(tmp_db, kind="rag", port=8000)
    with yhdb.transaction(tmp_db) as conn:
        md = dossier.build(conn, eid, ip)
    assert "rag_poisoning" in md
    assert "owasp_llm_checklist" in md


def test_dossier_carries_the_exact_fix_for_each_coverage_gap(tmp_db: Path) -> None:
    eid, ip = _seed(tmp_db, stage="scanned")
    with yhdb.transaction(tmp_db) as conn:
        md = dossier.build(conn, eid, ip)
    assert "What is still dark here" in md
    assert "nmap" in md, "a coverage gap is named without the command that closes it"


def test_dossier_is_empty_for_an_unknown_host(tmp_db: Path) -> None:
    eid, _ = _seed(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        assert dossier.build(conn, eid, "10.99.99.99") == ""


def test_dossier_never_recommends(tmp_db: Path) -> None:
    """It says what a surface IS and what is typically worth looking at. It must
    not rank techniques or tell the operator what to run next."""
    eid, ip = _seed(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        md = dossier.build(conn, eid, ip).lower()
    for phrase in ("next move", "recommended", "you should", "run this next", "priority"):
        assert phrase not in md, phrase


# ─── annotations: the optional LLM enrichment path ─────────────────────────
# yhwach never calls a model. Claude Code (the MCP client) is the model; the
# engine stores a typed row and the board compares two strings.


def test_annotation_round_trips_and_is_fresh(tmp_db: Path) -> None:
    eid, ip = _seed(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        hid = conn.execute("SELECT id FROM host WHERE ip=?", (ip,)).fetchone()["id"]
        yhdb.add_host_annotation(conn, int(hid), "banner",
                                 "ActiveMQ 5.17.4 behind a proxy that strips /admin",
                                 author="claude-code")
        rows = yhdb.host_annotations(conn, int(hid))
    assert len(rows) == 1
    assert rows[0]["section"] == "banner"
    assert not rows[0]["stale"]


def test_annotation_goes_stale_when_the_host_changes(tmp_db: Path) -> None:
    """The board never rewrites the hash, deletes a stale row, or calls a model —
    it compares two strings."""
    eid, ip = _seed(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        hid = int(conn.execute("SELECT id FROM host WHERE ip=?", (ip,)).fetchone()["id"])
        yhdb.add_host_annotation(conn, hid, "banner", "written before", author="claude-code")
        assert not yhdb.host_annotations(conn, hid)[0]["stale"]
        # anything learned about the host moves the fingerprint
        yhdb.add_finding(conn, hid, None, "misc", "something new", "low", "e",
                         engagement_id=eid)
        assert yhdb.host_annotations(conn, hid)[0]["stale"]


def test_annotation_replaces_rather_than_duplicating(tmp_db: Path) -> None:
    eid, ip = _seed(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        hid = int(conn.execute("SELECT id FROM host WHERE ip=?", (ip,)).fetchone()["id"])
        yhdb.add_host_annotation(conn, hid, "banner", "first", author="a")
        yhdb.add_host_annotation(conn, hid, "banner", "second", author="b")
        rows = yhdb.host_annotations(conn, hid)
    assert len(rows) == 1 and rows[0]["body"] == "second"


def test_host_fingerprint_is_stable_until_something_is_learned(tmp_db: Path) -> None:
    eid, ip = _seed(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        hid = int(conn.execute("SELECT id FROM host WHERE ip=?", (ip,)).fetchone()["id"])
        a = yhdb.host_fingerprint(conn, hid)
        assert yhdb.host_fingerprint(conn, hid) == a      # pure read, no drift
        yhdb.set_host_stage(conn, eid, ip, "foothold", note="shell")
        assert yhdb.host_fingerprint(conn, hid) != a


def test_mcp_dossier_and_annotate_round_trip(tmp_db: Path) -> None:
    from yhwach import mcp_tools as mt

    eid, ip = _seed(tmp_db)
    out = mt.tool_annotate(tmp_db, "L", ip, "banner", "LDAP signing is not enforced")
    assert "annotated" in out
    md = mt.tool_dossier(tmp_db, "L", ip)
    assert "What this box is" in md                      # the deterministic half
    assert "LDAP signing is not enforced" in md          # the annotation
    assert "annotation by claude-code" in md


def test_mcp_annotate_rejects_an_unknown_host_and_empty_text(tmp_db: Path) -> None:
    from yhwach import mcp_tools as mt

    _seed(tmp_db)
    assert "error" in mt.tool_annotate(tmp_db, "L", "10.99.99.99", "x", "text")
    assert "error" in mt.tool_annotate(tmp_db, "L", "10.0.0.5", "x", "   ")


def test_annotate_tool_description_forbids_direction() -> None:
    """The tool description is the only thing stopping an annotation rebuilding
    the recommender in prose."""
    import re

    from yhwach import mcp_tools as mt

    doc = re.sub(r"\s+", " ", mt.tool_annotate.__doc__).lower()
    assert "description, not direction" in doc
    assert "do not write what to do next" in doc


def test_dossier_classifies_services_when_no_probe_has_run(tmp_db: Path) -> None:
    """Surfaces are written by `yhwach probe`; a freshly INGESTED host has
    services and no surfaces at all. Briefing only on surfaces meant a scanned
    Domain Controller — ldap on 389, smb on 445, both classifiable from the port
    alone — still got no context."""
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.upsert_engagement(conn, lab="L", scope="10.0.0.0/24")
        hid = conn.execute(
            "INSERT INTO host (engagement_id, ip, hostname, os, stage, first_seen) "
            "VALUES (?, '10.0.0.60', 'dc01', 'windows', 'scanned', 't')", (eid,)).lastrowid
        for port, product in ((389, "Microsoft Windows LDAP"), (445, "microsoft-ds")):
            conn.execute("INSERT INTO service (host_id, port, proto, product, discovered_at) "
                         "VALUES (?, ?, 'tcp', ?, 't')", (int(hid), port, product))
        assert not conn.execute("SELECT 1 FROM surface WHERE host_id=?", (int(hid),)).fetchone()
        md = dossier.build(conn, eid, "10.0.0.60")

    assert "**ldap**" in md and "**smb**" in md
    assert "anonymous bind" in md
    assert "null/guest session" in md
    # and it says where the classification came from
    assert "no probe has run on this host yet" in md


def test_dossier_prefers_a_real_surface_over_the_port_guess(tmp_db: Path) -> None:
    eid, ip = _seed(tmp_db, kind="rag", port=8000)
    with yhdb.transaction(tmp_db) as conn:
        md = dossier.build(conn, eid, ip)
    assert "**rag**" in md
    assert "no probe has run on this host yet" not in md
