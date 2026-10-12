"""I65 — actionable recall.

The recall menu used to name a technique and stop. Operators then had to
remember the exact command and how to feed its output back. These tests lock
the actionable layer: every emitted action id resolves (via data/actions.yaml)
to a runnable command with {host}/{port} filled, a `then:` fold-back call, and
a ref — surfaced in `yhwach next`, in the `yhwach_action` MCP tool, and in the
`action` CLI command. Secrets never cross the wire inside a rendered command.
"""
from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from yhwach import actions_ref
from yhwach import db as yhdb
from yhwach import knowledge as kn
from yhwach import nextmoves as nm_
from yhwach.cli import main

# --- actions_ref.render -----------------------------------------------------


def test_render_fills_host_and_port() -> None:
    r = actions_ref.render("netexec_smb_null", host="10.0.0.5")
    assert r is not None
    assert r["cmd"] == "nxc smb 10.0.0.5 -u '' -p '' --shares"
    assert "{host}" not in r["cmd"]
    assert r["parses_as"] == "netexec_smb_null"


def test_render_leaves_json_body_braces_intact() -> None:
    # The k8s RBAC review carries a JSON -d body with literal braces. Rendering
    # must NOT treat those braces as placeholders (regression: str.format would
    # raise / mangle them).
    r = actions_ref.render("apiserver_anonymous_rbac_review", host="10.0.0.9", port=6443)
    assert r is not None
    assert "10.0.0.9:6443" in r["cmd"]
    assert '{"kind":"SelfSubjectRulesReview"' in r["cmd"]
    assert '"namespace":"default"' in r["cmd"]
    # the fold-back points the extractor at the matching interpret kind
    assert r["then"]["kind"] == "x:apiserver_anonymous_rbac_review"


def test_render_unknown_id_is_manual() -> None:
    assert actions_ref.render("no_such_action", host="10.0.0.1") is None
    # an entry without a cmd template is also manual
    assert actions_ref.entry("no_such_action") is None


def test_render_never_substitutes_a_secret_value(monkeypatch) -> None:
    # A {secret_ref} stays an env reference; the real secret never appears in
    # the rendered command line.
    monkeypatch.setattr(
        actions_ref, "_load",
        lambda: {"fake": {"cmd": "tool {host} --secret {secret_ref}", "risk": "propose"}},
    )
    r = actions_ref.render("fake", host="10.0.0.5")
    assert r is not None
    assert r["cmd"] == "tool 10.0.0.5 --secret $YH_SECRET"
    assert "{secret_ref}" not in r["cmd"]


def test_commands_returns_only_entries_with_a_template() -> None:
    cmds = actions_ref.commands()
    assert cmds, "actions.yaml should define command templates"
    assert all(isinstance(v, str) and v for v in cmds.values())
    assert "netexec_smb_null" in cmds


def test_every_template_substitutes_cleanly() -> None:
    # Drift guard: every cmd template fully resolves its host/port placeholders
    # when given a concrete target — a typo'd placeholder would survive.
    for aid in actions_ref.commands():
        r = actions_ref.render(aid, host="10.0.0.9", port=6443)
        assert r is not None
        assert "{host}" not in r["cmd"], f"{aid} left {{host}} unfilled"
        assert "{port}" not in r["cmd"], f"{aid} left {{port}} unfilled"


def test_every_parses_as_has_a_fold_back() -> None:
    # If an action declares parses_as, render must emit the fold-back call so the
    # operator is told how to feed the output back.
    for aid, e in actions_ref._load().items():
        if e.get("cmd") and e.get("parses_as"):
            r = actions_ref.render(aid, host="10.0.0.9", port=6443)
            assert r["then"]["kind"] == f"x:{e['parses_as']}", aid


# --- knowledge.Candidate.emits ----------------------------------------------


def _seed_chatbot(path: Path) -> int:
    with yhdb.transaction(path) as conn:
        eng = yhdb.upsert_engagement(conn, lab="act", scope="10.0.0.0/24")
        cur = conn.execute(
            "INSERT INTO host (engagement_id, ip, hostname, os, stage, first_seen) "
            "VALUES (?, '10.0.0.5', 'ai01', 'linux', 'scanned', '2026-01-01T00:00:00Z')",
            (eng,),
        )
        hid = int(cur.lastrowid)
        svc = conn.execute(
            "INSERT INTO service (host_id, port, proto, product, discovered_at) "
            "VALUES (?, 3000, 'tcp', 'gradio', '2026-01-01T00:00:00Z')",
            (hid,),
        )
        yhdb.upsert_surface(conn, hid, int(svc.lastrowid), "chatbot", "none", "{}")
        return eng


def test_candidates_carry_emitted_action_ids(tmp_db: Path) -> None:
    eng = _seed_chatbot(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        cands = kn.candidates_for(conn, eng)
    assert cands
    # emits is a frozen tuple of action ids (strings), parallel to the rule's emits.
    for c in cands:
        assert isinstance(c.emits, tuple)
        assert all(isinstance(a, str) for a in c.emits)
    # at least one candidate emits an action that actions.yaml can render.
    renderable = set(actions_ref.commands())
    assert any(set(c.emits) & renderable for c in cands)


# --- nextmoves render surfaces the command + fold-back ----------------------


def test_next_output_shows_command_and_fold_back(tmp_db: Path) -> None:
    eng = _seed_chatbot(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        nm = nm_.next_moves(conn, eng)
    text = "\n".join(nm_.render_next(nm))
    # rag_upload_discovery emits probe_writable_smb_share -> a concrete nxc command
    assert "$ nxc smb 10.0.0.5 -u '' -p '' --shares" in text
    assert "then: yhwach_interpret(kind='x:netexec_smb_null', host=10.0.0.5)" in text


def test_next_as_dict_carries_actions(tmp_db: Path) -> None:
    eng = _seed_chatbot(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        nm = nm_.next_moves(conn, eng)
    d = nm_.next_as_dict(nm)
    cands = d["auto"] + d["gated"]
    assert cands
    # every candidate dict exposes emits + an actions list (one per emit).
    for c in cands:
        assert "emits" in c
        assert len(c["actions"]) == len(c["emits"])
    # the smb-share action renders a cmd in the structured view too.
    acts = [a for c in cands for a in c["actions"]]
    assert any(a["action"] == "probe_writable_smb_share" and a["cmd"] for a in acts)


# --- yhwach_action MCP tool -------------------------------------------------


def _seed_ollama(path: Path) -> int:
    with yhdb.transaction(path) as conn:
        eng = yhdb.upsert_engagement(conn, lab="act", scope="10.0.0.0/24")
        cur = conn.execute(
            "INSERT INTO host (engagement_id, ip, hostname, os, stage, first_seen) "
            "VALUES (?, '10.0.0.5', 'ai01', 'linux', 'scanned', '2026-01-01T00:00:00Z')",
            (eng,),
        )
        hid = int(cur.lastrowid)
        svc = conn.execute(
            "INSERT INTO service (host_id, port, proto, product, discovered_at) "
            "VALUES (?, 11434, 'tcp', 'ollama', '2026-01-01T00:00:00Z')",
            (hid,),
        )
        yhdb.upsert_surface(conn, hid, int(svc.lastrowid), "ollama", "none", "{}")
        return eng


def test_candidate_carries_surface_port(tmp_db: Path) -> None:
    eng = _seed_ollama(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        cands = kn.candidates_for(conn, eng)
    ports = {c.port for c in cands if c.surface_kind == "ollama"}
    assert ports == {11434}


def test_port_using_templates_render_the_port_not_a_placeholder(tmp_db: Path) -> None:
    # Regression: an HTTP probe template uses {port}; both the text and the JSON
    # paths must fill it from the surface's service port, not leave a literal
    # {port} in a command the operator would paste.
    eng = _seed_ollama(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        nm = nm_.next_moves(conn, eng)
    text = "\n".join(nm_.render_next(nm))
    assert "{port}" not in text
    assert "http://10.0.0.5:11434/api/tags" in text
    d = nm_.next_as_dict(nm)
    cmds = [a["cmd"] for c in d["auto"] + d["gated"] for a in c["actions"] if a.get("cmd")]
    assert cmds
    assert all("{port}" not in cmd for cmd in cmds)


def test_tool_action_renders_known_action(tmp_db: Path) -> None:
    _seed_chatbot(tmp_db)
    from yhwach.mcp_tools import tool_action

    out = tool_action(tmp_db, "act", "netexec_smb_null", host="10.0.0.5")
    assert "$ nxc smb 10.0.0.5 -u '' -p '' --shares" in out
    assert "then: yhwach_interpret(kind='x:netexec_smb_null', host=10.0.0.5)" in out
    assert "ref:" in out


def test_tool_action_unknown_action_is_manual(tmp_db: Path) -> None:
    _seed_chatbot(tmp_db)
    from yhwach.mcp_tools import tool_action

    out = tool_action(tmp_db, "act", "no_such_action")
    assert "manual" in out.lower()


def test_tool_action_unknown_lab_errors(tmp_db: Path) -> None:
    from yhwach.mcp_tools import tool_action

    with pytest.raises(ValueError, match="unknown lab"):
        tool_action(tmp_db, "nope", "netexec_smb_null", host="10.0.0.5")


def test_tool_action_flags_incomplete_when_port_omitted(tmp_db: Path) -> None:
    # A port-templated action rendered without a port must NOT be handed over as
    # a runnable `$` command silently — it is annotated incomplete so the
    # operator does not paste a URL with a literal {port}.
    _seed_chatbot(tmp_db)
    from yhwach.mcp_tools import tool_action

    out = tool_action(tmp_db, "act", "probe_ollama_models", host="10.0.0.5")
    assert "{port}" in out  # the raw template still shows what is missing
    assert "incomplete" in out.lower()
    assert "port" in out.lower()


def test_tool_action_flags_incomplete_when_host_omitted(tmp_db: Path) -> None:
    _seed_chatbot(tmp_db)
    from yhwach.mcp_tools import tool_action

    out = tool_action(tmp_db, "act", "netexec_smb_null")
    assert "{host}" in out
    assert "incomplete" in out.lower()


def test_unfilled_detects_target_placeholders() -> None:
    assert actions_ref.unfilled("curl http://10.0.0.5:{port}/x") == ["{port}"]
    assert actions_ref.unfilled("nxc smb 10.0.0.5 --shares") == []
    # a resolved secret ref is never reported as unfilled
    assert actions_ref.unfilled("tool 10.0.0.5 --secret $YH_SECRET") == []


# --- action CLI command -----------------------------------------------------


def test_next_renders_every_renderable_emit_not_just_the_first(tmp_db: Path) -> None:
    # An smb null-session technique emits three distinct read-only tools. The
    # text menu (not only the JSON view) must show all three — the feature
    # exists so the operator misses no applicable move.
    with yhdb.transaction(tmp_db) as conn:
        eng = yhdb.upsert_engagement(conn, lab="act", scope="10.0.0.0/24")
        cur = conn.execute(
            "INSERT INTO host (engagement_id, ip, hostname, os, stage, first_seen) "
            "VALUES (?, '10.0.0.5', 'dc', 'windows', 'scanned', '2026-01-01T00:00:00Z')",
            (eng,),
        )
        hid = int(cur.lastrowid)
        svc = conn.execute(
            "INSERT INTO service (host_id, port, proto, product, discovered_at) "
            "VALUES (?, 445, 'tcp', 'smb', '2026-01-01T00:00:00Z')",
            (hid,),
        )
        yhdb.upsert_surface(conn, hid, int(svc.lastrowid), "smb", "none", "{}")
        nm = nm_.next_moves(conn, eng)
    text = "\n".join(nm_.render_next(nm))
    assert "nxc smb 10.0.0.5 -u '' -p '' --shares" in text
    assert "enum4linux-ng -A 10.0.0.5" in text
    assert "smbmap -H 10.0.0.5" in text


def test_cli_action_renders_json_body_intact(tmp_db: Path) -> None:
    _seed_chatbot(tmp_db)
    r = CliRunner().invoke(
        main,
        ["action", "--lab", "act", "apiserver_anonymous_rbac_review",
         "--host", "10.0.0.9", "--port", "6443", "--db", str(tmp_db)],
    )
    assert r.exit_code == 0, r.output
    assert "$ curl" in r.output
    assert '{"kind":"SelfSubjectRulesReview"' in r.output
    assert "10.0.0.9:6443" in r.output
