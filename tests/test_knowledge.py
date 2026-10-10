"""Tests for the matcher-only knowledge loader (candidate generation, no ranker)."""

from __future__ import annotations

from pathlib import Path

import pytest

from yhwach import db as yhdb
from yhwach import knowledge as kn

# --- loading & validation ---------------------------------------------------


def test_load_techniques_loads_full_catalog() -> None:
    techs = kn.load_techniques()
    # The restored catalog carries >100 technique rules across surfaces.
    assert len(techs) > 100
    ids = {t.id for t in techs}
    assert "ollama_unauth_api" in ids
    # ollama_unauth_api is read_only -> proceed autonomy, and AI-classed via LLM maps.
    ollama = next(t for t in techs if t.id == "ollama_unauth_api")
    assert ollama.risk == "read_only"
    assert ollama.autonomy == "proceed"
    assert ollama.technique_class == "ai"


def test_technique_alias_is_exhaustion_key() -> None:
    techs = {t.id: t for t in kn.load_techniques()}
    # ollama_probllama_rce declares `technique: ollama_probllama` as its family key.
    assert techs["ollama_probllama_rce"].technique == "ollama_probllama"
    # A rule without an explicit alias falls back to its own id.
    assert techs["ollama_unauth_api"].technique == "ollama_unauth_api"


def test_load_rejects_unauthorized_rule(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "- id: x\n  when: { surface: ollama }\n  emits: [{action: probe}]\n",
        encoding="utf-8",
    )
    with pytest.raises(kn.KnowledgeError, match="authorized_only"):
        kn.load_techniques(tmp_path)


def test_load_rejects_duplicate_id(tmp_path: Path) -> None:
    (tmp_path / "a.yaml").write_text(
        "- id: dup\n  when: { surface: ollama }\n  emits: [{action: p}]\n"
        "  authorized_only: true\n",
        encoding="utf-8",
    )
    (tmp_path / "b.yaml").write_text(
        "- id: dup\n  when: { surface: smb }\n  emits: [{action: p}]\n" "  authorized_only: true\n",
        encoding="utf-8",
    )
    with pytest.raises(kn.KnowledgeError, match="duplicate"):
        kn.load_techniques(tmp_path)


def test_parses_valid_action_class(tmp_path: Path) -> None:
    (tmp_path / "c.yaml").write_text(
        "- id: revshell\n  when: { surface: ollama }\n  emits: [{action: p}]\n"
        "  authorized_only: true\n  action_class: listener\n",
        encoding="utf-8",
    )
    techs = kn.load_techniques(tmp_path)
    assert techs[0].action_class == "listener"


def test_rejects_unknown_action_class(tmp_path: Path) -> None:
    (tmp_path / "c.yaml").write_text(
        "- id: x\n  when: { surface: ollama }\n  emits: [{action: p}]\n"
        "  authorized_only: true\n  action_class: nuke_from_orbit\n",
        encoding="utf-8",
    )
    with pytest.raises(kn.KnowledgeError, match="action_class"):
        kn.load_techniques(tmp_path)


def test_only_pivot_revshell_rules_set_action_class() -> None:
    """Post-arsenal-wiring invariant: action_class is set ONLY on rules that
    open a network listener (the pivot/revshell family). Every other rule
    stays action_class=None so `--allow-gated` (exploit autonomy) can run it.
    A future non-listener rule accidentally tagged 'listener' would trip
    this canary and prompt a doctrine review.
    """
    listener_ids = {
        "pivot_ligolo_windows",
        "pivot_chisel_linux",
        "pivot_ligolo_linux",
        "generate_windows_revshell",
        "generate_linux_revshell",
    }
    for t in kn.load_techniques():
        if t.id in listener_ids:
            assert t.action_class == "listener", (
                f"{t.id} must be action_class=listener"
            )
        else:
            assert t.action_class is None, (
                f"{t.id} unexpectedly sets action_class={t.action_class!r}; "
                "only pivot/revshell rules should"
            )


# --- matching ---------------------------------------------------------------


def _engagement_with_host(conn, *, ip: str = "10.0.0.5", os: str = "linux") -> tuple[int, int]:
    eid = yhdb.upsert_engagement(conn, lab="t", scope="10.0.0.0/24")
    cur = conn.execute(
        "INSERT INTO host (engagement_id, ip, os, stage, first_seen) "
        "VALUES (?, ?, ?, 'scanned', '2026-01-01T00:00:00Z')",
        (eid, ip, os),
    )
    return eid, int(cur.lastrowid)


def test_candidates_match_ollama_surface(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        eid, host_id = _engagement_with_host(conn)
        yhdb.upsert_surface(conn, host_id, None, "ollama", "none", "{}")

        cands = kn.candidates_for(conn, eid)

    ids = {c.technique_id for c in cands}
    assert "ollama_unauth_api" in ids
    hit = next(c for c in cands if c.technique_id == "ollama_unauth_api")
    assert hit.host_ip == "10.0.0.5"
    assert hit.surface_kind == "ollama"
    assert hit.risk == "read_only"
    assert hit.chained_from is None


def test_auth_clause_filters_out_authed_surface(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        eid, host_id = _engagement_with_host(conn)
        # ollama behind bearer auth: the `auth: none` rule must not match.
        yhdb.upsert_surface(conn, host_id, None, "ollama", "bearer", "{}")

        cands = kn.candidates_for(conn, eid)

    assert "ollama_unauth_api" not in {c.technique_id for c in cands}


def test_consumed_technique_is_not_resurfaced(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        eid, host_id = _engagement_with_host(conn)
        yhdb.upsert_surface(conn, host_id, None, "ollama", "none", "{}")
        conn.execute(
            "INSERT INTO technique_state (engagement_id, technique_id, status) "
            "VALUES (?, 'ollama_unauth_api', 'consumed')",
            (eid,),
        )

        cands = kn.candidates_for(conn, eid)
        cands_incl = kn.candidates_for(conn, eid, include_consumed=True)

    assert "ollama_unauth_api" not in {c.technique_id for c in cands}
    assert "ollama_unauth_api" in {c.technique_id for c in cands_incl}


def test_denylisted_host_is_filtered(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        eid, host_id = _engagement_with_host(conn)
        yhdb.upsert_surface(conn, host_id, None, "ollama", "none", "{}")
        conn.execute(
            "INSERT INTO lore_denylist_hit (engagement_id, host_id, artifact, seen_at) "
            "VALUES (?, ?, 'cloudbase-init', '2026-01-01T00:00:00Z')",
            (eid, host_id),
        )

        cands = kn.candidates_for(conn, eid)

    assert cands == []


def test_findings_include_chains_on_open_finding(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        eid, host_id = _engagement_with_host(conn)
        yhdb.upsert_surface(conn, host_id, None, "ollama", "none", "{}")

        # Before the finding: the probllama chain rule does not fire.
        before = {c.technique_id for c in kn.candidates_for(conn, eid)}
        assert "ollama_probllama_rce" not in before

        conn.execute(
            "INSERT INTO finding (engagement_id, host_id, class, title, severity, "
            "tag, status, discovered_at) "
            "VALUES (?, ?, 'LLM01', 'probllama', 'high', 'ollama_probllama', 'open', "
            "'2026-01-01T00:00:00Z')",
            (eid, host_id),
        )
        after = {c.technique_id for c in kn.candidates_for(conn, eid)}

    assert "ollama_probllama_rce" in after


def test_host_ip_scoping(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        eid, h1 = _engagement_with_host(conn, ip="10.0.0.5")
        yhdb.upsert_surface(conn, h1, None, "ollama", "none", "{}")
        cur = conn.execute(
            "INSERT INTO host (engagement_id, ip, os, stage, first_seen) "
            "VALUES (?, '10.0.0.6', 'linux', 'scanned', '2026-01-01T00:00:00Z')",
            (eid,),
        )
        h2 = int(cur.lastrowid)
        yhdb.upsert_surface(conn, h2, None, "ollama", "none", "{}")

        scoped = kn.candidates_for(conn, eid, host_ip="10.0.0.5")

    assert {c.host_ip for c in scoped} == {"10.0.0.5"}


# --- pivot.yaml (arsenal-wired) --------------------------------------------

_PIVOT_RULE_IDS = {
    "pivot_ligolo_windows",
    "pivot_chisel_linux",
    "pivot_ligolo_linux",
    "generate_windows_revshell",
    "generate_linux_revshell",
}


def test_pivot_yaml_loads_and_registers_all_rules() -> None:
    techs = {t.id: t for t in kn.load_techniques()}
    missing = _PIVOT_RULE_IDS - set(techs)
    assert not missing, f"pivot.yaml rules missing from catalog: {missing}"


def test_all_pivot_rules_are_gated_listener_action_class() -> None:
    """Every pivot/revshell rule opens a Kali-side listener — it MUST be
    action_class=listener so `--allow-gated` alone does not run it."""
    techs = {t.id: t for t in kn.load_techniques() if t.id in _PIVOT_RULE_IDS}
    for t in techs.values():
        assert t.action_class == "listener", (
            f"{t.id} must be action_class=listener (opens a network listener)"
        )
        assert t.risk == "exploit", f"{t.id} must be risk=exploit (not read_only)"


def test_pivot_ligolo_windows_source_names_svcmon_arsenal_key() -> None:
    """Rule source string must name the yhwach.arsenal key so `yhwach next`
    prints which binary the operator will ship."""
    techs = {t.id: t for t in kn.load_techniques()}
    src = (techs["pivot_ligolo_windows"].source or "").lower()
    assert "svcmon_win" in src
    assert "svcmon.exe" in src


def test_pivot_chisel_linux_source_names_chisel_arsenal_key() -> None:
    techs = {t.id: t for t in kn.load_techniques()}
    src = (techs["pivot_chisel_linux"].source or "").lower()
    assert "chisel" in src
    assert "/usr/local/bin/chisel" in src


def test_pivot_ligolo_windows_matches_windows_foothold(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        eid, host_id = _engagement_with_host(conn, ip="172.16.10.13", os="windows")
        conn.execute("UPDATE host SET stage='foothold' WHERE id=?", (host_id,))
        cands = kn.candidates_for(conn, eid)
    ids = {c.technique_id for c in cands}
    assert "pivot_ligolo_windows" in ids
    # Linux-only rules must NOT match a Windows host.
    assert "pivot_chisel_linux" not in ids
    assert "pivot_ligolo_linux" not in ids


def test_pivot_chisel_linux_matches_linux_foothold(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        eid, host_id = _engagement_with_host(conn, ip="172.16.10.13", os="linux")
        conn.execute("UPDATE host SET stage='foothold' WHERE id=?", (host_id,))
        cands = kn.candidates_for(conn, eid)
    ids = {c.technique_id for c in cands}
    assert "pivot_chisel_linux" in ids
    assert "pivot_ligolo_linux" in ids  # alt path also lit up
    assert "pivot_ligolo_windows" not in ids


def test_generate_windows_revshell_requires_windows_target(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        # Linux host — Windows revshell rule must NOT fire.
        eid_lin, _ = _engagement_with_host(conn, ip="10.0.0.5", os="linux")
        lin_cands = kn.candidates_for(conn, eid_lin)
        lin_ids = {c.technique_id for c in lin_cands}
    assert "generate_windows_revshell" not in lin_ids
    assert "generate_linux_revshell" in lin_ids


def test_generate_linux_revshell_only_on_linux(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        eid_win, _ = _engagement_with_host(conn, ip="10.0.0.99", os="windows")
        cands = kn.candidates_for(conn, eid_win)
        ids = {c.technique_id for c in cands}
    assert "generate_linux_revshell" not in ids
    assert "generate_windows_revshell" in ids


# ─── catalog cache ─────────────────────────────────────────────────────────
# Parsing the 13 playbook YAMLs was ~90% of a live-board render, and the board
# did it twice every three seconds. The cache is keyed on the catalog's own
# mtimes, so these tests pin the two ways a cache can go wrong: serving a stale
# catalog, and handing out a shared mutable list.


def _write_catalog(d, body: str) -> None:
    (d / "cache_probe.yaml").write_text(body, encoding="utf-8")


_RULE = """
- id: {tid}
  authorized_only: true
  risk: read_only
  surface: web
  when:
    surface: [web]
  emits: [probe]
  cmd: 'true'
"""


def test_catalog_cache_avoids_reparsing(tmp_path, monkeypatch) -> None:
    from yhwach import knowledge as kn

    _write_catalog(tmp_path, _RULE.format(tid="probe_one"))
    parses = []
    real = kn._load_techniques_uncached
    monkeypatch.setattr(kn, "_load_techniques_uncached",
                        lambda d: (parses.append(d), real(d))[1])

    first = kn.load_techniques(tmp_path)
    for _ in range(5):
        kn.load_techniques(tmp_path)
    assert [t.id for t in first] == ["probe_one"]
    assert len(parses) == 1, f"catalog parsed {len(parses)}x, expected 1"


def test_catalog_cache_invalidates_when_a_playbook_changes(tmp_path) -> None:
    from yhwach import knowledge as kn

    _write_catalog(tmp_path, _RULE.format(tid="probe_one"))
    assert [t.id for t in kn.load_techniques(tmp_path)] == ["probe_one"]

    _write_catalog(tmp_path, _RULE.format(tid="probe_one")
                   + _RULE.format(tid="probe_two"))
    ids = [t.id for t in kn.load_techniques(tmp_path)]
    assert ids == ["probe_one", "probe_two"], ids

    # a removed file must drop out too
    (tmp_path / "cache_probe.yaml").unlink()
    assert kn.load_techniques(tmp_path) == []


def test_catalog_cache_hands_out_a_fresh_list(tmp_path) -> None:
    """A caller that mutates the result must not corrupt the next caller's."""
    from yhwach import knowledge as kn

    _write_catalog(tmp_path, _RULE.format(tid="probe_one"))
    got = kn.load_techniques(tmp_path)
    got.clear()
    assert [t.id for t in kn.load_techniques(tmp_path)] == ["probe_one"]
