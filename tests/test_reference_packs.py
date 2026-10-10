"""The reference packs added in P0.5 (lessons / services / tags) render and filter."""
from __future__ import annotations

import pytest

from yhwach.reference import _FILES, render_pack


def test_new_packs_are_registered() -> None:
    for pack in ("lessons", "services", "tags"):
        assert pack in _FILES


def test_lessons_render_and_query() -> None:
    full = render_pack("lessons")
    assert "L-redis-loot" in full and "L-godpotato" in full
    # --query matches on any field (trigger_tag, lesson text, maps)
    only = render_pack("lessons", "redis")
    assert "L-redis-loot" in only and "godpotato" not in only.lower()


def test_services_render_and_query() -> None:
    full = render_pack("services")
    assert "redis" in full and "apiserver" in full
    only = render_pack("services", "mongodb")
    assert "mongodb" in only and "apiserver" not in only


def test_tags_render_shows_status() -> None:
    # classifier_repo is a stable context-set tag (brain-set, no parser producer).
    out = render_pack("tags", "classifier_repo")
    assert "classifier_repo" in out and "context" in out


def test_esc_catalog_covers_esc1_to_16_with_signal_and_chain() -> None:
    full = render_pack("esc")
    for esc in ("ESC1", "ESC9", "ESC15", "ESC16"):
        assert esc in full
    assert "find-signal:" in full and "chain:" in full
    # ESC15 carries its CVE; query filters to it.
    only = render_pack("esc", "esc15")
    assert "CVE-2024-49019" in only and "ESC1 " not in only


def test_lolbas_render_and_query() -> None:
    for pack in ("lolbas", "wadcoms"):
        assert pack in _FILES
    full = render_pack("lolbas")
    assert "certutil" in full and "comsvcs.dll" in full
    # query by category works (every field is scanned)
    only = render_pack("lolbas", "credentials")
    assert "comsvcs.dll" in only and "certutil" not in only


def test_wadcoms_render_and_query() -> None:
    full = render_pack("wadcoms")
    assert "kerberoast" in full and "psexec" in full
    only = render_pack("wadcoms", "lateral")
    assert "psexec" in only and "kerberoast" not in only
    # synthetic placeholders only — no real-looking creds
    assert "password123" in full


def test_default_creds_new_products() -> None:
    for product in ("redis", "minio", "keycloak", "mssql"):
        out = render_pack("default-creds", product)
        assert product in out
    # minioadmin default is present and query-filterable
    assert "minioadmin:minioadmin" in render_pack("default-creds", "minio")


def test_arsenal_pack_registered_and_renders() -> None:
    assert "arsenal" in _FILES
    full = render_pack("arsenal")
    # canonical proven path is present and rendered first (tier-sorted)
    assert "svcmon.exe" in full and "gen_cs_shell.sh" in full
    assert "[canonical]" in full
    assert full.index("[canonical]") < full.index("[quick-win]")
    # the new AIScripts surfaces are indexed
    for name in ("k8s_ml_enum.sh", "gitlab_enum.sh", "weaviate_export.py"):
        assert name in full


def test_arsenal_pack_query_filters_by_surface() -> None:
    only = render_pack("arsenal", "kubernetes")
    assert "k8s_ml_enum.sh" in only and "gitlab_enum.sh" not in only
    # query by tool name works too
    svc = render_pack("arsenal", "svcmon")
    assert "svcmon.exe" in svc and "gitlab_enum.sh" not in svc


def test_ai_attacks_pack_registered_and_covers_the_six_cookbooks() -> None:
    assert "ai-attacks" in _FILES
    full = render_pack("ai-attacks")
    for topic in ("rag_poisoning", "mcp_attack", "a2a_attack", "vector_db",
                  "cloud_loot", "prompt_injection", "owasp_llm_checklist",
                  "model_supply_chain"):
        assert topic in full
    # standards mapping is rendered so the write-up can cite it
    assert "OWASP" in full and "ATLAS" in full


def test_ai_attacks_query_filters_to_the_right_cookbook() -> None:
    # distinctive term only in the vector_db cookbook (the owasp checklist
    # cross-references every topic, so filter on a per-cookbook keyword and
    # assert on the "## <topic>" section header, not the bare word).
    only = render_pack("ai-attacks", "weaviate")
    assert "## vector_db" in only and "## cloud_loot" not in only
    # distinctive term only in cloud_loot
    cl = render_pack("ai-attacks", "assume-role")
    assert "## cloud_loot" in cl and "## vector_db" not in cl


def test_ai_attacks_foldback_is_yhwach_native() -> None:
    # fold-back references the native yhwach MCP tools (not retired slash-commands)
    full = render_pack("ai-attacks")
    assert "yhwach_add_finding" in full or "yhwach_add_cred" in full


def test_unknown_pack_raises() -> None:
    with pytest.raises(ValueError):
        render_pack("does-not-exist")


def test_lessons_for_matches_trigger_tags() -> None:
    from yhwach.reference import lessons_for

    hits = lessons_for({"chatbot"})
    assert any(h["id"] == "L-recall-leak" for h in hits)
    # case-insensitive, and empty / non-matching inputs return nothing
    assert lessons_for({"CHATBOT"})
    assert lessons_for(set()) == []
    assert lessons_for({"nonexistent_tag_xyz"}) == []
