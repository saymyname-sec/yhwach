"""The producer -> tag -> consumer invariant for the state (chaining) tag axis.

A chaining tag is CONSUMED by a rule's `findings_include` (or a non-stage
escalator `trigger`), and PRODUCED by code that emits it onto a finding
(interpret / parsers / probes / ingest / vulns / actions ...). A consumer tag
with no producer is an ORPHAN — the promotion/chain silently never fires.

This test computes the orphan set from the live tree and asserts every orphan is
DOCUMENTED in data/tags.yaml with a non-live status, so a NEW undocumented dead
tag fails CI the moment it is introduced:
  - status: dead     -> should have an automated producer but doesn't yet (later slice)
  - status: context  -> intentionally set by the brain/operator from context, no parser
  - status: planned  -> producer+consumer land together in a later slice
"""
from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
PLAYBOOKS = ROOT / "playbooks"

# Escalator triggers that are FSM host-stage markers, not finding tags — produced
# by a stage transition, not a finding emitter; excluded from the tag axis.
_STAGE_PREFIX = "stage_"

# The matcher reads findings_include from YAML generically; it is a consumer, not
# a producer, so it is excluded from the producer scan.
_NOT_A_PRODUCER = {"knowledge.py"}

_ALLOWED_ORPHAN_STATUS = {"dead", "context", "planned"}


def _as_list(v) -> list[str]:
    if v is None:
        return []
    if isinstance(v, str):
        return [v]
    if isinstance(v, list):
        return [str(x) for x in v]
    return []


def _consumer_tags() -> set[str]:
    """Every chaining tag a rule keys on: `when.findings_include` + non-stage triggers."""
    tags: set[str] = set()
    for f in sorted(PLAYBOOKS.glob("*.yaml")):
        docs = yaml.safe_load(f.read_text(encoding="utf-8")) or []
        if not isinstance(docs, list):
            continue
        for rule in docs:
            if not isinstance(rule, dict):
                continue
            when = rule.get("when") or {}
            if isinstance(when, dict):
                tags.update(_as_list(when.get("findings_include")))
            tags.update(_as_list(rule.get("findings_include")))
            tags.update(t for t in _as_list(rule.get("triggers"))
                        if not t.startswith(_STAGE_PREFIX))
    return tags


def _producer_blob() -> str:
    """All emitter-side source concatenated (every yhwach/*.py except the matcher).
    A tag literal appearing here means some code path knows how to emit it."""
    parts: list[str] = []
    for p in sorted((ROOT / "yhwach").rglob("*.py")):
        if p.name in _NOT_A_PRODUCER:
            continue
        parts.append(p.read_text(encoding="utf-8"))
    return "\n".join(parts)


def _documented_orphans() -> dict[str, str]:
    """tag -> status, for tags.yaml entries with a non-live (orphan-allowing) status."""
    reg = yaml.safe_load((ROOT / "data" / "tags.yaml").read_text(encoding="utf-8")) or []
    return {e["tag"]: e["status"] for e in reg
            if isinstance(e, dict) and e.get("status") in _ALLOWED_ORPHAN_STATUS}


def _orphans() -> set[str]:
    blob = _producer_blob()
    return {t for t in _consumer_tags()
            if f'"{t}"' not in blob and f"'{t}'" not in blob}


def test_every_orphan_tag_is_documented() -> None:
    undocumented = _orphans() - set(_documented_orphans())
    assert not undocumented, (
        "chaining tag(s) consumed by a rule but emitted by no producer and not "
        f"documented in data/tags.yaml: {sorted(undocumented)} — add the producer, "
        "or document it there with status dead|context|planned."
    )


def test_documented_orphans_are_still_orphans() -> None:
    """Keep data/tags.yaml honest: a tag flagged dead/context/planned must really
    have no producer (else the flag is stale and should be dropped to 'live')."""
    orphans = _orphans()
    consumers = _consumer_tags()
    for tag, status in _documented_orphans().items():
        if status == "planned":
            continue  # planned tags need not be consumed yet
        assert tag in consumers, f"tags.yaml marks '{tag}' {status} but no rule consumes it"
        assert tag in orphans, (
            f"tags.yaml marks '{tag}' {status} but a producer now emits it — set status: live"
        )
