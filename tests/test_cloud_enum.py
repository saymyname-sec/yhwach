"""I31 — kubectl / aws enumeration -> findings + facts.

Deterministic parses feeding the cloud chaining tags. No IAM/role-name sniffers
(a name is not a permission); secrets are COUNTED, never stored.
"""
from __future__ import annotations

from pathlib import Path

from yhwach import db as yhdb
from yhwach import sniff
from yhwach.mcp_tools import tool_interpret
from yhwach.parsers import cloud as yhcloud

_CANI = (
    "Resources   Non-Resource URLs   Resource Names   Verbs\n"
    "*.*         []                  []               [*]\n"
    "pods        []                  []               [create list]\n"
    "secrets     []                  []               [get list]\n"
    "configmaps  []                  []               [get]\n"
)
_AWS = '{"UserId":"AIDAEX","Account":"123456789012","Arn":"arn:aws:iam::123456789012:user/ci"}'
_PODS = ('{"items":[{"spec":{"hostPID":true,"containers":[{"securityContext":'
         '{"privileged":true}}]}},{"spec":{"containers":[{}]}}]}')
_SECRETS = '{"items":[{"kind":"Secret","metadata":{"name":"a"}},{"kind":"Secret","metadata":{"name":"b"}}]}'


# --- parsers ----------------------------------------------------------------


def test_can_i_flags_dangerous_grants_only() -> None:
    tags = {f.tag for f in yhcloud.parse_can_i(_CANI).findings}
    assert "pod_create_permission" in tags   # *.* [*] and pods [create]
    assert "k8s_sa_token" in tags            # secrets [get list]
    # a benign grant (configmaps [get]) raises nothing
    titles = [f.title for f in yhcloud.parse_can_i(_CANI).findings]
    assert not any("configmap" in t.lower() for t in titles)


def test_aws_sts_identity() -> None:
    res = yhcloud.parse_aws_sts(_AWS)
    assert res.facts["aws_account"] == "123456789012"
    assert "arn:aws:iam" in res.facts["aws_identity"]
    assert res.findings[0].tag == "aws_credentials"


def test_pods_json_counts_escape_surface() -> None:
    res = yhcloud.parse_pods_json(_PODS)
    assert res.facts["k8s_pods_total"] == "2"
    assert res.findings[0].tag == "pod_create_permission"


def test_secrets_counted_not_stored() -> None:
    res = yhcloud.parse_secrets_count(_SECRETS)
    assert res.facts["k8s_secrets_readable"] == "2"
    assert res.findings[0].tag == "k8s_sa_token"


def test_bad_json_is_empty() -> None:
    assert yhcloud.parse_aws_sts("not json").findings == []
    assert yhcloud.parse_pods_json("{bad").findings == []


def test_sniff() -> None:
    assert sniff.detect(_AWS) == "aws"
    assert sniff.detect(_CANI) == "kubectl"


# --- ingest -----------------------------------------------------------------


def _eng(path: Path) -> int:
    with yhdb.transaction(path) as conn:
        return yhdb.upsert_engagement(conn, lab="L", scope="10.0.0.0/8", kind="cloud")


def test_ingest_can_i_and_aws(tmp_db: Path) -> None:
    eid = _eng(tmp_db)
    tool_interpret(tmp_db, "L", _CANI)
    tool_interpret(tmp_db, "L", _AWS)
    with yhdb.transaction(tmp_db) as conn:
        tags = sorted({r[0] for r in conn.execute(
            "SELECT tag FROM finding WHERE engagement_id=? AND tag IS NOT NULL", (eid,))})
        facts = {r["key"] for r in yhdb.list_domain_facts(conn, eid)}
    assert {"pod_create_permission", "k8s_sa_token", "aws_credentials"} <= set(tags)
    assert "aws_identity" in facts


def test_ingest_routes_pods_and_secrets_json(tmp_db: Path) -> None:
    eid = _eng(tmp_db)
    tool_interpret(tmp_db, "L", _PODS, kind="kubectl")
    tool_interpret(tmp_db, "L", _SECRETS, kind="kubectl")
    with yhdb.transaction(tmp_db) as conn:
        facts = {r["key"]: r["value"] for r in yhdb.list_domain_facts(conn, eid)}
    assert facts["k8s_pods_total"] == "2"
    assert facts["k8s_secrets_readable"] == "2"
