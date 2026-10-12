"""Cloud/k8s enumeration output -> findings + facts (I31).

Deterministic parses only, feeding the chaining tags the cloud_k8s playbook
already consumes. Per the reviewer correction: no IAM/role-binding name sniffers
(a role name is not a permission); `get secrets -A` is COUNTED, never stored.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from yhwach.interpret import ExtractedFinding

# `kubectl auth can-i --list` row: "resource  []  []  [verb1 verb2]"
_CANI_ROW = re.compile(r"^(?P<res>\S+)\s+\S+\s+\S+\s+\[(?P<verbs>[^\]]*)\]\s*$")


@dataclass
class CloudResult:
    findings: list[ExtractedFinding] = field(default_factory=list)
    facts: dict[str, str] = field(default_factory=dict)


def parse_aws_sts(text: str) -> CloudResult:
    """`aws sts get-caller-identity` JSON -> the current identity (chains to the
    IAM-role-escalation rule via aws_credentials)."""
    res = CloudResult()
    try:
        d = json.loads(text)
    except json.JSONDecodeError:
        return res
    arn = d.get("Arn") or d.get("arn")
    account = d.get("Account") or d.get("account")
    if arn:
        res.facts["aws_identity"] = arn
        # Authenticating to the account confirms the cloud tenant is in scope,
        # which ungated the exploit-class cloud/Entra rules (I33).
        res.facts["cloud_tenant_in_scope"] = "true"
        if account:
            res.facts["aws_account"] = str(account)
        res.findings.append(ExtractedFinding(
            "T1078.004", "AWS caller identity", "info",
            f"authenticated as {arn}" + (f" (account {account})" if account else ""),
            tag="aws_credentials"))
    return res


def parse_can_i(text: str) -> CloudResult:
    """`kubectl auth can-i --list` -> findings for the dangerous grants only."""
    res = CloudResult()
    for raw in text.splitlines():
        m = _CANI_ROW.match(raw.strip())
        if not m:
            continue
        resource = m.group("res").lower()
        if resource in ("resources",):   # header row
            continue
        verbs = {v.strip().lower() for v in m.group("verbs").split() if v.strip()}
        if resource in ("*.*", "*") and "*" in verbs:
            res.findings.append(ExtractedFinding(
                "T1078", "Kubernetes cluster-admin", "critical",
                "the token can do *.* [*] — full cluster control", tag="pod_create_permission"))
        if resource in ("pods", "pods/exec", "pods/*", "deployments", "daemonsets") \
                and ("create" in verbs or "*" in verbs):
            res.findings.append(ExtractedFinding(
                "T1610", f"Can create {resource}", "high",
                f"create on {resource} -> schedule a privileged/hostPath pod to escape",
                tag="pod_create_permission"))
        if resource in ("secrets", "secrets/*") and (verbs & {"get", "list", "*"}):
            res.findings.append(ExtractedFinding(
                "T1552.007", "Can read Kubernetes secrets", "high",
                f"{'/'.join(sorted(verbs & {'get', 'list'})) or '*'} on secrets -> SA tokens, "
                "registry creds, app secrets", tag="k8s_sa_token"))
    return res


def parse_pods_json(text: str) -> CloudResult:
    """`kubectl get pods -A -o json` -> a COUNT of privileged / hostPID /
    hostPath pods (the escape surface). Pod specs are not stored."""
    res = CloudResult()
    try:
        d = json.loads(text)
    except json.JSONDecodeError:
        return res
    items = d.get("items") if isinstance(d, dict) else None
    if not isinstance(items, list):
        return res
    priv = hostpid = hostpath = 0
    for pod in items:
        spec = (pod or {}).get("spec") or {}
        if spec.get("hostPID") is True:
            hostpid += 1
        if any((v or {}).get("hostPath") for v in (spec.get("volumes") or [])):
            hostpath += 1
        for cont in spec.get("containers") or []:
            if ((cont or {}).get("securityContext") or {}).get("privileged") is True:
                priv += 1
                break
    res.facts["k8s_pods_total"] = str(len(items))
    if priv or hostpid or hostpath:
        res.findings.append(ExtractedFinding(
            "T1610", "Privileged/host-namespace pods", "high",
            f"{priv} privileged, {hostpid} hostPID, {hostpath} hostPath pod(s) — "
            "container-escape surface", tag="pod_create_permission"))
    return res


def parse_secrets_count(text: str) -> CloudResult:
    """`kubectl get secrets -A` -> a COUNT only (values are never read)."""
    res = CloudResult()
    try:
        d = json.loads(text)
        n = len(d.get("items") or []) if isinstance(d, dict) else 0
    except json.JSONDecodeError:
        # plain table: data rows minus the header; NAMESPACE/NAME header line.
        lines = [ln for ln in text.splitlines() if ln.strip()]
        n = max(0, len([ln for ln in lines if not ln.upper().startswith(("NAMESPACE", "NAME"))]))
    if n:
        res.facts["k8s_secrets_readable"] = str(n)
        res.findings.append(ExtractedFinding(
            "T1552.007", "Kubernetes secrets readable", "high",
            f"{n} secret(s) listable cluster-wide — enumerate for SA tokens / app creds",
            tag="k8s_sa_token"))
    return res


def detect_cloud_kind(text: str) -> str | None:
    """Which cloud parser fits this paste, or None."""
    head = text.lstrip()
    low = text.lower()
    if '"arn"' in low and ('"account"' in low or '"userid"' in low):
        return "aws_sts"
    if "non-resource urls" in low or "auth can-i" in low:
        return "can_i"
    if head.startswith("{"):
        if '"containers"' in low or '"securitycontext"' in low or '"hostpid"' in low:
            return "pods"
        if '"kind": "secret"' in low or '"kind":"secret"' in low:
            return "secrets"
        if '"items"' in low:
            return "pods"
    if "secrets" in low and ("namespace" in low or "\ndata" in low):
        return "secrets"
    return None
