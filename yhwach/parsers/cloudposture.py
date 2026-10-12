"""trivy and prowler output -> vulnerability rows / attack-relevant findings (I32).

trivy JSON becomes software + vulnerability rows. prowler FAILs are filtered
through an allowlist of attack-relevant checks (public exposure, IAM privesc,
secret exposure, weak auth) mapped to chaining tags — the CIS/PCI/NIST
compliance matrix is intentionally dropped (prowler already ships that report).
"""
from __future__ import annotations

import json
from dataclasses import dataclass

_TRIVY_SEV = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium",
              "LOW": "low", "UNKNOWN": "info"}

# Attack-relevant prowler check -> chaining tag. Matched as substrings of the
# CheckID / title, most specific intent first. Anything unmatched is compliance
# noise and is skipped.
_POSTURE_TAGS: list[tuple[tuple[str, ...], str, str]] = [
    (("public", "anonymous", "internet", "0.0.0.0", "world"), "cloud_public_exposure", "high"),
    (("admin", "privilege", "wildcard", "assumerole", "passrole"), "cloud_iam_privesc", "high"),
    (("secret", "kms key", "plaintext", "unencrypted", "hardcoded"), "cloud_secret_exposure", "high"),
    (("mfa", "root ", "root_", "access key"), "cloud_weak_auth", "medium"),
]


@dataclass
class TrivyVuln:
    cve: str
    pkg: str
    version: str | None
    fixed: str | None
    severity: str
    title: str
    target: str


@dataclass
class PostureFinding:
    check_id: str
    title: str
    severity: str
    service: str
    resource: str
    tag: str


def parse_trivy(text: str) -> list[TrivyVuln]:
    try:
        d = json.loads(text)
    except json.JSONDecodeError:
        return []
    out: list[TrivyVuln] = []
    for res in (d.get("Results") or []) if isinstance(d, dict) else []:
        target = res.get("Target") or ""
        for v in res.get("Vulnerabilities") or []:
            vid = v.get("VulnerabilityID")
            if not vid:
                continue
            out.append(TrivyVuln(
                cve=vid, pkg=v.get("PkgName") or "", version=v.get("InstalledVersion"),
                fixed=v.get("FixedVersion"), severity=_TRIVY_SEV.get(
                    (v.get("Severity") or "UNKNOWN").upper(), "info"),
                title=v.get("Title") or v.get("Description", "")[:120] or vid,
                target=target))
    return out


def _posture_tag(check_id: str, title: str) -> tuple[str, str] | None:
    blob = f"{check_id} {title}".lower()
    for needles, tag, sev in _POSTURE_TAGS:
        if any(n in blob for n in needles):
            return tag, sev
    return None


def parse_prowler(text: str) -> list[PostureFinding]:
    """prowler v3 native JSON (a list of check results). Only FAILs that match
    the attack-relevant allowlist are returned."""
    try:
        d = json.loads(text)
    except json.JSONDecodeError:
        return []
    rows = d if isinstance(d, list) else (d.get("findings") or [])
    out: list[PostureFinding] = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        status = (r.get("Status") or r.get("status") or "").upper()
        if status not in ("FAIL", "FAILED"):
            continue
        cid = r.get("CheckID") or r.get("check_id") or r.get("FindingUniqueId") or ""
        title = r.get("CheckTitle") or r.get("check_title") or r.get("StatusExtended") or cid
        hit = _posture_tag(cid, title)
        if not hit:
            continue   # compliance noise, dropped
        tag, default_sev = hit
        sev = (r.get("Severity") or r.get("severity") or default_sev).lower()
        if sev not in ("critical", "high", "medium", "low", "info"):
            sev = default_sev
        out.append(PostureFinding(
            check_id=cid, title=title, severity=sev,
            service=r.get("ServiceName") or r.get("service") or "",
            resource=r.get("ResourceId") or r.get("resource_id") or r.get("ResourceArn") or "",
            tag=tag))
    return out
