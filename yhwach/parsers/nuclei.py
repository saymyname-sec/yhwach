"""nuclei JSONL -> potential vulnerability rows (I50).

Each line is one nuclei finding. It lands as a vulnerability in state 'potential'
keyed on the TEMPLATE id (not the CVE — most templates have no CVE, and keying on
CVE collapsed every one into a single host row). A small promote pack maps known
templates/CVEs to the chaining tag recall already consumes. A credential-category
template's extracted results are loot, never sprayable creds.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from urllib.parse import urlparse

_CRED_TAGS = {"default-login", "creds", "credential", "token", "exposure", "disclosure"}
_PROMOTE_TAGS = {
    "rce": "exploitable_cve", "sqli": "exploitable_cve", "lfi": "exploitable_cve",
    "ssrf": "exploitable_cve", "ssti": "exploitable_cve", "deserialization": "exploitable_cve",
    "default-login": "default_creds",
}


@dataclass
class ParsedNuclei:
    template_id: str
    name: str
    severity: str                 # critical|high|medium|low|info|unknown
    host_ip: str
    port: int | None = None
    url: str | None = None
    cves: list[str] = field(default_factory=list)
    cvss: float | None = None
    tags: list[str] = field(default_factory=list)
    extracted: list[str] = field(default_factory=list)

    @property
    def is_credential(self) -> bool:
        return bool(self.extracted) and bool(set(self.tags) & _CRED_TAGS)

    @property
    def promote_tag(self) -> str | None:
        if self.cves:
            return "exploitable_cve"
        for t in self.tags:
            if t in _PROMOTE_TAGS:
                return _PROMOTE_TAGS[t]
        return None


def _host_port(url: str | None) -> tuple[str, int | None]:
    if not url:
        return "", None
    try:
        u = urlparse(url if "://" in url else "//" + url)
    except ValueError:
        return "", None
    host = u.hostname or ""
    port = u.port
    if port is None and u.scheme:
        port = 443 if u.scheme == "https" else 80
    return host, port


def parse_nuclei(text: str) -> list[ParsedNuclei]:
    """Parse nuclei -jsonl output (one JSON object per line). Malformed lines are
    skipped, not guessed at."""
    out: list[ParsedNuclei] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line[0] != "{":
            continue
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = d.get("info") or {}
        cls = info.get("classification") or {}
        cves = cls.get("cve-id") or cls.get("cve_id") or []
        if isinstance(cves, str):
            cves = [cves]
        cvss = cls.get("cvss-score") or cls.get("cvss_score")
        matched = d.get("matched-at") or d.get("matched_at") or d.get("host") or ""
        host, port = _host_port(matched)
        extracted = d.get("extracted-results") or d.get("extracted_results") or []
        if isinstance(extracted, str):
            extracted = [extracted]
        tid = d.get("template-id") or d.get("templateID") or d.get("template_id") or "nuclei"
        out.append(ParsedNuclei(
            template_id=tid,
            name=info.get("name") or tid,
            severity=(info.get("severity") or "unknown").lower(),
            host_ip=host, port=port, url=matched or None,
            cves=[c for c in cves if c],
            cvss=float(cvss) if isinstance(cvss, (int, float)) else None,
            tags=[t.lower() for t in (info.get("tags") or []) if isinstance(t, str)],
            extracted=[str(e) for e in extracted][:20],
        ))
    return out
