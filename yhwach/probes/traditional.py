"""Traditional (non-AI) surface detection.

Two mechanisms, both feeding the same `surface` table + planner as the AI probes:

  * classify_service — deterministic port -> surface kind (smb, ldap, ssh, rdp,
    mssql, winrm, ...). No network call.
  * HTTP app fingerprints — Jenkins, GitLab, generic web portal — a light GET
    that reads identifying headers / body.

So the operator reasons about the foothold (e.g. Jenkins script-console RCE) as
well as the AI surface. Traditional rules carry class:traditional, so the ranker
keeps them below AI hypotheses by doctrine (see planner.top_tasks).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

import requests

from yhwach.probes.ai import DEFAULT_TIMEOUT, _headers_lower


@dataclass
class TradResult:
    kind: str
    auth: str = "unknown"
    meta: dict[str, Any] = field(default_factory=dict)


# Deterministic port -> traditional surface kind. No network needed.
PORT_KIND: dict[int, str] = {
    21: "ftp",
    22: "ssh",
    88: "kerberos",
    139: "smb",
    445: "smb",
    389: "ldap",
    636: "ldap",
    3268: "ldap",
    1433: "mssql",
    3306: "mysql",
    5432: "postgres",
    3389: "rdp",
    5985: "winrm",
    5986: "winrm",
    # Message brokers — in an AI environment these often carry agent (A2A) traffic.
    1883: "mqtt",
    8883: "mqtt",
    5672: "amqp",
    8161: "activemq",       # ActiveMQ web console / Jolokia
    61616: "activemq_openwire",
    9092: "kafka",
    8200: "vault",
    6443: "kubernetes",     # K8s API server (default HTTPS)
    10250: "kubelet",       # Kubelet API
}

# Ports worth an HTTP fingerprint when not matched by PORT_KIND.
WEB_PORTS = {80, 443, 3000, 5000, 8000, 8080, 8081, 8443, 8888, 9000}


def classify_service(product: str | None, port: int) -> str | None:
    """Map a well-known port to a traditional surface kind (deterministic)."""
    return PORT_KIND.get(port)


def _extract_title(html: str | None) -> str | None:
    m = re.search(r"<title>(.*?)</title>", html or "", re.IGNORECASE | re.DOTALL)
    return m.group(1).strip()[:80] if m else None


def probe_jenkins(session, host, port, *, timeout=DEFAULT_TIMEOUT) -> TradResult | None:
    for scheme in ("http", "https"):
        try:
            r = session.get(f"{scheme}://{host}:{port}/", timeout=timeout)
        except requests.RequestException:
            continue
        h = _headers_lower(r)
        if "x-jenkins" in h or "x-hudson" in h:
            return TradResult(
                kind="jenkins",
                auth="unknown",
                meta={"version": h.get("x-jenkins"), "scheme": scheme},
            )
    return None


def probe_gitlab(session, host, port, *, timeout=DEFAULT_TIMEOUT) -> TradResult | None:
    for scheme in ("http", "https"):
        try:
            r = session.get(f"{scheme}://{host}:{port}/", timeout=timeout)
        except requests.RequestException:
            continue
        h = _headers_lower(r)
        body = (getattr(r, "text", "") or "")[:2000].lower()
        if "x-gitlab-feature-category" in h or "gitlab" in body:
            return TradResult(kind="gitlab", meta={"scheme": scheme})
    return None


# Signals that a page is a document-intake form (resume/CV/application upload).
# In an OSAI context with AI-powered internal tooling, such a form is a candidate
# indirect prompt-injection vector: a poisoned document reaches an AI screener.
_DOC_INTAKE_SIGNALS = (
    'type="file"', "multipart/form-data", "careers", "apply now", "open roles",
    "upload your", "resume", "cv upload", "application form", "job application",
)


def probe_web_app(session, host, port, *, timeout=DEFAULT_TIMEOUT) -> TradResult | None:
    """Generic web app, with document-intake detection promoted to its own kind."""
    for scheme in ("http", "https"):
        try:
            r = session.get(f"{scheme}://{host}:{port}/", timeout=timeout)
        except requests.RequestException:
            continue
        if r.status_code == 404 or r.status_code >= 500:
            continue
        if "html" not in _headers_lower(r).get("content-type", ""):
            continue
        body = getattr(r, "text", "") or ""
        title = _extract_title(body)
        low = body.lower()
        if any(sig in low for sig in _DOC_INTAKE_SIGNALS):
            return TradResult(
                kind="web_upload",
                meta={"scheme": scheme, "title": title,
                      "hint": "document-intake form — candidate indirect-injection "
                              "vector if submissions are AI-screened"},
            )
        return TradResult(kind="web", meta={"scheme": scheme, "title": title})
    return None


# Specific fingerprints first, generic web last.
WEB_FINGERPRINTS = [probe_jenkins, probe_gitlab, probe_web_app]


def detect_traditional(
    session,
    host: str,
    port: int,
    product: str | None = None,
    *,
    timeout: float = DEFAULT_TIMEOUT,
) -> TradResult | None:
    """Deterministic port match first; HTTP fingerprint for web ports otherwise."""
    kind = classify_service(product, port)
    if kind:
        return TradResult(kind=kind, meta={"product": product})
    if port in WEB_PORTS:
        for fp in WEB_FINGERPRINTS:
            res = fp(session, host, port, timeout=timeout)
            if res is not None:
                return res
    return None
