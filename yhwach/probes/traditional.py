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
    6443: "apiserver",      # K8s API server (renamed from "kubernetes": a rule keys on
                            # `surface: apiserver`, and detect_traditional returns on the
                            # first PORT_KIND hit — so this port lives in PORT_KIND, never
                            # the HTTP-fingerprint path. No shipped rule consumed "kubernetes".)
    10250: "kubelet",       # Kubelet API
    10255: "kubelet_ro",    # Kubelet read-only API
    # Data stores — wire protocols / distinctive default ports. Unauth recon (a
    # rule's own action) records the version banner; there is no HTTP fingerprint,
    # so these belong in PORT_KIND, not WEB_PORTS.
    6379: "redis",
    6380: "redis",
    26379: "redis_sentinel",
    11211: "memcached",
    27017: "mongodb",
    27018: "mongodb",
    27019: "mongodb",
    9200: "elasticsearch",
    9300: "elasticsearch",
    5601: "kibana",
    15672: "rabbitmq",      # management API/UI
    2181: "zookeeper",
    # Cloud-native control plane.
    2379: "etcd",
    2380: "etcd",
    2375: "docker_api",
    2376: "docker_api",
    8500: "consul",
    8300: "consul",
    # I43 — the classic network services every internal engagement meets. Read-only
    # triage lives in playbooks/network-services.yaml; the dangerous moves
    # (open-relay test, printer login, NFS mount, IPMI hash dump) are gated there.
    23: "telnet",
    25: "smtp",
    465: "smtp",
    587: "smtp",
    110: "pop3",
    995: "pop3",
    143: "imap",
    993: "imap",
    53: "dns",
    111: "rpcbind",         # NFS/portmapper
    2049: "nfs",
    135: "msrpc",           # endpoint mapper
    515: "printer",         # LPD
    631: "printer",         # IPP/CUPS
    9100: "printer",        # raw / JetDirect
    5900: "vnc",
    5901: "vnc",
    5902: "vnc",
    5903: "vnc",
    902: "esxi",            # VMware host agent
}

# UDP port -> surface kind. The classifier is now protocol-aware, so a UDP
# service is never mistaken for a TCP one on the same port number (SNMP vs an
# unrelated TCP 161, DNS 53/udp vs 53/tcp).
UDP_PORT_KIND: dict[int, str] = {
    161: "snmp",
    162: "snmp",
    623: "ipmi",
    69: "tftp",
    137: "netbios",
    500: "ike",
}

# Ports worth an HTTP fingerprint when not matched by PORT_KIND.
WEB_PORTS = {80, 443, 3000, 5000, 8000, 8080, 8081, 8443, 8888, 9000,
             8088, 8090, 8111, 9001}  # +superset/confluence/teamcity/minio-console

# Substring of an nmap -sV `product` string -> surface kind. Consulted only when
# the port misses PORT_KIND, so a datastore/service on a NON-STANDARD port is
# still classified (the single biggest "check every path" gap: classify_service
# used to drop `product` entirely and return PORT_KIND.get(port) alone).
_PRODUCT_KIND: dict[str, str] = {
    "redis": "redis",
    "memcached": "memcached",
    "mongodb": "mongodb",
    "mongo": "mongodb",
    "elasticsearch": "elasticsearch",
    "kibana": "kibana",
    "postgresql": "postgres",
    "mariadb": "mysql",
    "mysql": "mysql",
    "microsoft sql server": "mssql",
    "kafka": "kafka",
    "rabbitmq": "rabbitmq",
    "zookeeper": "zookeeper",
    "consul": "consul",
    "etcd": "etcd",
    "docker": "docker_api",
    "memcache": "memcached",
    # I43 — classic network services by nmap -sV product, for non-standard ports.
    "telnet": "telnet",
    "vnc": "vnc",
    "postfix": "smtp",
    "exim": "smtp",
    "sendmail": "smtp",
    "smtpd": "smtp",
    "dovecot": "imap",
    "courier": "imap",
    "bind": "dns",
    "dnsmasq": "dns",
    "rpcbind": "rpcbind",
    "portmapper": "rpcbind",
    "nfs": "nfs",
    "msrpc": "msrpc",
    "snmp": "snmp",
    "ipmi": "ipmi",
    "vmware esxi": "esxi",
    "vmware authentication": "esxi",
    "cups": "printer",
    "ipp": "printer",
    "jetdirect": "printer",
    "lpd": "printer",
}


def classify_service(product: str | None, port: int, proto: str = "tcp") -> str | None:
    """Map a service to a traditional surface kind (deterministic, no network).

    Protocol-aware: a UDP service is classified from UDP_PORT_KIND (so SNMP on
    161/udp is never confused with something on 161/tcp). Port first (the reliable
    signal); then the nmap `product` string so a known service on a non-standard
    port is still classified.
    """
    table = UDP_PORT_KIND if (proto or "tcp").lower() == "udp" else PORT_KIND
    kind = table.get(port)
    if kind:
        return kind
    if product:
        p = product.lower()
        for needle, mapped in _PRODUCT_KIND.items():
            if needle in p:
                return mapped
    return None


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


def probe_gitea(session, host, port, *, timeout=DEFAULT_TIMEOUT) -> TradResult | None:
    """Gitea, not GitLab: distinct product (different API, different attacks).

    Fingerprinted by the `i_like_gitea` session cookie, the `Gitea` author meta,
    or a `gitea` body reference. Version comes from the unauth /api/v1/version.
    Checked before probe_gitlab so a Gitea instance is never mislabelled GitLab.
    """
    for scheme in ("http", "https"):
        try:
            r = session.get(f"{scheme}://{host}:{port}/", timeout=timeout)
        except requests.RequestException:
            continue
        h = _headers_lower(r)
        body = (getattr(r, "text", "") or "")[:4000].lower()
        cookie = h.get("set-cookie", "").lower()
        if "i_like_gitea" in cookie or "gitea" in body:
            version = None
            try:
                v = session.get(f"{scheme}://{host}:{port}/api/v1/version", timeout=timeout)
                if v.status_code == 200:
                    version = (v.json() or {}).get("version")
            except (requests.RequestException, ValueError):
                pass
            return TradResult(kind="gitea", meta={"scheme": scheme, "version": version})
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
# In an environment with AI-powered internal tooling, such a form is a candidate
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


# Specific fingerprints first, generic web last. Gitea before GitLab so a Gitea
# instance is classified as its own product, not mislabelled a GitLab.
# Data-driven fingerprints for common self-hosted web apps. Each: the surface
# kind, header/body substrings that identify it, and an optional version endpoint.
# A match -> a product surface so web.yaml can key a per-product recon rule on it.
_WEBAPP_SIGS: list[dict] = [
    {"kind": "grafana", "sig": ("grafana",), "ver": "/api/health", "ver_key": "version"},
    {"kind": "keycloak", "sig": ("keycloak",), "ver": None, "ver_key": None},
    {"kind": "minio", "sig": ("minio",), "ver": None, "ver_key": None},
    {"kind": "confluence", "sig": ("x-confluence", "confluence"), "ver": None, "ver_key": None},
    {"kind": "teamcity", "sig": ("teamcity",), "ver": None, "ver_key": None},
    {"kind": "nexus", "sig": ("x-nexus", "nexus repository"), "ver": None, "ver_key": None},
    {"kind": "sonarqube", "sig": ("sonarqube",), "ver": "/api/server/version", "ver_key": None},
    {"kind": "superset", "sig": ("superset",), "ver": None, "ver_key": None},
    {"kind": "metabase", "sig": ("metabase",), "ver": None, "ver_key": None},
    {"kind": "jupyterhub", "sig": ("jupyterhub",), "ver": None, "ver_key": None},
    {"kind": "nextcloud", "sig": ("x-nextcloud", "nextcloud"), "ver": None, "ver_key": None},
    {"kind": "artifactory", "sig": ("x-jfrog", "artifactory"), "ver": None, "ver_key": None},
    {"kind": "jira", "sig": ("x-arequestid", "atlassian jira"), "ver": None, "ver_key": None},
]


def _fetch_version(session, scheme, host, port, entry, timeout) -> str | None:
    ep = entry.get("ver")
    if not ep:
        return None
    try:
        r = session.get(f"{scheme}://{host}:{port}{ep}", timeout=timeout)
        if r.status_code != 200:
            return None
        if entry.get("ver_key"):
            data = r.json()
            return data.get(entry["ver_key"]) if isinstance(data, dict) else None
        return ((getattr(r, "text", "") or "").strip()[:40]) or None
    except (requests.RequestException, ValueError):
        return None


def probe_webapp_products(session, host, port, *, timeout=DEFAULT_TIMEOUT) -> TradResult | None:
    """Fingerprint a self-hosted web app (grafana/keycloak/minio/...) by its
    header/body markers -> a product surface. Returns None if the page responds
    but matches nothing (the generic probe_web_app then handles it)."""
    for scheme in ("http", "https"):
        try:
            r = session.get(f"{scheme}://{host}:{port}/", timeout=timeout)
        except requests.RequestException:
            continue
        h = _headers_lower(r)
        hay = " ".join(h.keys()) + " " + " ".join(h.values()) + " " \
            + (getattr(r, "text", "") or "")[:4000].lower()
        for e in _WEBAPP_SIGS:
            if any(s in hay for s in e["sig"]):
                return TradResult(
                    kind=e["kind"],
                    meta={"scheme": scheme,
                          "version": _fetch_version(session, scheme, host, port, e, timeout)})
        return None
    return None


# Specific product fingerprints (jenkins/gitea/gitlab, then the webapp table),
# generic web last so an unrecognised page still becomes a `web` surface.
WEB_FINGERPRINTS = [probe_jenkins, probe_gitea, probe_gitlab, probe_webapp_products, probe_web_app]


def detect_traditional(
    session,
    host: str,
    port: int,
    product: str | None = None,
    *,
    proto: str = "tcp",
    timeout: float = DEFAULT_TIMEOUT,
) -> TradResult | None:
    """Deterministic port match first; HTTP fingerprint for web ports otherwise."""
    kind = classify_service(product, port, proto)
    if kind:
        return TradResult(kind=kind, meta={"product": product})
    if port in WEB_PORTS:
        for fp in WEB_FINGERPRINTS:
            res = fp(session, host, port, timeout=timeout)
            if res is not None:
                return res
    return None
