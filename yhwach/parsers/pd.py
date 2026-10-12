"""ProjectDiscovery (httpx, subfinder) JSONL and bbot NDJSON -> external assets.

Produces subdomain (domain) rows and, for a non-CDN host that resolves in scope,
a web_app row. Two corrections honoured by the ingest caller: never create a host
row for a CDN IP (it is not the client's box), and never trigger a spray hook from
a domain-keyed ingest.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from urllib.parse import urlparse


@dataclass
class DiscoveredAsset:
    name: str                       # the subdomain / hostname
    url: str | None = None          # a live URL, when the tool probed one
    ip: str | None = None           # resolved A record, when known
    status: int | None = None
    title: str | None = None
    server: str | None = None
    tech: list[str] = field(default_factory=list)
    cdn: bool = False               # behind a CDN/WAF -> the IP is NOT the client's host
    cdn_name: str | None = None
    source: str = "pd"


def _host_of(url: str) -> str:
    try:
        return urlparse(url if "://" in url else "//" + url).hostname or ""
    except ValueError:
        return ""


def _lines(text: str):
    for raw in text.splitlines():
        line = raw.strip()
        if line and line[0] == "{":
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def parse_subfinder(text: str) -> list[DiscoveredAsset]:
    """subfinder -oJ: {"host": "api.acme.com", "source": "crtsh"}."""
    out: list[DiscoveredAsset] = []
    for d in _lines(text):
        name = d.get("host") or d.get("input") or ""
        if name:
            out.append(DiscoveredAsset(name=name.lower(), source="subfinder"))
    return out


def parse_httpx(text: str) -> list[DiscoveredAsset]:
    """httpx -json: url, host, status-code, title, webserver, tech, a[], cdn."""
    out: list[DiscoveredAsset] = []
    for d in _lines(text):
        url = d.get("url") or ""
        name = (d.get("input") or d.get("host") or _host_of(url) or "").lower()
        if not name:
            continue
        ips = d.get("a") or []
        out.append(DiscoveredAsset(
            name=name, url=url or None,
            ip=(ips[0] if isinstance(ips, list) and ips else None),
            status=d.get("status_code") or d.get("status-code"),
            title=d.get("title") or None,
            server=d.get("webserver") or d.get("webserver_name") or None,
            tech=[t for t in (d.get("tech") or d.get("technologies") or []) if isinstance(t, str)],
            cdn=bool(d.get("cdn")),
            cdn_name=d.get("cdn_name") or d.get("cdn-name"),
            source="httpx",
        ))
    return out


def parse_bbot(text: str) -> list[DiscoveredAsset]:
    """bbot NDJSON events: DNS_NAME -> subdomain, URL -> web asset. A 'cdn-*' tag
    marks a CDN-fronted asset."""
    out: list[DiscoveredAsset] = []
    for d in _lines(text):
        etype = d.get("type")
        data = d.get("data")
        if not isinstance(data, str):
            # URL events sometimes carry a dict; take its 'url'.
            data = (data or {}).get("url") if isinstance(data, dict) else None
        if not data:
            continue
        tags = [t.lower() for t in (d.get("tags") or []) if isinstance(t, str)]
        cdn = any(t.startswith("cdn-") or t == "cdn" for t in tags)
        if etype == "DNS_NAME":
            out.append(DiscoveredAsset(name=data.lower(), cdn=cdn, source="bbot"))
        elif etype == "URL":
            name = _host_of(data).lower()
            if name:
                out.append(DiscoveredAsset(name=name, url=data, cdn=cdn, source="bbot"))
    return out
