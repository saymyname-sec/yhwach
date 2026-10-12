"""Burp "Save items" XML and HAR -> web_path METADATA only (I49).

Captured proxy traffic is a map of the app's routes: method, path, parameter
NAMES, auth requirement, status. yhwach records exactly that and NOTHING of the
bodies — it must never become a second plaintext token store. Request/response
bodies are stored only when an operator binds one to a finding (via
yhwach_add_evidence), not here.
"""
from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass, field
from urllib.parse import parse_qs, urlparse
from xml.etree import ElementTree as ET

_AUTH_HEADERS = ("authorization", "cookie", "x-api-key", "x-auth-token")


@dataclass
class RequestMeta:
    method: str
    host: str                       # hostname or IP from the URL
    port: int | None
    scheme: str
    path: str                       # path only (query stripped off into params)
    ip: str | None = None           # resolved IP when the capture carried one
    status: int | None = None
    params: list[str] = field(default_factory=list)  # NAMES only, never values
    auth_required: bool = False

    @property
    def base_url(self) -> str:
        p = f":{self.port}" if self.port and self.port not in (80, 443) else ""
        return f"{self.scheme}://{self.host}{p}"


def _param_names(query: str, body: str | None, content_type: str | None) -> list[str]:
    names: list[str] = []
    for src in (query, body if (content_type and "x-www-form-urlencoded" in content_type) else None):
        if not src:
            continue
        for k in parse_qs(src, keep_blank_values=True):
            if k and k not in names:
                names.append(k)
    return names


def _split_request(raw: str) -> tuple[dict, str | None]:
    """Return (lower-cased headers, body) from a raw HTTP request string."""
    head, _, body = raw.replace("\r\n", "\n").partition("\n\n")
    headers: dict[str, str] = {}
    for line in head.split("\n")[1:]:
        if ":" in line:
            k, _, v = line.partition(":")
            headers[k.strip().lower()] = v.strip()
    return headers, (body or None)


def parse_burp(text: str) -> list[RequestMeta]:
    """Burp Suite 'Save items' XML. Each <item> carries the resolved host ip."""
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return []
    out: list[RequestMeta] = []
    for item in root.iter("item"):
        url = (item.findtext("url") or "").strip()
        if not url:
            continue
        u = urlparse(url)
        host_el = item.find("host")
        ip = host_el.get("ip") if host_el is not None else None
        req = item.findtext("request") or ""
        if (item.find("request") is not None
                and (item.find("request").get("base64") or "").lower() == "true"):
            try:
                req = base64.b64decode(req).decode("utf-8", "replace")
            except (binascii.Error, ValueError):
                req = ""
        headers, body = _split_request(req) if req else ({}, None)
        status = item.findtext("status")
        out.append(RequestMeta(
            method=(item.findtext("method") or "GET").upper(),
            host=u.hostname or (host_el.text if host_el is not None else "") or "",
            port=u.port or (int(item.findtext("port")) if (item.findtext("port") or "").isdigit() else None),
            scheme=u.scheme or "http", path=u.path or "/", ip=ip,
            status=int(status) if status and status.isdigit() else None,
            params=_param_names(u.query, body, headers.get("content-type")),
            auth_required=any(h in headers for h in _AUTH_HEADERS),
        ))
    return out


def parse_har(text: str) -> list[RequestMeta]:
    """HAR 1.2 (browser/Burp/ZAP export)."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    out: list[RequestMeta] = []
    for ent in (data.get("log", {}) or {}).get("entries", []) or []:
        req = ent.get("request") or {}
        url = req.get("url") or ""
        if not url:
            continue
        u = urlparse(url)
        headers = {h.get("name", "").lower(): h.get("value", "")
                   for h in (req.get("headers") or [])}
        post = req.get("postData") or {}
        body_names = [p.get("name") for p in (post.get("params") or []) if p.get("name")]
        names = _param_names(u.query, None, None)
        for n in body_names:
            if n not in names:
                names.append(n)
        resp = ent.get("response") or {}
        out.append(RequestMeta(
            method=(req.get("method") or "GET").upper(),
            host=u.hostname or "", port=u.port,
            scheme=u.scheme or "http", path=u.path or "/",
            ip=ent.get("serverIPAddress") or None,
            status=resp.get("status") or None,
            params=names,
            auth_required=any(h in headers for h in _AUTH_HEADERS),
        ))
    return out
