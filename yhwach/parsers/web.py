"""Web content-discovery output -> web_path rows.

Parses the common shapes of gobuster / ffuf / feroxbuster / dirb into a normalized
`ParsedWebPath` list. The ingest handler binds them to a `web_app` (base URL) and
inserts them via db.add_web_path. Path *kind* is classified by keyword so the
ranker/operator can jump straight to the login/upload/admin/api/backup surfaces.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

# path keyword -> semantic kind. First match wins (order matters: specific first).
_KIND_RULES: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\.(git|svn|hg)(/|$)", re.I), "source"),
    (re.compile(r"(backup|\.bak|\.old|\.zip|\.tar|\.tgz|\.sql|dump)", re.I), "backup"),
    (re.compile(r"(login|signin|auth|sso|oauth)", re.I), "login"),
    (re.compile(r"(upload|import|fileupload)", re.I), "upload"),
    (re.compile(r"(admin|manage|console|dashboard|wp-admin|phpmyadmin)", re.I), "admin"),
    (re.compile(r"(api|graphql|v1|v2|rest|swagger|openapi|\.json)", re.I), "api"),
    (re.compile(r"(config|\.env|settings|web\.config|\.htaccess|credentials)", re.I), "config"),
]

# Paths worth auto-flagging as interesting regardless of status.
_INTERESTING_KINDS = {"source", "backup", "login", "upload", "admin", "api", "config"}


@dataclass
class ParsedWebPath:
    path: str
    status: int | None = None
    length: int | None = None
    redirect: str | None = None
    method: str = "GET"

    @property
    def kind(self) -> str | None:
        for pat, kind in _KIND_RULES:
            if pat.search(self.path):
                return kind
        return "dir" if self.path.endswith("/") else None

    @property
    def interesting(self) -> bool:
        return self.kind in _INTERESTING_KINDS


def _norm_path(raw: str, base_url: str | None) -> str:
    """Reduce a full URL to a path when it matches base_url; else keep as given."""
    raw = raw.strip()
    if raw.startswith(("http://", "https://")):
        sp = urlsplit(raw)
        return sp.path + (("?" + sp.query) if sp.query else "") or "/"
    if not raw.startswith("/"):
        raw = "/" + raw
    return raw


def parse_web(text: str, *, base_url: str | None = None) -> list[ParsedWebPath]:
    """Auto-detect the tool and parse its output into web paths."""
    stripped = text.lstrip()
    # ffuf JSON (-o out.json): {"results": [{"url","status","length",...}]}
    if stripped.startswith("{") and '"results"' in stripped[:2000]:
        try:
            data = json.loads(text)
            return _parse_ffuf_json(data, base_url)
        except (ValueError, TypeError):
            pass
    return _parse_plain(text, base_url)


def _parse_ffuf_json(data: dict, base_url: str | None) -> list[ParsedWebPath]:
    out: list[ParsedWebPath] = []
    for r in data.get("results", []) or []:
        url = r.get("url") or r.get("input", {}).get("FUZZ") or ""
        if not url:
            continue
        out.append(ParsedWebPath(
            path=_norm_path(url, base_url),
            status=_int(r.get("status")),
            length=_int(r.get("length")),
            redirect=r.get("redirectlocation") or None,
        ))
    return _dedupe(out)


# gobuster:     /admin (Status: 301) [Size: 178] [--> /admin/]
_GOBUSTER = re.compile(
    r"^(?P<path>/\S*)\s+\(Status:\s*(?P<status>\d+)\)\s*(?:\[Size:\s*(?P<size>\d+)\])?"
    r"(?:\s*\[--> (?P<redir>[^\]]+)\])?")
# feroxbuster:  200      GET       10l    20w   512c http://host/path  (or  => redirect)
_FEROX = re.compile(
    r"^(?P<status>\d{3})\s+\w+\s+\d+l\s+\d+w\s+(?P<size>\d+)c\s+(?P<url>\S+)"
    r"(?:\s*=>\s*(?P<redir>\S+))?")
# dirb:         + http://host/admin (CODE:301|SIZE:178)   /  ==> DIRECTORY: http://host/x/
_DIRB = re.compile(r"^\+?\s*(?P<url>https?://\S+)\s+\(CODE:(?P<status>\d+)\|SIZE:(?P<size>\d+)\)")
_DIRB_DIR = re.compile(r"==> DIRECTORY:\s*(?P<url>https?://\S+)")


def _parse_plain(text: str, base_url: str | None) -> list[ParsedWebPath]:
    out: list[ParsedWebPath] = []
    for line in text.splitlines():
        line = line.rstrip()
        s = line.strip()
        m = _GOBUSTER.match(s)
        if m:
            out.append(ParsedWebPath(
                path=_norm_path(m.group("path"), base_url),
                status=_int(m.group("status")), length=_int(m.group("size")),
                redirect=(m.group("redir") or "").strip() or None))
            continue
        m = _FEROX.match(s)
        if m:
            out.append(ParsedWebPath(
                path=_norm_path(m.group("url"), base_url),
                status=_int(m.group("status")), length=_int(m.group("size")),
                redirect=(m.group("redir") or "").strip() or None))
            continue
        m = _DIRB.match(s)
        if m:
            out.append(ParsedWebPath(
                path=_norm_path(m.group("url"), base_url),
                status=_int(m.group("status")), length=_int(m.group("size"))))
            continue
        m = _DIRB_DIR.search(s)
        if m:
            out.append(ParsedWebPath(path=_norm_path(m.group("url"), base_url), status=301))
    return _dedupe(out)


def _dedupe(paths: list[ParsedWebPath]) -> list[ParsedWebPath]:
    """Collapse duplicate (path, method), first occurrence wins."""
    seen: dict[tuple[str, str], ParsedWebPath] = {}
    for p in paths:
        seen.setdefault((p.path, p.method), p)
    return list(seen.values())


def _int(v) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None
