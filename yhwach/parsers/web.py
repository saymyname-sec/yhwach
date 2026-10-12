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
    # I23 — split specific API shapes out of the generic 'api' kind (before it).
    (re.compile(r"/graphql\b|/graphiql\b", re.I), "graphql"),
    (re.compile(r"(swagger|openapi|api-docs|/v2/api-docs|\.wadl)", re.I), "api_spec"),
    (re.compile(r"(actuator|phpinfo|server-status|/debug\b|/trace\b|stacktrace|_profiler)",
                re.I), "debug_page"),
    (re.compile(r"(api|v1|v2|rest|\.json)", re.I), "api"),
    (re.compile(r"(config|\.env|settings|web\.config|\.htaccess|credentials)", re.I), "config"),
]

# Paths worth auto-flagging as interesting regardless of status.
_INTERESTING_KINDS = {"source", "backup", "login", "upload", "admin", "api", "config",
                      "graphql", "api_spec", "debug_page"}

# I23 — parameter-name sets for param-driven chaining tags (independent of kind:
# a path can be an 'api' AND an idor_candidate AND carry a redirect param).
_IDOR_PARAMS = {"id", "uid", "user_id", "userid", "account", "acct", "number", "no",
                "order", "orderid", "invoice", "doc", "docid", "file", "fileid",
                "pid", "record", "rid", "cid", "key"}
_REDIRECT_PARAMS = {"redirect", "redirect_uri", "redirecturl", "redir", "url", "next",
                    "return", "returnurl", "dest", "destination", "callback", "continue",
                    "goto", "to", "rurl"}


def chaining_tags(path: str) -> list[str]:
    """Parameter-driven chaining tags for a path+query: 'idor_candidate' (an
    id-like or numeric parameter / numeric path segment) and 'redirect_param'
    (an open-redirect/SSRF-shaped parameter name)."""
    tags: list[str] = []
    base, _, query = path.partition("?")
    pnames: dict[str, str] = {}
    for kv in query.split("&"):
        if not kv:
            continue
        name, _, val = kv.partition("=")
        if name:
            pnames[name.lower()] = val
    if set(pnames) & _REDIRECT_PARAMS:
        tags.append("redirect_param")
    numeric_val = any(v.isdigit() for v in pnames.values())
    numeric_seg = any(seg.isdigit() for seg in base.split("/") if seg)
    if (set(pnames) & _IDOR_PARAMS) or numeric_val or numeric_seg:
        tags.append("idor_candidate")
    return tags


@dataclass
class ParsedWebPath:
    path: str
    status: int | None = None
    length: int | None = None
    redirect: str | None = None
    method: str = "GET"

    @property
    def params(self) -> str | None:
        """Query parameter names on this path — the injection surface.

        `web_path.params` is documented as exactly that in the schema and was
        structurally unwritable: the dataclass had no such field, so nothing
        could pass one. _norm_path already preserves the query string.
        """
        if "?" not in self.path:
            return None
        names = [kv.split("=", 1)[0] for kv in self.path.split("?", 1)[1].split("&") if kv]
        return ",".join(dict.fromkeys(n for n in names if n)) or None

    @property
    def auth_required(self) -> bool:
        """401/403 — "there is something here, and it is gated"."""
        return self.status in (401, 403)

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
