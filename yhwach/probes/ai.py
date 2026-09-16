"""HTTP probes for AI attack surfaces.

Each probe:
  * accepts a session (real `requests.Session` in prod, fake in tests)
  * has a short default timeout — never stalls the engagement
  * returns ProbeResult(kind, auth, meta) or None
  * never raises on network / JSON errors

Design rule: probes MUST be idempotent and side-effect free. All they do is
observe. Populating the world model happens in the caller.
"""
from __future__ import annotations

import warnings
from dataclasses import dataclass, field
from typing import Any, Callable

import requests
from urllib3.exceptions import InsecureRequestWarning

# Labs and self-hosted LLM servers ship self-signed certs constantly. Yhwach
# talks to authorized targets only, so we accept the risk and silence urllib3.
warnings.simplefilter("ignore", InsecureRequestWarning)

DEFAULT_TIMEOUT = 3.0
USER_AGENT = "Yhwach/0.0.1 (authorized-lab-testing)"


@dataclass
class ProbeResult:
    """One AI-surface detection outcome."""

    kind: str
    auth: str = "unknown"
    meta: dict[str, Any] = field(default_factory=dict)


def new_session() -> requests.Session:
    """A session with sane defaults for probing AI endpoints in a lab."""
    s = requests.Session()
    s.headers.update({"User-Agent": USER_AGENT})
    s.verify = False
    return s


# ---------------------------------------------------------------------------
# Individual probes
# ---------------------------------------------------------------------------

def probe_ollama(
    session: requests.Session,
    host: str,
    port: int,
    *,
    timeout: float = DEFAULT_TIMEOUT,
) -> ProbeResult | None:
    """Detect Ollama by GET /api/tags returning a JSON `models` list."""
    try:
        r = session.get(f"http://{host}:{port}/api/tags", timeout=timeout)
    except requests.RequestException:
        return None
    if r.status_code != 200:
        return None
    try:
        data = r.json()
    except ValueError:
        return None
    if not isinstance(data, dict) or "models" not in data:
        return None
    models = [m.get("name") for m in data.get("models", []) if isinstance(m, dict)]
    return ProbeResult(
        kind="ollama",
        auth="none",
        meta={"endpoint": "/api/tags", "models": models},
    )


def probe_openai_compat(
    session: requests.Session,
    host: str,
    port: int,
    *,
    timeout: float = DEFAULT_TIMEOUT,
) -> ProbeResult | None:
    """Detect OpenAI-compatible API at /v1/models. Tries http then https."""
    for scheme in ("http", "https"):
        try:
            r = session.get(f"{scheme}://{host}:{port}/v1/models", timeout=timeout)
        except requests.RequestException:
            continue
        if r.status_code in (401, 403):
            return ProbeResult(
                kind="openai_compat",
                auth="bearer",
                meta={"endpoint": "/v1/models", "scheme": scheme},
            )
        if r.status_code != 200:
            continue
        try:
            data = r.json()
        except ValueError:
            continue
        if not isinstance(data, dict) or "data" not in data:
            continue
        models = [m.get("id") for m in data.get("data", []) if isinstance(m, dict)]
        return ProbeResult(
            kind="openai_compat",
            auth="none",
            meta={"endpoint": "/v1/models", "scheme": scheme, "models": models},
        )
    return None


_CHATBOT_PATHS = ("/api/chat", "/chat", "/api/completion", "/api/message")

# Reply-shaped keys that mark a JSON body as an actual chat/LLM response.
_CHAT_REPLY_KEYS = ("response", "reply", "message", "content", "answer", "choices", "output")

# Header fingerprints of known NON-AI web apps. A hit here means "not a chatbot",
# no matter how the app answers a POST to /api/chat (Jenkins 403s on CSRF crumb).
_NON_AI_APP_HEADERS = ("x-jenkins", "x-hudson", "x-drupal-dynamic-cache", "x-gitlab-feature-category")

# Substrings that, in a 401/403 body or WWW-Authenticate header, hint the gated
# endpoint really is an LLM/chat API rather than generic framework auth/CSRF.
_LLM_AUTH_HINTS = ("chat", "llm", "openai", "completion", "assistant", "gpt", "model")


def _headers_lower(resp) -> dict:
    try:
        return {k.lower(): str(v) for k, v in resp.headers.items()}
    except Exception:
        return {}


def _looks_like_chat_json(data) -> bool:
    return isinstance(data, dict) and any(k in data for k in _CHAT_REPLY_KEYS)


def _is_known_non_ai_app(resp) -> bool:
    return any(h in _headers_lower(resp) for h in _NON_AI_APP_HEADERS)


def probe_chatbot(
    session: requests.Session,
    host: str,
    port: int,
    *,
    timeout: float = DEFAULT_TIMEOUT,
) -> ProbeResult | None:
    """Detect a chatbot by POSITIVE evidence, not merely a non-404.

    A 403/401 alone is not a chatbot — frameworks (Jenkins CSRF, generic auth)
    return those for unknown POST paths. We require either a 200 JSON body with a
    reply-shaped key, or an auth-gated response that actually hints at an LLM API.
    Known non-AI apps (Jenkins, GitLab, Drupal) are fingerprinted and rejected.
    """
    for scheme in ("http", "https"):
        # Fingerprint the root once per scheme; bail on a known non-AI app.
        try:
            root = session.get(f"{scheme}://{host}:{port}/", timeout=timeout)
            if _is_known_non_ai_app(root):
                return None
        except requests.RequestException:
            pass  # can't fingerprint; proceed cautiously with positive-evidence only

        for path in _CHATBOT_PATHS:
            try:
                r = session.post(
                    f"{scheme}://{host}:{port}{path}",
                    json={"message": "ping"},
                    timeout=timeout,
                )
            except requests.RequestException:
                continue

            if r.status_code == 200:
                try:
                    data = r.json()
                except ValueError:
                    data = None
                if _looks_like_chat_json(data):
                    return ProbeResult(
                        kind="chatbot",
                        auth="none",
                        meta={"endpoint": path, "scheme": scheme, "http_status": 200},
                    )
                continue  # 200 but not a chat body — not enough evidence

            if r.status_code in (401, 403):
                blob = (_headers_lower(r).get("www-authenticate", "") + " "
                        + (getattr(r, "text", "") or "")[:300]).lower()
                if any(hint in blob for hint in _LLM_AUTH_HINTS):
                    return ProbeResult(
                        kind="chatbot",
                        auth="bearer",
                        meta={"endpoint": path, "scheme": scheme, "http_status": r.status_code},
                    )
                continue  # generic auth/CSRF — not a chatbot

    return None


def probe_mcp(
    session: requests.Session,
    host: str,
    port: int,
    *,
    timeout: float = DEFAULT_TIMEOUT,
) -> ProbeResult | None:
    """Probe MCP via JSON-RPC tools/list on /mcp."""
    payload = {"jsonrpc": "2.0", "method": "tools/list", "id": 1}
    for path in ("/mcp", "/api/mcp"):
        try:
            r = session.post(f"http://{host}:{port}{path}", json=payload, timeout=timeout)
        except requests.RequestException:
            continue
        if r.status_code != 200:
            continue
        try:
            data = r.json()
        except ValueError:
            continue
        if (
            not isinstance(data, dict)
            or data.get("jsonrpc") != "2.0"
            or "result" not in data
        ):
            continue
        tools = [
            t.get("name")
            for t in data.get("result", {}).get("tools", [])
            if isinstance(t, dict)
        ]
        return ProbeResult(
            kind="mcp",
            auth="none",
            meta={"endpoint": path, "tools": tools},
        )
    return None


def probe_gradio(
    session: requests.Session,
    host: str,
    port: int,
    *,
    timeout: float = DEFAULT_TIMEOUT,
) -> ProbeResult | None:
    """Gradio serves /config as JSON with 'components' or 'version' keys."""
    try:
        r = session.get(f"http://{host}:{port}/config", timeout=timeout)
    except requests.RequestException:
        return None
    if r.status_code != 200:
        return None
    try:
        data = r.json()
    except ValueError:
        return None
    if not isinstance(data, dict):
        return None
    if not any(k in data for k in ("components", "version", "gradio_version")):
        return None
    return ProbeResult(
        kind="gradio",
        auth="none",
        meta={
            "endpoint": "/config",
            "version": data.get("version") or data.get("gradio_version"),
        },
    )


def probe_a2a(
    session: requests.Session,
    host: str,
    port: int,
    *,
    timeout: float = DEFAULT_TIMEOUT,
) -> ProbeResult | None:
    """Detect an A2A agent by its published agent card (/.well-known/agent.json)."""
    for scheme in ("http", "https"):
        for path in ("/.well-known/agent.json", "/.well-known/agent-card.json", "/agent.json"):
            try:
                r = session.get(f"{scheme}://{host}:{port}{path}", timeout=timeout)
            except requests.RequestException:
                continue
            if r.status_code != 200:
                continue
            try:
                data = r.json()
            except ValueError:
                continue
            # Agent cards carry a name plus skills/capabilities (distinctive of A2A).
            if isinstance(data, dict) and ("skills" in data or "capabilities" in data):
                return ProbeResult(
                    kind="a2a",
                    auth="none",
                    meta={"endpoint": path, "scheme": scheme, "name": data.get("name")},
                )
    return None


def probe_openapi(
    session: requests.Session,
    host: str,
    port: int,
    *,
    timeout: float = DEFAULT_TIMEOUT,
) -> ProbeResult | None:
    """Detect an OpenAPI/Swagger spec — reveals all endpoints and auth requirements."""
    spec_paths = (
        "/openapi.json", "/swagger.json", "/api-docs",
        "/v1/openapi.json", "/api/openapi.json",
    )
    for scheme in ("http", "https"):
        for path in spec_paths:
            try:
                r = session.get(f"{scheme}://{host}:{port}{path}", timeout=timeout)
            except requests.RequestException:
                continue
            if r.status_code != 200:
                continue
            try:
                data = r.json()
            except ValueError:
                continue
            if not isinstance(data, dict):
                continue
            if any(k in data for k in ("openapi", "swagger", "paths", "info")):
                paths = list(data.get("paths", {}).keys())[:20]
                return ProbeResult(
                    kind="openapi",
                    auth="none",
                    meta={
                        "endpoint": path, "scheme": scheme,
                        "version": data.get("openapi") or data.get("swagger"),
                        "title": (data.get("info") or {}).get("title"),
                        "paths": paths,
                    },
                )
    return None


def probe_vault(
    session: requests.Session,
    host: str,
    port: int,
    *,
    timeout: float = DEFAULT_TIMEOUT,
) -> ProbeResult | None:
    """Detect HashiCorp Vault by its /v1/sys/health endpoint."""
    for scheme in ("http", "https"):
        try:
            r = session.get(f"{scheme}://{host}:{port}/v1/sys/health", timeout=timeout)
        except requests.RequestException:
            continue
        if r.status_code not in (200, 429, 472, 473, 501, 503):
            continue
        try:
            data = r.json()
        except ValueError:
            continue
        if isinstance(data, dict) and "sealed" in data:
            return ProbeResult(
                kind="vault",
                auth="token",
                meta={
                    "endpoint": "/v1/sys/health", "scheme": scheme,
                    "version": data.get("version"),
                    "sealed": data.get("sealed"),
                    "initialized": data.get("initialized"),
                },
            )
    return None


def probe_vectordb(
    session: requests.Session,
    host: str,
    port: int,
    *,
    timeout: float = DEFAULT_TIMEOUT,
) -> ProbeResult | None:
    """Detect an exposed vector DB (Qdrant / Weaviate / Chroma)."""
    # Qdrant: GET /collections -> {"result":{"collections":[...]}}
    try:
        r = session.get(f"http://{host}:{port}/collections", timeout=timeout)
        if r.status_code == 200:
            data = r.json()
            if isinstance(data, dict) and isinstance(data.get("result"), dict) \
                    and "collections" in data["result"]:
                return ProbeResult(kind="vectordb", auth="none",
                                   meta={"engine": "qdrant", "endpoint": "/collections"})
    except (requests.RequestException, ValueError):
        pass
    # Weaviate: GET /v1/meta -> {"version": ...}
    try:
        r = session.get(f"http://{host}:{port}/v1/meta", timeout=timeout)
        if r.status_code == 200:
            data = r.json()
            if isinstance(data, dict) and ("version" in data or "hostname" in data):
                return ProbeResult(kind="vectordb", auth="none",
                                   meta={"engine": "weaviate", "endpoint": "/v1/meta",
                                         "version": data.get("version")})
    except (requests.RequestException, ValueError):
        pass
    # Chroma: GET /api/v1/heartbeat -> {"nanosecond heartbeat": ...}
    try:
        r = session.get(f"http://{host}:{port}/api/v1/heartbeat", timeout=timeout)
        if r.status_code == 200 and "heartbeat" in (getattr(r, "text", "") or "").lower():
            return ProbeResult(kind="vectordb", auth="none",
                               meta={"engine": "chroma", "endpoint": "/api/v1/heartbeat"})
    except requests.RequestException:
        pass
    return None


# ---------------------------------------------------------------------------
# Dispatch: port -> probes to try
# ---------------------------------------------------------------------------

ProbeFn = Callable[..., "ProbeResult | None"]

PROBES_BY_PORT: dict[int, list[ProbeFn]] = {
    80:    [probe_openai_compat, probe_chatbot, probe_gradio, probe_a2a, probe_openapi],
    443:   [probe_openai_compat, probe_chatbot, probe_gradio, probe_a2a, probe_openapi],
    6333:  [probe_vectordb],
    8200:  [probe_vault],
    11434: [probe_ollama],
    1234:  [probe_openai_compat, probe_chatbot, probe_openapi],
    3000:  [probe_openai_compat, probe_chatbot, probe_openapi],
    4000:  [probe_openai_compat, probe_chatbot, probe_openapi],
    5000:  [probe_openai_compat, probe_chatbot, probe_mcp, probe_openapi],
    5001:  [probe_openai_compat, probe_chatbot, probe_openapi],
    7860:  [probe_gradio, probe_chatbot],
    8000:  [probe_openai_compat, probe_chatbot, probe_mcp, probe_gradio, probe_a2a, probe_vectordb, probe_openapi],
    8001:  [probe_openai_compat, probe_chatbot, probe_openapi],
    8080:  [probe_openai_compat, probe_chatbot, probe_mcp, probe_a2a, probe_vectordb, probe_openapi],
    8443:  [probe_openai_compat, probe_chatbot, probe_mcp, probe_openapi],
    8888:  [probe_chatbot, probe_mcp],
    9000:  [probe_openai_compat, probe_chatbot, probe_a2a, probe_openapi],
}


def probes_for_port(port: int) -> list[ProbeFn]:
    """Return the ordered probes to try against this port, or []."""
    return PROBES_BY_PORT.get(port, [])


def run_probes(
    session: requests.Session,
    host: str,
    port: int,
    *,
    timeout: float = DEFAULT_TIMEOUT,
) -> ProbeResult | None:
    """Run the port's registered probes; return the first non-None result."""
    for probe in probes_for_port(port):
        result = probe(session, host, port, timeout=timeout)
        if result is not None:
            return result
    return None
