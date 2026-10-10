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

import re
import warnings
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import requests
from urllib3.exceptions import InsecureRequestWarning

# Labs and self-hosted LLM servers ship self-signed certs constantly. Yhwach
# talks to authorized targets only, so we accept the risk and silence urllib3.
warnings.simplefilter("ignore", InsecureRequestWarning)

DEFAULT_TIMEOUT = 3.0

# A probe response is attacker-controlled, and meta_json is stored verbatim and
# later rendered. Cap list length and string length at ingest so a hostile server
# cannot bloat the world model or the board.
_LIST_CAP = 20
_STR_CAP = 400


def _clip(v, cap: int = _STR_CAP) -> str | None:
    """A probe-supplied string, bounded. None stays None."""
    if v is None:
        return None
    s = str(v)
    return s if len(s) <= cap else s[:cap] + "…"


def _schema_params(schema) -> list[str]:
    """Parameter names from a JSON-Schema-ish `inputSchema`.

    A server can return anything here: `properties` may be a list, a string or
    null, and its keys may be non-strings. Sorting those raised and — because
    `run_probes` swallows a probe exception — the MCP surface was then silently
    never recorded at all.
    """
    props = (schema or {}).get("properties") if isinstance(schema, dict) else None
    if not isinstance(props, dict):
        return []
    return [_clip(k, 120) for k in sorted(map(str, props))][:_LIST_CAP]
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
    models = [_clip(m.get("name")) for m in data.get("models", []) if isinstance(m, dict)]
    meta = {"endpoint": "/api/tags", "models": models[:_LIST_CAP]}
    # cve_map.yaml carries an `ollama` product, but nothing recorded a version, so
    # the probe path could never produce a match. One extra GET fixes that.
    try:
        v = session.get(f"http://{host}:{port}/api/version", timeout=timeout)
        if v.status_code == 200:
            ver = v.json().get("version")
            if ver:
                meta["version"] = _clip(ver, 40)
    except (requests.RequestException, ValueError, AttributeError):
        pass
    return ProbeResult(kind="ollama", auth="none", meta=meta)


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


def probe_n8n(
    session: requests.Session,
    host: str,
    port: int,
    *,
    timeout: float = DEFAULT_TIMEOUT,
) -> ProbeResult | None:
    """Detect an n8n workflow-automation console via its unauth /rest/settings.

    n8n exposes /rest/settings without auth: a JSON body wrapping a `data` object
    that carries `versionCli`, `instanceId`, the user-management auth method and
    the MFA policy. n8n runs over HTTPS as often as HTTP (N8N_PROTOCOL=https on
    default port 5678), so try https first. The console itself is gated by a
    signed `n8n-auth` cookie, so auth is reported as `cookie` — but the settings
    leak (version + instanceId + whether MFA is enforced) is the recon lead, and
    an authenticated n8n Code node is RCE, which the playbook chains from here.
    """
    for scheme in ("https", "http"):
        try:
            r = session.get(f"{scheme}://{host}:{port}/rest/settings", timeout=timeout)
        except requests.RequestException:
            continue
        if r.status_code != 200:
            continue
        try:
            data = r.json()
        except ValueError:
            continue
        body = data.get("data") if isinstance(data, dict) else None
        if not isinstance(body, dict):
            continue
        # versionCli + instanceId are distinctive of n8n's settings payload.
        if "versionCli" not in body and "instanceId" not in body:
            continue
        um = body.get("userManagement") or {}
        mfa = body.get("mfa") or {}
        return ProbeResult(
            kind="n8n",
            auth="cookie",
            meta={
                "endpoint": "/rest/settings",
                "scheme": scheme,
                "version": body.get("versionCli"),
                "instance_id": body.get("instanceId"),
                "auth_method": um.get("authenticationMethod"),
                "mfa_enforced": bool(mfa.get("enforced")),
                "release_channel": body.get("releaseChannel"),
            },
        )
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
        raw_tools = [t for t in data.get("result", {}).get("tools", []) if isinstance(t, dict)]
        # Every string here is server-supplied, so every one is clipped — a name
        # and a parameter key are as attacker-controlled as a description.
        tools = [_clip(t.get("name")) for t in raw_tools][:_LIST_CAP]
        # A tool's DESCRIPTION and input schema are what make it reachable, and
        # the project's own ai_attacks `mcp_attack` topic is entirely about
        # finding the privileged tool. Both were fetched and dropped.
        tool_detail = [
            {
                "name": _clip(t.get("name")),
                "description": _clip(t.get("description")),
                "params": _schema_params(t.get("inputSchema")),
            }
            for t in raw_tools[:_LIST_CAP]
        ]
        return ProbeResult(
            kind="mcp",
            auth="none",
            meta={"endpoint": path, "tools": tools, "tool_detail": tool_detail},
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
                # `skills` and `capabilities` are the agent's advertised reach,
                # and ai_attacks `a2a_attack` step 1 is to read exactly them. The
                # probe gated on their presence and then threw them away.
                raw_skills = data.get("skills")
                skills = [
                    _clip(x.get("name") or x.get("id")) if isinstance(x, dict) else _clip(x)
                    for x in (raw_skills if isinstance(raw_skills, list) else [])
                ][:_LIST_CAP]
                caps = data.get("capabilities")
                if isinstance(caps, dict):
                    cap_list = sorted(k for k, v in caps.items() if v)[:_LIST_CAP]
                elif isinstance(caps, list):
                    cap_list = [_clip(c) for c in caps][:_LIST_CAP]
                else:
                    cap_list = []
                return ProbeResult(
                    kind="a2a",
                    auth="none",
                    meta={"endpoint": path, "scheme": scheme, "name": _clip(data.get("name")),
                          "description": _clip(data.get("description")),
                          "skills": skills, "capabilities": cap_list},
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
                # ai_attacks `vector_db` step 2 scrolls points out of a NAMED
                # collection; the probe gated on the list and discarded it.
                raw = data["result"]["collections"]
                names = [
                    _clip(c.get("name")) if isinstance(c, dict) else _clip(c)
                    for c in (raw if isinstance(raw, list) else [])
                ][:_LIST_CAP]
                return ProbeResult(kind="vectordb", auth="none",
                                   meta={"engine": "qdrant", "endpoint": "/collections",
                                         "collections": names})
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
# Self-hosted AI-infra version probes. Each recovers a product VERSION so
# software_from_result records a `software` row and `yhwach vulns` matches the
# ai-infra cve_map rows. Prepended before the generic probes on shared ports so
# run_probes (first-non-None) sets the version-bearing kind, not a generic one.
# ---------------------------------------------------------------------------

def _http_json(session, scheme: str, host: str, port: int, path: str, timeout: float):
    """GET a JSON endpoint; None on any network / status / parse failure."""
    try:
        r = session.get(f"{scheme}://{host}:{port}{path}", timeout=timeout)
    except requests.RequestException:
        return None
    if r.status_code != 200:
        return None
    try:
        return r.json()
    except ValueError:
        return None


def probe_mlflow(session, host, port, *, timeout=DEFAULT_TIMEOUT) -> ProbeResult | None:
    """MLflow serves its version as plain text at /version."""
    for scheme in ("http", "https"):
        try:
            r = session.get(f"{scheme}://{host}:{port}/version", timeout=timeout)
        except requests.RequestException:
            continue
        if r.status_code != 200:
            continue
        v = (getattr(r, "text", "") or "").strip()
        if re.match(r"^\d+\.\d+(\.\d+)?$", v):
            return ProbeResult(kind="mlflow", auth="none",
                               meta={"endpoint": "/version", "scheme": scheme, "version": v})
    return None


def probe_langflow(session, host, port, *, timeout=DEFAULT_TIMEOUT) -> ProbeResult | None:
    """Langflow exposes /api/v1/version -> {"version": ...} (or {"main": ...})."""
    for scheme in ("http", "https"):
        data = _http_json(session, scheme, host, port, "/api/v1/version", timeout)
        if isinstance(data, dict) and (data.get("version") or data.get("main")):
            return ProbeResult(kind="langflow", auth="none",
                               meta={"endpoint": "/api/v1/version", "scheme": scheme,
                                     "version": str(data.get("version") or data.get("main"))})
    return None


def probe_ray(session, host, port, *, timeout=DEFAULT_TIMEOUT) -> ProbeResult | None:
    """Ray dashboard exposes /api/version -> {"ray_version": ...} (maybe under data)."""
    for scheme in ("http", "https"):
        data = _http_json(session, scheme, host, port, "/api/version", timeout)
        if not isinstance(data, dict):
            continue
        inner = data.get("data") if isinstance(data.get("data"), dict) else data
        ver = inner.get("ray_version") or inner.get("version")
        if ver:
            return ProbeResult(kind="ray", auth="none",
                               meta={"endpoint": "/api/version", "scheme": scheme, "version": str(ver)})
    return None


def probe_triton(session, host, port, *, timeout=DEFAULT_TIMEOUT) -> ProbeResult | None:
    """NVIDIA Triton (KServe v2) exposes /v2 -> {"name":"triton","version":...}."""
    for scheme in ("http", "https"):
        data = _http_json(session, scheme, host, port, "/v2", timeout)
        if isinstance(data, dict) and data.get("version") \
                and "triton" in str(data.get("name", "")).lower():
            return ProbeResult(kind="triton", auth="none",
                               meta={"endpoint": "/v2", "scheme": scheme, "version": str(data["version"])})
    return None


def probe_comfyui(session, host, port, *, timeout=DEFAULT_TIMEOUT) -> ProbeResult | None:
    """ComfyUI exposes /system_stats -> {"system": {"comfyui_version": ...}, ...}."""
    for scheme in ("http", "https"):
        data = _http_json(session, scheme, host, port, "/system_stats", timeout)
        if not isinstance(data, dict) or "system" not in data:
            continue
        sysd = data.get("system") if isinstance(data.get("system"), dict) else {}
        ver = sysd.get("comfyui_version")
        return ProbeResult(kind="comfyui", auth="none",
                           meta={"endpoint": "/system_stats", "scheme": scheme,
                                 "version": str(ver) if ver else None})
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
    5000:  [probe_mlflow, probe_openai_compat, probe_chatbot, probe_mcp, probe_openapi],
    5001:  [probe_openai_compat, probe_chatbot, probe_openapi],
    5678:  [probe_n8n],
    7860:  [probe_langflow, probe_gradio, probe_chatbot],
    8000:  [probe_triton, probe_openai_compat, probe_chatbot, probe_mcp, probe_gradio, probe_a2a, probe_vectordb, probe_openapi],
    8001:  [probe_triton, probe_openai_compat, probe_chatbot, probe_openapi],
    8002:  [probe_triton],
    8080:  [probe_openai_compat, probe_chatbot, probe_mcp, probe_a2a, probe_vectordb, probe_openapi],
    8188:  [probe_comfyui],
    8265:  [probe_ray],
    8443:  [probe_openai_compat, probe_chatbot, probe_mcp, probe_openapi],
    8888:  [probe_chatbot, probe_mcp],
    9000:  [probe_openai_compat, probe_chatbot, probe_a2a, probe_openapi],
}


def probes_for_port(port: int) -> list[ProbeFn]:
    """Return the ordered probes to try against this port, or []."""
    return PROBES_BY_PORT.get(port, [])


# Probe kinds whose meta["version"] is a real product version worth recording as
# a software row (so version->CVE matching / `yhwach vulns` can pick it up). A
# probe found the product AND its version live — richer than nmap's banner.
_VERSIONED_PROBE_KINDS = {
    "n8n": "n8n",
    "gradio": "Gradio",
    "vault": "HashiCorp Vault",
    "gitea": "Gitea",
    # AI-infra product probes -> the cve_map product name (so `yhwach vulns` matches).
    "mlflow": "mlflow",
    "langflow": "langflow",
    "ray": "ray",
    "triton": "triton",
    "comfyui": "comfyui",
}


def software_from_result(result: ProbeResult) -> tuple[str, str] | None:
    """(product_name, version) to record as software from a probe result, else None.

    Lets the probe caller feed a version the probe recovered (e.g. n8n's
    versionCli, Gradio's /config version) into the software inventory, which the
    surface-only upsert never did — the reason probe-discovered versions never
    reached `yhwach vulns`.
    """
    meta = result.meta or {}
    version = meta.get("version")
    if not version:
        return None
    name = _VERSIONED_PROBE_KINDS.get(result.kind)
    if name:
        return name, str(version)
    if result.kind == "vectordb":
        return str(meta.get("engine") or "vectordb"), str(version)
    return None


def run_probes(
    session: requests.Session,
    host: str,
    port: int,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    on_probe=None,
) -> ProbeResult | None:
    """Run the port's registered probes; return the first non-None result.

    `on_probe(name, outcome, kind)` is called once per probe ACTUALLY RUN, with
    outcome in {hit, miss, error}. Without it a caller cannot tell "never probed"
    from "probed, nothing matched" — the loop returns on first hit, so the probes
    after it never ran and must not be recorded as misses.
    """
    for probe in probes_for_port(port):
        name = getattr(probe, "__name__", str(probe))
        try:
            result = probe(session, host, port, timeout=timeout)
        except Exception as exc:  # noqa: BLE001 — one bad probe must not stop the sweep
            # Record WHAT failed: a swallowed probe crash looked identical to a
            # clean miss, so a surface could go permanently undetected in silence.
            if on_probe:
                on_probe(name, "error", f"{type(exc).__name__}: {exc}"[:200])
            continue
        if on_probe:
            on_probe(name, "hit" if result is not None else "miss",
                     result.kind if result is not None else None)
        if result is not None:
            return result
    return None
