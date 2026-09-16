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


def probe_chatbot(
    session: requests.Session,
    host: str,
    port: int,
    *,
    timeout: float = DEFAULT_TIMEOUT,
) -> ProbeResult | None:
    """Anything that isn't a 404 on a common chat path counts as a chatbot."""
    for scheme in ("http", "https"):
        for path in _CHATBOT_PATHS:
            try:
                r = session.post(
                    f"{scheme}://{host}:{port}{path}",
                    json={"message": "ping"},
                    timeout=timeout,
                )
            except requests.RequestException:
                continue
            if r.status_code == 404:
                continue
            auth = "bearer" if r.status_code in (401, 403) else "unknown"
            return ProbeResult(
                kind="chatbot",
                auth=auth,
                meta={"endpoint": path, "scheme": scheme, "http_status": r.status_code},
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


# ---------------------------------------------------------------------------
# Dispatch: port -> probes to try
# ---------------------------------------------------------------------------

ProbeFn = Callable[..., "ProbeResult | None"]

PROBES_BY_PORT: dict[int, list[ProbeFn]] = {
    11434: [probe_ollama],
    1234:  [probe_openai_compat, probe_chatbot],
    3000:  [probe_openai_compat, probe_chatbot],
    4000:  [probe_openai_compat, probe_chatbot],
    5000:  [probe_openai_compat, probe_chatbot, probe_mcp],
    5001:  [probe_openai_compat, probe_chatbot],
    7860:  [probe_gradio, probe_chatbot],
    8000:  [probe_openai_compat, probe_chatbot, probe_mcp, probe_gradio],
    8001:  [probe_openai_compat, probe_chatbot],
    8080:  [probe_openai_compat, probe_chatbot, probe_mcp],
    8443:  [probe_openai_compat, probe_chatbot, probe_mcp],
    8888:  [probe_chatbot, probe_mcp],
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
