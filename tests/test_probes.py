"""Probe tests using a hand-rolled FakeSession (no real HTTP, no `responses` dep).

Each probe is called with a fake session that returns canned responses per
(method, path); anything unmocked raises a ConnectionError, which the probes
must swallow into `None`.
"""
from __future__ import annotations

from urllib.parse import urlparse

import pytest
import requests

from yhwach.probes.ai import (
    PROBES_BY_PORT,
    probe_chatbot,
    probe_gradio,
    probe_mcp,
    probe_ollama,
    probe_openai_compat,
    probes_for_port,
    run_probes,
)


class FakeResponse:
    def __init__(self, status_code: int = 200, json_data=None, headers=None, text: str = ""):
        self.status_code = status_code
        self._json = json_data
        self.headers = headers or {}
        self.text = text

    def json(self):
        if self._json is None:
            raise ValueError("no json")
        return self._json


class FakeSession:
    """Minimal session double: dispatches by (method, path)."""

    def __init__(self, mapping: dict[tuple[str, str], FakeResponse]):
        self.mapping = mapping
        self.calls: list[tuple[str, str]] = []

    def get(self, url: str, **_kwargs) -> FakeResponse:
        return self._respond("GET", url)

    def post(self, url: str, **_kwargs) -> FakeResponse:
        return self._respond("POST", url)

    def _respond(self, method: str, url: str) -> FakeResponse:
        path = urlparse(url).path
        self.calls.append((method, path))
        if (method, path) in self.mapping:
            return self.mapping[(method, path)]
        raise requests.exceptions.ConnectionError(f"no mock for {method} {path}")


# ---------------------------------------------------------------------------
# probe_ollama
# ---------------------------------------------------------------------------

def test_probe_ollama_success() -> None:
    session = FakeSession({
        ("GET", "/api/tags"): FakeResponse(200, {
            "models": [{"name": "llama3.2"}, {"name": "mistral"}]
        })
    })
    result = probe_ollama(session, "10.0.0.1", 11434)
    assert result is not None
    assert result.kind == "ollama"
    assert result.auth == "none"
    assert result.meta["endpoint"] == "/api/tags"
    assert set(result.meta["models"]) == {"llama3.2", "mistral"}


def test_probe_ollama_returns_none_on_404() -> None:
    session = FakeSession({("GET", "/api/tags"): FakeResponse(404)})
    assert probe_ollama(session, "10.0.0.1", 11434) is None


def test_probe_ollama_returns_none_on_wrong_shape() -> None:
    session = FakeSession({("GET", "/api/tags"): FakeResponse(200, {"nope": []})})
    assert probe_ollama(session, "10.0.0.1", 11434) is None


def test_probe_ollama_swallows_connection_error() -> None:
    session = FakeSession({})  # no mocks -> ConnectionError raised
    assert probe_ollama(session, "10.0.0.1", 11434) is None


# ---------------------------------------------------------------------------
# probe_openai_compat
# ---------------------------------------------------------------------------

def test_probe_openai_compat_success_no_auth() -> None:
    session = FakeSession({
        ("GET", "/v1/models"): FakeResponse(200, {"data": [{"id": "gpt-4"}, {"id": "gpt-3.5"}]})
    })
    result = probe_openai_compat(session, "10.0.0.1", 1234)
    assert result is not None
    assert result.kind == "openai_compat"
    assert result.auth == "none"
    assert set(result.meta["models"]) == {"gpt-4", "gpt-3.5"}
    assert result.meta["scheme"] == "http"


def test_probe_openai_compat_bearer_on_401() -> None:
    session = FakeSession({("GET", "/v1/models"): FakeResponse(401)})
    result = probe_openai_compat(session, "10.0.0.1", 1234)
    assert result is not None
    assert result.auth == "bearer"


def test_probe_openai_compat_none_on_missing_endpoint() -> None:
    session = FakeSession({})
    assert probe_openai_compat(session, "10.0.0.1", 1234) is None


# ---------------------------------------------------------------------------
# probe_chatbot
# ---------------------------------------------------------------------------

def test_probe_chatbot_detects_on_chat_json_body() -> None:
    session = FakeSession({("POST", "/api/chat"): FakeResponse(200, {"response": "hi there"})})
    result = probe_chatbot(session, "10.0.0.1", 8000)
    assert result is not None
    assert result.kind == "chatbot"
    assert result.auth == "none"
    assert result.meta["endpoint"] == "/api/chat"


def test_probe_chatbot_ignores_200_non_chat_json() -> None:
    # A 200 that isn't a chat body (e.g. a generic {"status":"ok"}) is not enough.
    session = FakeSession({("POST", "/api/chat"): FakeResponse(200, {"status": "ok"})})
    assert probe_chatbot(session, "10.0.0.1", 8000) is None


def test_probe_chatbot_bearer_only_with_llm_hint() -> None:
    session = FakeSession({
        ("POST", "/api/chat"): FakeResponse(401, text="Unauthorized: chat completion requires a token")
    })
    result = probe_chatbot(session, "10.0.0.1", 8000)
    assert result is not None
    assert result.auth == "bearer"


def test_probe_chatbot_rejects_jenkins_csrf_403() -> None:
    # Regression: Iron Crown FW01 - Jenkins on 8080 returned 403 "No valid crumb"
    # and was misclassified as a bearer chatbot. The X-Jenkins header must veto it.
    session = FakeSession({
        ("GET", "/"): FakeResponse(200, headers={"X-Jenkins": "2.555.1"}, text="<html>Jenkins</html>"),
        ("POST", "/api/chat"): FakeResponse(403, text="No valid crumb was included in the request"),
    })
    assert probe_chatbot(session, "192.168.239.10", 8080) is None


def test_probe_chatbot_ignores_bare_403_without_llm_hint() -> None:
    session = FakeSession({("POST", "/api/chat"): FakeResponse(403, text="Forbidden")})
    assert probe_chatbot(session, "10.0.0.1", 8000) is None


def test_probe_chatbot_ignores_404s() -> None:
    session = FakeSession({
        ("POST", "/api/chat"): FakeResponse(404),
        ("POST", "/chat"): FakeResponse(404),
        ("POST", "/api/completion"): FakeResponse(404),
        ("POST", "/api/message"): FakeResponse(404),
    })
    assert probe_chatbot(session, "10.0.0.1", 8000) is None


# ---------------------------------------------------------------------------
# probe_mcp
# ---------------------------------------------------------------------------

def test_probe_mcp_success() -> None:
    session = FakeSession({
        ("POST", "/mcp"): FakeResponse(200, {
            "jsonrpc": "2.0", "id": 1,
            "result": {"tools": [{"name": "run_command"}, {"name": "read_file"}]}
        })
    })
    result = probe_mcp(session, "10.0.0.1", 8080)
    assert result is not None
    assert result.kind == "mcp"
    assert set(result.meta["tools"]) == {"run_command", "read_file"}


def test_probe_mcp_ignores_non_jsonrpc_body() -> None:
    session = FakeSession({("POST", "/mcp"): FakeResponse(200, {"nope": True})})
    assert probe_mcp(session, "10.0.0.1", 8080) is None


# ---------------------------------------------------------------------------
# probe_gradio
# ---------------------------------------------------------------------------

def test_probe_gradio_success() -> None:
    session = FakeSession({
        ("GET", "/config"): FakeResponse(200, {"version": "4.16.0", "components": []})
    })
    result = probe_gradio(session, "10.0.0.1", 7860)
    assert result is not None
    assert result.kind == "gradio"
    assert result.meta["version"] == "4.16.0"


def test_probe_gradio_none_on_generic_json() -> None:
    session = FakeSession({("GET", "/config"): FakeResponse(200, {"hello": "world"})})
    assert probe_gradio(session, "10.0.0.1", 7860) is None


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

def test_probes_for_port_ollama_is_ollama_only() -> None:
    fns = probes_for_port(11434)
    assert fns == [probe_ollama]


def test_probes_for_port_unknown_returns_empty() -> None:
    assert probes_for_port(9999) == []


def test_run_probes_returns_first_hit_and_stops() -> None:
    # Port 8000 tries openai_compat first, then chatbot. openai fails (no
    # /v1/models); chatbot succeeds via a 200 chat-json body.
    session = FakeSession({
        ("POST", "/api/chat"): FakeResponse(200, {"reply": "pong"}),
    })
    result = run_probes(session, "10.0.0.1", 8000)
    assert result is not None
    assert result.kind == "chatbot"


def test_run_probes_returns_none_when_nothing_matches() -> None:
    session = FakeSession({})  # everything raises ConnectionError -> None
    assert run_probes(session, "10.0.0.1", 8000) is None


def test_run_probes_unknown_port_is_empty() -> None:
    assert run_probes(FakeSession({}), "10.0.0.1", 9999) is None


def test_probes_by_port_covers_expected_ports() -> None:
    # Regression guard: don't accidentally drop coverage of the classics.
    expected_ports = {11434, 7860, 8000, 3000, 5000}
    assert expected_ports.issubset(set(PROBES_BY_PORT.keys()))


@pytest.mark.parametrize("port", [11434, 7860, 8000, 8080, 5000])
def test_every_port_has_at_least_one_probe(port: int) -> None:
    assert len(probes_for_port(port)) >= 1


# ---------------------------------------------------------------------------
# probe_a2a / probe_vectordb  (Batch C)
# ---------------------------------------------------------------------------

def test_probe_a2a_agent_card() -> None:
    from yhwach.probes.ai import probe_a2a
    session = FakeSession({
        ("GET", "/.well-known/agent.json"): FakeResponse(200, {
            "name": "orchestrator", "skills": [{"id": "summarize"}], "url": "http://x"
        })
    })
    res = probe_a2a(session, "10.0.0.1", 8000)
    assert res is not None
    assert res.kind == "a2a"
    assert res.meta["name"] == "orchestrator"


def test_probe_a2a_ignores_non_agent_json() -> None:
    from yhwach.probes.ai import probe_a2a
    session = FakeSession({("GET", "/.well-known/agent.json"): FakeResponse(200, {"hello": "world"})})
    assert probe_a2a(session, "10.0.0.1", 8000) is None


def test_probe_vectordb_qdrant() -> None:
    from yhwach.probes.ai import probe_vectordb
    session = FakeSession({
        ("GET", "/collections"): FakeResponse(200, {"result": {"collections": [{"name": "docs"}]}})
    })
    res = probe_vectordb(session, "10.0.0.1", 6333)
    assert res is not None
    assert res.kind == "vectordb"
    assert res.meta["engine"] == "qdrant"


def test_probe_vectordb_weaviate() -> None:
    from yhwach.probes.ai import probe_vectordb
    session = FakeSession({
        ("GET", "/collections"): FakeResponse(404),
        ("GET", "/v1/meta"): FakeResponse(200, {"version": "1.24.1", "hostname": "weav"}),
    })
    res = probe_vectordb(session, "10.0.0.1", 8080)
    assert res is not None
    assert res.meta["engine"] == "weaviate"


def test_probe_vectordb_none() -> None:
    from yhwach.probes.ai import probe_vectordb
    assert probe_vectordb(FakeSession({}), "10.0.0.1", 8080) is None
