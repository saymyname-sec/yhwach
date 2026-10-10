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
    ProbeResult,
    probe_chatbot,
    probe_comfyui,
    probe_gradio,
    probe_langflow,
    probe_mcp,
    probe_mlflow,
    probe_n8n,
    probe_ollama,
    probe_openai_compat,
    probe_ray,
    probe_triton,
    probes_for_port,
    run_probes,
    software_from_result,
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
    # Regression: a firewall host - Jenkins on 8080 returned 403 "No valid crumb"
    # and was misclassified as a bearer chatbot. The X-Jenkins header must veto it.
    session = FakeSession({
        ("GET", "/"): FakeResponse(200, headers={"X-Jenkins": "2.555.1"}, text="<html>Jenkins</html>"),
        ("POST", "/api/chat"): FakeResponse(403, text="No valid crumb was included in the request"),
    })
    assert probe_chatbot(session, "10.10.10.10", 8080) is None


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


# ---------------------------------------------------------------------------
# probe_n8n
# ---------------------------------------------------------------------------

def test_probe_n8n_detects_via_rest_settings() -> None:
    session = FakeSession({
        ("GET", "/rest/settings"): FakeResponse(200, {
            "data": {
                "versionCli": "1.120.4",
                "instanceId": "b73a45740a5f",
                "releaseChannel": "dev",
                "userManagement": {"authenticationMethod": "email"},
                "mfa": {"enabled": True, "enforced": False},
            }
        }),
    })
    res = probe_n8n(session, "10.0.0.5", 5678)
    assert res is not None
    assert res.kind == "n8n"
    assert res.auth == "cookie"
    assert res.meta["version"] == "1.120.4"
    assert res.meta["instance_id"] == "b73a45740a5f"
    assert res.meta["auth_method"] == "email"
    assert res.meta["mfa_enforced"] is False


def test_probe_n8n_none_on_wrong_shape() -> None:
    session = FakeSession({("GET", "/rest/settings"): FakeResponse(200, {"data": {"foo": 1}})})
    assert probe_n8n(session, "10.0.0.5", 5678) is None


def test_probe_n8n_none_on_404() -> None:
    session = FakeSession({("GET", "/rest/settings"): FakeResponse(404)})
    assert probe_n8n(session, "10.0.0.5", 5678) is None


def test_probe_n8n_registered_on_5678() -> None:
    assert probe_n8n in probes_for_port(5678)
    assert 5678 in PROBES_BY_PORT


def test_run_probes_5678_returns_n8n() -> None:
    session = FakeSession({
        ("GET", "/rest/settings"): FakeResponse(
            200, {"data": {"versionCli": "1.120.4", "instanceId": "x"}}),
    })
    res = run_probes(session, "10.0.0.5", 5678)
    assert res is not None and res.kind == "n8n"


# ---------------------------------------------------------------------------
# software_from_result — probe-discovered versions feed the software inventory
# ---------------------------------------------------------------------------

def test_software_from_result_n8n() -> None:
    r = ProbeResult(kind="n8n", auth="cookie", meta={"version": "1.120.4"})
    assert software_from_result(r) == ("n8n", "1.120.4")


def test_software_from_result_gitea() -> None:
    r = ProbeResult(kind="gitea", auth="unknown", meta={"version": "1.22.6"})
    assert software_from_result(r) == ("Gitea", "1.22.6")


def test_software_from_result_vectordb_uses_engine() -> None:
    r = ProbeResult(kind="vectordb", auth="none", meta={"engine": "weaviate", "version": "1.25"})
    assert software_from_result(r) == ("weaviate", "1.25")


def test_software_from_result_none_without_version() -> None:
    assert software_from_result(ProbeResult(kind="chatbot", auth="none", meta={})) is None
    assert software_from_result(ProbeResult(kind="n8n", auth="cookie", meta={})) is None


# --- P1b: AI-infra version probes (activate the ai-infra cve_map rows) -------

def test_probe_mlflow_plaintext_version() -> None:
    s = FakeSession({("GET", "/version"): FakeResponse(200, text="2.9.2")})
    r = probe_mlflow(s, "10.0.0.1", 5000)
    assert r is not None and r.kind == "mlflow" and r.meta["version"] == "2.9.2"


def test_probe_langflow_version() -> None:
    s = FakeSession({("GET", "/api/v1/version"): FakeResponse(200, json_data={"version": "1.2.0"})})
    r = probe_langflow(s, "10.0.0.1", 7860)
    assert r is not None and r.kind == "langflow" and r.meta["version"] == "1.2.0"


def test_probe_ray_version_nested() -> None:
    s = FakeSession({("GET", "/api/version"): FakeResponse(200, json_data={"data": {"ray_version": "2.8.0"}})})
    r = probe_ray(s, "10.0.0.1", 8265)
    assert r is not None and r.kind == "ray" and r.meta["version"] == "2.8.0"


def test_probe_triton_requires_name_marker() -> None:
    ok = FakeSession({("GET", "/v2"): FakeResponse(200, json_data={"name": "triton", "version": "2.40.0"})})
    assert probe_triton(ok, "10.0.0.1", 8000).meta["version"] == "2.40.0"
    # a generic /v2 without the triton name marker -> None (no mislabel)
    no = FakeSession({("GET", "/v2"): FakeResponse(200, json_data={"version": "9"})})
    assert probe_triton(no, "10.0.0.1", 8000) is None


def test_probe_comfyui_detect_and_version() -> None:
    s = FakeSession({("GET", "/system_stats"): FakeResponse(
        200, json_data={"system": {"comfyui_version": "0.3.0"}, "devices": []})})
    r = probe_comfyui(s, "10.0.0.1", 8188)
    assert r is not None and r.kind == "comfyui" and r.meta["version"] == "0.3.0"


def test_versioned_probes_feed_software_inventory() -> None:
    for kind, product in [("mlflow", "mlflow"), ("langflow", "langflow"),
                          ("ray", "ray"), ("triton", "triton"), ("comfyui", "comfyui")]:
        sw = software_from_result(ProbeResult(kind=kind, meta={"version": "1.0.0"}))
        assert sw == (product, "1.0.0")


def test_infra_probes_prepended_before_generic() -> None:
    # run_probes returns the FIRST non-None -> product probe must be tried first.
    assert probes_for_port(5000)[0] is probe_mlflow
    assert probes_for_port(7860)[0] is probe_langflow
    assert probes_for_port(8000)[0] is probe_triton
    assert probes_for_port(8265) == [probe_ray]
    assert probes_for_port(8188) == [probe_comfyui]


# ---------------------------------------------------------------------------
# The probes used to fetch the richest field and then drop it. These pin that
# what is gated on is also what gets stored — no extra request needed for any of
# them, because the data was already in the parsed response.
# ---------------------------------------------------------------------------

def test_probe_mcp_keeps_tool_descriptions_and_params() -> None:
    """ai_attacks `mcp_attack` is entirely about finding the privileged tool,
    which means its description and input schema."""
    session = FakeSession({
        ("POST", "/mcp"): FakeResponse(200, {
            "jsonrpc": "2.0",
            "result": {"tools": [
                {"name": "read_file",
                 "description": "Read any path on the host filesystem",
                 "inputSchema": {"properties": {"path": {}, "encoding": {}}}},
                {"name": "ping", "description": "health check"},
            ]},
        })
    })
    r = probe_mcp(session, "10.0.0.1", 8080)
    assert r is not None and r.kind == "mcp"
    assert r.meta["tools"] == ["read_file", "ping"]
    detail = {d["name"]: d for d in r.meta["tool_detail"]}
    assert detail["read_file"]["description"] == "Read any path on the host filesystem"
    assert detail["read_file"]["params"] == ["encoding", "path"]
    assert detail["ping"]["params"] == []


def test_probe_a2a_keeps_the_skills_it_gates_on() -> None:
    from yhwach.probes.ai import probe_a2a

    session = FakeSession({
        ("GET", "/.well-known/agent.json"): FakeResponse(200, {
            "name": "billing-agent",
            "description": "settles invoices",
            "skills": [{"name": "refund"}, {"id": "charge"}],
            "capabilities": {"streaming": True, "pushNotifications": False},
        })
    })
    r = probe_a2a(session, "10.0.0.1", 8080)
    assert r is not None and r.kind == "a2a"
    assert r.meta["name"] == "billing-agent"
    assert r.meta["skills"] == ["refund", "charge"]
    assert r.meta["capabilities"] == ["streaming"]      # only the enabled ones
    assert r.meta["description"] == "settles invoices"


def test_probe_vectordb_keeps_qdrant_collection_names() -> None:
    from yhwach.probes.ai import probe_vectordb

    session = FakeSession({
        ("GET", "/collections"): FakeResponse(200, {
            "result": {"collections": [{"name": "wiki"}, {"name": "hr-docs"}]}
        })
    })
    r = probe_vectordb(session, "10.0.0.1", 6333)
    assert r is not None and r.meta["engine"] == "qdrant"
    assert r.meta["collections"] == ["wiki", "hr-docs"]


def test_probe_ollama_records_a_version_for_cve_matching() -> None:
    session = FakeSession({
        ("GET", "/api/tags"): FakeResponse(200, {"models": [{"name": "llama3"}]}),
        ("GET", "/api/version"): FakeResponse(200, {"version": "0.1.32"}),
    })
    r = probe_ollama(session, "10.0.0.1", 11434)
    assert r is not None and r.meta["version"] == "0.1.32"


def test_probe_ollama_still_works_without_a_version_endpoint() -> None:
    session = FakeSession({
        ("GET", "/api/tags"): FakeResponse(200, {"models": [{"name": "llama3"}]}),
    })
    r = probe_ollama(session, "10.0.0.1", 11434)
    assert r is not None and "version" not in r.meta


def test_probe_meta_is_bounded_against_a_hostile_server() -> None:
    """meta_json is stored verbatim and later rendered; a hostile server must not
    be able to bloat the world model."""
    from yhwach.probes.ai import _LIST_CAP, _STR_CAP

    session = FakeSession({
        ("POST", "/mcp"): FakeResponse(200, {
            "jsonrpc": "2.0",
            "result": {"tools": [
                {"name": f"t{i}", "description": "x" * (_STR_CAP + 500)}
                for i in range(_LIST_CAP + 30)
            ]},
        })
    })
    r = probe_mcp(session, "10.0.0.1", 8080)
    assert len(r.meta["tools"]) == _LIST_CAP
    assert len(r.meta["tool_detail"]) == _LIST_CAP
    assert len(r.meta["tool_detail"][0]["description"]) <= _STR_CAP + 1
