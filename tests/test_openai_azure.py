"""Tests for the additive OpenAI endpoint config + Responses-API wire.

Covers the path needed to reach an Azure API Management `gpt-foundry` gateway
with model `gpt-5.6-sol`: a configurable client (base URL, `api-key` header,
`api-version`) and the Responses API adapter. No network, no OpenAI SDK, no
keys — clients are faked and responses hand-built to the Responses shape.
"""

from __future__ import annotations

import json
import types

import pytest

from yhwach import brain as br
from yhwach import providers as pv
from yhwach.providers._endpoint import OpenAIEndpoint, build_client
from yhwach.providers.openai import (
    OpenAIProvider,
    OpenAIResponsesProvider,
    _guarded_call,
    _map_openai_error,
    is_reasoning_model,
)

# The exact settings from the user's Codex config.toml, as yhwach env vars.
AZURE_ENV = {
    "YHWACH_OPENAI_BASE_URL": "https://apims-dev-01-airesorce.azure-api.net/gpt-foundry/openai",
    "YHWACH_OPENAI_API_VERSION": "2025-03-01-preview",
    "YHWACH_OPENAI_KEY_HEADER": "api-key",
    "YHWACH_OPENAI_API_KEY_ENV": "ENV_CODEX_KEY",
    "YHWACH_OPENAI_WIRE": "responses",
    "ENV_CODEX_KEY": "secret-key-value",
}


# --- endpoint config --------------------------------------------------------


def test_endpoint_from_env_reads_azure_config() -> None:
    ep = OpenAIEndpoint.from_env(AZURE_ENV)
    assert ep.base_url.endswith("/gpt-foundry/openai")
    assert ep.api_version == "2025-03-01-preview"
    assert ep.key_header == "api-key"
    assert ep.key == "secret-key-value"  # resolved from ENV_CODEX_KEY
    assert ep.is_customized


def test_endpoint_client_kwargs_header_auth() -> None:
    ep = OpenAIEndpoint.from_env(AZURE_ENV)
    kw = ep.client_kwargs()
    assert kw["base_url"].endswith("/gpt-foundry/openai")
    assert kw["default_query"] == {"api-version": "2025-03-01-preview"}
    assert kw["default_headers"] == {"api-key": "secret-key-value"}
    # SDK still needs a non-empty api_key for its (ignored) Bearer header
    assert kw["api_key"] == "secret-key-value"


def test_endpoint_direct_key_value_wins() -> None:
    ep = OpenAIEndpoint.from_env(
        {
            "YHWACH_OPENAI_API_KEY": "direct",
            "YHWACH_OPENAI_API_KEY_ENV": "ENV_CODEX_KEY",
            "ENV_CODEX_KEY": "from-env",
        }
    )
    assert ep.key == "direct"


def test_endpoint_empty_env_is_plain_client() -> None:
    ep = OpenAIEndpoint.from_env({})
    assert not ep.is_customized
    assert ep.client_kwargs() == {}  # -> OpenAI() reads OPENAI_API_KEY itself


def test_endpoint_bearer_key_from_named_env() -> None:
    ep = OpenAIEndpoint.from_env({"YHWACH_OPENAI_API_KEY_ENV": "MY_KEY", "MY_KEY": "abc"})
    assert ep.client_kwargs() == {"api_key": "abc"}


def test_build_client_header_auth_without_key_errors() -> None:
    ep = OpenAIEndpoint(key_header="api-key", key=None)
    with pytest.raises(br.BrainError, match="header auth"):
        build_client(ep)


def test_build_client_missing_sdk_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "openai":
            raise ImportError("no openai")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    with pytest.raises(br.BrainError, match="yhwach\\[agent-openai\\]"):
        build_client(OpenAIEndpoint())


def test_build_client_constructs_with_kwargs(monkeypatch: pytest.MonkeyPatch) -> None:
    import yhwach.providers._endpoint as ep_mod

    captured = {}

    class FakeOpenAI:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    monkeypatch.setattr(ep_mod, "import_openai", lambda: FakeOpenAI)
    build_client(OpenAIEndpoint.from_env(AZURE_ENV))
    assert captured["base_url"].endswith("/gpt-foundry/openai")
    assert captured["default_headers"] == {"api-key": "secret-key-value"}
    assert captured["default_query"] == {"api-version": "2025-03-01-preview"}


# --- reasoning-model detection ----------------------------------------------


def test_sol_model_is_reasoning() -> None:
    assert is_reasoning_model("gpt-5.6-sol")
    assert is_reasoning_model("gpt-6-sol")
    assert is_reasoning_model("o3-mini")
    assert not is_reasoning_model("gpt-4o")


def test_resolve_provider_infers_openai_for_sol_model() -> None:
    assert pv.resolve_provider(None, model="gpt-5.6-sol", env={}) == "openai"


# --- provider selection: wire switch ----------------------------------------


def test_make_provider_selects_responses_wire() -> None:
    p = pv.make_provider("openai", env={"YHWACH_OPENAI_WIRE": "responses"})
    assert isinstance(p, OpenAIResponsesProvider)


def test_make_provider_defaults_to_chat_wire() -> None:
    p = pv.make_provider("openai", env={})
    assert isinstance(p, OpenAIProvider)
    assert not isinstance(p, OpenAIResponsesProvider)


# --- Responses adapter: request building ------------------------------------


def test_responses_build_request_shape() -> None:
    p = OpenAIResponsesProvider()
    req = p.build_request(model="gpt-5.6-sol", system="PERSONA", context="the brief", effort="high")
    assert req["model"] == "gpt-5.6-sol"
    assert req["instructions"] == "PERSONA"  # persona is instructions, not a message
    assert req["input"][-1] == {"role": "user", "content": "the brief"}
    # flat function tool (name at top level), forced
    tool = req["tools"][0]
    assert tool["type"] == "function"
    assert tool["name"] == "emit_action"
    assert tool["parameters"] == br.EMIT_ACTION_SCHEMA
    assert req["tool_choice"] == {"type": "function", "name": "emit_action"}
    # responses caps with max_output_tokens; sol model is reasoning
    assert req["max_output_tokens"] == 16000
    assert req["reasoning"] == {"effort": "high"}
    assert "max_tokens" not in req


def test_responses_build_request_maps_xhigh_effort() -> None:
    p = OpenAIResponsesProvider()
    req = p.build_request(model="gpt-5.6-sol", system="s", context="c", effort="xhigh")
    assert req["reasoning"] == {"effort": "high"}


def test_responses_build_request_preserves_history() -> None:
    p = OpenAIResponsesProvider()
    history = [{"role": "user", "content": "earlier"}, {"role": "assistant", "content": "r"}]
    req = p.build_request(model="gpt-5.6-sol", system="s", context="now", history=history)
    assert req["input"][:2] == history
    assert req["input"][-1]["content"] == "now"


# --- Responses adapter: response parsing ------------------------------------


def _responses_reply(*, output, status="completed", usage=None):
    return types.SimpleNamespace(output=output, status=status, usage=usage)


def _function_call(name, arguments):
    return types.SimpleNamespace(type="function_call", name=name, arguments=arguments)


def test_responses_extract_action_from_function_call() -> None:
    args = json.dumps(
        {
            "action": "run_technique",
            "technique_id": "ollama_unauth_api",
            "host_ip": "10.0.0.5",
            "args": {"note": "read-only"},
            "rationale": "unauth ollama",
        }
    )
    resp = _responses_reply(output=[_function_call("emit_action", args)])
    action = OpenAIResponsesProvider.extract_action(resp)
    assert action.action == "run_technique"
    assert action.technique_id == "ollama_unauth_api"
    assert action.host_ip == "10.0.0.5"
    assert action.args == {"note": "read-only"}


def test_responses_extract_action_defaults_optional_fields() -> None:
    args = json.dumps({"action": "mark_phase_done", "rationale": "clean"})
    resp = _responses_reply(output=[_function_call("emit_action", args)])
    action = OpenAIResponsesProvider.extract_action(resp)
    assert action.technique_id is None
    assert action.args == {}


def test_responses_refusal_content_part_raises() -> None:
    part = types.SimpleNamespace(type="refusal", refusal="I can't help with that")
    message = types.SimpleNamespace(type="message", content=[part])
    resp = _responses_reply(output=[message], status="completed")
    with pytest.raises(br.BrainRefusalError) as exc:
        OpenAIResponsesProvider.extract_action(resp)
    assert exc.value.explanation == "I can't help with that"


def test_responses_content_filter_incomplete_raises() -> None:
    details = types.SimpleNamespace(reason="content_filter")
    resp = types.SimpleNamespace(output=[], status="incomplete", incomplete_details=details)
    with pytest.raises(br.BrainRefusalError) as exc:
        OpenAIResponsesProvider.extract_action(resp)
    assert exc.value.category == "content_filter"


def test_responses_no_function_call_raises() -> None:
    resp = _responses_reply(output=[], status="completed")
    with pytest.raises(br.BrainNoActionError):
        OpenAIResponsesProvider.extract_action(resp)


def test_responses_usage_normalizes_field_names() -> None:
    usage = types.SimpleNamespace(input_tokens=12, output_tokens=8)
    resp = _responses_reply(output=[], usage=usage)
    assert OpenAIResponsesProvider.usage(resp) == {"input": 12, "output": 8, "total": 20}


# --- Brain driving the Responses provider end-to-end ------------------------


class FakeResponsesClient:
    """Records the last responses.create kwargs; returns a canned reply."""

    def __init__(self, reply):
        self._reply = reply
        self.last_kwargs = None
        self.responses = types.SimpleNamespace(create=self._create)

    def _create(self, **kwargs):
        self.last_kwargs = kwargs
        return self._reply


def test_brain_with_responses_provider_decides() -> None:
    args = json.dumps({"action": "note", "rationale": "ok"})
    reply = _responses_reply(
        output=[_function_call("emit_action", args)],
        usage=types.SimpleNamespace(input_tokens=5, output_tokens=3),
    )
    client = FakeResponsesClient(reply)
    b = br.Brain(
        br.Role.DOER,
        system="PERSONA",
        model="gpt-5.6-sol",
        provider=OpenAIResponsesProvider(),
        client=client,
    )

    action = b.decide("brief text")

    assert action.action == "note"
    assert b.last_usage == {"input": 5, "output": 3, "total": 8}
    # request went out in Responses shape
    assert client.last_kwargs["instructions"] == "PERSONA"
    assert client.last_kwargs["model"] == "gpt-5.6-sol"
    assert client.last_kwargs["input"][-1]["content"] == "brief text"
    assert client.last_kwargs["tool_choice"] == {"type": "function", "name": "emit_action"}


# --- provider error mapping (graceful refusal, no traceback) -----------------


class FakeAPIError(Exception):
    """Mimics an openai SDK APIStatusError (status_code / code / message / body)."""

    def __init__(self, status_code, *, code=None, message=None, body=None):
        super().__init__(message or "")
        self.status_code = status_code
        self.code = code
        self.message = message
        self.body = body


def test_map_cyber_policy_to_refusal() -> None:
    err = FakeAPIError(
        400,
        code="cyber_policy",
        message="This content was flagged for possible cybersecurity risk.",
        body={"error": {"code": "cyber_policy", "message": "flagged"}},
    )
    mapped = _map_openai_error(err)
    assert isinstance(mapped, br.BrainRefusalError)
    assert mapped.category == "cyber_policy"
    assert "cybersecurity" in mapped.explanation


def test_map_reads_code_from_body_when_absent() -> None:
    err = FakeAPIError(400, body={"error": {"code": "content_filter", "message": "no"}})
    mapped = _map_openai_error(err)
    assert isinstance(mapped, br.BrainRefusalError)
    assert mapped.category == "content_filter"
    assert mapped.explanation == "no"


def test_map_generic_api_error_is_brain_error_not_refusal() -> None:
    err = FakeAPIError(500, message="server error")
    mapped = _map_openai_error(err)
    assert isinstance(mapped, br.BrainError)
    assert not isinstance(mapped, br.BrainRefusalError)
    assert "500" in str(mapped)


def test_map_non_api_exception_returns_none() -> None:
    assert _map_openai_error(ValueError("boom")) is None


def test_guarded_call_maps_policy_error() -> None:
    def create(**kwargs):
        raise FakeAPIError(400, code="cyber_policy", message="flagged")

    with pytest.raises(br.BrainRefusalError):
        _guarded_call(create, {"model": "gpt-5.6-sol"})


def test_guarded_call_passes_through_success() -> None:
    def create(**kwargs):
        return "ok"

    assert _guarded_call(create, {}) == "ok"


def test_guarded_call_reraises_non_api_error() -> None:
    def create(**kwargs):
        raise ValueError("boom")

    with pytest.raises(ValueError):
        _guarded_call(create, {})


def test_brain_decide_raises_brain_error_on_policy_refusal() -> None:
    """The whole point: a provider policy 400 becomes a BrainError the
    orchestrator already catches — not a raw openai traceback."""

    class RefusingClient:
        def __init__(self):
            def create(**kwargs):
                raise FakeAPIError(400, code="cyber_policy", message="flagged")

            self.responses = types.SimpleNamespace(create=create)

    b = br.Brain(
        br.Role.DOER,
        system="x",
        model="gpt-5.6-sol",
        provider=OpenAIResponsesProvider(),
        client=RefusingClient(),
    )
    with pytest.raises(br.BrainError):
        b.decide("brief")
