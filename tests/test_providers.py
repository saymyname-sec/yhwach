"""Tests for the provider layer (wire 1): the OpenAI adapter and the runtime
provider resolver. No network, no vendor SDKs installed, no keys — clients are
faked and responses are hand-built to each vendor's response shape."""

from __future__ import annotations

import json
import types

import pytest

from yhwach import brain as br
from yhwach import providers as pv
from yhwach.providers.anthropic import AnthropicProvider
from yhwach.providers.openai import OpenAIProvider

# --- fakes mimicking the OpenAI Chat Completions response shape --------------


def _oai_tool_call(name: str, arguments):
    fn = types.SimpleNamespace(name=name, arguments=arguments)
    return types.SimpleNamespace(function=fn)


def _oai_response(*, tool_calls=None, refusal=None, finish_reason="tool_calls", usage=None):
    message = types.SimpleNamespace(tool_calls=tool_calls or [], refusal=refusal)
    choice = types.SimpleNamespace(message=message, finish_reason=finish_reason)
    return types.SimpleNamespace(choices=[choice], usage=usage)


class FakeOpenAIClient:
    """Records the last chat.completions.create kwargs; returns a canned response."""

    def __init__(self, response):
        self._response = response
        self.last_kwargs = None
        create = self._create
        self.chat = types.SimpleNamespace(completions=types.SimpleNamespace(create=create))

    def _create(self, **kwargs):
        self.last_kwargs = kwargs
        return self._response


# --- resolve_provider truth table -------------------------------------------


def test_resolve_explicit_flag_wins() -> None:
    env = {"YHWACH_PROVIDER": "anthropic", "OPENAI_API_KEY": "x"}
    assert pv.resolve_provider("openai", model="claude-opus-5", env=env) == "openai"


def test_resolve_env_over_model_and_keys() -> None:
    env = {"YHWACH_PROVIDER": "openai", "ANTHROPIC_API_KEY": "x"}
    assert pv.resolve_provider(None, model="claude-opus-5", env=env) == "openai"


def test_resolve_infers_from_model_prefix() -> None:
    assert pv.resolve_provider(None, model="gpt-5", env={}) == "openai"
    assert pv.resolve_provider(None, model="o3-mini", env={}) == "openai"
    assert pv.resolve_provider(None, model="claude-opus-5", env={}) == "anthropic"


def test_resolve_single_key_present() -> None:
    assert pv.resolve_provider(None, env={"OPENAI_API_KEY": "x"}) == "openai"
    assert pv.resolve_provider(None, env={"ANTHROPIC_API_KEY": "x"}) == "anthropic"


def test_resolve_ambiguous_raises() -> None:
    env = {"ANTHROPIC_API_KEY": "x", "OPENAI_API_KEY": "y"}
    with pytest.raises(pv.ProviderAmbiguityError):
        pv.resolve_provider(None, env=env)


def test_resolve_no_signal_defaults_anthropic() -> None:
    assert pv.resolve_provider(None, env={}) == "anthropic"


def test_resolve_unknown_name_raises() -> None:
    with pytest.raises(pv.ProviderError):
        pv.resolve_provider("gemini", env={})
    with pytest.raises(pv.ProviderError):
        pv.resolve_provider(None, env={"YHWACH_PROVIDER": "gemini"})


def test_infer_helper() -> None:
    assert pv.infer_provider_from_model("GPT-5") == "openai"
    assert pv.infer_provider_from_model("claude-sonnet-5") == "anthropic"
    assert pv.infer_provider_from_model("mixtral") is None
    assert pv.infer_provider_from_model(None) is None


def test_make_provider() -> None:
    assert isinstance(pv.make_provider("anthropic"), AnthropicProvider)
    assert isinstance(pv.make_provider("openai"), OpenAIProvider)
    assert pv.make_provider("OpenAI").name == "openai"


# --- OpenAI adapter: request building ---------------------------------------


def test_openai_build_request_shape() -> None:
    p = OpenAIProvider()
    req = p.build_request(model="gpt-5", system="PERSONA", context="the brief", effort="high")
    # persona is the first system message, brief is the last user message
    assert req["messages"][0] == {"role": "system", "content": "PERSONA"}
    assert req["messages"][-1] == {"role": "user", "content": "the brief"}
    # emit_action offered as a function tool and forced
    tool = req["tools"][0]
    assert tool["type"] == "function"
    assert tool["function"]["name"] == "emit_action"
    assert tool["function"]["parameters"] == br.EMIT_ACTION_SCHEMA
    assert req["tool_choice"]["function"]["name"] == "emit_action"


def test_openai_reasoning_model_gets_effort_and_completion_cap() -> None:
    p = OpenAIProvider()
    req = p.build_request(model="gpt-5", system="s", context="c", effort="xhigh")
    # xhigh (Anthropic-only) maps down; reasoning models take reasoning_effort
    assert req["reasoning_effort"] == "high"
    assert req["max_completion_tokens"] == 16000
    assert "max_tokens" not in req


def test_openai_non_reasoning_model_uses_max_tokens() -> None:
    p = OpenAIProvider()
    req = p.build_request(model="gpt-4o", system="s", context="c")
    assert req["max_tokens"] == 16000
    assert "reasoning_effort" not in req


def test_openai_build_request_preserves_history() -> None:
    p = OpenAIProvider()
    history = [
        {"role": "user", "content": "earlier"},
        {"role": "assistant", "content": "reply"},
    ]
    req = p.build_request(model="gpt-5", system="s", context="now", history=history)
    assert req["messages"][0]["role"] == "system"
    assert req["messages"][1:3] == history
    assert req["messages"][-1]["content"] == "now"


# --- OpenAI adapter: response parsing ---------------------------------------


def test_openai_extract_action_from_tool_call() -> None:
    args = json.dumps(
        {
            "action": "run_technique",
            "technique_id": "ollama_unauth_api",
            "host_ip": "10.0.0.5",
            "args": {"note": "read-only"},
            "rationale": "unauth ollama, free recon",
        }
    )
    resp = _oai_response(tool_calls=[_oai_tool_call("emit_action", args)])
    action = OpenAIProvider.extract_action(resp)
    assert action.action == "run_technique"
    assert action.technique_id == "ollama_unauth_api"
    assert action.host_ip == "10.0.0.5"
    assert action.args == {"note": "read-only"}
    assert action.rationale == "unauth ollama, free recon"


def test_openai_extract_action_defaults_optional_fields() -> None:
    args = json.dumps({"action": "mark_phase_done", "rationale": "clean"})
    resp = _oai_response(tool_calls=[_oai_tool_call("emit_action", args)])
    action = OpenAIProvider.extract_action(resp)
    assert action.technique_id is None
    assert action.host_ip is None
    assert action.args == {}


def test_openai_refusal_via_message_field_raises() -> None:
    resp = _oai_response(refusal="I can't help with that", finish_reason="stop")
    with pytest.raises(br.BrainRefusalError) as exc:
        OpenAIProvider.extract_action(resp)
    assert exc.value.explanation == "I can't help with that"


def test_openai_refusal_via_content_filter_raises() -> None:
    resp = _oai_response(finish_reason="content_filter")
    with pytest.raises(br.BrainRefusalError) as exc:
        OpenAIProvider.extract_action(resp)
    assert exc.value.category == "content_filter"


def test_openai_no_tool_call_raises() -> None:
    resp = _oai_response(tool_calls=[], finish_reason="stop")
    with pytest.raises(br.BrainNoActionError):
        OpenAIProvider.extract_action(resp)


def test_openai_no_choices_raises() -> None:
    resp = types.SimpleNamespace(choices=[], usage=None)
    with pytest.raises(br.BrainNoActionError):
        OpenAIProvider.extract_action(resp)


def test_openai_usage_normalizes_field_names() -> None:
    usage = types.SimpleNamespace(prompt_tokens=11, completion_tokens=7)
    resp = _oai_response(
        tool_calls=[_oai_tool_call("emit_action", '{"action":"note","rationale":"x"}')],
        usage=usage,
    )
    assert OpenAIProvider.usage(resp) == {"input": 11, "output": 7, "total": 18}


# --- Brain driving the OpenAI provider end-to-end ---------------------------


def test_brain_with_openai_provider_decides() -> None:
    args = json.dumps({"action": "note", "rationale": "ok"})
    resp = _oai_response(
        tool_calls=[_oai_tool_call("emit_action", args)],
        usage=types.SimpleNamespace(prompt_tokens=3, completion_tokens=2),
    )
    client = FakeOpenAIClient(resp)
    b = br.Brain(br.Role.DOER, system="PERSONA", provider="openai", client=client)

    action = b.decide("brief text")

    assert action.action == "note"
    assert b.model == "gpt-5"  # openai DOER default
    assert b.last_usage == {"input": 3, "output": 2, "total": 5}
    # the request went out in OpenAI shape
    assert client.last_kwargs["messages"][0]["role"] == "system"
    assert client.last_kwargs["messages"][-1]["content"] == "brief text"
    assert client.last_kwargs["tool_choice"]["function"]["name"] == "emit_action"


def test_brain_accepts_provider_instance() -> None:
    b = br.Brain(br.Role.INTERPRET, system="x", provider=OpenAIProvider())
    assert b.provider.name == "openai"
    assert b.model == "gpt-5-mini"  # openai INTERPRET default


def test_brain_explicit_model_overrides_openai_tiering() -> None:
    b = br.Brain(br.Role.DOER, system="x", provider="openai", model="gpt-4o")
    assert b.model == "gpt-4o"


def test_missing_openai_is_a_clear_error(monkeypatch: pytest.MonkeyPatch) -> None:
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "openai":
            raise ImportError("no openai")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    b = br.Brain(system="x", provider="openai")  # no injected client -> will import
    with pytest.raises(br.BrainError, match="yhwach\\[agent-openai\\]"):
        b.decide("brief")
