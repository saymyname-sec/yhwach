"""Tests for the brain (SDK caller). No network, no anthropic install, no key —
the SDK client is faked and responses are hand-built to the SDK's shape."""

from __future__ import annotations

import types

import pytest

from yhwach import brain as br

# --- fakes mimicking the anthropic SDK response shape -----------------------


def _tool_use_block(name: str, data: dict):
    return types.SimpleNamespace(type="tool_use", name=name, input=data)


def _text_block(text: str):
    return types.SimpleNamespace(type="text", text=text)


def _response(content, *, stop_reason="tool_use", stop_details=None):
    return types.SimpleNamespace(
        content=content, stop_reason=stop_reason, stop_details=stop_details
    )


class FakeClient:
    """Records the last messages.create kwargs and returns a canned response."""

    def __init__(self, response):
        self._response = response
        self.last_kwargs = None
        self.messages = types.SimpleNamespace(create=self._create)

    def _create(self, **kwargs):
        self.last_kwargs = kwargs
        return self._response


# --- model tiering ----------------------------------------------------------


def test_role_picks_default_model() -> None:
    assert br.Brain(br.Role.DOER, system="x").model == br.MODEL_STRONG
    assert br.Brain(br.Role.JUDGE, system="x").model == br.MODEL_STRONG
    assert br.Brain(br.Role.INTERPRET, system="x").model == br.MODEL_CHEAP
    assert br.Brain(br.Role.RANK, system="x").model == br.MODEL_MID


def test_explicit_model_overrides_role() -> None:
    b = br.Brain(br.Role.INTERPRET, model="claude-opus-5", system="x")
    assert b.model == "claude-opus-5"


# --- request building (pure) ------------------------------------------------


def test_build_request_shape() -> None:
    b = br.Brain(br.Role.DOER, system="PERSONA", effort="xhigh")
    req = b.build_request("the brief goes here")

    assert req["model"] == br.MODEL_STRONG
    assert req["thinking"] == {"type": "adaptive"}
    assert req["output_config"]["effort"] == "xhigh"
    # persona is the cached system prefix
    assert req["system"][0]["text"] == "PERSONA"
    assert req["system"][0]["cache_control"] == {"type": "ephemeral"}
    # emit_action tool is offered
    assert req["tools"][0]["name"] == "emit_action"
    # volatile context is the last user message
    assert req["messages"][-1] == {"role": "user", "content": "the brief goes here"}


def test_build_request_preserves_history() -> None:
    b = br.Brain(system="x")
    history = [
        {"role": "user", "content": "earlier"},
        {"role": "assistant", "content": "reply"},
    ]
    req = b.build_request("now", history=history)
    assert req["messages"][:2] == history
    assert req["messages"][-1]["content"] == "now"


def test_system_prompt_falls_back_to_persona_file() -> None:
    # No override -> loads the bundled operator persona (non-empty).
    b = br.Brain()
    text = b.system_prompt()
    assert isinstance(text, str) and text.strip()


# --- response parsing (pure) ------------------------------------------------


def test_extract_action_from_tool_use() -> None:
    resp = _response(
        [
            _tool_use_block(
                "emit_action",
                {
                    "action": "run_technique",
                    "technique_id": "ollama_unauth_api",
                    "host_ip": "10.0.0.5",
                    "args": {"note": "read-only"},
                    "rationale": "unauth ollama, free recon",
                },
            )
        ]
    )
    action = br.Brain._extract_action(resp)
    assert action.action == "run_technique"
    assert action.technique_id == "ollama_unauth_api"
    assert action.host_ip == "10.0.0.5"
    assert action.args == {"note": "read-only"}
    assert action.rationale == "unauth ollama, free recon"


def test_extract_action_tolerates_json_string_input() -> None:
    resp = _response([_tool_use_block("emit_action", '{"action": "note", "rationale": "hmm"}')])
    action = br.Brain._extract_action(resp)
    assert action.action == "note"
    assert action.args == {}


def test_extract_action_defaults_optional_fields() -> None:
    resp = _response(
        [_tool_use_block("emit_action", {"action": "mark_phase_done", "rationale": "clean"})]
    )
    action = br.Brain._extract_action(resp)
    assert action.technique_id is None
    assert action.host_ip is None
    assert action.args == {}


def test_refusal_raises() -> None:
    resp = _response(
        [],
        stop_reason="refusal",
        stop_details=types.SimpleNamespace(category="cyber", explanation="nope"),
    )
    with pytest.raises(br.BrainRefusalError) as exc:
        br.Brain._extract_action(resp)
    assert exc.value.category == "cyber"


def test_no_action_raises() -> None:
    resp = _response([_text_block("I thought about it but didn't act")], stop_reason="end_turn")
    with pytest.raises(br.BrainNoActionError):
        br.Brain._extract_action(resp)


# --- the full turn with an injected client ----------------------------------


def test_decide_uses_injected_client() -> None:
    resp = _response([_tool_use_block("emit_action", {"action": "note", "rationale": "ok"})])
    client = FakeClient(resp)
    b = br.Brain(br.Role.DOER, system="PERSONA", client=client)

    action = b.decide("brief text")

    assert action.action == "note"
    # the live path built and passed a well-formed request
    assert client.last_kwargs["model"] == br.MODEL_STRONG
    assert client.last_kwargs["messages"][-1]["content"] == "brief text"


def test_missing_anthropic_is_a_clear_error(monkeypatch: pytest.MonkeyPatch) -> None:
    # Force the lazy import to fail and assert a helpful message.
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "anthropic":
            raise ImportError("no anthropic")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    b = br.Brain(system="x")  # no injected client -> will try to import
    with pytest.raises(br.BrainError, match="yhwach\\[agent\\]"):
        b.decide("brief")
