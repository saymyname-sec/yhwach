"""OpenAI adapter (wire 1) - optional (extra: ``agent-openai``).

Uses the Chat Completions API with function calling, which maps one-to-one onto
yhwach's single-tool `emit_action` design:

  * the persona is the first `system` message (OpenAI caches long stable
    prefixes automatically, so no manual cache breakpoint);
  * `emit_action` is offered as a function tool and forced with `tool_choice`,
    which replaces Anthropic's prompt-only guarantee that the tool is called;
  * for reasoning-capable models the per-call `effort` maps to `reasoning_effort`
    and the cap is `max_completion_tokens`; other models take `max_tokens`.

The response's `tool_calls[0].function.arguments` is a JSON *string*; the shared
`action_from_payload` handles the decoded dict.

`OpenAIResponsesProvider` (bottom of file) is the same adapter over the
**Responses API** for gateways/deployments that require that wire (e.g. Azure
`gpt-foundry` / `gpt-5.6-sol`); it is selected with `YHWACH_OPENAI_WIRE=responses`.
Both share the endpoint config in `_endpoint` (base URL, custom key header,
api-version), so pointing at a custom gateway is configuration, not code.
"""

from __future__ import annotations

import json
from typing import Any

from yhwach.brain import (
    EMIT_ACTION_DESCRIPTION,
    EMIT_ACTION_NAME,
    EMIT_ACTION_SCHEMA,
    Action,
    BrainError,
    BrainNoActionError,
    BrainRefusalError,
    Role,
    action_from_payload,
)
from yhwach.providers._endpoint import build_client

# Role -> model tiering for OpenAI. Indicative ids; override per call with
# --model. Strong for DOER/JUDGE, cheap for INTERPRET/RANK, mirroring Anthropic.
MODELS: dict[Role, str] = {
    Role.DOER: "gpt-5",
    Role.JUDGE: "gpt-5",
    Role.INTERPRET: "gpt-5-mini",
    Role.RANK: "gpt-5-mini",
}

# Model-id prefixes that accept `reasoning_effort` / `max_completion_tokens`.
_REASONING_PREFIXES = ("o1", "o3", "o4", "gpt-5", "gpt-6")
# The gpt-*-sol family are reasoning models regardless of version (gpt-5.6-sol,
# gpt-6-sol, gpt-6.1-sol, ...), matched by this substring too.
_REASONING_SUBSTRINGS = ("-sol",)

# Anthropic uses "xhigh"; OpenAI's reasoning_effort does not. Map it down.
_EFFORT_MAP = {
    "minimal": "minimal",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "xhigh": "high",
}


def is_reasoning_model(model: str) -> bool:
    """True for reasoning-capable models (o-series / gpt-5-and-up, incl. the
    gpt-*-sol family), which take reasoning params instead of plain sampling."""
    m = model.strip().lower()
    return any(m.startswith(p) for p in _REASONING_PREFIXES) or any(
        s in m for s in _REASONING_SUBSTRINGS
    )


def _reasoning_effort(effort: str) -> str:
    return _EFFORT_MAP.get(effort, "high")


# Error codes that mean the model/provider declined the content (as opposed to a
# transport or config fault). `cyber_policy` is OpenAI's cybersecurity-content
# gate; the others are the general content filters. These map to a clean
# BrainRefusalError so the orchestrator halts gracefully instead of crashing.
_POLICY_CODES = frozenset(
    {"cyber_policy", "content_filter", "content_policy_violation", "content_policy"}
)


def _map_openai_error(exc: Exception) -> BrainError | None:
    """Translate an OpenAI SDK error into a yhwach BrainError. Duck-typed so this
    module never imports the SDK. Returns None for non-API exceptions (which
    propagate unchanged)."""
    status = getattr(exc, "status_code", None)
    if status is None:
        return None  # not an OpenAI APIStatusError — let it propagate as-is
    code = getattr(exc, "code", None)
    message = getattr(exc, "message", None)
    body = getattr(exc, "body", None)
    if isinstance(body, dict):
        err = body.get("error", body)
        if isinstance(err, dict):
            code = code or err.get("code")
            message = message or err.get("message")
    message = message or str(exc)
    if (code in _POLICY_CODES) or status == 403:
        # A content refusal won't self-correct on retry — surface it like any
        # other model refusal.
        return BrainRefusalError(code or "policy", message)
    label = f"OpenAI API error {status}" + (f" [{code}]" if code else "")
    return BrainError(f"{label}: {message}")


def _guarded_call(create, request: dict[str, Any]) -> Any:
    """Run a `*.create(**request)` call, converting OpenAI API errors into
    BrainError so the loop can handle them cleanly (no raw traceback)."""
    try:
        return create(**request)
    except Exception as exc:  # noqa: BLE001 - remapped below or re-raised
        mapped = _map_openai_error(exc)
        if mapped is not None:
            raise mapped from exc
        raise


class OpenAIProvider:
    """Calls an OpenAI model via the OpenAI Python SDK (Chat Completions).

    The client is built from endpoint config in the environment (see
    `_endpoint`), so with nothing set it is the standard api.openai.com + Bearer
    behavior, and with the YHWACH_OPENAI_* vars it points at a custom / Azure
    gateway. Wire = Chat Completions."""

    name = "openai"
    models = MODELS

    # -- client (lazy, optional dep) ----------------------------------------

    def make_client(self) -> Any:
        # Reads OPENAI_API_KEY (or a configured key/header) from the environment.
        # Never hardcode a key.
        return build_client()

    # -- request building (pure) --------------------------------------------

    @staticmethod
    def _is_reasoning(model: str) -> bool:
        return is_reasoning_model(model)

    def build_request(
        self,
        *,
        model: str,
        system: str,
        context: str,
        history: list[dict] | None = None,
        effort: str = "high",
        max_tokens: int = 16000,
    ) -> dict[str, Any]:
        messages: list[dict] = [{"role": "system", "content": system}]
        messages.extend(history or [])
        messages.append({"role": "user", "content": context})
        req: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "tools": [
                {
                    "type": "function",
                    "function": {
                        "name": EMIT_ACTION_NAME,
                        "description": EMIT_ACTION_DESCRIPTION,
                        "parameters": EMIT_ACTION_SCHEMA,
                    },
                }
            ],
            # Force the single tool call; the orchestrator validates the args.
            "tool_choice": {
                "type": "function",
                "function": {"name": EMIT_ACTION_NAME},
            },
        }
        if self._is_reasoning(model):
            req["reasoning_effort"] = _reasoning_effort(effort)
            req["max_completion_tokens"] = max_tokens
        else:
            req["max_tokens"] = max_tokens
        return req

    # -- the call -----------------------------------------------------------

    def call(self, client: Any, request: dict[str, Any]) -> Any:
        return _guarded_call(client.chat.completions.create, request)

    # -- response parsing (pure) --------------------------------------------

    @staticmethod
    def extract_action(raw: Any) -> Action:
        choices = getattr(raw, "choices", None) or []
        if not choices:
            raise BrainNoActionError("model returned no choices")
        choice = choices[0]
        finish = getattr(choice, "finish_reason", None)
        msg = getattr(choice, "message", None)
        refusal = getattr(msg, "refusal", None) if msg is not None else None
        if refusal or finish == "content_filter":
            raise BrainRefusalError(
                "content_filter" if finish == "content_filter" else None,
                refusal,
            )

        tool_calls = getattr(msg, "tool_calls", None) or [] if msg is not None else []
        for tc in tool_calls:
            fn = getattr(tc, "function", None)
            if fn is not None and getattr(fn, "name", None) == EMIT_ACTION_NAME:
                data = fn.arguments
                if isinstance(data, str):  # OpenAI hands args back as a JSON string
                    data = json.loads(data)
                return action_from_payload(data)

        raise BrainNoActionError(f"model returned no emit_action call (finish_reason={finish})")

    @staticmethod
    def usage(raw: Any) -> dict[str, int]:
        u = getattr(raw, "usage", None)
        it = int(getattr(u, "prompt_tokens", 0) or 0) if u else 0
        ot = int(getattr(u, "completion_tokens", 0) or 0) if u else 0
        return {"input": it, "output": ot, "total": it + ot}


class OpenAIResponsesProvider(OpenAIProvider):
    """Calls an OpenAI-compatible model via the **Responses API**
    (`client.responses.create`), selected with `YHWACH_OPENAI_WIRE=responses`.

    This is the wire some gateways/deployments require — e.g. the Azure API
    Management `gpt-foundry` endpoint with model `gpt-5.6-sol`. Only the wire
    differs from the Chat Completions provider; provider selection, model
    tiering, endpoint config and the emit_action contract are shared.

    Shape differences from Chat Completions:
      * the persona is `instructions`; the turn is `input` (a list of items);
      * the function tool is *flat* (name at top level, not nested);
      * `tool_choice` names the function to force it;
      * the cap is `max_output_tokens`; reasoning models take `reasoning.effort`;
      * the reply is `output` items — a `function_call` item carries `.arguments`
        as a JSON string; usage is `input_tokens` / `output_tokens`.
    """

    def build_request(
        self,
        *,
        model: str,
        system: str,
        context: str,
        history: list[dict] | None = None,
        effort: str = "high",
        max_tokens: int = 16000,
    ) -> dict[str, Any]:
        input_items: list[dict] = list(history or [])
        input_items.append({"role": "user", "content": context})
        req: dict[str, Any] = {
            "model": model,
            "instructions": system,
            "input": input_items,
            "tools": [
                {
                    "type": "function",
                    "name": EMIT_ACTION_NAME,
                    "description": EMIT_ACTION_DESCRIPTION,
                    "parameters": EMIT_ACTION_SCHEMA,
                }
            ],
            # Force the single tool call; the orchestrator validates the args.
            "tool_choice": {"type": "function", "name": EMIT_ACTION_NAME},
            "max_output_tokens": max_tokens,
        }
        if is_reasoning_model(model):
            req["reasoning"] = {"effort": _reasoning_effort(effort)}
        return req

    def call(self, client: Any, request: dict[str, Any]) -> Any:
        return _guarded_call(client.responses.create, request)

    @staticmethod
    def extract_action(raw: Any) -> Action:
        status = getattr(raw, "status", None)
        for item in getattr(raw, "output", []) or []:
            itype = getattr(item, "type", None)
            if itype == "function_call" and getattr(item, "name", None) == EMIT_ACTION_NAME:
                data = getattr(item, "arguments", None)
                if isinstance(data, str):  # Responses hands args back as a JSON string
                    data = json.loads(data)
                return action_from_payload(data or {})
            if itype == "message":
                for part in getattr(item, "content", []) or []:
                    if getattr(part, "type", None) == "refusal":
                        raise BrainRefusalError(None, getattr(part, "refusal", None))

        if status == "incomplete":
            details = getattr(raw, "incomplete_details", None)
            reason = getattr(details, "reason", None) if details is not None else None
            if reason == "content_filter":
                raise BrainRefusalError("content_filter", None)

        raise BrainNoActionError(f"model returned no emit_action call (status={status})")

    @staticmethod
    def usage(raw: Any) -> dict[str, int]:
        u = getattr(raw, "usage", None)
        it = int(getattr(u, "input_tokens", 0) or 0) if u else 0
        ot = int(getattr(u, "output_tokens", 0) or 0) if u else 0
        return {"input": it, "output": ot, "total": it + ot}
