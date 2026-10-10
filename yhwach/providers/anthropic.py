"""Anthropic adapter (wire 1) - the default provider.

Holds exactly the request shape and response parsing yhwach used before the
provider split: a cached persona prefix in `system`, the `emit_action` tool,
adaptive thinking, and per-call effort. Behavior is unchanged; it just lives
behind the Provider interface now.
"""

from __future__ import annotations

import json
from typing import Any

from yhwach.brain import (
    DEFAULT_MODEL_FOR,
    EMIT_ACTION_TOOL,
    Action,
    BrainError,
    BrainNoActionError,
    BrainRefusalError,
    action_from_payload,
)


class AnthropicProvider:
    """Calls Claude via the Anthropic Python SDK (extra: ``agent``)."""

    name = "anthropic"
    # Role -> model tiering. Shared with brain.DEFAULT_MODEL_FOR (single source).
    models = DEFAULT_MODEL_FOR

    # -- client (lazy, optional dep) ----------------------------------------

    def make_client(self) -> Any:
        try:
            from anthropic import Anthropic
        except ImportError as exc:  # pragma: no cover - import-guard
            raise BrainError(
                "the 'anthropic' package is required to call the model. "
                "Install it with:  pip install 'yhwach[agent]'"
            ) from exc
        # Reads ANTHROPIC_API_KEY from the environment. Never hardcode a key.
        return Anthropic()

    # -- request building (pure) --------------------------------------------

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
        messages = list(history or [])
        messages.append({"role": "user", "content": context})
        return {
            "model": model,
            "max_tokens": max_tokens,
            "system": [
                {
                    "type": "text",
                    "text": system,
                    "cache_control": {"type": "ephemeral"},
                }
            ],
            "messages": messages,
            "tools": [EMIT_ACTION_TOOL],
            "thinking": {"type": "adaptive"},
            "output_config": {"effort": effort},
        }

    # -- the call -----------------------------------------------------------

    def call(self, client: Any, request: dict[str, Any]) -> Any:
        return client.messages.create(**request)

    # -- response parsing (pure) --------------------------------------------

    @staticmethod
    def extract_action(raw: Any) -> Action:
        stop = getattr(raw, "stop_reason", None)
        if stop == "refusal":
            details = getattr(raw, "stop_details", None)
            raise BrainRefusalError(
                getattr(details, "category", None),
                getattr(details, "explanation", None),
            )

        for block in getattr(raw, "content", []) or []:
            if getattr(block, "type", None) == "tool_use" and block.name == "emit_action":
                data = block.input
                if isinstance(data, str):  # tolerate a JSON string input
                    data = json.loads(data)
                return action_from_payload(data)

        raise BrainNoActionError(f"model returned no emit_action call (stop_reason={stop})")

    @staticmethod
    def usage(raw: Any) -> dict[str, int]:
        u = getattr(raw, "usage", None)
        it = int(getattr(u, "input_tokens", 0) or 0) if u else 0
        ot = int(getattr(u, "output_tokens", 0) or 0) if u else 0
        return {"input": it, "output": ot, "total": it + ot}
