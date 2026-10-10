"""Brain: the agent's model caller (wire 1).

This is where yhwach calls the model. Per AGENT.md § "Runtime & connectivity",
wire 1 is a **provider adapter** authed with an API key from the environment —
not the Claude Code CLI, not MCP (MCP is wire 2, the tools the model reaches
*back* into). **Anthropic is the default**; OpenAI is available via the same
seam (see `yhwach.providers`), chosen at runtime with a flag / env var / model
id so swapping keys never needs a code edit.

A turn is: context in -> a single typed `Action` out. The brain does not run
the action, touch the world model, or decide the loop — the orchestrator owns
all of that. The brain only reasons over the handed-in context (persona + brief
+ candidates) and emits what it wants to do next, as structured data.

Design notes:
  * The vendor SDK is an **optional, lazily-imported** dependency (extras:
    `agent` for Anthropic, `agent-openai` for OpenAI). Importing this module
    never imports a vendor SDK, so the engine, tests and CI stay clean without a
    key or SDK installed.
  * The provider is **injectable** (`Brain(provider=...)`) and so is the SDK
    client (`Brain(client=...)`). Request-building and response-parsing live in
    the provider and are pure and unit-testable with a fake client; only the
    live call needs a key.
  * **Model tiering** is per call: a cheap model for interpret/rank, the strong
    model for craft and the judge (AGENT.md § Runtime). Each provider carries
    its own role -> model-id map.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from yhwach import persona_path

if TYPE_CHECKING:  # import only for type checkers, never at runtime
    from yhwach.providers.base import Provider


# --- model tiering ----------------------------------------------------------

# Model IDs are the current Claude generation. Strong = Opus for craft/judge;
# cheap = Haiku/Sonnet for high-volume interpret/rank. Override per Brain.
MODEL_STRONG = "claude-opus-5"
MODEL_MID = "claude-sonnet-5"
MODEL_CHEAP = "claude-haiku-4-5"


class Role(StrEnum):
    """What the brain is being asked to do this call — picks the default model."""

    DOER = "doer"  # reason over candidates, pick/craft the next move
    JUDGE = "judge"  # rule "is this phase done?" from evidence
    INTERPRET = "interpret"  # turn ambiguous tool output into a finding
    RANK = "rank"  # order candidates (cheap)


# The Anthropic (default) tiering. Each provider adapter carries its own copy;
# AnthropicProvider.models is this map.
DEFAULT_MODEL_FOR: dict[Role, str] = {
    Role.DOER: MODEL_STRONG,
    Role.JUDGE: MODEL_STRONG,
    Role.INTERPRET: MODEL_CHEAP,
    Role.RANK: MODEL_MID,
}


# --- the typed action the brain emits ---------------------------------------


@dataclass(frozen=True)
class Action:
    """A single decision from one brain turn. `action` is the verb (e.g.
    run_technique, request_approval, mark_phase_done, note); `args` carries its
    parameters; `rationale` is the one-line why. The orchestrator validates and
    executes — the brain never runs anything itself."""

    action: str
    rationale: str
    technique_id: str | None = None
    host_ip: str | None = None
    args: dict[str, Any] = field(default_factory=dict)


def action_from_payload(data: dict[str, Any]) -> Action:
    """Build an Action from a parsed emit_action tool payload. Shared by every
    provider adapter so the normalization is identical across vendors."""
    return Action(
        action=data["action"],
        rationale=data["rationale"],
        technique_id=data.get("technique_id"),
        host_ip=data.get("host_ip"),
        args=data.get("args") or {},
    )


# The tool the model calls to emit its decision. Defined once, vendor-neutral,
# then each provider wraps it in its own tool envelope. Not `strict`/closed on
# purpose: `args` is deliberately free-form (additionalProperties), which strict
# mode forbids — the orchestrator validates the parsed action instead.
EMIT_ACTION_NAME = "emit_action"
EMIT_ACTION_DESCRIPTION = (
    "Emit the single next action to take, with a one-line rationale. "
    "Call this exactly once. Do not narrate outside the tool call."
)
EMIT_ACTION_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "action": {
            "type": "string",
            "description": "the action verb: run_technique (run a fixed-command "
            "candidate), craft_and_run (deliver a payload you write — prompt "
            "injection / SSTI / tool abuse — put it in args.payload with "
            "args.method/path/param/content_type), request_approval, "
            "mark_phase_done, note",
        },
        "technique_id": {
            "type": ["string", "null"],
            "description": "catalog technique id this action targets, if any",
        },
        "host_ip": {
            "type": ["string", "null"],
            "description": "target host IP, if the action is host-scoped",
        },
        "args": {
            "type": "object",
            "description": "action-specific parameters",
        },
        "rationale": {
            "type": "string",
            "description": "one line: why this move, now",
        },
    },
    "required": ["action", "rationale"],
}

# Anthropic-shaped tool envelope (name/description/input_schema), kept as a
# module constant for the Anthropic adapter and back-compat.
EMIT_ACTION_TOOL: dict[str, Any] = {
    "name": EMIT_ACTION_NAME,
    "description": EMIT_ACTION_DESCRIPTION,
    "input_schema": EMIT_ACTION_SCHEMA,
}


class BrainError(RuntimeError):
    """Base for brain-call failures."""


class BrainRefusalError(BrainError):
    """The model declined the request (provider refusal signal)."""

    def __init__(self, category: str | None, explanation: str | None) -> None:
        self.category = category
        self.explanation = explanation
        super().__init__(f"model refused (category={category}): {explanation}")


class BrainNoActionError(BrainError):
    """The model returned without calling emit_action (e.g. hit max_tokens)."""


# --- provider construction --------------------------------------------------


def _coerce_provider(provider: Provider | str | None) -> Provider:
    """Turn None (default) / a name / an instance into a Provider instance.
    Lazily imports the adapter so no vendor SDK is imported at module load."""
    if provider is None:
        from yhwach.providers.anthropic import AnthropicProvider

        return AnthropicProvider()
    if isinstance(provider, str):
        from yhwach.providers import make_provider

        return make_provider(provider)
    return provider


# --- the brain -------------------------------------------------------------


class Brain:
    """One configured model caller. Cheap to construct; the SDK client is created
    lazily on first live call (or injected for tests). The vendor lives in the
    `provider` adapter — Anthropic by default."""

    def __init__(
        self,
        role: Role = Role.DOER,
        *,
        model: str | None = None,
        effort: str = "high",
        max_tokens: int = 16000,
        system: str | None = None,
        provider: Provider | str | None = None,
        client: Any | None = None,
    ) -> None:
        self.role = role
        self.provider = _coerce_provider(provider)
        self.model = model or self.provider.models[role]
        self.effort = effort
        self.max_tokens = max_tokens
        self._system = system
        self._client = client
        # token usage of the last decide() call, for budget accounting
        self.last_usage: dict[str, int] = {"input": 0, "output": 0, "total": 0}

    # -- client (lazy, optional dep) ----------------------------------------

    def _get_client(self) -> Any:
        if self._client is None:
            self._client = self.provider.make_client()
        return self._client

    # -- system prompt (persona) --------------------------------------------

    def system_prompt(self) -> str:
        """The persona frame. Explicit override wins; else the bundled operator
        persona travels with the engine (persona/operator.md)."""
        if self._system is not None:
            return self._system
        return persona_path().read_text(encoding="utf-8")

    # -- request building (pure) --------------------------------------------

    def build_request(self, context: str, *, history: list[dict] | None = None) -> dict:
        """Assemble the create() kwargs via the provider. Pure — no network."""
        return self.provider.build_request(
            model=self.model,
            system=self.system_prompt(),
            context=context,
            history=history,
            effort=self.effort,
            max_tokens=self.max_tokens,
        )

    # -- response parsing (pure) --------------------------------------------

    @staticmethod
    def _extract_action(response: Any) -> Action:
        """Back-compat shim: parse an Anthropic-shaped response. New code should
        use `brain.provider.extract_action`."""
        from yhwach.providers.anthropic import AnthropicProvider

        return AnthropicProvider.extract_action(response)

    # -- the turn -----------------------------------------------------------

    def decide(self, context: str, *, history: list[dict] | None = None) -> Action:
        """One brain turn: context in -> typed Action out. Makes the live call
        through the provider, then parses. The only method that touches the
        network."""
        client = self._get_client()
        raw = self.provider.call(client, self.build_request(context, history=history))
        self.last_usage = self.provider.usage(raw)
        return self.provider.extract_action(raw)
