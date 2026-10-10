"""Provider selection for wire 1 (the model caller).

`brain.Brain` is provider-agnostic; a `Provider` adapter owns the vendor-specific
request/parse/usage. This package holds the adapters and the runtime resolver
that decides which one to use, so swapping Anthropic <-> OpenAI is configuration
(a flag, an env var, or the model id), never a code edit.

Selection precedence (highest first), see `resolve_provider`:
  1. explicit provider name (e.g. a --provider flag)
  2. YHWACH_PROVIDER env var
  3. inferred from the model id (claude* -> anthropic, gpt*/o* -> openai)
  4. the single API key that is present in the environment
  5. both keys present and nothing else -> ambiguous, raise (never guess the
     one that costs money)
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # avoid importing adapters (and their brain import) at load
    from yhwach.providers.base import Provider

# Canonical provider names. The order is also the default preference order.
PROVIDER_NAMES: tuple[str, ...] = ("anthropic", "openai")

# Env var holding the API key for each provider.
API_KEY_ENV: dict[str, str] = {
    "anthropic": "ANTHROPIC_API_KEY",
    "openai": "OPENAI_API_KEY",
}

# Model-id prefixes that uniquely imply a provider.
_MODEL_PREFIXES: dict[str, tuple[str, ...]] = {
    "anthropic": ("claude",),
    "openai": ("gpt", "o1", "o3", "o4"),
}


class ProviderError(RuntimeError):
    """Bad provider selection (unknown name, unusable configuration)."""


class ProviderAmbiguityError(ProviderError):
    """More than one provider is possible and nothing chose between them."""


def infer_provider_from_model(model: str | None) -> str | None:
    """Return the provider a model id implies, or None if it implies none."""
    if not model:
        return None
    m = model.strip().lower()
    for name, prefixes in _MODEL_PREFIXES.items():
        if any(m.startswith(p) for p in prefixes):
            return name
    return None


def _normalize(name: str, *, source: str) -> str:
    n = name.strip().lower()
    if n not in PROVIDER_NAMES:
        raise ProviderError(
            f"{source} names an unknown provider {name!r}; "
            f"choose from {', '.join(PROVIDER_NAMES)}"
        )
    return n


def resolve_provider(
    provider: str | None = None,
    *,
    model: str | None = None,
    env: Mapping[str, str] | None = None,
) -> str:
    """Decide which provider to use, by the documented precedence. Pure: reads
    only the passed args and `env` (defaults to os.environ). Raises
    ProviderError / ProviderAmbiguityError rather than guessing."""
    env = os.environ if env is None else env

    if provider:
        return _normalize(provider, source="--provider")

    env_choice = env.get("YHWACH_PROVIDER")
    if env_choice:
        return _normalize(env_choice, source="YHWACH_PROVIDER")

    inferred = infer_provider_from_model(model)
    if inferred:
        return inferred

    present = [name for name in PROVIDER_NAMES if env.get(API_KEY_ENV[name])]
    if len(present) == 1:
        return present[0]
    if len(present) > 1:
        raise ProviderAmbiguityError(
            "both "
            + " and ".join(API_KEY_ENV[n] for n in present)
            + " are set; disambiguate with --provider, YHWACH_PROVIDER, or a "
            "--model whose name implies the provider (claude* / gpt*)."
        )

    # No key at all: keep the historical default. The missing-key error surfaces
    # later, at the live call, with an actionable message.
    return "anthropic"


def _openai_wire(env: Mapping[str, str]) -> str:
    """Which OpenAI wire to use: 'chat' (default) or 'responses'."""
    wire = (env.get("YHWACH_OPENAI_WIRE") or "chat").strip().lower()
    return "responses" if wire in ("responses", "response") else "chat"


def make_provider(name: str, *, env: Mapping[str, str] | None = None) -> Provider:
    """Construct a provider adapter by name. Cheap — the vendor SDK is not
    imported until the adapter's first live call (`make_client`).

    For OpenAI the wire (Chat Completions vs Responses API) is read from
    YHWACH_OPENAI_WIRE, so a gateway that requires the Responses API is selected
    by config, not a different provider name."""
    env = os.environ if env is None else env
    n = _normalize(name, source="provider")
    if n == "anthropic":
        from yhwach.providers.anthropic import AnthropicProvider

        return AnthropicProvider()
    if n == "openai":
        if _openai_wire(env) == "responses":
            from yhwach.providers.openai import OpenAIResponsesProvider

            return OpenAIResponsesProvider()
        from yhwach.providers.openai import OpenAIProvider

        return OpenAIProvider()
    raise ProviderError(f"unknown provider {name!r}")  # pragma: no cover


__all__ = [
    "PROVIDER_NAMES",
    "API_KEY_ENV",
    "ProviderError",
    "ProviderAmbiguityError",
    "infer_provider_from_model",
    "resolve_provider",
    "make_provider",
]
