"""Endpoint configuration for the OpenAI provider (additive).

The default OpenAI provider talks to api.openai.com with a Bearer key from
`OPENAI_API_KEY`. Some deployments (e.g. an Azure API Management gateway that
fronts an OpenAI-compatible model) need a custom base URL, a key sent in a
custom header, and an `api-version` query param. This module reads that from the
environment so pointing yhwach at such a gateway is configuration, not code.

Env vars (all optional; unset -> the standard api.openai.com + Bearer behavior):

  YHWACH_OPENAI_BASE_URL     base URL of the endpoint (also honors OPENAI_BASE_URL)
  YHWACH_OPENAI_API_VERSION  value for the `api-version` query param
  YHWACH_OPENAI_KEY_HEADER   header to carry the key (e.g. "api-key"); unset -> Bearer
  YHWACH_OPENAI_API_KEY_ENV  NAME of the env var holding the key (e.g. "ENV_CODEX_KEY")
  YHWACH_OPENAI_API_KEY      the key value directly (takes precedence over the *_ENV form)
  YHWACH_OPENAI_WIRE         "chat" (default) or "responses" — selects the wire API

Nothing here is secret: the key value is only read from the environment and
handed to the SDK client; it is never logged or written to disk.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from yhwach.brain import BrainError


@dataclass(frozen=True)
class OpenAIEndpoint:
    """Resolved endpoint configuration for building an OpenAI SDK client."""

    base_url: str | None = None
    key: str | None = None  # None -> let the SDK read OPENAI_API_KEY itself
    key_header: str | None = None  # e.g. "api-key"; None -> standard Bearer auth
    api_version: str | None = None  # -> {"api-version": ...} default_query

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> OpenAIEndpoint:
        env = os.environ if env is None else env
        base_url = env.get("YHWACH_OPENAI_BASE_URL") or env.get("OPENAI_BASE_URL") or None

        # Key value: an explicit value wins; else the NAME of an env var to read;
        # else None so the SDK falls back to OPENAI_API_KEY on its own.
        key = env.get("YHWACH_OPENAI_API_KEY")
        if not key:
            key_env_name = env.get("YHWACH_OPENAI_API_KEY_ENV")
            key = env.get(key_env_name) if key_env_name else None

        return cls(
            base_url=base_url,
            key=key or None,
            key_header=env.get("YHWACH_OPENAI_KEY_HEADER") or None,
            api_version=env.get("YHWACH_OPENAI_API_VERSION") or None,
        )

    @property
    def is_customized(self) -> bool:
        """True if any endpoint override is set (otherwise: plain OpenAI())."""
        return any((self.base_url, self.key, self.key_header, self.api_version))

    def client_kwargs(self) -> dict[str, Any]:
        """The kwargs for openai.OpenAI(...). Pure — no import, no network."""
        kw: dict[str, Any] = {}
        if self.base_url:
            kw["base_url"] = self.base_url
        if self.api_version:
            kw["default_query"] = {"api-version": self.api_version}
        if self.key_header:
            # Header auth (e.g. Azure APIM): the key rides in a custom header.
            # The SDK still requires a non-empty api_key for its Bearer header,
            # which the gateway ignores — send the same value (or a placeholder).
            kw["default_headers"] = {self.key_header: self.key or ""}
            kw["api_key"] = self.key or "unused"
        elif self.key is not None:
            kw["api_key"] = self.key
        return kw


def import_openai() -> Any:
    """Lazily import the OpenAI class with the standard install-hint on failure."""
    try:
        from openai import OpenAI
    except ImportError as exc:  # pragma: no cover - import-guard
        raise BrainError(
            "the 'openai' package is required to call the model. "
            "Install it with:  pip install 'yhwach[agent-openai]'"
        ) from exc
    return OpenAI


def build_client(endpoint: OpenAIEndpoint | None = None) -> Any:
    """Construct an openai.OpenAI client from endpoint config (env by default)."""
    endpoint = OpenAIEndpoint.from_env() if endpoint is None else endpoint
    if endpoint.key_header and not endpoint.key:
        raise BrainError(
            f"header auth requested (YHWACH_OPENAI_KEY_HEADER="
            f"{endpoint.key_header!r}) but no key was found. Set the key with "
            f"YHWACH_OPENAI_API_KEY, or name its env var with "
            f"YHWACH_OPENAI_API_KEY_ENV."
        )
    client_cls = import_openai()
    return client_cls(**endpoint.client_kwargs())
