"""The Provider adapter interface (wire 1).

A Provider owns everything vendor-specific about calling the model and reading
its answer, so `brain.Brain` can stay provider-agnostic. Each adapter is pure
and unit-testable with a fake client; only `make_client` touches the network
(and the optional vendor SDK, imported lazily there).

The five things an adapter translates:
  * make_client   - build the vendor SDK client (reads that vendor's API key)
  * build_request - assemble the create() kwargs in the vendor's shape
  * call          - the single network line (e.g. client.messages.create)
  * extract_action- normalize the raw response into a typed Action (or raise
                    BrainRefusalError / BrainNoActionError)
  * usage         - normalize token usage into {"input","output","total"}

`models` carries the per-provider role -> model-id tiering (strong for DOER and
the judge, cheap for INTERPRET/RANK).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

if TYPE_CHECKING:
    from yhwach.brain import Action, Role


@runtime_checkable
class Provider(Protocol):
    """Structural type for a wire-1 adapter. AnthropicProvider / OpenAIProvider
    satisfy it; a fake in a test can too."""

    name: str
    models: dict[Role, str]

    def make_client(self) -> Any:
        """Create the vendor SDK client. Lazily imports the SDK; raises
        BrainError with an install hint if the extra is missing."""
        ...

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
        """Assemble the create() kwargs. Pure - no network."""
        ...

    def call(self, client: Any, request: dict[str, Any]) -> Any:
        """Make the one live create() call and return the raw response."""
        ...

    def extract_action(self, raw: Any) -> Action:
        """Normalize the raw response into an Action, or raise Brain*Error."""
        ...

    def usage(self, raw: Any) -> dict[str, int]:
        """Normalize token usage into {"input","output","total"}."""
        ...
