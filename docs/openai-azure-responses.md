# OpenAI over a custom / Azure gateway (Responses API)

yhwach's self-driving brain can call an OpenAI-compatible model that lives behind
a custom gateway — for example an **Azure API Management** endpoint fronting a
`gpt-foundry` deployment (model `gpt-5.6-sol`). This is configuration only; the
provider seam and the `emit_action` contract are unchanged.

yhwach does **not** read a Codex `config.toml`. You reproduce those settings with
environment variables and run flags.

## Mapping a Codex `config.toml` to yhwach

Given a Codex config like:

```toml
model_provider = "azure_foundry"
model = "gpt-5.6-sol"

[model_providers.azure_foundry]
base_url = "https://apims-dev-01-airesorce.azure-api.net/gpt-foundry/openai"
wire_api = "responses"
query_params = { api-version = "2025-03-01-preview" }
env_http_headers = { "api-key" = "ENV_CODEX_KEY" }
```

the yhwach equivalent is:

| Codex setting | yhwach env var |
|---|---|
| `base_url` | `YHWACH_OPENAI_BASE_URL` |
| `wire_api = "responses"` | `YHWACH_OPENAI_WIRE=responses` |
| `query_params.api-version` | `YHWACH_OPENAI_API_VERSION` |
| `env_http_headers."api-key" = "ENV_CODEX_KEY"` | `YHWACH_OPENAI_KEY_HEADER=api-key` + `YHWACH_OPENAI_API_KEY_ENV=ENV_CODEX_KEY` |
| `model` | `--model gpt-5.6-sol` |

## Run it

```bash
pip install -e ".[agent-openai]"

# the gateway
export YHWACH_OPENAI_BASE_URL="https://apims-dev-01-airesorce.azure-api.net/gpt-foundry/openai"
export YHWACH_OPENAI_WIRE=responses
export YHWACH_OPENAI_API_VERSION=2025-03-01-preview
export YHWACH_OPENAI_KEY_HEADER=api-key
export YHWACH_OPENAI_API_KEY_ENV=ENV_CODEX_KEY

# the key the gateway checks (the value the api-key header carries)
export ENV_CODEX_KEY=<your-gateway-key>

yhwach run --lab lab01 --model gpt-5.6-sol
```

`--model gpt-5.6-sol` selects the OpenAI provider on its own (the `gpt` prefix),
so `--provider openai` is optional. `YHWACH_OPENAI_WIRE=responses` switches the
adapter from Chat Completions to the Responses API.

## Env var reference

| Var | Meaning | Default |
|---|---|---|
| `YHWACH_OPENAI_BASE_URL` | endpoint base URL (also honors `OPENAI_BASE_URL`) | api.openai.com |
| `YHWACH_OPENAI_WIRE` | `chat` or `responses` | `chat` |
| `YHWACH_OPENAI_API_VERSION` | value for the `api-version` query param | none |
| `YHWACH_OPENAI_KEY_HEADER` | header that carries the key (e.g. `api-key`) | none → Bearer auth |
| `YHWACH_OPENAI_API_KEY_ENV` | **name** of the env var holding the key | `OPENAI_API_KEY` |
| `YHWACH_OPENAI_API_KEY` | the key value directly (wins over `*_ENV`) | none |

With none of these set, the OpenAI provider behaves exactly as before: standard
`api.openai.com` with a Bearer `OPENAI_API_KEY`. The key value is only read from
the environment and handed to the SDK client; it is never logged or written to
disk.

## Notes

- **Key auth.** With `YHWACH_OPENAI_KEY_HEADER=api-key`, the key rides in that
  header (what Azure APIM checks). The SDK still sends a Bearer header with the
  same value, which the gateway ignores.
- **Reasoning models.** The `gpt-*-sol` family (and gpt-5/gpt-6 class, o-series)
  are treated as reasoning models, so effort maps to `reasoning.effort` and the
  cap is `max_output_tokens`.
- **Verify wiring without a key.** `yhwach run --lab lab01 --dry-run` walks the
  whole loop with no model call, and the unit tests in
  `tests/test_openai_azure.py` cover the endpoint config and the Responses
  adapter with fakes.
