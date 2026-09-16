# Contributing to Yhwach

Yhwach is early. The most valuable contributions right now:

- **Playbook rules** — YAML under `playbooks/`, each traceable to a technique or class (OWASP-LLM, ATLAS, CVE, CWE). One rule per document; multiple documents per file OK.
- **Actions** — an `emits` id needs a command. Add an entry to `ACTION_REGISTRY` in `yhwach/actions.py` (or a standalone exploit script under `actions/`); see [actions/README.md](actions/README.md) for the run-vs-render policy.
- **Fixtures** — engagement snapshots under `tests/fixtures/` with an expected top-ranked hypothesis. These become permanent regression tests.
- **Lore denylist entries** — known OffSec dev artifacts (like `cloudbase-init`) that should be filtered from ranker output.
- **Parsers** — deterministic ingestion for a tool the engine doesn't yet understand.

## Rules for rules

- Every rule cites a source (module note, HackTricks path, InternalAllTheThings, ATLAS technique).
- Every rule has `authorized_only: true`.
- Every rule has ≥1 matching fixture (CI enforces).
- No hardcoded targets, credentials, or real engagement data in commits.

## Fixture format

See [tests/README.md](tests/README.md).

## Style

- Python: black, ruff, type hints.
- YAML: 2-space indent, snake_case keys.
- Commit messages: imperative, one-line summary + body if reasoning is non-obvious.

## Legal

By contributing you affirm that all data in your contribution comes from authorized labs or synthetic scenarios, not production systems or unauthorized targets.
