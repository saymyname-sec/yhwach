# Experimental — self-driving runtime (API key)

> ⚠️ **Not the supported way to run yhwach, and a work in progress.**
> The supported path is the **MCP server** (`yhwach mcp`), driven by Claude Code or
> Codex CLI with **no API key** — see the main [README](../../README.md).

yhwach also ships an optional runtime where it **calls a model itself** through an API key
and drives the loop autonomously: `yhwach/brain.py` (the SDK caller), `judge.py` (rules a
phase "done"), `orchestrator.py`, `workers.py`, and the provider adapters in
`yhwach/providers/` (Anthropic / OpenAI / Azure gateway). The CLI entry is `yhwach run`,
behind the `.[agent]` / `.[agent-openai]` extras.

**Status: experimental — needs more work.** It stays in the tree as a power mode and as the
deterministic `yhwach run --dry-run` harness, but it is **not** where current investment goes,
it is less battle-tested than the MCP path, and these docs may lag the code. For real use,
register yhwach as an MCP server and let Claude Code / Codex CLI be the brain.

Docs for this path:
- [`self-driving-openai-vm.md`](self-driving-openai-vm.md) — running the self-driving loop (OpenAI brain, unbudgeted)
- [`openai-azure-responses.md`](openai-azure-responses.md) — OpenAI / Azure API-Management gateway config
- [`agent-mode.md`](agent-mode.md) — the **CTF/exam methodology router** (optional `/lab` glue). It
  encodes lab doctrine ("proof = points", "speed beats stealth") and is **not** for real client
  engagements; never install it as your global `~/.claude/CLAUDE.md`. For real work, let
  `yhwach init --kind` write a per-engagement instruction fragment instead.
