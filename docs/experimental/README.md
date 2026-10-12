# Experimental / historical

> The supported way to run yhwach is the **MCP server** (`yhwach mcp`), driven by
> Claude Code or Codex CLI with **no API key** — see the main [README](../../README.md)
> and [ARCHITECTURE.md](../../ARCHITECTURE.md).

## The self-driving runtime was removed

yhwach once shipped an optional runtime where it **called a model itself** through an
API key and drove the loop autonomously (`yhwach run`, the `brain` / `judge` /
`orchestrator` / `workers` modules, the provider adapters, and the `[agent]` extras).
That runtime has been **removed**. yhwach is an advisor with a memory: the MCP client
is the brain, and yhwach never calls a model. The old code lives in git history if you
need it.

## What stays here

- [`agent-mode.md`](agent-mode.md) — the **CTF/exam methodology router** (optional `/lab`
  glue for lab/CTF work). It drives yhwach over the supported MCP tools, but encodes lab
  doctrine ("proof = points", "speed beats stealth") that is **wrong for real client
  engagements** — never install it as your global `~/.claude/CLAUDE.md`. For real work,
  let `yhwach init --kind` write a per-engagement instruction fragment instead.
