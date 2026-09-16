# Deploy — wiring Yhwach to Claude Code on Kali

Yhwach is host-agnostic. It ships a strict operator persona and a JSON Autonomy Contract; whatever LLM host runs the judgment call, Yhwach dictates the reasoning frame. Two integration paths, from strongest to simplest.

## Path A — Yhwach as an MCP server (recommended)

`yhwach mcp` (needs `pip install yhwach[mcp]`) runs a stdio MCP server that exposes the engine
to Claude Code on Kali. It supports both the mcp<2 `FastMCP` API (what Kali's OSAI stack pins)
and the mcp>=2 rename. Each tool resolves the engagement DB from `$YHWACH_DB` (default
`~/osai/current/state/yhwach.db`), so you set the lab once via the environment.

Tools exposed today (all take `lab`; read-only unless noted):

- `yhwach_status`    — engagement scoreboard (hosts by stage, services, tasks, vault)
- `yhwach_plan`      — match playbooks against the world model; populate the task queue
- `yhwach_next`      — the operator context block (persona + state + ranked candidates + commands)
- `yhwach_findings`  — recorded findings, most severe first
- `yhwach_report`    — full Markdown engagement report
- `yhwach_spray`     — credential-spray commands (vault creds × sprayable surfaces)
- `yhwach_add_cred`  — add a credential to the vault
- `yhwach_advance`   — advance a host's FSM stage

**Yhwach never calls a model here.** `yhwach_next` returns the persona-framed context block for
the host (Claude Code) to reason over into an Autonomy Contract — the reasoning frame travels
with the engine, but the model call is the host's. (Persona-wrapped `craft`/`interpret`
delegation tools are on the roadmap; see [ROADMAP.md](../ROADMAP.md).)

Register in Claude Code (Kali):

```bash
YHWACH_DB=~/osai/current/state/yhwach.db claude mcp add yhwach -- yhwach mcp
```

or, editing the config directly:

```json
{
  "mcpServers": {
    "yhwach": {
      "command": "yhwach",
      "args": ["mcp"],
      "env": { "YHWACH_DB": "~/osai/current/state/yhwach.db" }
    }
  }
}
```

## Path B — CLI-only

If you prefer to keep everything in Bash: `yhwach next` prints the Autonomy Contract to stdout; the operator reads it and acts. No LLM call from Yhwach's side. Simpler, but the reasoning inherits the host CLI's persona (which is exactly the drift Yhwach exists to prevent). Use this when experimenting or when the MCP is not yet wired.

## The engagement notebook — Obsidian MCP

The notebook is an **Obsidian vault**, and it is the single source of truth for write-ups. Yhwach
does not store or render notes; the operator (Claude Code) writes them directly through an
**Obsidian MCP** at every objective. Register that MCP alongside Yhwach's:

1. In Obsidian, enable the **Local REST API** community plugin and copy its API key. Note the
   host/port it binds to (default `127.0.0.1:27124` HTTPS / `27123` HTTP; on a VMware setup it may
   bind to the host-only adapter so Kali can reach it).
2. Register an Obsidian MCP server in Claude Code (e.g. `obsidian-mcp` or any MCP that wraps the
   Local REST API), passing the API key and base URL via env — **never commit the key**.
3. The operator persona (`persona/operator.md`, full structure in `persona/notebook.md`) tells the
   model to create/update the index, per-host, Attack Chain, Credentials, Findings, Network Map,
   and Next Steps notes — in full detail — as the engagement progresses.

`yhwach advance` and `yhwach cred` print a reminder at each objective, and `yhwach next
--contract` carries a standing NOTEBOOK directive, so the write-up keeps pace with the run.

## Verifying independence

To confirm which reasoning frame Yhwach injects:

```bash
yhwach persona                          # prints the exact operator persona in use + its hash
```

The persona is content-hashed; a change to it flags all determinism fixtures for rebaseline
(`yhwach selftest`). Every judgment call reasons over `yhwach next --contract`, which is built
from the SQL-selected state slice plus this persona — not the host CLI's own personality.

## MCP server security note

Yhwach's MCP server is intended for local use on the operator host (Kali). It does not authenticate callers — treat it like any local MCP. Do not expose the port beyond loopback. Ligolo tunnels reach loopback of the tunnel endpoint; keep the MCP off any interface a target can route to.
