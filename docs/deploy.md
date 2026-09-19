# Deploy — wiring Yhwach to Claude Code on Kali

Yhwach is host-agnostic. It ships a strict operator persona and an Autonomy-Contract format the
operator writes back in; Yhwach itself never calls a model — it emits the persona-framed handoff and
the host LLM (Claude Code on Kali) does the reasoning. Whatever host runs it, Yhwach's frame shapes
the judgment. Two integration paths, from strongest to simplest.

## Path A — Yhwach as an MCP server (recommended)

`yhwach mcp` (needs `pip install yhwach[mcp]`) runs a stdio MCP server that exposes the engine
to Claude Code on Kali. It supports both the mcp<2 `FastMCP` API (what Kali's OSAI stack pins)
and the mcp>=2 rename. Each tool resolves the engagement DB from `$YHWACH_DB` (default
`~/osai/current/state/yhwach.db`), so you set the lab once via the environment.

Tools exposed today (all take `lab`; read-only unless noted) — at parity with the CLI, so an
MCP-only operator can drive a whole engagement:

- `yhwach_engage`    — initialise/resume a lab (scope + optional domain/dc); call this first
- `yhwach_status`    — engagement scoreboard (hosts by stage, services, tasks, vault)
- `yhwach_ingest`    — ingest an nmap XML / linPEAS / winPEAS / bloodhound / certipy file
- `yhwach_enum`      — run nmap through HexStrike and ingest the result (delegated enumeration)
- `yhwach_probe`     — probe scanned hosts for AI + traditional surfaces
- `yhwach_plan`      — match playbooks against the world model; populate the task queue
- `yhwach_next`      — the operator context block (persona + state + ranked candidates + commands)
- `yhwach_run`       — render a task's actions; with `go=true`, execute read-only ones + extract findings
- `yhwach_findings`  — recorded findings, most severe first
- `yhwach_proof`     — bind a flag + screenshot to a host and advance `foothold → looted`
- `yhwach_pivot`     — record a pivot (subnet reachable via a host), render the Ligolo deploy, advance to `pivoted`
- `yhwach_advance`   — advance a host's FSM stage
- `yhwach_consume`   — mark a technique consumed (planner stops proposing it)
- `yhwach_add_cred` / `yhwach_creds` — add to / read the credential vault
- `yhwach_spray`     — credential-spray commands (vault creds × sprayable surfaces)
- `yhwach_report`    — full Markdown engagement report

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

## The engagement notebook — a LOCAL Obsidian vault (no MCP)

The narrative notebook is a **local Obsidian vault**: plain markdown files under
`/home/kapi/osai/ObisidanOSAI/<lab>/` on Kali, written with the normal file tools. There is no
Obsidian MCP — install Obsidian on Kali and open that folder to view it. The split:

- **yhwach.db** owns the ATOMS (hosts/creds/findings+tags/proofs/objectives) — recorded via
  `yhwach cred`/`proof`/`ingest`.
- **The vault** owns the NARRATIVE (chains, PoC, per-host/finding detail) plus a generated
  `_RESUME.md` (the context-recovery seed). Structure in `persona/notebook.md`.

The operator toolkit lives at `~/osai/notekit/`:

1. `scaffold_vault.sh <lab>` — create the note-set (run by `/osai-engage`).
2. `gen_resume.py` / `heartbeat.py` — the 10-min reconciliation heartbeat regenerates `_RESUME.md`
   from yhwach, backfills stubs, and flags evidence debt.
3. `shot.sh <host>_<slug> <host>` — a proof screenshot with UTC+local date/time burned in.

`yhwach next --contract` carries a standing NOTEBOOK directive, so the write-up keeps pace with the run.

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
