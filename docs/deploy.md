# Deploy — wiring Yhwach to Claude Code on Kali

Yhwach is host-agnostic. It ships a strict operator persona and an Autonomy-Contract format the
operator writes back in; Yhwach itself never calls a model — it emits the persona-framed handoff and
the host LLM (Claude Code on Kali) does the reasoning. Whatever host runs it, Yhwach's frame shapes
the judgment. Two integration paths, from strongest to simplest.

## Path A — Yhwach as an MCP server (recommended)

`yhwach mcp` (needs `pip install yhwach[mcp]`) runs a stdio MCP server that exposes the engine
to Claude Code on Kali. It supports both the mcp<2 `FastMCP` API (what common Kali mcp installs pin)
and the mcp>=2 rename. Each tool resolves the engagement DB from `$YHWACH_DB` (default
`$YHWACH_DATA_DIR/state/yhwach.db`), so you set the lab once via the environment.

Tools exposed today (all take `lab`; read-only unless noted) — at parity with the CLI, so an
MCP-only operator can drive a whole engagement:

- `yhwach_engage`    — initialise/resume a lab (scope + optional domain/dc); call this first
- `yhwach_status`    — engagement scoreboard (hosts by stage, services, creds, gaps). **Call it
  first after a context reset** to catch up, then `yhwach_brief`.
- `yhwach_brief`     — the AI-legible engagement map (reach / hold / surfaces / gaps / objectives)
  + the complete recall menu of applicable techniques per host. This is the orient step.
- `yhwach_path`      — the shortest known route to the objective (prefer moves on it)
- `yhwach_ingest`    — ingest an nmap XML / linPEAS / winPEAS / bloodhound / certipy / netexec / web file
- `yhwach_enum`      — run nmap through HexStrike and ingest the result (delegated enumeration)
- `yhwach_scan` / `yhwach_recon` / `yhwach_probe` — drain the scan queue / full per-host picture / surface detection
- `yhwach_gaps`      — under-enumerated hosts + the exact nmap that closes each gap (full-port /
  `-sV` / UDP top-100) **and** un-triaged services (`service_enum`), from recorded coverage
- `yhwach_findings` / `yhwach_add_finding` — read / record findings (most severe first)
- `yhwach_add_cred` / `yhwach_creds` / `yhwach_spray` — add / read the vault, spray creds × surfaces
- `yhwach_add_loot` / `yhwach_vulns` — record loot / offline version→CVE enrichment
- `yhwach_poc` / `yhwach_poc_step` — record a reproducible flag chain (screenshot-gated)
- `yhwach_pivot` / `yhwach_add_interface` — record a pivot + render the ligolo/chisel deploy
- `yhwach_advance` / `yhwach_set_host` / `yhwach_tag` / `yhwach_untag` / `yhwach_derive` — FSM + tags + spray-candidate derivation
- `yhwach_ref`       — offline reference packs (incl. `arsenal`, `ai-attacks`, gtfobins/lolbas/esc/…)
- `yhwach_report` / `yhwach_export_notes` — Markdown report / DB-derived vault-table scaffolding

**Yhwach never calls a model here.** `yhwach_brief` / `yhwach_path` return the state + the recall
menu for the host (Claude Code) to reason over — the frame travels with the engine, the model call
is the host's. There is no EV ranker: the model ranks the menu.

Register in Claude Code (Kali):

```bash
YHWACH_DB=$YHWACH_DATA_DIR/state/yhwach.db claude mcp add yhwach -- yhwach mcp
```

or, editing the config directly:

```json
{
  "mcpServers": {
    "yhwach": {
      "command": "yhwach",
      "args": ["mcp"],
      "env": { "YHWACH_DB": "$YHWACH_DATA_DIR/state/yhwach.db" }
    }
  }
}
```

## Path B — CLI-only

If you prefer to keep everything in Bash: `yhwach brief` prints the engagement map to stdout; the operator reads it and acts. No LLM call from Yhwach's side. Simpler, but the reasoning inherits the host CLI's persona. Use this when experimenting or when the MCP is not yet wired.

## The engagement notebook — a LOCAL Obsidian vault (no MCP)

The narrative notebook is a **local Obsidian vault**: plain markdown files under
`$YHWACH_VAULT_DIR/<lab>/` on Kali, written with the normal file tools. There is no
Obsidian MCP — install Obsidian on Kali and open that folder to view it. The split:

- **yhwach.db** owns the ATOMS (hosts/creds/findings+tags/proofs/objectives) — recorded via
  `yhwach cred`/`proof`/`ingest`.
- **The vault** owns the NARRATIVE (chains, PoC, per-host/finding detail) plus a generated
  `_RESUME.md` (the context-recovery seed). Structure in `persona/notebook.md`.

The operator toolkit lives at `~/engagements/notekit/`:

1. `scaffold_vault.sh <lab>` — create the note-set (run by `/engage`).
2. `gen_resume.py` / `heartbeat.py` — the 10-min reconciliation heartbeat regenerates `_RESUME.md`
   from yhwach, backfills stubs, and flags evidence debt.
3. `shot.sh <host>_<slug> <host>` — a proof screenshot with UTC+local date/time burned in.

The persona (`persona/notebook.md`) carries a standing NOTEBOOK directive, so the write-up keeps pace with the run.

## Verifying independence

To confirm which reasoning frame Yhwach injects:

```bash
yhwach persona                          # prints the exact operator persona in use + its hash
```

The persona is content-hashed, and every `log_event` stamps that hash (plus a rule-set hash)
so a run can be replayed against the exact doctrine that produced it. Every judgment call reasons
over `yhwach brief`, which is built from the SQL-selected state slice plus this persona — not the
host CLI's own personality.

## MCP server security note

Yhwach's MCP server is intended for local use on the operator host (Kali). It does not authenticate callers — treat it like any local MCP. Do not expose the port beyond loopback. Ligolo tunnels reach loopback of the tunnel endpoint; keep the MCP off any interface a target can route to.
