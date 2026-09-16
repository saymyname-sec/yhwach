# Deploy — wiring Yhwach to Claude Code on Kali

Yhwach is host-agnostic. It ships a strict operator persona and a JSON Autonomy Contract; whatever LLM host runs the judgment call, Yhwach dictates the reasoning frame. Two integration paths, from strongest to simplest.

## Path A — Yhwach as an MCP server (recommended)

Yhwach exposes an MCP server with these tools:

- `yhwach.engage`
- `yhwach.ingest`
- `yhwach.next`          # LLM RANK call, engine-managed
- `yhwach.craft`         # LLM CRAFT call, engine-managed
- `yhwach.interpret`     # LLM INTERPRET call, engine-managed
- `yhwach.record_proof`
- `yhwach.status`
- `yhwach.replay`

For the three LLM tools, Yhwach delegates the actual model call back to the host (Claude Code on Kali) — but wraps it: the operator persona is injected as the system prompt of that call, the state slice is the user message, and the response is parsed against `persona/contract.md` before returning. **The host CLI's own personality never sees the judgment turn.** That is the independence guarantee.

Register in Claude Code (Kali):

```json
// ~/.config/claude/config.json
{
  "mcpServers": {
    "yhwach": {
      "command": "yhwach",
      "args": ["mcp"]
    }
  }
}
```

## Path B — CLI-only

If you prefer to keep everything in Bash: `yhwach next` prints the Autonomy Contract to stdout; the operator reads it and acts. No LLM call from Yhwach's side. Simpler, but the reasoning inherits the host CLI's persona (which is exactly the drift Yhwach exists to prevent). Use this when experimenting or when the MCP is not yet wired.

## Verifying independence

To confirm Yhwach's persona overrode the host CLI on the last judgment call:

```bash
yhwach persona --print                  # prints exact system prompt in use + hash
yhwach replay <event_id>                # re-runs a past judgment call; output must be byte-identical
```

If replay drifts, the persona wasn't in effect, or a rule/persona hash changed.

## MCP server security note

Yhwach's MCP server is intended for local use on the operator host (Kali). It does not authenticate callers — treat it like any local MCP. Do not expose the port beyond loopback. Ligolo tunnels reach loopback of the tunnel endpoint; keep the MCP off any interface a target can route to.
