# CLI (planned)

Subcommands the engine will expose. Not implemented yet; this is a scoping doc so the shape is agreed before the Python lands.

## `yhwach engage --lab <name> --scope <cidr,...> [--domain <d>] [--dc <ip>]`

Initialize a lab. Creates the SQLite DB (default: `~/osai/current/state/yhwach.db`), seeds an `engagement` row, imports scope.

Sits *alongside* `/osai-engage` — /osai-engage owns lab bootstrap directories; Yhwach owns the world model inside them.

## `yhwach ingest <file> [--kind nmap|winpeas|linpeas|nuclei|http|hexstrike]`

Parse a tool output file. Auto-detects `--kind` when omitted. Advances host FSMs where predicates now pass. Idempotent — running twice on the same file is a no-op except for the timestamp on `event`.

## `yhwach next [--host <ip>] [--focus <topic>]`

Query the planner: rank open tasks by EV, print the Autonomy Contract for the top pick. Optionally scoped to a host or a topic ("AD", "AI targets", "what next").

Calls the LLM operator for RANK; the persona is loaded from `persona/operator.md`; input is the SQL-selected state slice. Output is a validated Contract JSON, pretty-printed as human form.

## `yhwach status`

Read-only scoreboard: hosts x stage, points scored, points open, open tasks, blocked tasks. No LLM call.

## `yhwach record-proof --host <ip> --file <flag_path> --screenshot <path>`

Bind a proof file + screenshot to a `proof` row and advance the host to `looted`. Refuses if the screenshot does not exist. Optional `--vault <path>` mirrors to Obsidian via MCP.

## `yhwach craft <technique_id> --target <surface_id>`

CRAFT call: LLM produces a payload for the given technique against the given surface. Persona-driven, structured output only. Payload goes into `recommended.autonomous[0]`.

## `yhwach interpret <file> --expect <signal> [--surface <id>]`

INTERPRET call: LLM extracts a `finding` (or null) from a raw output slice. Writes the finding to the DB. `--expect` is a hint to the operator (e.g. "look for tool exposure", "look for SSRF").

## `yhwach render [--target obsidian|report|both]`

Sync the world model to Obsidian (via MCP) and/or write a Markdown engagement report. Idempotent.

## `yhwach heartbeat`

Cheap append-only tick to `event` + a state snapshot. Meant to be driven by the OSAI heartbeat hook.

## `yhwach persona --print`

Print the exact operator persona currently in use, plus its content hash. Useful for verifying that Yhwach's frame — not the host CLI's — is what shaped the last judgment call.

## `yhwach replay <event_id>`

Re-run a past judgment call with the same inputs. Output must be byte-identical (temperature = 0, same persona hash). Drift = test failure.

## `yhwach mcp`

Run Yhwach as an MCP server. See `docs/deploy.md`.
