# CLI

The commands the engine exposes today, via the `yhwach` entry point (Click group).

DB location resolution (every command):

1. `--db` flag on the subcommand
2. `$YHWACH_DB`
3. `~/osai/current/state/yhwach.db` (matches `/osai-engage`'s lab directory)

Engagement artifacts (`recon/`, `loot/`) are derived relative to the DB: for the canonical
`<lab>/state/yhwach.db` layout they sit at `<lab>/<name>`; for a flat DB path they sit beside the
DB. Notes are **not** an artifact dir — the notebook is the Obsidian vault, written by the
operator via the Obsidian MCP (see [../persona/notebook.md](../persona/notebook.md)).

Almost every command takes `--lab <name>` to select the engagement.

## Engagement setup

### `yhwach engage --lab <name> --scope <cidr,...> [--domain <d>] [--dc <ip>]`

Create the SQLite DB if needed and upsert the engagement row (scope, optional AD domain/DC). The
`--scope` tokens are validated as IPs/CIDRs; a malformed token is rejected.

### `yhwach ingest <file> --lab <name> [--kind nmap|linpeas|winpeas|bloodhound|certipy] [--host <ip>]`

Parse a tool output file into the world model. `nmap` XML → hosts + services (idempotent).
`linpeas`/`winpeas` → host-scoped privesc findings (requires `--host`) and advances that host
to `enumerated`. `bloodhound` → AD findings + `findings_include` chaining tags (kerberoastable,
dcsync, unconstrained_delegation, …) on `--host` (the DC); accepts the normalized AD-facts JSON a
BloodHound MCP emits, or raw SharpHound collection files. `certipy` → ADCS findings (`adcs_vuln`)
from a certipy `-vulnerable -json` report on `--host` (the CA/DC). `bloodhound`/`certipy` don't
change the host stage.

### `yhwach enum --lab <name> --target <ip/cidr> [--ports <spec>] [--hexstrike-url <url>]`

Run nmap through HexStrike (delegated enumeration), save the raw XML to `recon/`, and ingest
it. **Refuses an out-of-scope `--target`** (checked against the engagement scope) before any
HexStrike traffic; a hostname target warns instead. Warns if the HexStrike URL is not loopback
(unauthenticated RCE over a network).

### `yhwach probe --lab <name> [--host <ip>] [--timeout <s>]`

Send short-timeout HTTP requests to scanned hosts and upsert detected **surfaces** — AI
(Ollama / OpenAI-compat / chatbot / MCP / Gradio / A2A / vector DB) and traditional
(Jenkins / GitLab / SMB / LDAP / MSSQL / WinRM / SSH / web / brokers).

## Planning and handoff

### `yhwach plan --lab <name>`

Deterministic — no LLM. Match every playbook rule's `when` clause against current surfaces and
upsert an EV-scored task per match. Reports rules loaded/matched, tasks created/updated, and any
rules skipped (technique consumed, denylisted host, or unsupported `when` keys).

### `yhwach next --lab <name> [--limit N] [--host <ip>] [--contract] [--no-persona] [--json]`

Default: a compact EV-ranked list of pending tasks. With `--contract`: the full operator context
block — persona frame, state, vault, P0 leads, **DEAD ENDS** (moves already reported as
failed/blocked), **ENUM GAPS**, and the ranked candidates with their commands — for Claude Code to
reason over into an Autonomy Contract. Yhwach never calls a model itself.

`--no-persona` replaces the ~7 KB persona body with its sha256: the frame is already in the
operator's context after turn 1, so later turns cost a fraction of the tokens while still pinning
*which* frame is in effect. `--json` emits the same slice as data (persona by digest) for an
operator that would rather parse than read.

### `yhwach recall --lab <name> [--events N] [--tasks N] [--json]`

**Catch up after a context reset.** A compact, persona-free digest of the engagement: elapsed time,
hosts by stage, counts, WINS and DEAD ENDS from the attempt ledger, P0 leads, enum gaps, blocked
hosts, the recent event timeline, and the next ranked moves. This is the first command to run in a
fresh operator session or after a `/compact` — the chat history is not the record, the DB is.

### `yhwach outcome --lab <name> --result success|fail|blocked|partial (--task <id> | --rule <id> [--host <ip>]) [--why <line>] [--evidence <ref>]`

**Record how a move went.** `technique_state` only ever recorded success; this records the other
three outcomes too, in the append-only `attempt` ledger:

| result | effect |
|---|---|
| `success` | technique consumed (planner stops proposing it), task → `done` |
| `fail` | task → `abandoned`, EV halved per failure at the next `plan`, listed as a DEAD END |
| `blocked` | task → `blocked`, same decay + DEAD END listing |
| `partial` | task stays queued; the attempt is still on the record |

Always pass `--why` — one line, for the operator you will be after your context is compacted. An
unrecorded attempt is an attempt you will repeat.

### `yhwach gaps --lab <name> [--host <ip>] [--all] [--json]`

Under-enumerated hosts and the exact scan that closes each gap, from the `scan_coverage` rows the
nmap ingest records (what a run actually **covered** — port range, `-sV`, UDP — not what it found).
A host is complete only with a full-port TCP scan, service versions and a UDP top-100 sweep.
Advisory, not a gate: `advance --to enumerated` warns rather than refusing, because scans
legitimately arrive out of band.

### `yhwach run --lab <name> --task <id> [--go] [--hexstrike-url <url>]`

Render the actions for a task. Read-only, self-contained actions run with `--go` (output captured
to `loot/`, findings extracted deterministically, lore-denylist artifacts flagged); proposal/
destructive/render-only actions are always printed for the operator to run. With `--hexstrike-url`
the read-only actions execute through HexStrike (delegated) instead of a local subprocess — same
extraction path, so AD enum output feeds the parsers automatically.

### `yhwach actions [--risk read_only|propose|destructive]`

List the registered actions (id, risk tier, run vs. render-only) from `yhwach/actions.py`.

## Post-foothold

### `yhwach advance --lab <name> --host <ip> --to <stage> [--force]`

Advance a host's FSM stage (`undiscovered → scanned → enumerated → foothold → looted → pivoted →
done`, or `blocked`). Monotonic by default (`--force` allows moving backwards). Reaching an
objective prints a reminder to write the host note in the Obsidian vault (via the Obsidian MCP).
Advancing to `enumerated` also warns (without refusing) when that host still has scan-coverage
gaps — see `yhwach gaps`.

### `yhwach proof --lab <name> --host <ip> --screenshot <path> [--flag <path>] [--flag-content <s>] [--no-advance]`

Bind a flag + screenshot to a host and advance it `foothold → looted`. The screenshot file must
exist — Yhwach refuses otherwise, because the screenshot is the evidence that gates `looted` (the
same gate `advance --to looted` enforces; `advance --force` overrides it). `--no-advance` records
the proof without moving the stage. Prints a reminder to mirror the screenshot into the Obsidian
vault.

### `yhwach pivot --lab <name> --via-host <ip> --subnet <cidr> [--lport N] [--no-advance]`

Record a pivot — a subnet now reachable through a host — and render the deploy commands: the
pre-staged obfuscated Ligolo agent (`svcmon.exe`) for a Windows pivot, a stock agent otherwise,
plus the Kali-side proxy/route. Recording the tunnel unblocks that host's `looted → pivoted`
transition (the engine refuses `pivoted` without one; `advance --force` overrides).

### `yhwach cred --lab <name> --user <id> [--secret <s>] [--kind ...] [--source ...] [--host <ip>]`

Add a credential to the vault (`password`/`ntlm`/`kerberos`/`ssh_key`/`api_key`/`token`/`dpapi`).
Credentials are never exhausted. Loot is an objective — the command reminds you to add it to the
Credentials note in the Obsidian vault.

### `yhwach creds --lab <name>`

List the credential vault (secrets masked).

### `yhwach spray --lab <name> [--proto smb|winrm|ssh|ldap|mssql|rdp]`

Render credential-spray commands (vault creds × sprayable surfaces). Proposal-tier: Yhwach
renders, the operator runs.

### `yhwach consume <technique> --lab <name> [--host <ip>]`

Mark a technique (rule id or `technique:` key) consumed for the engagement. Re-run `plan` to drop
it from the queue. OSAI labs don't reuse infra flaws. (`yhwach outcome --result success` does this
for you and records the attempt; use `consume` for a technique that never went through the queue.)

## Findings and reporting

### `yhwach findings --lab <name>`

List recorded findings, most severe first, with evidence.

### `yhwach report --lab <name> [--out <file>]`

Render a Markdown engagement report (scoreboard, findings, hosts, proofs, reachability/pivots, and
a timeline from the event log) to stdout or a file.

## Calibration and introspection

### `yhwach snapshot --lab <name> [--out <file>]`

Dump the current world model as a fixture YAML (with a blank `expected:` block to fill in) so a
real run becomes a permanent golden test.

### `yhwach selftest [--fixtures <dir>]`

Run every `*.yaml` golden fixture (recursively) and report pass/fail. Non-zero exit on failure.

### `yhwach persona`

Print the operator persona currently in effect plus its content hash — proof of which reasoning
frame Yhwach injects.

### `yhwach mcp`

Run Yhwach as an MCP (stdio) server for Claude Code. Needs `pip install yhwach[mcp]`. See
[../docs/deploy.md](../docs/deploy.md).
