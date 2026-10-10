---
description: Start or resume a lab and drive it through Yhwach (autonomous mode)
argument-hint: "[--lab <name> --scope <cidr> [--domain <d>] [--dc <ip>]]  (omit args to resume)"
---

# lab — Yhwach-driven

Arguments: `$ARGUMENTS`

This is **yhwach (autonomous) mode**: Yhwach is the world model + source of truth, and
you are the operator it hands off to. Atoms (hosts / creds / findings / proofs / coverage)
live in `yhwach.db`; the narrative lives in a local Obsidian vault under
`$YHWACH_VAULT_DIR/<lab>/`. Don't keep engagement state in your head or ad-hoc files.
(Outside this command, Claude runs in normal manual mode — yhwach is not required.)

## Step 0 — engage or resume
- **Args given** (fresh lab): call **`yhwach_engage`** with the lab / scope / domain / dc
  parsed from `$ARGUMENTS` (creates the DB + engagement — no bash needed).
- **No args** (resume): skip engage.

Then always call **`yhwach_status`** to load where we are (hosts by stage, services, creds,
open gaps). This is your rehydrate after any `/clear`.

## Step 1 — populate the world model (only if status shows nothing yet)
`yhwach_enum <scope-or-target>` (nmap via HexStrike → ingested) → `yhwach_probe` (AI +
traditional surfaces) → `yhwach_gaps` (any host not full-ported / no `-sV` / no UDP → fix it
NOW). If hosts already exist, skip to the loop.

## Step 2 — run the loop
Repeat until out of scored objectives or ~2h left (then compile the report):

1. **Orient** — `yhwach_brief` gives the AI-legible engagement map (state, leads, the complete
   recall menu of applicable techniques per host); `yhwach_path` prints the shortest known
   route to the objective; `yhwach_gaps` names what's still owed. Reason OBSERVE → ORIENT →
   DECIDE → ACT → ASSESS; pick the top move and say why. Yhwach hands you the *complete menu* —
   **you** rank it from the notes, leads, dead ends, and creds in hand (there is no EV ranker).
   Before committing to a host, `yhwach_recon --host <ip>` prints everything the model holds on it.
2. **Execute** — HexStrike MCP (enum/web), the arsenal (`yhwach revshell` / `yhwach pivot`,
   or `yhwach ref arsenal` for a quick-win script), `yhwach ref ai-attacks -q <topic>` for an
   AI chain, or the metasploit MCP.
3. **Fold the result back into Yhwach** (same turn):
   - `yhwach_ingest <file> --kind nmap|linpeas|winpeas|bloodhound|certipy|netexec|web --host <ip>`
     (web needs `--url`; netexec adds shares/users/admin/policy; bloodhound builds the AD graph)
   - `yhwach_vulns` after ingesting versions (offline version→CVE)
   - `yhwach_add_cred` on every recovered secret · `yhwach_add_finding` / `yhwach_add_loot`
   - `yhwach_poc` + `yhwach_poc_step` on a flag (records the reproducible chain; screenshot gated)
   - `yhwach_pivot --via-host <ip> --subnet <cidr>` on a new subnet · `yhwach_advance` when a
     host crosses a stage boundary
4. **Write the vault note** for this objective (local files under `$YHWACH_VAULT_DIR/<lab>/`), in
   full detail. `yhwach_export_notes` auto-scaffolds the DB-derived tables (services/software,
   vulns, web, users & groups, shares, per-host) so you write only the prose around them.
5. Re-orient — `yhwach_brief` / `yhwach_gaps` — then back to step 1.

## Rules
- **AI hosts first** — they are the priority tier. Yhwach surfaces AI surfaces early; a P0
  lead in the brief can override.
- **Proof = points** — `yhwach_poc` records the chain; capture the screenshot as you take the
  flag (whoami/hostname for traditional; the triggering request + model response for AI).
- **Full-Kali enumeration is primary; arsenal scripts are quick-wins.** Enumerate every service
  with HexStrike + the free shell before reaching for a script; "no script matched" ≠ "done".
- **Autonomy:** proceed on read-only/enum without asking; show the Autonomy Contract before
  exploitation; ask only on scope edges / destructive / two truly equal paths.
- **Arsenal is wired** — Windows foothold `yhwach revshell --os win` (gen_cs_shell.sh, AV-tested);
  Windows pivot `yhwach pivot` (svcmon.exe); never hand-craft. Fresh port per host, record it.
- Continuity lives in Yhwach's DB + the vault, not the context window — `/clear` freely, then
  `yhwach_status` + `yhwach_brief` to resume.

Begin now: run Step 0, then take the highest-value move.
