---
description: Start or resume an OSAI lab and drive it through Yhwach
argument-hint: "[--lab <name> --scope <cidr> [--domain <d>] [--dc <ip>]]  (omit args to resume)"
---

# OSAI lab — Yhwach-driven

Arguments: `$ARGUMENTS`

You are the **operator**. Yhwach is the world model + planner + handoff and the source of truth —
do not keep engagement state in your head or in ad-hoc files. Set `YHWACH_DB=~/osai/current/state/yhwach.db`.

## Step 0 — engage or resume
- **Args given** (fresh lab): call **`yhwach_engage`** with the lab / scope / domain / dc parsed
  from `$ARGUMENTS` (this creates the DB + engagement — no bash needed). Also run
  `/osai-engage $ARGUMENTS` if the lab directories don't exist yet.
- **No args** (resume): skip engage.

Then always call **`yhwach_status`** to load where we are (hosts by stage, services, tasks, vault).
This is your rehydrate after any `/clear`.

## Step 1 — get the world model populated (only if status shows nothing yet)
`yhwach_enum <scope-or-target>` (nmap via HexStrike → ingested) → `yhwach_probe` (AI + traditional
surfaces) → `yhwach_plan` (rank tasks). If hosts already exist, skip to the loop.

## Step 2 — run the loop
Repeat until out of scored objectives or ~2h left (then `/osai-report`):

1. **`yhwach_next`** — it returns your persona frame, the **P0 LEADS** (do these first), the
   **PATH TO OBJECTIVE** (shortest known route to Domain Admins — prefer moves on it), and the
   EV-ranked candidates with concrete commands. Reason OBSERVE → ORIENT → DECIDE → ACT → ASSESS;
   pick the top move and say why. Before committing to a host, `yhwach_recon --host <ip>` prints
   everything the model holds on it.
2. **Execute** it — HexStrike MCP, a `/osai-*` skill, or the metasploit MCP.
3. **Fold the result back into Yhwach**:
   `yhwach_ingest <file> --kind nmap|linpeas|winpeas|bloodhound|certipy|netexec|web --host <ip>`
   (web needs `--url`; netexec adds shares/users/admin/policy, bloodhound builds the AD graph) ·
   `yhwach_vulns` after ingesting versions (offline version→CVE → `exploit_known_cve`) ·
   `yhwach_run --task N --go` (read-only auto-runs, findings + tags extracted) · `yhwach_cred` ·
   `yhwach_proof --host <ip> --screenshot <path>` on flags · `yhwach_pivot --via-host <ip> --subnet <cidr>`
   on new subnets · `yhwach_advance` / `yhwach_consume` · `yhwach_outcome` when a move resolves.
4. **Write the vault note** for this objective (local files under /home/kapi/osai/ObisidanOSAI/<lab>/),
   in full detail. `yhwach_export_notes` auto-scaffolds the DB-derived tables (services/software,
   vulns, web, users & groups, shares, per-host) as local files so you write only the prose around them.
5. **`yhwach_plan`** to re-rank, then back to `yhwach_next`.

## Rules
- **AI hosts first** — they are the 75-pt pass mark. Trust Yhwach's AI-first ranking; a P0 lead can override.
- **Proof = points** — `yhwach_proof` gates `foothold → looted` and refuses without a real screenshot.
- **Autonomy:** proceed on read-only/enum without asking; show the Autonomy Contract before exploitation;
  ask only on scope edges / destructive / two truly equal paths.
- **Pre-staged tooling** in `~/osai/current/tools/` (`svcmon.exe`, `svc.exe`) — use it, read the port
  from `instructions.txt`, never hand-craft.
- Continuity lives in Yhwach's DB + the Obsidian vault, not the context window — `/clear` freely, then
  `yhwach_status` + `yhwach_next` to resume.

Begin now: run Step 0, then take the highest-EV move.
