# Yhwach architecture — the engagement memory for an AI operator

**Yhwach is a database. It collects everything about the engagement and tags what is still
unexplored. It does not decide anything.** The AI (Claude) reads the memory and finds the paths.

This supersedes the "deterministic engine / EV ranker / next move" model. The ranker, the playbook
rules, and `yhwach next`/`plan`/`run` are removed — they only confused the operator. Judgment is the
model's job; yhwach's job is a complete, honest, traversable record.

## The two responsibilities
1. **Collect** — every fact from every tool/file/response lands in `yhwach.db`: hosts, services,
   software/versions, web dirs/params/vhosts, SMB/NFS shares + access, AD principals/groups/privileges,
   users, files (path + summary + secret?), credentials/tokens, findings, loot, tunnels, objectives —
   and the **edges** between them (which cred works on which host, which host reaches which subnet,
   which finding unlocks which target). Fresh DB per engagement.
2. **Tag what's left** — every fact carries a status tag so the AI can see the frontier:
   `host:unscanned|scanned|enumerated`, `service:unprobed`, `share:unread`, `file:unread`,
   `cred:untried-on[…]`, `surface:gated(needs cred X)`, `subnet:unreached`. A discovered-but-unscanned
   name (from an `/etc/hosts`, a cert SAN, a config) is auto-added as `host:unscanned` so it never
   falls off the map.

## The read surface — `yhwach brief`
The one thing the AI reads when asked to reason. Grouped for path-finding, not ranked:
- **REACH** — hosts touchable now + how (shell / tunnel / web-auth) + current subnet(s)
- **HOLD** — creds/tokens/keys + where each is validated / still untried
- **SURFACES** — per reachable host: open services + web/SMB/AI surfaces + auth state
- **UNLOCKS** — gated targets + the atom that would open them (AI target X needs cred for svc Y)
- **UNEXPLORED** — the frontier from the tags (unscanned hosts, unprobed services, unread shares/files,
  discovered-but-unscanned names, coverage gaps)
- **OBJECTIVES** — flags + which host + reached-via
Sliceable: `yhwach brief [--host X | --reach | --unlocks | --unexplored]`.

## The loop (operator methodology, enforced by the tags, not a ranker)
```
enumerate EVERYTHING reachable  →  collect it into yhwach (ingest/cred)  →  loot  →
write the vault note  →  new host in a new subnet? persist (revshell) + Ligolo + `yhwach pivot`  →
re-enumerate the new subnet  →  repeat
```
- **Everything can contain info**: ports, files, web apps, shares, AD. A target is "done" only when
  `yhwach brief` shows no `un*` tags for it — the tags are the completeness signal.
- **AI targets are the priority** but often cred-gated; `UNLOCKS` shows which credential/path opens
  them, so the AI knows to fetch the cred on a traditional path first, then return.
- **Reasoning is on-demand**: only when Kapi asks does the AI read `yhwach brief` and propose the path.

## Notebook (local Obsidian vault, no MCP)
`/home/kapi/osai/ObisidanOSAI/<lab>/` — the human narrative + a generated `_RESUME.md` snapshot of the
brief. **Every flag the AI finds gets a note with the exact, reproducible "how to get it" chain.**
Proofs/screenshots are the operator's job — yhwach and CLAUDE.md say nothing about them.

## What yhwach is NOT
No EV ranker, no playbook rules, no autonomy gates, no `next`/`plan`/`run`, no proof/screenshot
handling. If a feature decides *what to do next*, it does not belong in yhwach.
