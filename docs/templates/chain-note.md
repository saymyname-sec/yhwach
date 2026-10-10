# <ID> — <host> — <technique>

> **Status:** captured ✅ / in progress / blocked · **Proof:** `<flag file path>` · **Submit as:** `<IP / hostname>` · **Points:** <n>
> **Re-verified:** <date> — followed this note top-to-bottom on a fresh revert.
> **Capture points:** ☐ first shell ☐ privilege boundary ☐ proof

<!--
One note per flag / objective. Copy this file to chains/<ID>-<host>-<technique>.md.
Rules that made chain notes report-ready in real engagements:
- Write each step right after you run it, never "later".
- Commands run top-to-bottom as pasted: real IPs / users / paths inline. No $VARS the
  reader can't resolve, no ~/ or temp paths, no "same as Step 2 of another note".
- Output is a verbatim excerpt from the step's .txt sidecar, not a summary.
- Each embed sits on its own line, never in backticks or code blocks.
- A capture point with no screenshot gets the literal token  ⚠️ SCREENSHOT-MISSING .
-->

## 1. Target + objective

| | |
|---|---|
| Host | `<hostname>` · `<IP>` |
| Service | `<port/proto — product version>` |
| Objective | `<flag / proof file, or the objective in one line>` |
| Points | <n> |

## 2. Vulnerability

<Class / CVE / misconfiguration in one or two sentences — this becomes the finding in the report.>
<For chains that combine weaknesses: a numbered list, one per weakness.>

## 3. Prerequisites

Start here with nothing else:

- Access: <tunnel / route / VPN needed — link the note that set it up>
- Credentials: `<principal>` — from [[<chain note that produced it>]] (verified <date>)
- Tooling: <tools and versions, scripts in `scripts/`, keys in `loot/`>

## 4. Steps

### Step 1 — <verb> <object>

```bash
<the exact command, real values inline>
```

Output (verbatim, from `<timestamp>_<label>.txt`):

```
<key lines of console output>
```

<One line: what this proves — e.g. "privilege boundary crossed: user → local admin".>

![[<timestamp>_<label>.png]]

### Step 2 — <verb> <object>

```bash
<command>
```

Output (verbatim, from `<timestamp>_<label>.txt`):

```
<output>
```

<!-- Useful extras: a "control" step showing the blocked request before the bypass;
     a table of derived inputs and the step that produced each; GOTCHA notes on decoys. -->

## 5. Proof

One command, run **on the target as the compromised user**, whose output shows who you
are, where you are and the flag together:

```bash
<command that prints whoami/id + hostname + IP + the flag>
```

```
<verbatim output>
```

![[<timestamp>_<ID>-proof.png]]

<!-- AI targets: the exact triggering request AND the result showing real execution
     (tool output, job trace, listener hit) — never just the model repeating your input. -->

## 6. Source & modifications

### `scripts/<name>`

- **What it does:** <one line>
- **Source:** custom / <upstream URL> / <CVE or advisory>
- **Modifications:** none / <what you changed and why>
- **Run as:** `<exact command line, port used>`

```<language>
<full source>
```

## 7. Cleanup / notes

- Persistence installed: <what, where, how to remove>
- Left on target: <files, accounts, services>
- Durable vs ephemeral: <what survives a revert (creds, keys) and what must be redone (shells, tunnels, sessions)>
- Related: [[attack-chain]] · [[credentials]] · [[exhausted-approaches]]
