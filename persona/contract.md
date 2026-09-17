# Autonomy Contract — output schema reference

The shape the **operator** writes its judgment in — two representations, same content: a
human-readable form and a JSON form. This is the operator's own discipline, not a format Yhwach
parses or validates: the engine emits the `yhwach next --contract` handoff and reads results back
through its typed CLI/MCP tools (`run`, `ingest`, `advance`, `proof`, `cred`, …). Keep the contract
tight because *you* are the check on it.

## Human form

```
STATE:        where the engagement is (one line)
FINDINGS:     - bullet
              - bullet
HYPOTHESES:   - <technique> · L(H|M|L) · pts(N) · rule(<id>) · why
              - ...
RESEARCH:     what was looked up + finding (or "none")
RECOMMENDED:  the pick + why it wins
  -> Manual:     $ command 1
                 $ command 2
  -> Autonomous: skill_or_action_1 -> skill_or_action_2
NEXT:         what this unlocks
AUTONOMY:     proceed | propose | ask
```

## JSON form

```json
{
  "state": "string, one line",
  "findings": ["string", "..."],
  "hypotheses": [
    {
      "technique": "string",
      "likelihood": "H|M|L",
      "points": 0,
      "playbook_rule_id": "string",
      "why": "string, one line"
    }
  ],
  "research": "string (or 'none')",
  "recommended": {
    "why": "string, one line",
    "manual": ["command 1", "command 2"],
    "autonomous": ["action_1", "action_2"]
  },
  "next": "string, one line",
  "autonomy": "proceed|propose|ask"
}
```

## Self-check (operator discipline — not engine-enforced)

- All fields present (except in the CRAFT / INTERPRET variants below).
- `hypotheses`: at least 1 for CRAFT, at least 2 for RANK.
- Every `playbook_rule_id` matches a real rule in `playbooks/**/*.yaml` — `yhwach next` lists the
  candidate rule ids, so cite from those.
- `autonomy` is one of proceed | propose | ask.

## CRAFT variant

For a CRAFT response the output is minimal: `recommended.autonomous[0]` carries the payload (fenced or escaped). Other fields may be `""` / `[]`.

## INTERPRET variant

For an INTERPRET call the response is either a `finding` object:

```json
{
  "class": "LLM01|LLM02|...|CWE-...|CVE-...|ATLAS-...",
  "title": "string, one line",
  "severity": "critical|high|medium|low",
  "evidence": "string, one line",
  "playbook_rule_id": "string"
}
```

or literal `null` (no finding in the output).
