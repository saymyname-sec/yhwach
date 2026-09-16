# Autonomy Contract — output schema reference

Two representations, same content: the human-readable form the operator writes, and the JSON the engine parses. The engine tolerates the human form and extracts fields; the JSON form is what tests compare against.

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

## Validation

- All fields required (except in CRAFT / INTERPRET variants below).
- `hypotheses`: minimum 1 for CRAFT, minimum 2 for RANK.
- `playbook_rule_id`: must match an entry in `playbooks/**/*.yaml`.
- `autonomy`: enum-strict.

## CRAFT variant

For a CRAFT call the response is minimal: `recommended.autonomous[0]` carries the payload (fenced or escaped). Other fields may be `""` / `[]`. Tests verify `recommended.autonomous[0]` non-empty and shape-appropriate for the target surface.

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
