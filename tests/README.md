# Testing Yhwach

Reasoning quality is the risk. Testing is the defense.

## Layers

- **Structural.** `yhwach next` always returns a valid Contract (all fields present, JSON parses, autonomy tier enum-valid, every hypothesis `playbook_rule_id` matches a rule in `playbooks/**/*.yaml`). Property-based. Fast.
- **Determinism.** Same fixture in -> same next-action out with `temperature = 0` and a fixed persona hash. Any drift is a regression.
- **Coverage.** Every playbook rule triggered by >= 1 fixture; every fixture triggers >= 1 rule. Prevents dead rules and blind spots.
- **Golden (labeled).** Each fixture declares an expected `top_hypothesis.playbook_rule_id`. Deviations require a rule change or a fixture update — never silent.

## Fixture format

```yaml
# tests/fixtures/ai_chatbot_no_guardrails.yaml
name: ai_chatbot_no_guardrails
description: |
  Web app on port 8000 with /api/chat endpoint. Ollama on 11434 exposed.
  No auth on either. Classic OSAI capstone opener.

world_model:
  engagement:
    lab: fixture
    scope: [10.10.10.0/24]
  hosts:
    - ip: 10.10.10.15
      os: linux
      stage: scanned
      services:
        - {port: 8000, proto: tcp, product: uvicorn, version: 0.24.0}
        - {port: 11434, proto: tcp, product: ollama, version: 0.1.28}
      surfaces:
        - {kind: chatbot, auth: none, meta: {endpoint: /api/chat}}
        - {kind: ollama, auth: none, meta: {}}

expected:
  autonomy: proceed
  top_hypothesis:
    playbook_rule_id: ollama_unauth_api
    likelihood: H
  must_include_hypotheses:
    - ollama_unauth_api
    - chatbot_direct_injection_probe
    - rag_upload_discovery
  must_not_include: []
```

## The async lab loop — this is the primary test source

1. Run a lab on Kali with Yhwach driving.
2. Engine actions are logged to the `event` table.
3. Post-lab: `yhwach snapshot --lab <name> --out tests/fixtures/labs/<labname>/<host>.yaml`
   dumps the world model as a fixture with a blank `expected:` block.
4. Fill in `expected.top_hypothesis` with the pick you judge correct (your correction, if the
   engine's live pick was wrong).
5. Design pass on Windows: fix rules until the fixture passes (`yhwach selftest` / `pytest`).

Every wrong call becomes a permanent regression test. The corpus grows monotonically.

## Determinism knobs

- Persona is content-hashed. A persona change flags all determinism tests for rebaseline.
- Playbook rules are content-hashed. Changing a rule flags dependent fixtures.
- LLM call inputs are hashed. Same-hash call may replay from cache during test runs (no LLM roundtrip).
