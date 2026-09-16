# Actions

Actions are the executable primitives that playbook rules reference by id. Each action is one of:

- **A shell/Python subprocess** — Yhwach spawns it, captures stdout, feeds it to the appropriate parser.
- **An MCP tool call** — Yhwach dispatches via HexStrike MCP, msf MCP, Obsidian MCP.
- **An LLM call** — CRAFT or INTERPRET, per `persona/contract.md`.

## Existing OSAI scripts we adopt

The following scripts (kept in Kapi's OSAI repo, referenced here as first-class actions in Phase 1) become Yhwach actions when the AI-surface slice lands:

- `session_enum_osai.py` -> `enumerate_chatbot_sessions`  (LLM01/02)
- `MITM_spoofer_stealthy` / `MITM_Spoofer_credential_stealer.py` -> `a2a_mitm`  (LLM01, A2A)
- `poison_injector.py` -> `forge_a2a_message`  (LLM01)
- `spoof_server.py` -> `agent_card_dns_spoof`  (A2A)
- `create_collision_document.py` -> `rag_collision_upload`  (LLM04)
- `zero_width_obfuscator.py` -> `rag_hide_injection`  (LLM01)
- `inspect_embeddings.py` -> `vectordb_inspect`  (LLM08)
- `inversion_attack.py` -> `embedding_inversion`  (LLM08)
- `weaviate_export.py` -> `vectordb_export`  (LLM08/02)
- `poison_template.py` -> `mcp_template_poison`  (LLM06)
- `sympify_payload.py` -> `mcp_sympify_rce`  (LLM06)
- `zwc_encode.py` -> `zero_width_encode`  (LLM01)
- `tokenizer_swap.py` -> `tokenizer_backdoor`  (LLM03)
- `train_poison.py` -> `training_data_poison`  (LLM04)
- `aws_ml_enum.sh` -> `enumerate_aws_ml`  (infra)
- `k8s_ml_enum.sh` -> `enumerate_k8s_ml`  (infra)
- `agent_port_discovery.sh` / `model_fingerprint.sh` -> `ai_surface_recon`  (LLM02)

Payload builders (not actions themselves, invoked by other actions):

- `loader_windows.py`, `loader_linux.py`, `xor_encrypt.py`, `revgen.sh`, `gen_cs_shell.sh`, `injectRemote.ps1`

## Adding an action

Actions live in `actions/`. Each file has a header block Yhwach parses on startup:

```python
# yhwach-action: <id>
# yhwach-inputs: <comma-separated arg names>
# yhwach-outputs: <parser_kind>          # nmap | http | winpeas | linpeas | raw
# authorized_only: true
```

Yhwach:

- Refuses to run an action file that lacks these headers.
- Sandboxes the subprocess (per-lab CWD, timeout, stdout/stderr captured to `~/osai/current/loot/`).
- Never runs an action whose enclosing rule has `authorized_only: false` — such rules cannot exist in this repo (CI check).
