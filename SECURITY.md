# Security

## Authorized use only

Yhwach is offensive-security tooling. Use it only against systems you own or are
explicitly licensed to test. See [AUTHORIZATION.md](AUTHORIZATION.md). The project
and its authors are not responsible for misuse.

## Threat model & safety posture

Yhwach runs **locally**, as the operator's advisor. It is **not** a hosted service and
holds **no secrets of its own**. By design, on the operator's own box:

- **No API key.** The supported runtime is the MCP server (`yhwach mcp`); the MCP
  client is the brain. Yhwach never calls a model and needs no credential of its own.
- **Secrets are shown in clear** in the local world model and briefs. This is
  intentional for a single-operator local tool — the DB is yours. Two concrete
  hardening steps are kept regardless: the SQLite DB and its sidecars are created
  `0600` and the engagement directory `0700` (POSIX), and secrets are **masked in the
  `yhwach_query` JSON/text envelope** unless `reveal` is passed.

### Deterministic safety invariants

These are enforced in Python, not left to the model's judgment:

- **The board never binds `0.0.0.0`/`::`.** `yhwach ui` refuses a wildcard bind; it is
  a read view for the local operator only.
- **Record-only by default.** Outside `lab`/`ctf` engagements, scan/enum/probe/spray
  are gated and require an explicit, human **`yhwach arm`** — arming is a CLI act and
  is **never** an MCP argument. `YHWACH_AUTOSPRAY=0` is a hard override.
- **Typed scope with one chokepoint.** Every outbound action passes `assert_target`
  (exclude-wins); an empty scope refuses everything. Link-local/loopback/metadata IPs
  (e.g. `169.254.169.254`) are never materialised as targets.
- **Credential spray policy.** Dumped hashes and cracked passwords are `spray_policy =
  manual` and are **never** swept; only an explicitly named credential may spray.
  Provided credentials are never silently downgraded.
- **Capture is metadata-only.** Burp/HAR ingestion stores method, path, parameter
  *names*, auth requirement and status — never request/response bodies or secret
  values. Session fingerprints are a cookie/header *name* + value-hash (or JWT `sub`),
  never a hash of the whole header.

### Operator responsibilities

- **HexStrike is unauthenticated RCE.** Bind it to `127.0.0.1` and firewall its port
  (see [docs/setup.md](docs/setup.md)). Re-check the firewall after every pivot so a
  compromised target can never reach it.
- Keep the engagement directory and world-model DB on storage only you control.
- The experimental self-driving runtime (`yhwach run`, the `[agent]` extra) **does**
  consume an API key and is unsupported; prefer the MCP path.

## Reporting a vulnerability

To report a security issue in yhwach itself (not in a target you are testing), open a
GitHub security advisory on the repository, or contact the maintainer privately rather
than filing a public issue with exploit detail. Please include a minimal reproduction
and the affected version (`yhwach --version`).
