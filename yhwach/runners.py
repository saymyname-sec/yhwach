"""Runners: turn a chosen candidate into a real tool execution.

The executor's `runner` seam (yhwach.actions.Runner) is what actually drives a
tool and returns a RunResult. `HexStrikeRunner` is the production runner for
**authorized lab enumeration**: for a candidate it looks up the technique's
`emits` actions, maps the read-only ones to concrete commands, runs them through
HexStrike, and pipes the output through `interpret_all` — the same deterministic
extractors the rest of yhwach uses — to produce typed findings.

Scope: this wires the **read-only enumeration** actions (SMB/LDAP/AD null-session
recon, AI-surface HTTP probes, spec/version fingerprints). An action with no
command mapped yields a `partial` result noting it isn't wired — honest, never a
faked success. Exploit-tier moves are gated by policy and are not run here.

OPSEC unchanged from hexstrike.py: point this only at a loopback / your-tunnel
HexStrike, never one exposed on an untrusted network.
"""

from __future__ import annotations

import json
import shlex
import sqlite3

from yhwach import interpret
from yhwach import knowledge as kn
from yhwach.actions import RunResult
from yhwach.hexstrike import HexStrikeClient

# What a delivered payload and its response are worth keeping. Both are stored in
# an event payload, which the operator reads back; `poc.add_step` caps its own
# output excerpt the same way.
_PAYLOAD_CAP = 2000
_RESPONSE_CAP = 4000

# Default ports for AI/traditional surfaces when the surface has no service row.
_DEFAULT_PORTS = {
    "ollama": 11434,
    "openai_compat": 8080,
    "openwebui": 8080,
    "gradio": 7860,
    "chatbot": 80,
    "rag": 80,
    "mcp": 8000,
    "a2a": 80,
    "vectordb": 8080,
    "redis": 6379,
    "metabase": 3000,
}

# Read-only enumeration commands, keyed by the catalog `emits` action id. {host}
# and {port} are filled per candidate. Only actions with a real extractor in
# interpret.py earn a command here, so their output becomes typed findings.
_COMMANDS: dict[str, str] = {
    # SMB / AD (netexec / smbmap / enum4linux / ldap) — null-session recon
    "netexec_smb_null": "nxc smb {host} -u '' -p '' --shares",
    "probe_writable_smb_share": "nxc smb {host} -u '' -p '' --shares",
    "smbmap_shares": "smbmap -H {host}",
    "enum4linux_ng": "enum4linux-ng -A {host}",
    "netexec_ldap": "nxc ldap {host}",
    "ldapsearch_anon": "ldapsearch -x -H ldap://{host} -s base namingcontexts",
    "netexec_pass_pol": "nxc smb {host} -u '' -p '' --pass-pol",
    "netexec_rid_brute": "nxc smb {host} -u '' -p '' --rid-brute",
    "netexec_maq": "nxc ldap {host} -u '' -p '' -M maq",
    "netexec_get_desc_users": "nxc ldap {host} -u '' -p '' -M get-desc-users",
    "ldap_anon_dump": "nxc ldap {host} -u '' -p '' --users",
    # Web/app recon — read-only GETs
    "jenkins_auth_check": "curl -s --max-time 8 http://{host}:{port}/api/json",
    "jenkins_oauth2proxy_bypass": "curl -si --max-time 8 http://{host}:{port}/api/json/x.css",
    "gitlab_public_repos": "curl -s --max-time 8 http://{host}:{port}/api/v4/projects?per_page=20",
    # AI surfaces — HTTP probes via curl (read-only GETs)
    "probe_ollama_models": "curl -s --max-time 8 http://{host}:{port}/api/tags",
    "probe_ollama_version": "curl -s --max-time 8 http://{host}:{port}/api/version",
    "probe_openapi_spec": "curl -s --max-time 8 http://{host}:{port}/openapi.json",
    "enumerate_models": "curl -s --max-time 8 http://{host}:{port}/v1/models",
    "mcp_tools_list": "curl -s --max-time 8 http://{host}:{port}/tools",
    "gradio_api_enumerate": "curl -s --max-time 8 http://{host}:{port}/config",
    "probe_n8n_version": "curl -s --max-time 8 http://{host}:{port}/rest/settings",
    # Kubernetes — anonymous read-only enum (braces in the JSON body are doubled
    # so str.format only substitutes {host}/{port}).
    "apiserver_version": "curl -sk --max-time 8 https://{host}:{port}/version",
    "apiserver_anonymous_rbac_review": (
        "curl -sk --max-time 8 -XPOST "
        "https://{host}:{port}/apis/authorization.k8s.io/v1/selfsubjectrulesreviews "
        "-H 'Content-Type: application/json' "
        "-d '{{\"kind\":\"SelfSubjectRulesReview\",\"apiVersion\":\"authorization.k8s.io/v1\","
        "\"spec\":{{\"namespace\":\"default\"}}}}'"
    ),
    "kubelet_pods_list": "curl -sk --max-time 8 https://{host}:{port}/pods",
    # Data stores / app setup — unauth reads (no credential, no payload)
    "redis_unauth_info": "redis-cli -h {host} -p {port} INFO server",
    "webapp_setup_probe": "curl -s --max-time 8 http://{host}:{port}/api/session/properties",
}

# Deliberately NOT fixed commands (they belong to other paths, not remote recon):
#   - cred-gated AD (kerberoast, asreproast, LAPS, gpohound, delegation): need a
#     recovered credential — future vault-reuse runner.
#   - post-foothold (IMDS/aws/k8s/registry): run from inside a host, not remotely.
#   - local-loot (inspect_private_key, inspect_workflow_config): parse looted files.
#   - CRAFT probes (ssti/lfi/ssrf/langflow/rag/try_direct_generate): need a
#     brain-generated payload — handled by the craft_and_run path, not here.


class HexStrikeRunner:
    """Executes read-only enumeration for a candidate via HexStrike."""

    def __init__(
        self,
        client: HexStrikeClient,
        conn: sqlite3.Connection,
        engagement_id: int,
        *,
        techniques: list | None = None,
    ) -> None:
        self.client = client
        self.conn = conn
        self.engagement_id = engagement_id
        self._by_id = {t.id: t for t in (techniques or kn.load_techniques())}

    def __call__(self, cand) -> RunResult:
        tech = self._by_id.get(cand.technique_id)
        emits = [e.get("action") for e in (tech.emits if tech else []) if isinstance(e, dict)]
        host = cand.host_ip
        port = self._port(cand)
        ctx = {
            "host": host,
            "IP": host,  # extractors read ctx["IP"] / ctx["URL"]
            "port": port,
            "URL": f"http://{host}:{port}" if port else host,
        }

        findings: list[dict] = []
        ran: list[str] = []
        any_ok = False
        notes: list[str] = []

        for action in emits:
            tmpl = _COMMANDS.get(action)
            if not tmpl:
                continue
            cmd = tmpl.format(host=host, port=port or "")
            try:
                data = self.client.run_command(cmd)
            except Exception as exc:  # network / HexStrike error — record, keep going
                notes.append(f"{action}: {type(exc).__name__}")
                continue
            ran.append(action)
            any_ok = any_ok or bool(data.get("success")) or data.get("return_code") == 0
            out = data.get("stdout", "") or ""
            for ef in interpret.interpret_all(action, out, ctx):
                findings.append(
                    {
                        "cls": ef.cls,
                        "title": ef.title,
                        "severity": ef.severity,
                        "evidence": ef.evidence,
                        "tag": ef.tag,
                    }
                )

        if not ran:
            return RunResult(
                result="partial",
                reason=f"no read-only runner wired for {cand.technique_id}",
                evidence=f"emits={emits or '[]'}",
            )
        result = "success" if any_ok else "partial"
        evidence = (
            f"{len(findings)} finding(s) from {', '.join(ran)}"
            if findings
            else f"ran {', '.join(ran)}"
        )
        if notes:
            evidence += f" (errors: {', '.join(notes)})"
        return RunResult(
            result=result,
            reason=f"hexstrike: {', '.join(ran)}",
            evidence=evidence,
            findings=findings,
        )

    def craft(self, cand, args: dict) -> RunResult:
        """Deliver a brain-crafted payload to the target and interpret the reply.

        This is the CRAFT path (prompt injection / SSTI / tool abuse / LFI / SSRF):
        the brain reasons over the surface and supplies `payload` plus how to
        deliver it (`method`/`path`/`param`/`content_type`); we assemble a curl,
        run it through HexStrike, and parse the response with the extractor named
        by `expect` (default: the technique's first emit action). All payloads are
        shell-quoted."""
        payload = args.get("payload")
        if not payload:
            return RunResult(result="partial", reason="craft_and_run needs args.payload")
        host = cand.host_ip
        port = self._port(cand)
        path = args.get("path") or "/"
        ctx = {
            "host": host,
            "IP": host,
            "port": port,
            "URL": f"http://{host}:{port}{path}",
        }
        cmd = self._build_craft_command(host, port, args)
        try:
            data = self.client.run_command(cmd)
        except Exception as exc:
            return RunResult(
                result="fail",
                reason=f"delivery error: {type(exc).__name__}",
                evidence=str(exc)[:120],
            )
        out = data.get("stdout", "") or ""
        tech = self._by_id.get(cand.technique_id)
        emits = [e.get("action") for e in (tech.emits if tech else []) if isinstance(e, dict)]
        expect = args.get("expect") or (emits[0] if emits else cand.technique_id)
        findings = [
            {
                "cls": ef.cls,
                "title": ef.title,
                "severity": ef.severity,
                "evidence": ef.evidence,
                "tag": ef.tag,
            }
            for ef in interpret.interpret_all(expect, out, ctx)
        ]
        ok = bool(data.get("success")) or data.get("return_code") == 0
        result = "success" if findings else ("partial" if ok else "fail")
        evidence = (
            f"{len(findings)} finding(s) via {expect}" if findings else f"delivered; {out[:100]}"
        )
        # A refusal is a fact, not an absence: it is what tells the operator to
        # escalate direct -> indirect -> encoded. interpret only used the regex
        # to SUPPRESS a finding, so the guardrail text reached no row at all.
        if findings:
            verdict = "signal"
        elif not ok:
            # Delivery itself failed. Calling that "silent" claimed the payload
            # landed and the target said nothing, which is a different fact.
            verdict = "not_delivered"
        elif interpret.looks_like_refusal(out):
            verdict = "refused"
        else:
            verdict = "silent"
        return RunResult(
            result=result, reason=f"craft->{expect}", evidence=evidence, findings=findings,
            payload=str(args.get("payload") or "")[:_PAYLOAD_CAP] or None,
            response=out[:_RESPONSE_CAP] or None,
            verdict=verdict,
        )

    def _build_craft_command(self, host: str, port: int | None, args: dict) -> str:
        """Assemble a shell-safe curl that delivers the payload. The brain controls
        method/path/param/content_type; the payload is always shlex-quoted."""
        method = (args.get("method") or "POST").upper()
        path = args.get("path") or "/"
        param = args.get("param")
        ctype = (args.get("content_type") or "json").lower()
        payload = str(args.get("payload"))
        base = f"http://{host}:{port}{path}"

        if method == "GET":
            if param:
                return (
                    f"curl -s --max-time 10 -G {shlex.quote(base)} "
                    f"--data-urlencode {shlex.quote(f'{param}={payload}')}"
                )
            return f"curl -s --max-time 10 {shlex.quote(base + payload)}"
        if ctype == "json":
            body = (
                payload if payload.lstrip()[:1] in "{[" else json.dumps({param or "input": payload})
            )
            return (
                f"curl -s --max-time 10 -X POST {shlex.quote(base)} "
                f"-H 'Content-Type: application/json' -d {shlex.quote(body)}"
            )
        if ctype == "form":
            field = param or "input"
            return (
                f"curl -s --max-time 10 -X POST {shlex.quote(base)} "
                f"-d {shlex.quote(f'{field}={payload}')}"
            )
        return f"curl -s --max-time 10 -X POST {shlex.quote(base)} -d {shlex.quote(payload)}"

    def _port(self, cand) -> int | None:
        if cand.surface_id:
            row = self.conn.execute(
                "SELECT svc.port p FROM surface s LEFT JOIN service svc ON svc.id=s.service_id "
                "WHERE s.id=?",
                (cand.surface_id,),
            ).fetchone()
            if row and row["p"]:
                return int(row["p"])
        return _DEFAULT_PORTS.get(cand.surface_kind)


# ── ArsenalDeployRunner ─────────────────────────────────────────────────────

class ArsenalDeployRunner:
    """Runner for pivot/revshell candidates from ``playbooks/pivot.yaml``.

    Dispatches on ``cand.technique_id`` into
    :data:`yhwach.pivot_renderers.RENDERERS` and returns a ``RunResult`` whose
    ``evidence`` field carries the exact command block the operator will run.

    Auto-execution is intentionally **not** built in this first cut: every
    handled rule is ``risk: exploit`` + ``action_class: listener`` (see
    ``playbooks/pivot.yaml``), so the executor already gates the candidate
    behind ``--allow listener`` before it ever calls this runner. When gated
    execution IS granted, delivery precedence will be Metasploit session ->
    Adaptix -> manual-render; that plumbing goes in a follow-up when we add a
    session registry the runner can look into. Today the runner is the single source of truth for
    "what would you run" — the CLI/MCP call it too.

    Params:
      * ``conn`` / ``engagement_id`` — memory access for host lookups.
      * ``kali_ip`` — required for renderers (embedded in the emitted cmds).
      * ``defaults`` — optional overrides for lport / subnet / kind /
        chisel-socks-port. When a candidate cannot determine a value from
        memory (e.g. the pivot host row has no OS) and no default is given,
        the runner returns ``partial`` with a descriptive reason rather than
        guessing — no faked commands.
    """

    def __init__(
        self,
        conn: sqlite3.Connection,
        engagement_id: int,
        *,
        kali_ip: str,
        defaults: dict | None = None,
    ) -> None:
        self.conn = conn
        self.engagement_id = engagement_id
        self.kali_ip = kali_ip
        self.defaults = dict(defaults or {})

    def _host_os(self, host_ip: str) -> str | None:
        row = self.conn.execute(
            "SELECT os FROM host WHERE engagement_id = ? AND ip = ?",
            (self.engagement_id, host_ip),
        ).fetchone()
        return row["os"] if row else None

    def render(self, cand) -> list[str]:
        """Pure render: return the command block for a candidate.

        Public so ``yhwach revshell`` / ``yhwach pivot`` (CLI) and
        ``tool_pivot`` (MCP) can call the same rendering path the runner
        uses — one source of truth for command generation.
        """
        from yhwach import pivot_renderers as pr

        renderer = pr.RENDERERS.get(cand.technique_id)
        if renderer is None:
            raise ValueError(
                f"ArsenalDeployRunner: no renderer for technique {cand.technique_id!r}; "
                f"pivot_renderers.RENDERERS covers only {sorted(pr.RENDERERS)}"
            )

        if cand.technique_id.startswith("pivot_"):
            subnet = self.defaults.get("subnet")
            if not subnet:
                raise ValueError(
                    f"ArsenalDeployRunner: pivot {cand.technique_id} requires "
                    "defaults['subnet'] — the CIDR the pivot exposes"
                )
            kwargs = {
                "target_ip": cand.host_ip,
                "kali_ip": self.kali_ip,
                "subnet": subnet,
            }
            if "lport" in self.defaults:
                kwargs["lport"] = self.defaults["lport"]
            if cand.technique_id == "pivot_chisel_linux" and "socks_port" in self.defaults:
                kwargs["socks_port"] = self.defaults["socks_port"]
            return renderer(**kwargs)

        # generate_* revshell renderers — kali_ip + lport are the essentials.
        lport = self.defaults.get("lport")
        if not lport:
            raise ValueError(
                f"ArsenalDeployRunner: revshell {cand.technique_id} requires "
                "defaults['lport'] — the operator-picked listener port"
            )
        kwargs = {"kali_ip": self.kali_ip, "lport": int(lport)}
        for opt in ("outdir", "iface", "max_retries", "jitter_ms"):
            if opt in self.defaults:
                kwargs[opt] = self.defaults[opt]
        # gen_linux_shell.sh does not accept retries/jitter; drop them silently.
        if cand.technique_id == "generate_linux_revshell":
            kwargs.pop("max_retries", None)
            kwargs.pop("jitter_ms", None)
        return renderer(**kwargs)

    def __call__(self, cand) -> RunResult:
        """Executor seam: render the command block, return partial result.

        ``partial`` is honest here: yhwach did NOT ship the binary or open
        the listener itself — the operator (or a follow-up delivery runner)
        does. The command block is the deliverable, carried in ``evidence``.
        """
        try:
            lines = self.render(cand)
        except ValueError as exc:
            return RunResult(
                result="partial", reason=f"unrenderable: {exc}",
                evidence=None, findings=[],
            )
        return RunResult(
            result="partial",
            reason=(
                f"{cand.technique_id}: rendered arsenal-deploy commands "
                "(operator runs; open network listener is action_class=listener)"
            ),
            evidence="\n".join(lines),
            findings=[],
        )
