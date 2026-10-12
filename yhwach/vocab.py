"""One argument vocabulary for the MCP wire (I61).

FastMCP only forwards each tool's short spec string to the model, so the rich
docstrings on the functions never reach it — the model is left guessing argument
shapes. ``describe`` regenerates a tool's description from its own signature plus
this single vocabulary table, appending an ``args:`` line (required args marked
``*``, with a hint) and a runnable ``example:`` line. ``catalog`` renders the
whole surface for ``yhwach_schema``.

Pure and SDK-free: imported by both mcp_server (descriptions) and mcp_tools
(the yhwach_schema tool), so the two never disagree about what an argument means.
"""
from __future__ import annotations

import inspect
from collections.abc import Callable

# arg name -> (hint shown in the args: line, example literal shown in example:)
# The example literal is emitted verbatim into the call, so strings carry quotes.
VOCAB: dict[str, tuple[str, str]] = {
    "lab": ("engagement name (resolves the DB)", '"acme-internal"'),
    "scope": ("tokens: ip, cidr, hostname, *.wildcard; exclude wins", '"10.0.0.0/24,*.acme.test"'),
    "domain": ("AD domain (FQDN)", '"acme.test"'),
    "dc": ("domain controller host/IP", '"10.0.0.10"'),
    "client": ("client/org name for the engagement", '"Acme Corp"'),
    "host": ("target host IP", '"10.0.0.5"'),
    "host_ip": ("target host IP", '"10.0.0.5"'),
    "via_host": ("the host you pivot THROUGH", '"10.0.0.5"'),
    "source_host": ("host the artefact came from", '"10.0.0.5"'),
    "validated_on": ("host the cred was proven on", '"10.0.0.5"'),
    "subnet": ("subnet reachable via the pivot", '"10.0.1.0/24"'),
    "port": ("service port", "445"),
    "ports": ("comma-separated ports", '"445,139"'),
    "url": ("target URL", '"http://10.0.0.5:8080/"'),
    "action_id": ("a recall action id from yhwach_next", '"netexec_smb_null"'),
    "view": ("a yhwach_query view name (see yhwach_schema)", '"services"'),
    "where": ("filter, col or col__op=val (op: eq/ne/gt/ge/lt/le/like/in/is_null)", '"port=445"'),
    "q": ("free-text search across the view", '"admin"'),
    "fields": ("comma-separated columns to return", '"ip,port,product"'),
    "order": ("sort column (prefix - for desc)", '"-port"'),
    "limit": ("max rows/sections to return", "50"),
    "offset": ("rows to skip (paging)", "0"),
    "reveal": ("show secrets in the clear (default masked)", "true"),
    "fmt": ("text|json (json returns a paged envelope with a next-call)", '"json"'),
    "max_chars": ("cap output size; drops trailing rows and prints the next call", "4000"),
    "kind": ("the type/category for this call (tool-specific)", '"nmap"'),
    "severity": ("critical|high|medium|low|info", '"high"'),
    "status": ("open|confirmed|exploited|false_positive|duplicate|remediated|dead", '"confirmed"'),
    "cls": ("finding class/category", '"disclosure"'),
    "title": ("short title", '"Anonymous SMB share"'),
    "evidence": ("proof text or a file path", '"PUBLIC share readable null-session"'),
    "location": ("where the finding lives (endpoint/path/param)", '"/api/users/{id}"'),
    "finding": ("finding id to bind to", "12"),
    "finding_id": ("finding id", "12"),
    "result": ("success|fail|blocked|partial", '"fail"'),
    "rule": ("a technique/rule id from the catalog", '"smb_enumeration"'),
    "technique": ("free-text technique name (off-catalog)", '"manual LFI"'),
    "reason": ("why it failed/was blocked", '"account lockout policy"'),
    "identifier": ("username or label", '"svc_backup"'),
    "user": ("username or label", '"svc_backup"'),
    "secret": ("password / hash / key / token", '"P@ssw0rd!"'),
    "provided": ("True if the client gave this cred (never downgraded)", "true"),
    "tag": ("free-form host label", '"dc"'),
    "note": ("short written note", '"anon LDAP bind allowed"'),
    "annotation": ("short written note", '"anon LDAP bind allowed"'),
    "text": ("pasted tool output to interpret", '"<paste nxc output>"'),
    "objective": ("objective/flag label", '"domain-admin"'),
    "points": ("objective points", "10"),
    "capture": ("objective label to mark captured", '"user.txt"'),
    "add": ("objective label to add", '"root.txt"'),
    "command": ("the verbatim command run", '"nxc smb 10.0.0.5 -u a -p b"'),
    "output": ("the command's verbatim output", '"<output>"'),
    "cve": ("CVE id", '"CVE-2023-1234"'),
    "source": ("where it came from", '"secretsdump"'),
    "contains_secret": ("True if the artefact holds a secret", "true"),
    "local_path": ("local path of a looted file", '"loot/web.config"'),
    "path": ("a file path", '"loot/shot.png"'),
    "summary": ("one-line summary", '"backup config with db creds"'),
    "caption": ("short caption for the evidence", '"null-session share list"'),
    "stage": ("FSM stage filter", '"foothold"'),
    "section": ("which section to render", '"REACH"'),
    "mode": ("quick|full|udp", '"full"'),
    "max_hosts": ("cap the batch size", "8"),
    "protocol": ("ssh|smb|winrm|ldap|mssql|rdp|ftp|http-basic", '"smb"'),
    "cred": ("restrict to one credential identifier", '"svc_backup"'),
    "force": ("re-attempt even if cached", "true"),
    "spray": ("also insert derived creds into the vault", "true"),
    "dry_run": ("classify/plan without writing", "true"),
    "targets": ("comma-separated usernames to generate for", '"svc_sql,backup"'),
    "file": ("tool-output file to ingest", '"scan.xml"'),
    "hostname": ("the host's name", '"DC01"'),
    "os": ("operating system", '"windows"'),
    "role": ("what the box mainly hosts", '"Domain Controller"'),
    "role_kind": ("short role tag", '"dc"'),
    "ip": ("an IP address", '"10.0.0.5"'),
    "mac": ("MAC address", '"00:11:22:33:44:55"'),
    "pack": ("a reference pack name", '"wadcoms"'),
    "query": ("filter within the reference pack", '"smb"'),
    "src": ("path start node (name or principal:<id>/host:<id>)", '"host:1"'),
    "dst": ("path end node", '"Domain Admins"'),
    "out_dir": ("output directory", '"notes"'),
    "action": ("sub-command (tool-specific)", '"list"'),
    "tool": ("a yhwach tool name to describe", '"yhwach_add_finding"'),
    "body": ("the notice text (what was communicated)", '"notified client of critical RCE"'),
    "channel": ("how it was communicated", '"call"'),
    "program": ("bounty program name", '"acme-bbp"'),
    "endpoint": ("the affected endpoint/path", '"/api/users/{id}"'),
    "param": ("the affected parameter", '"id"'),
    "remove": ("artifact id to mark confirmed removed", "3"),
    "principal": ("an account/group name", '"svc_backup"'),
    "findings": ("list of {title, severity, cls?, host?, tag?, evidence?} dicts",
                 '[{"title":"Anon SMB","severity":"high","host":"10.0.0.5"}]'),
    "creds": ("list of {identifier, secret, kind?, source?, provided?} dicts",
              '[{"identifier":"svc","secret":"P@ss","kind":"password"}]'),
}


def _hint(name: str) -> str | None:
    pair = VOCAB.get(name)
    return pair[0] if pair else None


def _example(name: str) -> str:
    pair = VOCAB.get(name)
    return pair[1] if pair else f'"<{name}>"'


def _params(fn: Callable) -> list[tuple[str, inspect.Parameter]]:
    return [(n, p) for n, p in inspect.signature(fn).parameters.items()
            if n != "db_path"]


def describe(name: str, fn: Callable, base_desc: str) -> str:
    """base_desc plus a generated `args:` line and a runnable `example:` call."""
    params = _params(fn)
    if not params:
        return base_desc
    arg_bits: list[str] = []
    for n, p in params:
        required = p.default is inspect.Parameter.empty
        bit = n + ("*" if required else "")
        h = _hint(n)
        if h:
            bit += f" ({h})"
        arg_bits.append(bit)
    required = [(n, p) for n, p in params if p.default is inspect.Parameter.empty]
    shown = required or params[:2]
    call = ", ".join(f"{n}={_example(n)}" for n, _ in shown)
    return (f"{base_desc}\nargs: " + ", ".join(arg_bits)
            + f"\nexample: {name}({call})   (* = required)")


def catalog(specs, *, tool: str | None = None) -> str:
    """Render the whole MCP surface for yhwach_schema.

    With `tool`, the one enriched description; otherwise an index of every tool,
    the query views and operators, and the shared argument vocabulary.
    """
    from yhwach import views as yhviews

    if tool:
        for n, fn, desc in specs:
            if n == tool:
                return describe(n, fn, desc)
        return (f"unknown tool '{tool}' — call yhwach_schema() for the full list")

    lines = ["yhwach tool surface — call yhwach_schema(tool='<name>') for args + example.", ""]
    for n, _fn, desc in specs:
        lines.append(f"  {n} — {desc.splitlines()[0]}")
    lines += ["", "yhwach_query views: " + ", ".join(sorted(yhviews.VIEWS))]
    lines.append("yhwach_query operators (col__op=val): " + ", ".join(sorted(yhviews._OPS)))
    lines += ["", "common arguments:"]
    for argname in sorted(VOCAB):
        lines.append(f"  {argname} — {VOCAB[argname][0]}")
    return "\n".join(lines)
