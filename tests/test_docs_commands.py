"""I67 — documentation parity guard.

Every `yhwach <command>` and `yhwach_<tool>` that appears in a *supported* doc's
fenced code block (the runnable examples people copy-paste) must actually exist in
the CLI group and in the MCP TOOL_SPECS. This catches the classic drift where a
command is renamed or removed but the docs still advertise it.

Scope: fenced code blocks only (prose-in-backticks is inherently ambiguous — e.g.
"yhwach recalls what it tried" is not an invocation). Internal design notes and the
experimental self-driving docs are excluded; they are flagged as possibly-lagging.
"""
from __future__ import annotations

import re
from pathlib import Path

from yhwach.cli import main
from yhwach.mcp_tools import TOOL_SPECS

ROOT = Path(__file__).parent.parent
CLI_COMMANDS = set(main.commands)
MCP_TOOLS = {t[0] for t in TOOL_SPECS}

# docs that are NOT the supported command surface (internal analysis / design / experimental)
_EXCLUDE_DOCS = {"real-engagement-roadmap.md", "design-ui-information-surface.md"}

_FENCE = re.compile(r"```[a-zA-Z]*\n(.*?)```", re.S)
_ENV_PREFIX = re.compile(r"^(?:[A-Z_][A-Z0-9_]*=\S+\s+)+")
_CMD = re.compile(r"yhwach ([a-z][a-z-]*)")
_TOOL = re.compile(r"\byhwach_([a-z][a-z_]*)")


def _scanned_docs() -> list[Path]:
    docs = [
        ROOT / "README.md", ROOT / "ARCHITECTURE.md", ROOT / "AGENT.md",
        ROOT / "AUTHORIZATION.md", ROOT / "CONTRIBUTING.md",
    ]
    docs += [p for p in (ROOT / "docs").glob("*.md") if p.name not in _EXCLUDE_DOCS]
    docs += list((ROOT / "docs" / "commands").glob("*.md"))
    return [p for p in docs if p.exists()]


def _invocations(blob: str):
    """Yield (command, tool) candidates from a fenced-code blob, treating only
    shell-invocation positions as commands (line start, or after | && ;), after
    stripping a `$ ` prompt and any `ENV=val ` assignment prefixes."""
    for line in blob.splitlines():
        line = line.strip()
        if line.startswith("$ "):
            line = line[2:]
        for part in re.split(r"\|{1,2}|&&|;|\s--\s", line):
            part = _ENV_PREFIX.sub("", part.strip())
            m = re.match(r"yhwach ([a-z][a-z-]*)", part)
            if m:
                yield ("cmd", m.group(1))
        for tm in _TOOL.findall(line):
            yield ("tool", "yhwach_" + tm)


def _collect():
    cmds, tools = {}, {}
    for p in _scanned_docs():
        for blk in _FENCE.findall(p.read_text(encoding="utf-8", errors="replace")):
            for kind, name in _invocations(blk):
                (cmds if kind == "cmd" else tools).setdefault(name, set()).add(p.name)
    return cmds, tools


def test_scanned_doc_set_is_populated() -> None:
    # guard against a path change silently scanning nothing (which would make the
    # parity assertions vacuously pass).
    docs = _scanned_docs()
    assert len(docs) >= 6, [p.name for p in docs]
    assert (ROOT / "README.md") in docs


def test_documented_cli_commands_exist() -> None:
    cmds, _ = _collect()
    unknown = {c: sorted(v) for c, v in cmds.items() if c not in CLI_COMMANDS}
    assert not unknown, f"docs reference non-existent CLI commands: {unknown}"


def test_documented_mcp_tools_exist() -> None:
    _, tools = _collect()
    unknown = {t: sorted(v) for t, v in tools.items() if t not in MCP_TOOLS}
    assert not unknown, f"docs reference non-existent MCP tools: {unknown}"


def test_core_commands_are_actually_documented() -> None:
    # the guard is only meaningful if the docs exercise a real slice of the surface
    cmds, _ = _collect()
    for essential in ("engage", "brief", "status", "mcp"):
        assert essential in cmds, f"{essential!r} should appear in a documented example"
