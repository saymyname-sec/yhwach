"""I61 — generated tool descriptions + yhwach_schema.

FastMCP only forwards each tool's short spec string to the model, so these tests
lock the enrichment: every tool's description gains a generated `args:` line
(required args marked, hints from one vocabulary) and a runnable `example:` call,
yhwach_schema discovers the whole surface, and yhwach_tag warns that a tag does
not unlock recall rules.
"""
from __future__ import annotations

import inspect

from click.testing import CliRunner

from yhwach import vocab
from yhwach.cli import main
from yhwach.mcp_tools import TOOL_SPECS, tool_schema

_SPECS = {n: (fn, d) for n, fn, d in TOOL_SPECS}


def test_describe_marks_required_and_renders_example() -> None:
    fn, desc = _SPECS["yhwach_add_finding"]
    out = vocab.describe("yhwach_add_finding", fn, desc)
    assert desc in out  # base description preserved
    assert "args:" in out
    assert "lab*" in out  # required arg marked
    assert "host (" in out and "host*" not in out  # optional arg not marked
    assert out.rstrip().count("\n") >= 2
    # the example is a real call naming the required args
    assert "example: yhwach_add_finding(" in out
    assert 'lab="acme-internal"' in out
    assert 'severity="high"' in out


def test_describe_uses_signature_defaults_for_requiredness() -> None:
    # action_id has no default -> required*; host/port have defaults -> optional.
    fn, desc = _SPECS["yhwach_action"]
    out = vocab.describe("yhwach_action", fn, desc)
    assert "action_id*" in out
    assert "host (" in out and "port (" in out
    assert "host*" not in out and "port*" not in out


def test_every_tool_description_generates_without_error() -> None:
    # Drift guard: describe() must handle every real tool signature.
    for name, fn, desc in TOOL_SPECS:
        out = vocab.describe(name, fn, desc)
        assert out.startswith(desc)
        params = [n for n in inspect.signature(fn).parameters if n != "db_path"]
        if params:
            assert f"example: {name}(" in out
        else:
            assert out == desc  # no args -> unchanged


def test_example_values_are_only_for_required_args() -> None:
    # A tool with no required args beyond lab still shows a usable example.
    fn, desc = _SPECS["yhwach_status"]
    out = vocab.describe("yhwach_status", fn, desc)
    assert "example: yhwach_status(" in out


def test_schema_lists_tools_views_and_operators() -> None:
    full = tool_schema(None)
    assert "yhwach_next" in full
    assert "yhwach_schema" in full  # self-listed
    assert "yhwach_query views:" in full
    assert "yhwach_query operators" in full
    # the shared vocabulary is exposed
    assert "lab — engagement name" in full


def test_schema_per_tool_returns_args_and_example() -> None:
    out = tool_schema(None, tool="yhwach_query")
    assert "args:" in out
    assert "example: yhwach_query(" in out
    assert "view*" in out


def test_schema_unknown_tool_is_graceful() -> None:
    out = tool_schema(None, tool="yhwach_nope")
    assert "unknown tool" in out


def test_tag_description_warns_it_does_not_unlock_rules() -> None:
    _fn, desc = _SPECS["yhwach_tag"]
    assert "does NOT unlock" in desc or "does not unlock" in desc.lower()


def test_cli_schema_command() -> None:
    r = CliRunner().invoke(main, ["schema"])
    assert r.exit_code == 0
    assert "yhwach_next" in r.output
    r2 = CliRunner().invoke(main, ["schema", "yhwach_add_finding"])
    assert r2.exit_code == 0
    assert "example: yhwach_add_finding(" in r2.output


def test_vocab_examples_are_well_formed() -> None:
    # Every vocab example literal is non-empty; string examples are quoted.
    for name, (hint, example) in vocab.VOCAB.items():
        assert hint and example, name
        assert example.strip() == example, name
