"""I12 — PoC steps keyed by finding + the redacted submission template.

A step can cite the finding it proves. The default render keeps real values
inline for reproduction; the submission render (redact=True) masks every vault
secret to [REDACTED] and is not written to disk.
"""
from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from yhwach import db as yhdb
from yhwach import poc
from yhwach.cli import main
from yhwach.mcp_tools import tool_poc, tool_poc_step


def _seed(path: Path) -> int:
    with yhdb.transaction(path) as conn:
        eid = yhdb.upsert_engagement(conn, lab="L", scope="10.0.0.0/24")
        yhdb.add_credential(conn, eid, "admin", "SuperSecret123", "password", "dump")
        fid, _ = yhdb.add_finding(conn, None, None, "rce", "RCE", "critical", "x",
                                  engagement_id=eid)
        poc.add_step(conn, eid, "rce-chain", title="auth",
                     command="nxc smb 10.0.0.5 -u admin -p SuperSecret123",
                     output="Pwn3d! token=SuperSecret123", finding_id=fid)
        return eid


def test_step_is_keyed_to_a_finding(tmp_db: Path) -> None:
    _seed(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.engagement_id_for(conn, "L")
        steps = poc.steps_for(conn, eid, "rce-chain")
    assert steps[0]["finding_id"] == 1


def test_plain_render_keeps_values_inline(tmp_db: Path) -> None:
    _seed(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.engagement_id_for(conn, "L")
        md = poc.render_poc(conn, eid, "rce-chain", write=False)
    assert "SuperSecret123" in md          # reproducible as-is
    assert "finding: #1" in md             # the finding it proves


def test_redacted_submission_masks_secrets(tmp_db: Path) -> None:
    _seed(tmp_db)
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.engagement_id_for(conn, "L")
        md = poc.render_poc(conn, eid, "rce-chain", write=False, redact=True)
    assert "SuperSecret123" not in md
    assert "[REDACTED]" in md
    assert "finding: #1" in md


def test_short_secrets_not_masked(tmp_db: Path) -> None:
    # a 3-char secret is too short to mask (would redact noise)
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.upsert_engagement(conn, lab="L", scope="10.0.0.0/24")
        yhdb.add_credential(conn, eid, "u", "abc", "password", "dump")
        poc.add_step(conn, eid, "c", title="t", command="echo abc runs")
        md = poc.render_poc(conn, eid, "c", write=False, redact=True)
    assert "abc" in md   # not masked


def test_redacted_render_not_written_to_disk(tmp_db: Path, tmp_path: Path) -> None:
    _seed(tmp_db)
    out = tool_poc(tmp_db, "L", objective="rce-chain", redact=True)
    assert "[REDACTED]" in out
    # the on-disk chain (if any) keeps the real value; the redacted export does not
    assert "SuperSecret123" not in out


def test_mcp_poc_step_accepts_finding(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.upsert_engagement(conn, lab="L", scope="10.0.0.0/24")
        fid, _ = yhdb.add_finding(conn, None, None, "idor", "IDOR", "high", "x",
                                  engagement_id=eid)
    tool_poc_step(tmp_db, "L", objective="idor-poc", title="swap id",
                  command="curl /users/2", finding=fid)
    with yhdb.transaction(tmp_db) as conn:
        eid = yhdb.engagement_id_for(conn, "L")
        assert poc.steps_for(conn, eid, "idor-poc")[0]["finding_id"] == fid


def test_cli_poc_redact(tmp_db: Path) -> None:
    _seed(tmp_db)
    r = CliRunner().invoke(main, ["poc", "--lab", "L", "--objective", "rce-chain",
                                  "--redact", "--db", str(tmp_db)])
    assert r.exit_code == 0
    assert "[REDACTED]" in r.output
    assert "SuperSecret123" not in r.output
