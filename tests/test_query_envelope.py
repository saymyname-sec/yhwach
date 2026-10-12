"""I62 — JSON envelope, paging and output bounds on the query surface.

The model needs a stable, paged, bounded read surface: a JSON envelope with an
id on every row, real limit/offset paging (not opaque cursors), a truncation
footer that prints the exact follow-up call, and a max_chars cap that drops
trailing rows and resumes after them. These tests lock that contract.
"""
from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from yhwach import db as yhdb
from yhwach.cli import main
from yhwach.mcp_tools import tool_query


def _seed(path: Path, n: int = 6) -> int:
    with yhdb.transaction(path) as conn:
        eng = yhdb.upsert_engagement(conn, lab="L", scope="10.0.0.0/24")
        for i in range(n):
            conn.execute(
                "INSERT INTO host (engagement_id, ip, stage, first_seen) "
                "VALUES (?, ?, 'scanned', '2026-01-01T00:00:00Z')",
                (eng, f"10.0.0.{i}"),
            )
        return eng


def test_text_footer_prints_exact_next_call(tmp_db: Path) -> None:
    _seed(tmp_db)
    out = tool_query(tmp_db, "L", "hosts", limit=2)
    assert "yhwach_query(view='hosts', offset=2)" in out
    assert "of 6" in out


def test_json_envelope_shape(tmp_db: Path) -> None:
    _seed(tmp_db)
    env = json.loads(tool_query(tmp_db, "L", "hosts", limit=2, fmt="json"))
    assert set(env) == {"view", "total", "offset", "limit", "count",
                        "truncated", "rows", "next"}
    assert env["total"] == 6
    assert env["count"] == 2
    assert env["offset"] == 0
    assert env["truncated"] is False
    assert env["next"] == "yhwach_query(view='hosts', offset=2, fmt='json')"


def test_json_last_page_has_no_next(tmp_db: Path) -> None:
    _seed(tmp_db, n=2)
    env = json.loads(tool_query(tmp_db, "L", "hosts", limit=25, fmt="json"))
    assert env["count"] == 2
    assert env["next"] is None


def test_every_row_carries_an_id_even_with_narrowed_fields(tmp_db: Path) -> None:
    _seed(tmp_db)
    env = json.loads(tool_query(tmp_db, "L", "hosts", fields=["ip"], fmt="json", limit=3))
    assert env["rows"]
    for row in env["rows"]:
        assert "id" in row
        assert "ip" in row


def test_offset_paging_advances(tmp_db: Path) -> None:
    _seed(tmp_db)
    p1 = json.loads(tool_query(tmp_db, "L", "hosts", limit=3, offset=0, fmt="json"))
    p2 = json.loads(tool_query(tmp_db, "L", "hosts", limit=3, offset=3, fmt="json"))
    ids1 = {r["id"] for r in p1["rows"]}
    ids2 = {r["id"] for r in p2["rows"]}
    assert ids1.isdisjoint(ids2)
    assert p2["next"] is None  # 6 rows, offset 3 + 3 shown = done


def test_max_chars_json_drops_trailing_rows_and_resumes(tmp_db: Path) -> None:
    _seed(tmp_db)
    env = json.loads(tool_query(tmp_db, "L", "hosts", limit=6, fmt="json", max_chars=400))
    assert env["truncated"] is True
    assert env["count"] < 6
    # the next call resumes exactly after the rows that survived
    assert env["next"] == f"yhwach_query(view='hosts', offset={env['count']}, fmt='json')"


def test_max_chars_text_caps_and_prints_next(tmp_db: Path) -> None:
    _seed(tmp_db)
    out = tool_query(tmp_db, "L", "hosts", limit=6, max_chars=200)
    assert len(out) <= 200 or "capped" in out
    assert "yhwach_query(view='hosts'" in out


def test_max_chars_json_honors_the_cap_on_returned_string(tmp_db: Path) -> None:
    # Regression: the cap must be measured against the indented string actually
    # returned, not a compact one — otherwise the result overflows at the margin.
    _seed(tmp_db)
    for cap in (300, 420, 500, 900):
        out = tool_query(tmp_db, "L", "hosts", limit=6, fmt="json", max_chars=cap)
        env = json.loads(out)
        if env["count"] > 0:  # a non-empty page must fit the cap exactly
            assert len(out) <= cap, (cap, len(out))


def test_json_masks_secrets_unless_revealed(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        eng = yhdb.upsert_engagement(conn, lab="L", scope="10.0.0.0/24")
        yhdb.add_credential(conn, eng, "svc", "SuperSecret1", "password", "dump")
    masked = json.loads(tool_query(tmp_db, "L", "creds", fmt="json"))
    assert masked["rows"][0]["secret"] == "••••••"
    assert "SuperSecret1" not in json.dumps(masked)
    revealed = json.loads(tool_query(tmp_db, "L", "creds", fmt="json", reveal=True))
    assert revealed["rows"][0]["secret"] == "SuperSecret1"


def test_offset_beyond_total_is_empty_no_next(tmp_db: Path) -> None:
    _seed(tmp_db, n=3)
    env = json.loads(tool_query(tmp_db, "L", "hosts", offset=100, fmt="json"))
    assert env["count"] == 0
    assert env["rows"] == []
    assert env["next"] is None


def test_unknown_fmt_is_rejected(tmp_db: Path) -> None:
    import pytest

    _seed(tmp_db)
    with pytest.raises(ValueError, match="unknown fmt"):
        tool_query(tmp_db, "L", "hosts", fmt="yaml")


def test_cli_query_json_and_paging(tmp_db: Path) -> None:
    _seed(tmp_db)
    r = CliRunner().invoke(
        main, ["query", "--lab", "L", "hosts", "--json", "--limit", "2", "--db", str(tmp_db)],
    )
    assert r.exit_code == 0, r.output
    env = json.loads(r.output)
    assert env["count"] == 2
    assert env["next"].startswith("yhwach_query(view='hosts', offset=2")
