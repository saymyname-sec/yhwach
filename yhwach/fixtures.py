"""Fixture harness: the calibration loop's backbone.

Three moves:
  * seed_world_model  — build a world model in a DB from a YAML fixture
  * snapshot_world_model — reverse: dump a live engagement back to a fixture dict
  * evaluate_fixture  — run the planner and check ranked output vs golden expectations

Every real (authorized) lab scenario, snapshotted, becomes a permanent
regression. A rule change that would have mis-ranked a past scenario fails CI.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import yaml

from yhwach import db as yhdb


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_fixture(path: Path | str) -> dict:
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict) or "world_model" not in data:
        raise ValueError(f"fixture {path} missing 'world_model'")
    return data


def seed_world_model(conn, fixture: dict) -> int:
    """Build hosts/services/surfaces from a fixture. Returns engagement_id."""
    wm = fixture["world_model"]
    eng = wm["engagement"]
    scope = eng.get("scope", "")
    scope_str = ",".join(scope) if isinstance(scope, list) else str(scope)
    eng_id = yhdb.upsert_engagement(
        conn, lab=eng["lab"], scope=scope_str,
        domain=eng.get("domain"), dc_ip=eng.get("dc"),
    )
    now = _now()

    for h in wm.get("hosts", []):
        cur = conn.execute(
            "INSERT INTO host (engagement_id, ip, hostname, os, role, stage, first_seen) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (eng_id, h["ip"], h.get("hostname"), h.get("os"), h.get("role"),
             h.get("stage", "scanned"), now),
        )
        host_id = int(cur.lastrowid)

        port_to_svc: dict[int, int] = {}
        for s in h.get("services", []):
            cur = conn.execute(
                "INSERT INTO service (host_id, port, proto, product, version, discovered_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (host_id, s["port"], s.get("proto", "tcp"), s.get("product"),
                 s.get("version"), now),
            )
            port_to_svc[s["port"]] = int(cur.lastrowid)

        for surf in h.get("surfaces", []):
            svc_id = port_to_svc.get(surf.get("service_port"))
            meta = json.dumps(surf.get("meta", {}), sort_keys=True)
            yhdb.upsert_surface(
                conn, host_id, svc_id, surf["kind"], surf.get("auth", "unknown"), meta
            )

    return eng_id


def snapshot_world_model(conn, engagement_id: int) -> dict:
    """Reverse of seed: dump a live engagement's world model as a fixture dict."""
    eng = conn.execute(
        "SELECT lab, scope, domain FROM engagement WHERE id = ?", (engagement_id,)
    ).fetchone()

    hosts_out: list[dict] = []
    hosts = conn.execute(
        "SELECT id, ip, hostname, os, role, stage FROM host "
        "WHERE engagement_id = ? ORDER BY ip",
        (engagement_id,),
    ).fetchall()

    for h in hosts:
        svc_rows = conn.execute(
            "SELECT id, port, proto, product, version FROM service "
            "WHERE host_id = ? ORDER BY port",
            (h["id"],),
        ).fetchall()
        svc_port_by_id = {r["id"]: r["port"] for r in svc_rows}
        services = [
            {"port": r["port"], "proto": r["proto"],
             "product": r["product"], "version": r["version"]}
            for r in svc_rows
        ]
        surf_rows = conn.execute(
            "SELECT service_id, kind, auth, meta_json FROM surface "
            "WHERE host_id = ? ORDER BY kind",
            (h["id"],),
        ).fetchall()
        surfaces = [
            {
                "kind": r["kind"],
                "auth": r["auth"],
                "service_port": svc_port_by_id.get(r["service_id"]),
                "meta": json.loads(r["meta_json"]) if r["meta_json"] else {},
            }
            for r in surf_rows
        ]
        hosts_out.append({
            "ip": h["ip"], "hostname": h["hostname"], "os": h["os"],
            "role": h["role"], "stage": h["stage"],
            "services": services, "surfaces": surfaces,
        })

    scope = eng["scope"].split(",") if eng["scope"] else []
    return {
        "name": eng["lab"],
        "world_model": {
            "engagement": {"lab": eng["lab"], "scope": scope, "domain": eng["domain"]},
            "hosts": hosts_out,
        },
    }


def default_fixtures_dir() -> Path:
    """Fixtures dir: packaged `_fixtures` for an installed wheel, else the repo
    `tests/fixtures` for a source checkout."""
    pkg = Path(__file__).resolve().parent / "_fixtures"
    if pkg.is_dir():
        return pkg
    return Path(__file__).resolve().parent.parent / "tests" / "fixtures"
