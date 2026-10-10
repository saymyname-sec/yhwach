"""data/service_matrix.yaml is the single source of truth for service identity.

These tests assert the code (PORT_KIND / coverage.SERVICE_ENUM_KINDS) agrees with
the matrix, so the eight places service identity lives never drift apart — the
drift class that produced the G1-G4 "won't-classify / won't-fire" bugs.
"""
from __future__ import annotations

from pathlib import Path

import yaml

from yhwach.coverage import SERVICE_ENUM_KINDS
from yhwach.probes.traditional import PORT_KIND

ROOT = Path(__file__).resolve().parents[1]


def _matrix() -> list[dict]:
    rows = yaml.safe_load((ROOT / "data" / "service_matrix.yaml").read_text(encoding="utf-8"))
    return [r for r in rows if isinstance(r, dict)]


def test_rows_are_well_formed() -> None:
    for r in _matrix():
        assert r.get("kind"), f"matrix row missing 'kind': {r}"
        assert r.get("surface_kind"), f"{r['kind']}: missing surface_kind"
        assert r.get("classify"), f"{r['kind']}: missing classify"


def test_port_classified_rows_agree_with_port_kind() -> None:
    """A port a row claims (classify includes 'port') must map to that row's
    surface_kind in PORT_KIND — no divergence between matrix and the port map."""
    for r in _matrix():
        if "port" not in (r.get("classify") or []):
            continue
        for p in r.get("tcp_ports", []) or []:
            if p in PORT_KIND:
                assert PORT_KIND[p] == r["surface_kind"], (
                    f"drift: matrix says port {p} -> {r['surface_kind']}, "
                    f"PORT_KIND says {PORT_KIND[p]}"
                )


def test_every_service_enum_port_kind_has_a_matrix_row() -> None:
    """Every PORT_KIND entry whose kind is service-enumerable must appear in the
    matrix with that port — so a datastore/control-plane surface can never be in
    the code but missing from the source-of-truth (and its triage/coverage)."""
    by_kind: dict[str, set[int]] = {}
    for r in _matrix():
        for p in r.get("tcp_ports", []) or []:
            by_kind.setdefault(r["surface_kind"], set()).add(p)
    for port, kind in PORT_KIND.items():
        if kind in SERVICE_ENUM_KINDS:
            assert kind in by_kind, f"PORT_KIND has {kind} ({port}) but service_matrix.yaml has no row"
            assert port in by_kind[kind], f"matrix row {kind} is missing port {port}"


def test_matrix_kinds_are_unique() -> None:
    kinds = [r["kind"] for r in _matrix()]
    dupes = {k for k in kinds if kinds.count(k) > 1}
    assert not dupes, f"duplicate kind rows in service_matrix.yaml: {sorted(dupes)}"


def test_every_port_kind_has_a_matrix_row() -> None:
    """Stronger than the service-enumerable check above: ANY kind the port map
    can produce must have triage context, or `yhwach ref services <kind>` and the
    per-host dossier come back empty for it. A Domain Controller — smb, ldap,
    kerberos, winrm — used to hit exactly that hole."""
    have = {r["kind"] for r in _matrix()}
    missing = sorted({k for k in PORT_KIND.values() if k not in have})
    assert not missing, f"PORT_KIND kinds with no service_matrix row: {missing}"


def test_traditional_rows_do_not_open_a_new_coverage_gate() -> None:
    """These kinds are covered by the AD and web playbooks. Flipping
    service_enum on would flood `yhwach gaps` with debt the operator did not owe."""
    for r in _matrix():
        if r["kind"] in {"smb", "ldap", "kerberos", "winrm", "ssh", "rdp", "ftp",
                         "web", "web_upload"}:
            assert r.get("service_enum") is False, f"{r['kind']} would fire a new gate"


def test_common_services_carry_triage_context() -> None:
    by_kind = {r["kind"]: r for r in _matrix()}
    for kind in ("smb", "ldap", "kerberos", "winrm", "ssh", "rdp", "ftp", "web"):
        assert by_kind[kind].get("enum_ref"), f"{kind}: no enum_ref to brief the operator with"
        assert by_kind[kind].get("taxonomy"), f"{kind}: no taxonomy mapping"
