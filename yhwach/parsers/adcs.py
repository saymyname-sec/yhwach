"""certipy output -> ADCS findings with a chaining tag.

`certipy find -vulnerable -json` emits a JSON report whose `Certificate
Templates` map flags each vulnerable template with an ESC list (under a
`[!] Vulnerabilities` key). We turn each vulnerable template into a finding
tagged `adcs_vuln`, which the `adcs_esc_abuse` rule (playbooks/ad.yaml) chains
off to propose a certipy request. Attach on ingest to the CA / DC host.
"""
from __future__ import annotations

import json

from yhwach.interpret import ExtractedFinding

# ESCs that hand you a cert impersonating a privileged user outright.
_HIGH_IMPACT = {"ESC1", "ESC3", "ESC4", "ESC6", "ESC8", "ESC9", "ESC11", "ESC15"}

# Per-ESC chaining tags. Written as explicit literals (not an f-string) so the
# tag-graph invariant (tests/test_tag_graph.py) sees this module as the producer.
# A host carrying one of these lets the matching playbooks/ad.yaml rule fire; the
# ESC-specific abuse is looked up via `yhwach ref esc -q escN`.
_ESC_TAG = {
    "ESC1": "adcs_esc1", "ESC2": "adcs_esc2", "ESC3": "adcs_esc3", "ESC4": "adcs_esc4",
    "ESC5": "adcs_esc5", "ESC6": "adcs_esc6", "ESC7": "adcs_esc7", "ESC8": "adcs_esc8",
    "ESC9": "adcs_esc9", "ESC10": "adcs_esc10", "ESC11": "adcs_esc11", "ESC12": "adcs_esc12",
    "ESC13": "adcs_esc13", "ESC14": "adcs_esc14", "ESC15": "adcs_esc15", "ESC16": "adcs_esc16",
}


def parse_certipy(text: str) -> list[ExtractedFinding]:
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return []
    if not isinstance(data, dict):
        return []
    templates = data.get("Certificate Templates")
    if not isinstance(templates, dict):
        return []

    out: list[ExtractedFinding] = []
    for tmpl in templates.values():
        if not isinstance(tmpl, dict):
            continue
        name = tmpl.get("Template Name") or tmpl.get("name") or "(template)"
        vulns = next((v for k, v in tmpl.items()
                      if "vulnerab" in k.lower() and isinstance(v, dict)), None)
        if not vulns:
            continue
        escs = sorted(vulns, key=lambda e: (len(e), e))
        sev = "critical" if any(e.upper() in _HIGH_IMPACT for e in escs) else "high"
        detail = "; ".join(f"{e}: {str(vulns[e])[:48]}" for e in escs)
        # Aggregate finding -> the adcs_esc_abuse catch-all rule.
        out.append(ExtractedFinding(
            "T1649", f"ADCS vulnerable template: {name} ({', '.join(escs)})",
            sev, detail[:180], tag="adcs_vuln"))
        # Per-ESC findings -> the ESC-specific ad.yaml rules (esc9/11/13/14/15/16).
        for e in escs:
            tag = _ESC_TAG.get(e.upper())
            if tag is None:
                continue
            esc_sev = "critical" if e.upper() in _HIGH_IMPACT else "high"
            out.append(ExtractedFinding(
                "T1649", f"ADCS {e.upper()} on template {name}",
                esc_sev, str(vulns[e])[:120], tag=tag))
    return out
