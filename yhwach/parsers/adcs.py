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
        out.append(ExtractedFinding(
            "T1649", f"ADCS vulnerable template: {name} ({', '.join(escs)})",
            sev, detail[:180], tag="adcs_vuln"))
    return out
