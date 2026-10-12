"""Nessus (.nessus v2) and OpenVAS/GVM XML -> keyed vulnerability rows (G2a).

The network consultant's daily baseline. yhwach does not reimplement a scanner:
it parses the normalised export into typed rows (plugin id, port, CVSS, solution,
a capped output excerpt) and owns the 'what next' — a small promote pack maps a
few high-signal plugins to the chaining tags recall already consumes.

Qualys/Nexpose CSV are client VM-team artefacts and are intentionally not parsed.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from xml.etree import ElementTree as ET

_OUTPUT_CAP = 600  # plugin-output excerpt ceiling; evidence is never a raw dump

# Nessus severity int -> yhwach band.
_NESSUS_SEV = {"0": "info", "1": "low", "2": "medium", "3": "high", "4": "critical"}


@dataclass
class ParsedVuln:
    host_ip: str
    plugin_id: str | None
    title: str
    severity: str                 # critical|high|medium|low|info
    cvss: float | None = None
    port: int | None = None
    proto: str | None = None
    cves: list[str] = field(default_factory=list)
    solution: str | None = None
    output: str | None = None


def _cvss(v: str | None) -> float | None:
    try:
        return float(v) if v not in (None, "") else None
    except ValueError:
        return None


def _band_from_cvss(score: float | None) -> str:
    if score is None:
        return "info"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def _cap(text: str | None) -> str | None:
    if not text:
        return None
    t = " ".join(text.split())
    return t[:_OUTPUT_CAP] + ("…" if len(t) > _OUTPUT_CAP else "")


def parse_nessus(text: str) -> list[ParsedVuln]:
    """Parse a .nessus v2 export. Info-severity items are kept (coverage)."""
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return []
    out: list[ParsedVuln] = []
    for rh in root.iter("ReportHost"):
        ip = rh.get("name") or ""
        for item in rh.findall("ReportItem"):
            sev = _NESSUS_SEV.get(item.get("severity") or "0", "info")
            cvss = _cvss(item.findtext("cvss3_base_score") or item.findtext("cvss_base_score"))
            cves = [c.text.strip() for c in item.findall("cve") if c.text]
            port_s = item.get("port")
            port = int(port_s) if port_s and port_s.isdigit() and port_s != "0" else None
            out.append(ParsedVuln(
                host_ip=ip, plugin_id=item.get("pluginID"),
                title=item.get("pluginName") or "Nessus finding",
                severity=sev, cvss=cvss, port=port, proto=item.get("protocol"),
                cves=cves, solution=_cap(item.findtext("solution")),
                output=_cap(item.findtext("plugin_output")),
            ))
    return out


def parse_openvas(text: str) -> list[ParsedVuln]:
    """Parse a GVM/OpenVAS XML report (<results><result>…)."""
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return []
    out: list[ParsedVuln] = []
    for res in root.iter("result"):
        host = (res.findtext("host") or "").strip()
        # host may carry child text + an <asset>; take the leading IP token.
        ip = host.split()[0] if host else ""
        port_raw = (res.findtext("port") or "").strip()  # '445/tcp' | 'general/tcp'
        port = proto = None
        m = re.match(r"(\d+)/(\w+)", port_raw)
        if m:
            port, proto = int(m.group(1)), m.group(2)
        nvt = res.find("nvt")
        cvss = _cvss(res.findtext("severity") or (nvt.findtext("cvss_base") if nvt is not None else None))
        cves: list[str] = []
        oid = title = solution = None
        if nvt is not None:
            oid = nvt.get("oid")
            title = nvt.findtext("name")
            solution = _cap(nvt.findtext("solution"))
            for ref in nvt.iter("ref"):
                if (ref.get("type") or "").lower() == "cve" and ref.get("id"):
                    cves.append(ref.get("id"))
        out.append(ParsedVuln(
            host_ip=ip, plugin_id=oid, title=title or "OpenVAS finding",
            severity=_band_from_cvss(cvss), cvss=cvss, port=port, proto=proto,
            cves=cves, solution=solution, output=_cap(res.findtext("description")),
        ))
    return out


# --- promote pack -----------------------------------------------------------
# A few high-signal detections mapped to the chaining tag recall already uses.
# Keyed by Nessus plugin id, OpenVAS OID, or a CVE / title substring.
_PLUGIN_TAGS: dict[str, str] = {
    "57608": "smb_signing_off",   # SMB signing not required
    "97833": "exploitable_cve",   # MS17-010 (Nessus)
    "97737": "exploitable_cve",   # MS17-010 uncredentialed
}
_CVE_TAGS: list[tuple[str, str]] = [
    ("CVE-2017-0144", "exploitable_cve"),   # MS17-010 / EternalBlue
    ("CVE-2020-1472", "exploitable_cve"),   # ZeroLogon
    ("CVE-2021-34527", "exploitable_cve"),  # PrintNightmare
    ("CVE-2019-0708", "exploitable_cve"),   # BlueKeep
]
_TITLE_TAGS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"ms17-010|eternalblue", re.I), "exploitable_cve"),
    (re.compile(r"smb signing (?:not|is not) required", re.I), "smb_signing_off"),
    (re.compile(r"zerologon", re.I), "exploitable_cve"),
]


def promote_tag(v: ParsedVuln) -> str | None:
    """The chaining tag this vuln should also light up, or None."""
    if v.plugin_id and v.plugin_id in _PLUGIN_TAGS:
        return _PLUGIN_TAGS[v.plugin_id]
    for cve in v.cves:
        for pat, tag in _CVE_TAGS:
            if cve.upper() == pat:
                return tag
    for pat, tag in _TITLE_TAGS:
        if pat.search(v.title):
            return tag
    return None
