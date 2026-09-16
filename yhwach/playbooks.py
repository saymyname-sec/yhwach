"""Playbook loading and validation.

A *technique rule* is a YAML mapping with both a `when` clause and an `emits`
list. Meta files (`_primitives.yaml`, `lore_denylist.yaml`) are not technique
rules — their entries lack `when` — and are ignored by `load_rules`.

Rules carry static EV inputs: `likelihood` (H/M/L) and `time_cost`
(fast/med/slow). EV = likelihood_weight * points / time_cost_divisor.
See ARCHITECTURE.md.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

LIKELIHOOD_WEIGHT = {"H": 1.0, "M": 0.6, "L": 0.3}
TIME_COST_DIVISOR = {"fast": 1.0, "med": 2.0, "slow": 4.0}

# Rule `risk` vocabulary -> (normalized task risk, autonomy tier).
_RISK_NORMALIZE = {
    "read_only": ("read_only", "proceed"),
    "propose": ("exploit", "propose"),
    "exploit": ("exploit", "propose"),
    "destructive": ("destructive", "ask"),
}

DEFAULT_LIKELIHOOD = "M"
DEFAULT_TIME_COST = "med"


class PlaybookError(ValueError):
    """Raised on a malformed technique rule or a duplicate rule id."""


@dataclass
class Rule:
    id: str
    when: dict[str, Any]
    emits: list[dict]
    points: int
    likelihood: str
    time_cost: str
    risk: str
    autonomy: str
    maps: list[str] = field(default_factory=list)
    routes: str | None = None
    source: str | None = None
    _class: str | None = None

    @property
    def ev_score(self) -> float:
        like = LIKELIHOOD_WEIGHT.get(self.likelihood, LIKELIHOOD_WEIGHT[DEFAULT_LIKELIHOOD])
        div = TIME_COST_DIVISOR.get(self.time_cost, TIME_COST_DIVISOR[DEFAULT_TIME_COST])
        return round(like * self.points / div, 4)

    @property
    def technique_class(self) -> str:
        """ai | traditional | ad — drives the AI-first tier in the ranker.

        Explicit `class:` in the rule wins; otherwise derived from the OWASP-LLM
        maps (any LLMxx -> ai), defaulting to traditional.
        """
        if self._class:
            return self._class
        if any(str(m).upper().startswith("LLM") for m in self.maps):
            return "ai"
        return "traditional"


def _is_technique_rule(entry: Any) -> bool:
    return isinstance(entry, dict) and "when" in entry and "emits" in entry


def load_rules(playbook_dir: Path | str) -> list[Rule]:
    """Load and validate all technique rules from playbook YAML files.

    Skips meta entries (those without a `when` clause). Raises PlaybookError on
    a malformed technique rule or a duplicate id.
    """
    playbook_dir = Path(playbook_dir)
    rules: list[Rule] = []
    seen_ids: set[str] = set()

    for path in sorted(playbook_dir.glob("*.yaml")):
        with path.open(encoding="utf-8") as f:
            docs = yaml.safe_load(f)
        if not isinstance(docs, list):
            continue
        for entry in docs:
            if not _is_technique_rule(entry):
                continue
            rule = _build_rule(entry, source_file=path.name)
            if rule.id in seen_ids:
                raise PlaybookError(f"duplicate rule id '{rule.id}' (in {path.name})")
            seen_ids.add(rule.id)
            rules.append(rule)

    return rules


def _build_rule(entry: dict, *, source_file: str) -> Rule:
    rid = entry.get("id")
    if not rid:
        raise PlaybookError(f"rule without id in {source_file}: {entry!r}")

    if not entry.get("authorized_only", False):
        raise PlaybookError(f"rule '{rid}' must set authorized_only: true")

    points = entry.get("points", 0)
    if not isinstance(points, int) or not (0 <= points <= 15):
        raise PlaybookError(f"rule '{rid}' points must be an int in 0..15")

    raw_risk = entry.get("risk", "read_only")
    if raw_risk not in _RISK_NORMALIZE:
        raise PlaybookError(f"rule '{rid}' has unknown risk '{raw_risk}'")
    risk, autonomy = _RISK_NORMALIZE[raw_risk]

    likelihood = entry.get("likelihood", DEFAULT_LIKELIHOOD)
    if likelihood not in LIKELIHOOD_WEIGHT:
        raise PlaybookError(f"rule '{rid}' likelihood must be one of H/M/L")

    time_cost = entry.get("time_cost", DEFAULT_TIME_COST)
    if time_cost not in TIME_COST_DIVISOR:
        raise PlaybookError(f"rule '{rid}' time_cost must be one of fast/med/slow")

    emits = entry.get("emits", [])
    if not isinstance(emits, list) or not emits:
        raise PlaybookError(f"rule '{rid}' must have a non-empty emits list")

    when = entry.get("when") or {}
    if not isinstance(when, dict):
        raise PlaybookError(f"rule '{rid}' when clause must be a mapping")

    klass = entry.get("class")
    if klass is not None and klass not in ("ai", "traditional", "ad"):
        raise PlaybookError(f"rule '{rid}' class must be ai/traditional/ad")

    return Rule(
        id=rid,
        when=when,
        emits=emits,
        points=points,
        likelihood=likelihood,
        time_cost=time_cost,
        risk=risk,
        autonomy=autonomy,
        maps=entry.get("maps") or [],
        routes=entry.get("routes"),
        source=entry.get("source"),
        _class=klass,
    )


def default_playbook_dir() -> Path:
    """Repo-relative playbooks dir (source checkout / editable install)."""
    return Path(__file__).resolve().parent.parent / "playbooks"
