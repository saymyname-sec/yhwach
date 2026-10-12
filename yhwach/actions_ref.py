"""Action reference — the runnable command and fold-back pointer per action id.

Loaded from ``data/actions.yaml``, the command source for the *live* recall wire
(``yhwach next`` and ``yhwach_action``). The legacy autonomous runner keeps its
own ``runners._COMMANDS`` map and is intentionally left untouched, so the two can
drift — there is no automatic guard yet (a drift test is future work). ``render``
fills the {host}/{port}/{url}/{domain} placeholders and leaves a {secret_ref} as
an env var reference — a secret value never crosses the wire in a rendered command.
"""
from __future__ import annotations

import functools

import yaml

from yhwach import data_path


@functools.lru_cache(maxsize=1)
def _load() -> dict[str, dict]:
    try:
        d = yaml.safe_load(data_path("actions.yaml").read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError):
        return {}
    return {k: (v or {}) for k, v in (d or {}).items()}


_TARGET_PLACEHOLDERS = ("{host}", "{port}", "{url}", "{domain}")


def unfilled(cmd: str) -> list[str]:
    """Target placeholders still present in a rendered command (the caller did
    not supply that value). ``{secret_ref}`` is always resolved, so it is not
    listed — a half-substituted command must never be handed over as runnable."""
    return [p for p in _TARGET_PLACEHOLDERS if p in cmd]


def entry(action_id: str) -> dict | None:
    """The raw actions.yaml entry for an action id, or None (manual)."""
    return _load().get(action_id)


def commands() -> dict[str, str]:
    """{action_id: cmd template} for every entry that carries a command."""
    return {k: v["cmd"] for k, v in _load().items() if v.get("cmd")}


def render(action_id: str, *, host: str | None = None, port: int | None = None,
           url: str | None = None, domain: str | None = None) -> dict | None:
    """Render one action for a concrete target.

    Returns {cmd, parses_as, ref, needs, risk, note, then} or None when the id
    has no command template (a manual action). `then` is the fold-back hint:
    the yhwach call to make with the output. Secrets are NOT substituted — a
    {secret_ref} placeholder stays as `$YH_SECRET` for the operator's shell.

    Placeholders are replaced literally (not via str.format) so JSON bodies with
    braces in a command survive untouched.
    """
    e = _load().get(action_id)
    if not e or not e.get("cmd"):
        return None
    cmd = e["cmd"]
    for key, val in (("{host}", host), ("{port}", None if port is None else str(port)),
                     ("{url}", url), ("{domain}", domain), ("{secret_ref}", "$YH_SECRET")):
        if val is not None:
            cmd = cmd.replace(key, val)
    parses_as = e.get("parses_as")
    then = None
    if parses_as:
        then = {"call": "yhwach_interpret", "kind": f"x:{parses_as}",
                "with": "the command's output"}
    return {"cmd": cmd, "parses_as": parses_as, "ref": e.get("ref"),
            "needs": e.get("needs", []), "risk": e.get("risk"),
            "note": e.get("note"), "then": then}
