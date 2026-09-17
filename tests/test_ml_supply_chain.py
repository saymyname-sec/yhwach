"""AI/ML supply-chain detectors and the five chains they unlock.

Five rules shipped with a `findings_include` tag that no parser or extractor
ever produced, so the planner could never fire them:

    ai_code_review        -> zero_width_code_review_evasion
    code_scanner          -> gitlab_ai_scanner_bypass
    model_checkpoint_load -> model_checkpoint_pickle_rce
    pickle_endpoint       -> pickle_deserialization_rce
    training_pipeline     -> training_pipeline_poisoning

Each test here drives a chain end to end — real tool output -> extractor ->
tagged finding -> `match_rules` against the real playbooks -> the rule appears
in the queue. The false-positive tests matter just as much: a wrong tag costs
an exploitation turn, so silence is the safe default.
"""
from __future__ import annotations

from pathlib import Path

from yhwach import db as yhdb
from yhwach.interpret import interpret_all
from yhwach.parsers.peas import parse_peas
from yhwach.planner import match_rules, top_tasks
from yhwach.playbooks import default_playbook_dir, load_rules


def _seed(tmp_db: Path, kind: str, port: int = 8080) -> int:
    """Engagement + one scanned host carrying a surface of `kind`."""
    with yhdb.transaction(tmp_db) as conn:
        eng = yhdb.upsert_engagement(conn, lab="ml", scope="10.0.0.0/24")
        hid = conn.execute(
            "INSERT INTO host (engagement_id, ip, os, stage, first_seen) "
            "VALUES (?, '10.0.0.5', 'linux', 'scanned', 't')", (eng,)).lastrowid
        sid = conn.execute(
            "INSERT INTO service (host_id, port, proto, discovered_at) "
            "VALUES (?, ?, 'tcp', 't')", (hid, port)).lastrowid
        yhdb.upsert_surface(conn, int(hid), int(sid), kind, "none", "{}")
    return eng


def _record(tmp_db: Path, findings: list) -> None:
    """Persist extractor output the way engine.execute_task does."""
    with yhdb.transaction(tmp_db) as conn:
        hid = conn.execute("SELECT id FROM host LIMIT 1").fetchone()["id"]
        for f in findings:
            yhdb.add_finding(conn, hid, None, f.cls, f.title, f.severity, f.evidence, tag=f.tag)


def _queued(tmp_db: Path, eng: int) -> list[str]:
    rules = load_rules(default_playbook_dir())
    with yhdb.transaction(tmp_db) as conn:
        match_rules(conn, eng, rules)
        return [t["playbook_rule_id"] for t in top_tasks(conn, eng, 100)]


def _tags(findings: list) -> set[str]:
    return {f.tag for f in findings if f.tag}


# --- pickle_endpoint --------------------------------------------------------

_TOOL_LIST = """
[+] Tools exposed by the assistant:
  - web_search(query: str)
  - calculator(expression: str)   -> evaluated with sympy.sympify()
  - load_model(path: str)         -> POST /load_model
"""


def test_tool_list_reveals_pickle_surface(tmp_db: Path) -> None:
    found = interpret_all("craft_tool_enumeration", _TOOL_LIST, {"URL": "http://10.0.0.5:8080"})
    assert "pickle_endpoint" in _tags(found)
    hit = next(f for f in found if f.tag == "pickle_endpoint")
    assert hit.cls == "CWE-502" and hit.severity == "high"


def test_pickle_chain_unlocks_the_rce_rule(tmp_db: Path) -> None:
    eng = _seed(tmp_db, "chatbot")
    assert "pickle_deserialization_rce" not in _queued(tmp_db, eng)
    _record(tmp_db, interpret_all("craft_tool_enumeration", _TOOL_LIST, {"URL": "u"}))
    assert "pickle_deserialization_rce" in _queued(tmp_db, eng)


def test_openapi_spec_pickle_path(tmp_db: Path) -> None:
    spec = '{"paths": {"/deserialize": {"post": {"summary": "restore a session.pkl"}}}}'
    assert "pickle_endpoint" in _tags(interpret_all("probe_openapi_spec", spec, {}))


# --- model_checkpoint_load --------------------------------------------------

def test_model_listing_reveals_checkpoint_load(tmp_db: Path) -> None:
    out = '{"data": [{"id": "mistral-7b", "source": "torch.load(/srv/models/latest.ckpt)"}]}'
    found = interpret_all("enumerate_models", out, {"URL": "http://10.0.0.5:8000"})
    tags = _tags(found)
    assert "model_checkpoint_load" in tags
    # The composed extractor must not have shadowed the original one.
    assert any("OpenAI-compatible" in f.title for f in found)


def test_linpeas_writable_checkpoint_is_high(tmp_db: Path) -> None:
    peas = "[+] Interesting writable files\n  -rw-rw-rw- /srv/models/resnet_final.pth\n"
    found = parse_peas(peas, "linpeas")
    hit = next(f for f in found if f.tag == "model_checkpoint_load")
    assert hit.severity == "high" and "resnet_final.pth" in hit.evidence


def test_linpeas_readonly_checkpoint_is_medium(tmp_db: Path) -> None:
    peas = "  -r--r--r-- root root /opt/serve/pytorch_model.bin\n"
    hit = next(f for f in parse_peas(peas, "linpeas") if f.tag == "model_checkpoint_load")
    assert hit.severity == "medium"


def test_checkpoint_chain_unlocks_the_host_scoped_rule(tmp_db: Path) -> None:
    eng = _seed(tmp_db, "chatbot")
    assert "model_checkpoint_pickle_rce" not in _queued(tmp_db, eng)
    _record(tmp_db, parse_peas("  -rw-rw-rw- /srv/models/latest.ckpt\n", "linpeas"))
    assert "model_checkpoint_pickle_rce" in _queued(tmp_db, eng)


def test_safetensors_is_not_a_pickle_signal(tmp_db: Path) -> None:
    """The format exists precisely so it is not a pickle — never tag it."""
    peas = "  -rw-rw-rw- /srv/models/model.safetensors\n"
    assert _tags(parse_peas(peas, "linpeas")) == set()


# --- training_pipeline ------------------------------------------------------

def test_training_artifacts_tagged_from_peas(tmp_db: Path) -> None:
    peas = "  /opt/ft/adapter_config.json\n  /opt/ft/adapter_model.bin\n"
    assert "training_pipeline" in _tags(parse_peas(peas, "linpeas"))


def test_training_chain_unlocks_the_poisoning_rule(tmp_db: Path) -> None:
    eng = _seed(tmp_db, "chatbot")
    assert "training_pipeline_poisoning" not in _queued(tmp_db, eng)
    _record(tmp_db, interpret_all(
        "probe_openapi_spec", '{"paths": {"/v1/fine_tuning/jobs": {}}}', {}))
    assert "training_pipeline_poisoning" in _queued(tmp_db, eng)


# --- ai_code_review / code_scanner -----------------------------------------

_GITLAB_RECON = """
{"projects": [{"path": "payments-api", "ci_config_path": ".gitlab-ci.yml"}]}
stages: [build, sast, ai-review]
  pre-receive hook: semgrep --config auto
  approvals: gitlab-duo code review required
"""


def test_gitlab_recon_tags_both_guards(tmp_db: Path) -> None:
    found = interpret_all("gitlab_public_repos", _GITLAB_RECON, {"URL": "http://10.0.0.5"})
    assert _tags(found) == {"code_scanner", "ai_code_review"}


def test_gitlab_chain_unlocks_both_bypass_rules(tmp_db: Path) -> None:
    eng = _seed(tmp_db, "gitlab", port=80)
    before = _queued(tmp_db, eng)
    assert "gitlab_ai_scanner_bypass" not in before
    assert "zero_width_code_review_evasion" not in before
    _record(tmp_db, interpret_all("gitlab_public_repos", _GITLAB_RECON, {"URL": "u"}))
    after = _queued(tmp_db, eng)
    assert "gitlab_ai_scanner_bypass" in after
    assert "zero_width_code_review_evasion" in after


# --- silence on benign output ----------------------------------------------

def test_benign_output_tags_nothing(tmp_db: Path) -> None:
    benign = [
        ("craft_tool_enumeration", "- web_search(query)\n- get_weather(city)"),
        ("probe_openapi_spec", '{"paths": {"/health": {"get": {}}}}'),
        ("gitlab_public_repos", '{"projects": [{"path": "docs", "visibility": "public"}]}'),
        ("enumerate_models", '{"data": [{"id": "gpt-4o-mini"}]}'),
    ]
    for action, output in benign:
        assert _tags(interpret_all(action, output, {})) == set(), action


def test_safe_yaml_load_is_not_flagged(tmp_db: Path) -> None:
    """`yaml.load(f, Loader=SafeLoader)` is the fix, not the bug."""
    assert _tags(interpret_all(
        "probe_openapi_spec", "config = yaml.load(f, Loader=yaml.SafeLoader)", {})) == set()
