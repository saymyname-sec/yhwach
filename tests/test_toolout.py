"""Parser robustness against realistic captured tool output.

These fixtures (tests/fixtures/toolout/) are shaped like real netexec / kerbrute /
enum4linux-ng / ldapsearch / certipy / SharpHound output — the point is to catch
format drift the minimal synthetic strings in the other tests would miss. When a
real lab produces output a parser mishandles, drop it here and harden the parser.
"""
from __future__ import annotations

from pathlib import Path

from yhwach.interpret import interpret_all
from yhwach.parsers.adcs import parse_certipy
from yhwach.parsers.bloodhound import parse_bloodhound
from yhwach.parsers.peas import parse_linpeas, parse_winpeas

_DIR = Path(__file__).parent / "fixtures" / "toolout"


def _read(name: str) -> str:
    return (_DIR / name).read_text(encoding="utf-8")


def test_nxc_smb_realistic_multi_signal() -> None:
    fs = interpret_all("netexec_smb_null", _read("nxc_smb.txt"), {"IP": "10.10.10.20"})
    tags = {f.tag for f in fs}
    assert "smb_signing_off" in tags       # (signing:False)
    assert "null_session" in tags          # READ,WRITE shares + domain\user
    assert any(f.severity == "critical" for f in fs)   # (Pwn3d!)


def test_nxc_coerce_services_tags() -> None:
    tags = {f.tag for f in interpret_all("nxc_coerce_service_check",
                                         _read("nxc_coerce_services.txt"), {"IP": "10.10.10.10"})}
    assert tags == {"coercion_target", "webclient_running"}   # 'not enabled' line ignored


def test_nxc_rid_brute_userlist() -> None:
    fs = interpret_all("netexec_rid_brute", _read("nxc_rid_brute.txt"), {"IP": "10.10.11.231"})
    assert any(f.tag == "domain_users" for f in fs)


def test_nxc_laps_password_tagged() -> None:
    fs = interpret_all("netexec_laps", _read("nxc_laps.txt"), {"IP": "10.10.10.10"})
    assert fs and fs[0].tag == "laps_password" and fs[0].severity == "critical"


def test_nxc_laps_expiration_only_not_tagged() -> None:
    # A bare expiration timestamp (no ms-Mcs-AdmPwd value) must not tag.
    assert not interpret_all("netexec_laps", "ms-mcs-admpwdexpirationtime: 13344556677", {"IP": "x"})


def test_nxc_desc_users_finds_password() -> None:
    fs = interpret_all("netexec_get_desc_users", _read("nxc_desc_users.txt"), {"IP": "10.0.2.11"})
    assert fs and fs[0].tag == "desc_password"
    assert "svc_backup" in fs[0].evidence   # not Guest/krbtgt (benign descriptions)


def test_constrained_delegation_tag() -> None:
    fs = interpret_all("ldap_find_constrained_delegation",
                       _read("bloodyad_constrained_deleg.txt"), {"IP": "10.10.10.10"})
    assert fs and fs[0].tag == "constrained_delegation"


def test_nxc_maq_positive_quota_tagged() -> None:
    fs = interpret_all("netexec_maq", _read("nxc_maq.txt"), {"IP": "10.10.10.10"})
    assert fs and fs[0].tag == "machine_account_quota" and "MachineAccountQuota=10" in fs[0].evidence


def test_nxc_maq_zero_quota_not_tagged() -> None:
    assert not interpret_all("netexec_maq", "MAQ  DC01  MachineAccountQuota: 0", {"IP": "x"})


def test_nxc_badsuccessor_tag() -> None:
    fs = interpret_all("nxc_badsuccessor_check", _read("nxc_badsuccessor.txt"), {"IP": "10.10.10.10"})
    assert fs and fs[0].tag == "dmsa_badsuccessor" and fs[0].severity == "critical"


def test_nxc_pass_pol_no_lockout() -> None:
    fs = interpret_all("netexec_pass_pol", _read("nxc_pass_pol.txt"), {"IP": "10.10.10.10"})
    assert fs and fs[0].tag == "password_policy"
    assert "spray freely" in fs[0].evidence   # Threshold: None


def test_timeroast_hashes_tagged() -> None:
    fs = interpret_all("timeroast_ntp", _read("timeroast_hashes.txt"), {"IP": "10.10.10.10"})
    assert fs and fs[0].tag == "timeroastable" and "2 $sntp-ms$" in fs[0].evidence


def test_kerbrute_userlist() -> None:
    fs = interpret_all("kerbrute_userenum", _read("kerbrute_users.txt"), {"IP": "10.10.10.20"})
    assert any(f.tag == "domain_users" for f in fs)


def test_enum4linux_users_and_smb() -> None:
    fs = interpret_all("enum4linux_ng", _read("enum4linux_users.txt"), {"IP": "10.10.10.20"})
    assert any(f.tag == "domain_users" for f in fs)   # 'username:' lines


def test_ldapsearch_anon_naming_context() -> None:
    fs = interpret_all("ldapsearch_anon", _read("ldapsearch_anon.txt"), {"IP": "10.10.10.20"})
    assert fs and fs[0].tag == "ldap_anon" and "corp.local" in fs[0].evidence


def test_certipy_real_json() -> None:
    fs = parse_certipy(_read("certipy_find.json"))
    assert len(fs) == 1                    # SafeUser skipped, VulnUserESC1 kept
    assert fs[0].tag == "adcs_vuln" and "ESC1" in fs[0].title and fs[0].severity == "critical"


def test_sharphound_users_collection() -> None:
    tags = {f.tag for f in parse_bloodhound(_read("sharphound_users.json"))}
    assert tags == {"kerberoastable", "asreproastable"}   # SPN user + no-preauth user


def test_bloodhound_facts_incl_unknown_edge() -> None:
    tags = {f.tag for f in parse_bloodhound(_read("bloodhound_facts.json"))}
    assert {"kerberoastable", "dcsync", "unconstrained_delegation"}.issubset(tags)
    assert "some_new_edge_type" in tags   # forward-compatible


def test_excessive_agency_toolcall_success() -> None:
    fs = interpret_all("craft_tool_agency_abuse", _read("excessive_agency_toolcall.json"),
                       {"URL": "https://10.0.0.15"})
    assert fs and fs[0].tag == "excessive_agency_confirmed" and fs[0].severity == "critical"


def test_winpeas_privesc_multi_tag() -> None:
    tags = {f.tag for f in parse_winpeas(_read("winpeas_privesc.txt"))}
    assert {"writable_scheduled_task", "lsa_defaultpassword", "dpapi_master_key",
            "seimpersonate"}.issubset(tags)


def test_linpeas_supplychain_tags() -> None:
    tags = {f.tag for f in parse_linpeas(_read("linpeas_supplychain.txt"))}
    assert {"gitlab_token", "python_requirements", "mcp_config_writable"}.issubset(tags)


def test_linpeas_cloud_tags() -> None:
    tags = {f.tag for f in parse_linpeas(_read("linpeas_cloud.txt"))}
    assert {"k8s_sa_token", "nvidia_toolkit"}.issubset(tags)


def test_k8s_can_create_pods() -> None:
    fs = interpret_all("k8s_sa_token_enum", _read("k8s_selfsubjectrules.json"), {"IP": "pod"})
    assert fs and fs[0].tag == "pod_create_permission"


def test_imds_creds_tags_aws() -> None:
    fs = interpret_all("probe_imds_v1", _read("imds_creds.json"), {"URL": "http://10.0.0.10"})
    assert fs and fs[0].tag == "aws_credentials" and fs[0].severity == "critical"


def test_sagemaker_passrole_tag() -> None:
    fs = interpret_all("aws_iam_role_chain", _read("aws_iam_perms.txt"), {})
    assert fs and fs[0].tag == "sagemaker_create_notebook"


def test_ssrf_egress_proxy_tags_confirmed() -> None:
    fs = interpret_all("probe_ssrf_egress_proxy", _read("ssrf_file_passwd.txt"),
                       {"URL": "http://10.0.0.10"})
    assert fs and fs[0].tag == "ssrf_confirmed" and fs[0].severity == "critical"


def test_jenkins_proxy_bypass_tags_unsecured() -> None:
    fs = interpret_all("jenkins_oauth2proxy_bypass", _read("jenkins_proxy_bypass.txt"),
                       {"URL": "http://10.0.0.30:8443"})
    assert fs and fs[0].tag == "jenkins_unsecured" and fs[0].severity == "critical"


def test_lfi_passwd_tags_confirmed() -> None:
    fs = interpret_all("probe_tool_lfi_traversal", _read("lfi_passwd.txt"),
                       {"URL": "http://10.0.0.90"})
    assert fs and fs[0].tag == "lfi_confirmed" and fs[0].cls == "LLM06"


def test_ssti_reflection_tags_jinja2() -> None:
    fs = interpret_all("craft_ssti_probe", _read("ssti_reflection.json"),
                       {"URL": "http://10.0.0.105"})
    assert fs and fs[0].tag == "jinja2_template" and fs[0].cls == "LLM01"


def test_ssti_probe_literal_echo_is_no_finding() -> None:
    # An app that echoes the payload without evaluating it must NOT be tagged.
    assert not interpret_all("craft_ssti_probe", '{"rendered":"X{{7*7}}X"}', {})


def test_langflow_exec_probe_tags_host() -> None:
    fs = interpret_all("probe_langflow_exec", _read("langflow_exec_probe.txt"),
                       {"URL": "http://10.0.0.30"})
    assert fs and fs[0].tag == "langflow_exec" and fs[0].severity == "critical"


def test_ollama_version_fixture_is_vulnerable() -> None:
    fs = interpret_all("probe_ollama_version", _read("ollama_version.json"),
                       {"URL": "http://10.0.0.45:11434"})
    assert fs and fs[0].tag == "ollama_probllama" and fs[0].cls == "CVE-2024-37032"


def test_n8n_version_fixture_is_vulnerable() -> None:
    fs = interpret_all("probe_n8n_version", _read("n8n_version.json"),
                       {"URL": "https://10.0.0.30:5678"})
    assert fs and fs[0].tag == "n8n_ni8mare" and fs[0].cls == "CVE-2026-21858"


def test_n8n_version_patched_is_clean() -> None:
    fs = interpret_all("probe_n8n_version", '{"data":{"versionCli":"1.121.0"}}',
                       {"URL": "https://10.0.0.30:5678"})
    assert fs == []


def test_n8n_env_leaks_encryption_key() -> None:
    fs = interpret_all("n8n_ni8mare_file_read", _read("n8n_env.txt"),
                       {"URL": "https://10.0.0.30:5678"})
    assert fs and fs[0].tag == "n8n_encryption_key" and fs[0].cls == "CWE-522"


def test_gpohound_control_tag() -> None:
    fs = interpret_all("gpohound_enum", _read("gpohound_analysis.txt"), {"IP": "10.10.10.10"})
    assert fs and fs[0].tag == "gpo_control"


def test_enum_trusts_tag() -> None:
    fs = interpret_all("enumerate_domain_trusts", _read("nxc_enum_trusts.txt"), {"IP": "10.10.10.10"})
    assert fs and fs[0].tag == "domain_trust"


def test_bloodhound_domain_trust_fact() -> None:
    tags = {f.tag for f in parse_bloodhound('[{"kind":"domain_trust","principal":"corp.local"}]')}
    assert "domain_trust" in tags


def test_bloodhound_relay_facts() -> None:
    tags = {f.tag for f in parse_bloodhound(_read("bloodhound_relay_facts.json"))}
    assert {"webclient_running", "ntlm_relay_dc", "no_smb_signing"}.issubset(tags)


def test_bloodhound_shadow_cred_target() -> None:
    fs = parse_bloodhound(_read("bloodhound_shadowcred.json"))
    sc = next(f for f in fs if f.tag == "shadow_cred_target")
    assert sc.severity == "critical" and sc.cls == "T1556"
    assert "KeyCredentialLink" in sc.title


def test_rag_import_tags_write_primitive() -> None:
    fs = interpret_all("rag_authenticated_import", _read("rag_import.json"),
                       {"URL": "http://10.0.0.55:3000"})
    assert fs and fs[0].tag == "rag_import_ok" and fs[0].cls == "LLM06"


def test_a2a_task_capture_tags_creds() -> None:
    fs = interpret_all("a2a_capture_task_creds", _read("a2a_task_capture.txt"),
                       {"IP": "172.16.232.10"})
    assert fs and fs[0].tag == "a2a_creds_captured" and fs[0].severity == "critical"
    assert "sa" in fs[0].evidence
