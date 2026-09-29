"""MCP araç izin listesi + agent kimliği (ContextForge eklentisi, gerçek UserContext ile)."""
import pytest

pytest.importorskip("cpex.framework")

from cpex.framework import GlobalContext, PluginConfig, PluginContext, ToolPreInvokePayload  # noqa: E402
from cpex.framework.models import UserContext  # noqa: E402

from telveguard_contextforge import TelveguardPlugin  # noqa: E402

ACCESS = {
    "default": "allow",
    "rules": [
        {"name": "stajyer-dis-arac-yok", "teams": ["stajyer"], "deny": ["github*", "email*"]},
        {"name": "silme-yasak", "teams": ["*"], "deny": ["*delete*"]},
    ],
}


def plugin(tool_access):
    cfg = PluginConfig(name="T", kind="telveguard_contextforge.TelveguardPlugin",
                       hooks=["tool_pre_invoke"], config={"tool_access": tool_access})
    return TelveguardPlugin(cfg)


def ctx(user="ayse@sirket.com", teams=None, groups=None, service_account=None, original_name=None):
    uc = UserContext(user_id=user, teams=teams, groups=groups or [], service_account=service_account)
    meta = {"tool": {"original_name": original_name}} if original_name else {}
    return PluginContext(global_context=GlobalContext(request_id="r", user_context=uc, metadata=meta))


async def call(p, name, c):
    return await p.tool_pre_invoke(ToolPreInvokePayload(name=name, args={"q": "x"}), c)


@pytest.mark.parametrize("tool", ["github_create_pr", "gw-github-create-pr", "EMAIL_SEND", "mcp.email-send"])
async def test_team_deny_rule_blocks_including_prefixed_names(tool):
    r = await call(plugin(ACCESS), tool, ctx(teams=["stajyer"]))
    assert r.continue_processing is False and r.violation.code == "TELVEGUARD_TOOL_DENIED"
    assert r.violation.details["rule"] == "stajyer-dis-arac-yok"
    assert r.violation.details["user"] == "ayse@sirket.com"


async def test_other_team_allowed():
    r = await call(plugin(ACCESS), "github_create_pr", ctx(teams=["analitik"]))
    assert r.continue_processing is True


async def test_wildcard_team_rule_applies_to_everyone():
    r = await call(plugin(ACCESS), "crm_delete_customer", ctx(teams=["analitik"]))
    assert r.violation.details["rule"] == "silme-yasak"


async def test_deny_wins_over_other_teams_allow():
    """stajyer + analitik: analitik'in izni stajyer yasağını aşamaz."""
    acc = {"default": "deny", "rules": [
        {"name": "analitik", "teams": ["analitik"], "allow": ["github_*"]},
        {"name": "stajyer", "teams": ["stajyer"], "deny": ["github*"]}]}
    r = await call(plugin(acc), "github_create_pr", ctx(teams=["analitik", "stajyer"]))
    assert r.continue_processing is False and r.violation.details["rule"] == "stajyer"


async def test_default_deny_only_explicit_allow():
    acc = {"default": "deny", "rules": [{"name": "crm", "teams": ["musteri"], "allow": ["crm_*"]}]}
    p = plugin(acc)
    assert (await call(p, "crm_lookup", ctx(teams=["musteri"]))).continue_processing is True
    r = await call(p, "web_fetch", ctx(teams=["musteri"]))
    assert r.continue_processing is False and r.violation.details["rule"] == "default-deny"
    assert (await call(p, "crm_lookup", ctx(teams=["baska"]))).continue_processing is False


async def test_allow_is_strict_on_prefixed_names():
    """'crm_*' izni önekli ad üzerinden geniş eşleşmez: 'evil_crm_x' açılmamalı.
    ContextForge orijinal adı verirse o kullanılır."""
    acc = {"default": "deny", "rules": [{"teams": ["*"], "allow": ["crm_*"]}]}
    p = plugin(acc)
    assert (await call(p, "evil-crm-x", ctx(teams=["a"]))).continue_processing is False
    assert (await call(p, "gw-crm-lookup", ctx(teams=["a"], original_name="crm_lookup"))).continue_processing is True


async def test_user_pattern_and_groups():
    acc = {"default": "allow", "rules": [
        {"name": "dis-kullanici", "users": ["*@disari.com"], "deny": ["*"]},
        {"name": "grup", "teams": ["yuklenici"], "deny": ["repo_*"]}]}
    p = plugin(acc)
    assert (await call(p, "crm_lookup", ctx(user="x@disari.com"))).violation.details["rule"] == "dis-kullanici"
    # Ekip yoksa gruplar da eşleşir
    assert (await call(p, "repo_read", ctx(groups=["yuklenici"]))).violation.details["rule"] == "grup"


async def test_agent_identity_recorded_for_allowed_calls():
    r = await call(plugin(ACCESS), "crm_lookup",
                   ctx(user="ayse@sirket.com", teams=["analitik"], service_account="raporlama-agent"))
    assert r.continue_processing is True
    assert r.metadata["telveguard"] == {"caller": "ayse@sirket.com", "teams": ["analitik"],
                                        "service_account": "raporlama-agent"}


async def test_no_rules_no_overhead_and_no_user_context():
    p = plugin({})
    c = PluginContext(global_context=GlobalContext(request_id="r", user="servis"))
    r = await call(p, "anything", c)
    assert r.continue_processing is True and r.metadata["telveguard"]["caller"] == "servis"


def test_invalid_default_rejected():
    with pytest.raises(Exception):
        plugin({"default": "belki"})
