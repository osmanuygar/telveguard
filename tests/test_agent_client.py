"""telve: hook protokolleri (Cursor, Claude Code), kurulum ve çevrimdışı davranış."""
import json

import pytest

from telveguard_agent import client, config, hooks, install
from tests.test_tr_pii import make_tckn


@pytest.fixture()
def cfg(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    monkeypatch.delenv("TELVEGUARD_URL", raising=False)
    monkeypatch.setattr(config, "managed_path", lambda: tmp_path / "managed" / "agent.json")
    config.save_user({"gateway": "https://telveguard.example"})
    return config.load()


@pytest.fixture()
def gateway(monkeypatch):
    """Gateway'in yerine: verilen karar sırayla döner, istekler kaydedilir."""
    calls, answers = [], []

    def fake(cfg, client, event, text, model="", routed=False, user_hint=""):
        calls.append({"client": client, "event": event, "text": text, "model": model, "routed": routed,
                      "user_hint": user_hint})
        a = answers.pop(0) if answers else {"action": "allow"}
        return {"message": "", "masked_text": None, **a}
    monkeypatch.setattr(hooks, "check", fake)
    return calls, answers


def test_cursor_prompt_block(cfg, gateway):
    calls, answers = gateway
    answers.append({"action": "block", "message": "durdu"})
    out = hooks.cursor(cfg, {"hook_event_name": "beforeSubmitPrompt", "prompt": "x", "model": "gpt-5"})
    assert out == {"continue": False, "user_message": "durdu"}
    assert calls[0]["event"] == "prompt" and calls[0]["model"] == "gpt-5"


def test_cursor_user_email_passed_as_identity_hint(cfg, gateway):
    calls, _ = gateway
    hooks.cursor(cfg, {"hook_event_name": "beforeSubmitPrompt", "prompt": "x", "user_email": "ayse@sirket.com"})
    hooks.cursor(cfg, {"hook_event_name": "beforeReadFile", "content": "y", "user_email": "ayse@sirket.com"})
    assert [c["user_hint"] for c in calls] == ["ayse@sirket.com", "ayse@sirket.com"]


def test_identity_order_token_then_config_then_tool_then_os(cfg, monkeypatch):
    monkeypatch.delenv("TELVEGUARD_TOKEN", raising=False)
    monkeypatch.setenv("USER", "ayse.os")
    assert client.auth_headers(cfg)["x-telveguard-user"] == "ayse.os"
    assert client.auth_headers(cfg, "ayse@sirket.com")["x-telveguard-user"] == "ayse@sirket.com"
    config.save_user({"user": "ayse.yilmaz@sirket.com", "team": "yazilim"})
    h = client.auth_headers(config.load(), "baska@sirket.com")
    assert h == {"x-telveguard-user": "ayse.yilmaz@sirket.com", "x-telveguard-team": "yazilim"}
    monkeypatch.setenv("TELVEGUARD_TOKEN", "jwt")   # giriş yapılmışsa beyan gönderilmez
    assert client.auth_headers(config.load(), "baska@sirket.com") == {"authorization": "Bearer jwt"}


def test_cursor_prompt_attachment_checked(cfg, gateway, tmp_path):
    calls, answers = gateway
    f = tmp_path / "musteri.csv"
    f.write_text("ad,tc\nA,1\n", encoding="utf-8")
    answers.extend([{"action": "allow"}, {"action": "block", "message": "ek"}])
    out = hooks.cursor(cfg, {"hook_event_name": "beforeSubmitPrompt", "prompt": "özetle",
                             "attachments": [{"type": "file", "file_path": str(f)}]})
    assert out["continue"] is False and calls[1] == {**calls[1], "event": "file", "text": "ad,tc\nA,1\n"}


def test_cursor_file_and_tab_use_permission(cfg, gateway):
    _, answers = gateway
    answers.append({"action": "block", "message": "sır"})
    assert hooks.cursor(cfg, {"hook_event_name": "beforeReadFile", "content": "k"}) == \
        {"permission": "deny", "user_message": "sır"}
    assert hooks.cursor(cfg, {"hook_event_name": "beforeTabFileRead", "content": "temiz"}) == {"permission": "allow"}


def test_clean_file_cached(cfg, gateway):
    calls, _ = gateway
    for _ in range(3):
        hooks.cursor(cfg, {"hook_event_name": "beforeTabFileRead", "content": "aynı içerik"})
    assert len(calls) == 1


def test_cursor_shell_and_mcp(cfg, gateway):
    calls, answers = gateway
    answers.append({"action": "block", "message": "dur"})
    out = hooks.cursor(cfg, {"hook_event_name": "beforeShellExecution", "command": "curl x"})
    assert out["permission"] == "deny" and out["agent_message"] == "dur"
    hooks.cursor(cfg, {"hook_event_name": "beforeMCPExecution", "tool_name": "send", "tool_input": {"to": "a"}})
    assert calls[1]["event"] == "tool_input" and '"to": "a"' in calls[1]["text"]


def test_claude_prompt_block_suppresses_original(cfg, gateway):
    calls, answers = gateway
    answers.append({"action": "block", "message": "dur"})
    out = hooks.claude(cfg, {"hook_event_name": "UserPromptSubmit", "prompt": "x"}, routed=True)
    assert out["decision"] == "block" and out["hookSpecificOutput"]["suppressOriginalPrompt"] is True
    assert calls[0]["routed"] is True


def test_claude_pre_tool(cfg, gateway):
    calls, answers = gateway
    answers.append({"action": "block", "message": "dur"})
    out = hooks.claude(cfg, {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "env"}})
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert calls[0] == {**calls[0], "event": "shell", "text": "env"}


def test_claude_post_tool_masks_keeping_shape(cfg, gateway):
    calls, answers = gateway
    resp = {"stdout": "tc=12345678901", "stderr": "", "interrupted": False, "isImage": False}
    answers.append({"action": "mask", "message": "m",
                    "masked_text": json.dumps({**resp, "stdout": "tc=[TCKN_1]"})})
    out = hooks.claude(cfg, {"hook_event_name": "PostToolUse", "tool_name": "Bash", "tool_response": resp})
    assert out["hookSpecificOutput"]["updatedToolOutput"] == {**resp, "stdout": "tc=[TCKN_1]"}
    assert calls[0]["event"] == "tool_output"


def test_claude_post_tool_block_replaces_content_not_fields(cfg, gateway):
    _, answers = gateway
    resp = {"type": "text", "file": {"filePath": "/a.txt", "content": "uzun içerik\n" * 20, "numLines": 20}}
    answers.append({"action": "block", "message": "dur", "masked_text": None})
    out = hooks.claude(cfg, {"hook_event_name": "PostToolUse", "tool_name": "Read", "tool_response": resp})
    new = out["hookSpecificOutput"]["updatedToolOutput"]
    assert new["type"] == "text" and new["file"]["filePath"] == "/a.txt" and new["file"]["numLines"] == 20
    assert new["file"]["content"] == hooks.BLOCK_NOTICE


def test_offline_local_scan(cfg, monkeypatch):
    """Gateway yok, fail_closed değil: yerel tarama riskliyi durdurur, temizi geçirir."""
    def down(*a, **k):
        raise hooks.GatewayError("ulaşılamadı")
    monkeypatch.setattr(hooks, "check", down)
    tckn = make_tckn()
    assert hooks.decide(cfg, "cursor", "prompt", f"TC {tckn}")["action"] == "block"
    assert hooks.decide(cfg, "cursor", "prompt", "merhaba")["action"] == "allow"
    r = hooks.decide(cfg, "claude-code", "tool_output", f"tc={tckn}")
    assert r["action"] == "mask" and tckn not in r["masked_text"]


def test_offline_fail_closed(cfg, monkeypatch, tmp_path):
    def down(*a, **k):
        raise hooks.GatewayError("ulaşılamadı")
    monkeypatch.setattr(hooks, "check", down)
    managed = tmp_path / "managed" / "agent.json"
    managed.parent.mkdir()
    managed.write_text('{"fail_closed": true}')
    c = config.load()
    assert c.fail_closed and "fail_closed" in c.managed_keys
    assert hooks.decide(c, "cursor", "prompt", "merhaba")["action"] == "block"


def test_managed_config_wins(cfg, tmp_path, monkeypatch):
    managed = tmp_path / "managed" / "agent.json"
    managed.parent.mkdir()
    managed.write_text('{"gateway": "https://kurum.example"}')
    monkeypatch.setenv("TELVEGUARD_URL", "https://kullanici.example")
    assert config.load().gateway_url == "https://kurum.example"


# ---------------- kurulum ----------------

def test_cursor_install_preserves_other_hooks_and_is_idempotent():
    existing = {"version": 1, "hooks": {"afterFileEdit": [{"command": "./format.sh"}],
                                        "beforeSubmitPrompt": [{"command": "./other.sh"}]}}
    once = install.cursor_config(existing, "/opt/telve/bin/telve", fail_closed=True)
    twice = install.cursor_config(once, "/opt/telve/bin/telve", fail_closed=True)
    assert once == twice
    assert twice["hooks"]["afterFileEdit"] == [{"command": "./format.sh"}]
    assert twice["hooks"]["beforeSubmitPrompt"] == [
        {"command": "./other.sh"},
        {"command": "/opt/telve/bin/telve hook cursor", "timeout": 15, "failClosed": True}]
    assert set(hooks.CURSOR_EVENTS) <= set(twice["hooks"])
    removed = install.cursor_config(twice, "/opt/telve/bin/telve", False, remove=True)
    assert removed == existing


def test_claude_install_route_and_uninstall():
    existing = {"model": "sonnet", "hooks": {"Stop": [{"hooks": [{"type": "command", "command": "say bitti"}]}]}}
    path = "/Users/a b/telve"
    data = install.claude_config(existing, path, "https://tg.example", route=True)
    assert data["env"]["ANTHROPIC_BASE_URL"] == "https://tg.example"
    assert data["apiKeyHelper"] == '"/Users/a b/telve" token'
    cmd = data["hooks"]["PostToolUse"][0]["hooks"][0]["command"]
    assert cmd == '"/Users/a b/telve" hook claude --routed'
    assert data["hooks"]["PostToolUse"][0]["matcher"] == hooks.CLAUDE_POST_MATCHER
    again = install.claude_config(data, path, "https://tg.example", route=True)
    assert again == data
    assert install.claude_config(data, path, remove=True) == existing


def test_enterprise_paths_do_not_overwrite_managed_settings():
    """Claude Code: kurumun managed-settings.json'una değil, ayrı bir drop-in dosyasına."""
    p = install.claude_path("enterprise")
    assert p.name == "telveguard.json" and p.parent.name == "managed-settings.d"
    assert install.cursor_path("enterprise").name == "hooks.json"
