"""Model adına göre sağlayıcı yönlendirmesi (providers) ve Azure OpenAI."""
import json

import httpx
import pytest
from fastapi.testclient import TestClient

from app import main
from app.providers import ProviderError, ProviderRegistry
from tests.test_tr_pii import make_tckn

CFG = {"providers": [
    {"name": "Google Gemini", "match": ["gemini-"], "type": "openai",
     "url": "https://gemini.example/v1beta/openai", "key_env": "TEST_GEMINI_KEY", "country": "ABD"},
    {"name": "Azure OpenAI", "match": ["azure-"], "type": "azure", "url": "https://kurum.openai.azure.example",
     "key_env": "TEST_AZURE_KEY", "country": "İsveç (AB)"},
    {"name": "Azure klasik", "match": ["az2-"], "type": "azure", "url": "https://eski.openai.azure.example",
     "api_version": "2024-10-21", "deployments": {"az2-gpt4o": "uretim-gpt4o"}},
    {"name": "Kurum Qwen", "match": ["qwen"], "type": "openai", "url": "http://qwen.local/v1",
     "destination": "internal"},
    {"name": "Harici Qwen", "match": ["gpt-disari"], "type": "openai", "url": "http://disari.example/v1"},
    {"name": "Anthropic", "match": ["claude-"], "type": "anthropic", "url": "https://anthropic.example",
     "key_env": "TEST_ANTHROPIC_KEY"},
]}

sent = {}


def upstream(request: httpx.Request) -> httpx.Response:
    body = json.loads(request.content)
    sent.update(url=str(request.url), headers=dict(request.headers), body=body)
    if request.url.path.endswith("/messages"):
        return httpx.Response(200, json={"id": "m", "type": "message", "role": "assistant", "model": body["model"],
                                         "content": [{"type": "text", "text": "tamam"}], "stop_reason": "end_turn",
                                         "usage": {"input_tokens": 3, "output_tokens": 2}})
    if request.url.path.endswith("/responses"):
        return httpx.Response(200, json={"id": "r", "object": "response", "output": [], "usage": {}})
    return httpx.Response(200, json={"id": "x", "created": 0, "model": body.get("model"), "choices": [
        {"index": 0, "finish_reason": "stop", "message": {"role": "assistant",
                                                           "content": "Aldım: " + body["messages"][-1]["content"]}}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5}})


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setenv("TEST_GEMINI_KEY", "gemini-test-degeri")
    monkeypatch.setenv("TEST_AZURE_KEY", "azure-test-degeri")
    monkeypatch.setenv("TEST_ANTHROPIC_KEY", "anthropic-test-degeri")
    main.app.state.http = httpx.AsyncClient(transport=httpx.MockTransport(upstream))
    with TestClient(main.app) as c:
        c.app.state.providers = ProviderRegistry.from_config(CFG)
        sent.clear()
        yield c


def chat(client, model, content="merhaba"):
    return client.post("/v1/chat/completions", json={"model": model, "messages": [{"role": "user", "content": content}]})


def test_gemini_goes_to_its_own_url_with_its_key(client):
    tckn = make_tckn()
    r = chat(client, "gemini-2.5-pro", f"TC {tckn}")
    assert r.status_code == 200
    assert sent["url"] == "https://gemini.example/v1beta/openai/chat/completions"
    assert sent["headers"]["authorization"] == "Bearer gemini-test-degeri"
    assert "[TCKN_1]" in sent["body"]["messages"][-1]["content"]      # yurt dışı: maskeli
    assert tckn in r.json()["choices"][0]["message"]["content"]


def test_azure_v1_api(client):
    assert chat(client, "azure-gpt-4o").status_code == 200
    assert sent["url"] == "https://kurum.openai.azure.example/openai/v1/chat/completions"
    assert sent["headers"]["api-key"] == "azure-test-degeri" and "authorization" not in sent["headers"]


def test_azure_classic_deployment_url(client):
    chat(client, "az2-gpt4o")
    assert sent["url"] == ("https://eski.openai.azure.example/openai/deployments/uretim-gpt4o/chat/completions"
                           "?api-version=2024-10-21")
    chat(client, "az2-baska")                                  # eşleme yoksa model adı = deployment
    assert "/deployments/az2-baska/" in sent["url"]


def test_azure_responses(client):
    r = client.post("/v1/responses", json={"model": "azure-gpt-4o", "input": "merhaba"})
    assert sent["url"] == "https://kurum.openai.azure.example/openai/v1/responses", r.text


def test_provider_destination_wins_over_policy_prefix(client):
    """Politikada 'gpt-' yurt dışı; sağlayıcı 'qwen' kurum içi: maskelenmez. Tersi de geçerli."""
    tckn = make_tckn()
    chat(client, "qwen3-32b", f"TC {tckn}")
    assert sent["url"].startswith("http://qwen.local/v1") and tckn in sent["body"]["messages"][-1]["content"]
    chat(client, "gpt-disari-1", f"TC {tckn}")
    assert "[TCKN_1]" in sent["body"]["messages"][-1]["content"]


def test_anthropic_provider_for_messages(client):
    r = client.post("/v1/messages", json={"model": "claude-sonnet-5", "max_tokens": 10,
                                          "messages": [{"role": "user", "content": "merhaba"}]})
    assert r.status_code == 200
    assert sent["url"] == "https://anthropic.example/v1/messages"
    assert sent["headers"]["x-api-key"] == "anthropic-test-degeri"


def test_format_mismatch_is_clear_error_and_nothing_sent(client):
    r = chat(client, "claude-sonnet-5")          # yalnızca Anthropic biçimi tanımlı
    assert r.status_code == 400 and r.json()["error"]["code"] == "no_upstream"
    assert "messages" in r.json()["error"]["message"] and sent == {}


def test_unmatched_model_uses_legacy_upstream(client):
    chat(client, "gpt-4o")
    assert sent["url"] == "https://api.openai.com/v1/chat/completions"


def test_simulate_and_policy_info_show_provider(client, monkeypatch):
    monkeypatch.setenv("TELVEGUARD_ADMIN_TOKEN", "t")
    h = {"Authorization": "Bearer t"}
    body = client.post("/v1/policy/simulate", headers=h, json={
        "model": "azure-gpt-4o", "messages": [{"role": "user", "content": "x"}]}).json()
    assert body["provider"] == "Azure OpenAI" and body["destination"] == "external"
    info = client.get("/v1/policy/info", headers=h).json()
    azure = next(p for p in info["providers"] if p["name"] == "Azure OpenAI")
    assert azure == {"name": "Azure OpenAI", "match": ["azure-"], "type": "azure", "destination": "external"}
    assert "url" not in azure and "key_env" not in azure


def test_reports_use_provider_name_and_country():
    from app import compliance, xray
    reg = ProviderRegistry.from_config(CFG)
    assert xray.provider_of("azure-gpt-4o", reg) == "Azure OpenAI"
    assert xray.provider_of("gpt-4o", reg) == "OpenAI"           # eşleşme yoksa eski tahmin
    rows = [{"entity": "TCKN", "destination": "external", "provider": "Azure OpenAI", "team": "a",
             "model": "azure-gpt-4o", "requests": 1}]
    report = compliance.build_verbis({}, rows, "2 yıl", provider_countries=reg.countries())
    assert any("İsveç (AB)" in r["aktarilan_ulkeler"] for r in report["rows"])


@pytest.mark.parametrize("bad, fragment", [
    ({"match": ["x-"], "url": "https://a"}, None),                                       # geçerli
    ({"match": [], "url": "https://a"}, "match"),
    ({"match": ["x-"], "url": "ftp://a"}, "url"),
    ({"match": ["x-"], "url": "https://a", "type": "gemini"}, "type"),
    ({"match": ["x-"], "url": "https://a", "destination": "abd"}, "destination"),
    ({"match": ["x-"], "url": "https://a", "key_env": "TELVEGUARD_ADMIN_TOKEN"}, "key_env"),
    ({"match": ["x-"], "url": "https://a", "key_env": "CLICKHOUSE_PASSWORD"}, "key_env"),
    ({"match": ["x-"], "url": "https://a", "api_key": "sk"}, "YAML"),
    ({"match": ["x-"], "url": "https://a", "api_version": "2024-10-21"}, "azure"),
])
def test_config_validation(bad, fragment):
    if fragment is None:
        ProviderRegistry.from_config({"providers": [bad]})
        return
    with pytest.raises(ProviderError, match=fragment):
        ProviderRegistry.from_config({"providers": [bad]})


def test_no_providers_section_changes_nothing():
    reg = ProviderRegistry.from_config({"rules": []})
    assert reg.resolve("gemini-2.5-pro", "chat") == (None, None)
