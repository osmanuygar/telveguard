"""
Uçtan uca: gerçek ContextForge imajı + Telveguard eklentisi + sahte MCP sunucusu.

    docker build -f contextforge/Containerfile -t telveguard/contextforge:dev .
    docker compose -f docker-compose.contextforge.yml up -d
    TELVEGUARD_CF_URL=http://localhost:4444 pytest tests/e2e/test_contextforge_e2e.py -v

Ortam değişkeni yoksa atlanır.
"""
import os

import httpx
import pytest

from tests.test_tr_pii import make_tckn

CF = os.getenv("TELVEGUARD_CF_URL")
pytestmark = pytest.mark.skipif(not CF, reason="TELVEGUARD_CF_URL verilmedi")

ADMIN = {"email": "admin@example.com", "password": "Telveguard-e2e-Passw0rd!"}
MOCK_MCP_URL = "http://mock-mcp:9100/mcp"


@pytest.fixture(scope="module")
def api():
    token = httpx.post(f"{CF}/auth/email/login", json=ADMIN, timeout=30).json()["access_token"]
    client = httpx.Client(base_url=CF, headers={"Authorization": f"Bearer {token}"}, timeout=60)
    r = client.post("/gateways", json={"name": "mockcrm", "url": MOCK_MCP_URL, "transport": "STREAMABLEHTTP"})
    assert r.status_code in (200, 201, 409), r.text  # 409: önceki koşudan kayıtlı
    yield client
    client.close()


@pytest.fixture(scope="module")
def tools(api):
    """Orijinal ad -> ContextForge'daki ad (ör. email_send -> mockcrm-email-send)."""
    items = api.get("/tools").json()
    items = items if isinstance(items, list) else items.get("items", [])
    return {t.get("originalName") or t.get("original_name") or t["name"]: t["name"] for t in items}


def call(api, name, arguments):
    r = api.post("/rpc", json={"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                               "params": {"name": name, "arguments": arguments}})
    return r.json()


def text_of(resp):
    return resp["result"]["content"][0]["text"]


def test_plugin_sees_prefixed_tool_names(tools):
    # Dış araç tespitinin neden normalize edilmesi gerektiğinin kanıtı
    assert tools["email_send"] != "email_send"


def test_tool_result_pii_masked(api, tools):
    resp = call(api, tools["crm_lookup"], {"musteri_id": 1})
    assert make_tckn(1) not in str(resp)  # structuredContent dahil hiçbir yerde
    assert "[TCKN_1]" in text_of(resp)


def test_exfiltration_to_email_blocked(api, tools):
    resp = call(api, tools["email_send"], {"to": "x@disari.com", "body": f"Kimlik: {make_tckn(1)}"})
    assert resp["error"]["data"]["plugin_error_code"] == "TELVEGUARD_PII_EXFILTRATION"


def test_email_without_pii_allowed(api, tools):
    resp = call(api, tools["email_send"], {"to": "x@disari.com", "body": "Toplantı 14:00"})
    assert "error" not in resp


def test_indirect_injection_in_tool_result_blocked(api, tools):
    resp = call(api, tools["web_fetch"], {"url": "http://ornek"})
    assert resp["error"]["data"]["plugin_error_code"] == "TELVEGUARD_PROMPT_INJECTION"


def test_placeholders_reset_per_tools_call(api, tools):
    """Bilinen sınır (ContextForge v1.0.10): her tools/call ayrı istek, context tablosu
    taşınmıyor; farklı müşterilerin TCKN'leri ayrı çağrılarda ikisi de [TCKN_1] olur.
    Bu test kırılırsa ContextForge tabloyu taşımaya başlamıştır: eklenti notunu güncelleyin."""
    a = text_of(call(api, tools["crm_lookup"], {"musteri_id": 1}))
    b = text_of(call(api, tools["crm_lookup"], {"musteri_id": 2}))
    assert "[TCKN_1]" in a and "[TCKN_1]" in b


def test_destructive_tool_denied_with_real_user_context(api, tools):
    """Araç izin listesi gerçek ContextForge'da: kural uygulanır ve kimlik UserContext'ten gelir."""
    resp = call(api, tools["delete_customer"], {"musteri_id": 1})
    data = resp["error"]["data"]
    assert data["plugin_error_code"] == "TELVEGUARD_TOOL_DENIED"
    assert data["details"]["rule"] == "yikici-araclar-yasak"
    assert data["details"]["user"] == ADMIN["email"]          # ContextForge kimliği eklentiye ulaştı
