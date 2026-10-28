"""Kurumsal sözlük ContextForge'da: gateway ucu (GET /v1/contextforge/dictionary) ve eklentinin
sözlüğü dosyadan / gateway'den yüklemesi."""
import http.server
import json
import threading

import pytest

from tests.test_gateway import client  # noqa: F401  (fixture)

TOKEN = "cf-token"
H = {"Authorization": f"Bearer {TOKEN}"}
SOZLUK = {"dictionary": [
    {"entity": "KURUM_PROJE", "label": "Proje kod adı", "terms": ["Proje Anka", "Mavi Kartal"]},
    {"entity": "KURUM_SUNUCU", "patterns": [r"[a-z0-9-]+\.sirket\.local"]},
]}


# ---------------- gateway ucu ----------------

def test_endpoint_returns_terms_loadable_by_core(client, monkeypatch):  # noqa: F811
    from telveguard_core import TrPiiEngine
    from telveguard_core.dictionary import Dictionary
    monkeypatch.setenv("CONTEXTFORGE_TOKEN", TOKEN)
    client.app.state.dictionary = Dictionary.from_config(SOZLUK)
    r = client.get("/v1/contextforge/dictionary", headers=H)
    assert r.status_code == 200
    body = r.json()
    # Aynen yüklenir; eşleşme gateway'deki sözlükle aynı
    pii = TrPiiEngine()
    Dictionary.from_config(body).install(pii)
    text = "PROJE  anka toplantısı db01.sirket.local üzerinde"
    assert [f.entity for f in pii.analyze(text)] == ["KURUM_PROJE", "KURUM_SUNUCU"]
    assert body["dictionary"][0]["label"] == "Proje kod adı"
    assert client.get("/v1/contextforge/dictionary",
                      headers={**H, "If-None-Match": r.headers["etag"]}).status_code == 304


def test_endpoint_requires_its_own_token(client, monkeypatch):  # noqa: F811
    monkeypatch.delenv("CONTEXTFORGE_TOKEN", raising=False)
    assert client.get("/v1/contextforge/dictionary", headers=H).status_code == 404
    monkeypatch.setenv("CONTEXTFORGE_TOKEN", TOKEN)
    monkeypatch.setenv("SHADOW_AI_TOKEN", "eklenti-token")
    # Eklenti token'ı (her bilgisayarda) düz metin terimleri alamaz
    assert client.get("/v1/contextforge/dictionary",
                      headers={"Authorization": "Bearer eklenti-token"}).status_code == 401


# ---------------- eklenti ----------------

cpex = pytest.importorskip("cpex.framework")


def _plugin(**config):
    from telveguard_contextforge import TelveguardPlugin
    cfg = cpex.PluginConfig(name="Telveguard", kind="telveguard_contextforge.TelveguardPlugin",
                            hooks=["prompt_pre_fetch", "tool_pre_invoke", "tool_post_invoke"], config=config)
    return TelveguardPlugin(cfg)


def _ctx():
    return cpex.PluginContext(global_context=cpex.GlobalContext(request_id="t1"))


async def _post(plugin, text, tool="crm_lookup"):
    r = await plugin.tool_post_invoke(cpex.ToolPostInvokePayload(
        name=tool, result={"content": [{"type": "text", "text": text}]}), _ctx())
    return r.modified_payload.result["content"][0]["text"] if r.modified_payload else text


@pytest.fixture()
def policy_file(tmp_path):
    import yaml
    p = tmp_path / "politika.yaml"
    p.write_text(yaml.safe_dump({"rules": [], **SOZLUK}, allow_unicode=True), encoding="utf-8")
    return str(p)


async def test_plugin_masks_dictionary_terms_from_file(policy_file):
    plugin = _plugin(dictionary_file=policy_file)
    assert await _post(plugin, "Mavi Kartal teslim tarihi") == "[KURUM_PROJE_1] teslim tarihi"


async def test_plugin_blocks_dictionary_term_to_external_tool(policy_file):
    plugin = _plugin(dictionary_file=policy_file)
    r = await plugin.tool_pre_invoke(cpex.ToolPreInvokePayload(
        name="slack_post", args={"text": "Proje Anka gecikiyor"}), _ctx())
    assert r.continue_processing is False
    assert r.violation.code == "TELVEGUARD_PII_EXFILTRATION" and "KURUM_PROJE" in r.violation.details["entities"]


def test_plugin_fails_fast_on_unreadable_dictionary_file(tmp_path):
    with pytest.raises(OSError):
        _plugin(dictionary_file=str(tmp_path / "yok.yaml"))


class _Gateway:
    """Sahte gateway: /v1/contextforge/dictionary, ETag ve token kontrolü."""

    def __init__(self, payload):
        self.payload, self.requests = payload, []
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                outer.requests.append(dict(self.headers))
                if self.headers.get("Authorization") != f"Bearer {TOKEN}":
                    self.send_response(401)
                    self.end_headers()
                    return
                if self.headers.get("If-None-Match") == f'"{outer.payload["version"]}"':
                    self.send_response(304)
                    self.end_headers()
                    return
                body = json.dumps(outer.payload).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_):
                pass

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()   # dinleyen soket kapanmazsa bağlantı zaman aşımına kadar bekler


@pytest.fixture()
def gateway(monkeypatch):
    from telveguard_core.dictionary import Dictionary
    monkeypatch.setenv("TELVEGUARD_CONTEXTFORGE_TOKEN", TOKEN)
    g = _Gateway(Dictionary.from_config(SOZLUK).server_payload())
    yield g
    g.close()


async def test_plugin_loads_dictionary_from_gateway(gateway):
    plugin = _plugin(dictionary_gateway_url=gateway.url)
    await plugin.initialize()
    assert await _post(plugin, "db01.sirket.local kapalı") == "[KURUM_SUNUCU_1] kapalı"
    # Yenilemede değişmediyse 304: sözlük yeniden kurulmaz
    await plugin._refresh_dictionary()
    assert gateway.requests[-1]["If-None-Match"] == f'"{gateway.payload["version"]}"'
    assert await _post(plugin, "Proje Anka") == "[KURUM_PROJE_1]"


async def test_plugin_keeps_last_dictionary_when_gateway_down(gateway, monkeypatch):
    plugin = _plugin(dictionary_gateway_url=gateway.url, dictionary_refresh_seconds=30)
    await plugin.initialize()
    gateway.close()
    await plugin._refresh_dictionary()            # ağ hatası: uyarı, eldekiyle devam
    assert await _post(plugin, "Mavi Kartal") == "[KURUM_PROJE_1]"


async def test_plugin_wrong_token_leaves_dictionary_empty(gateway, monkeypatch):
    monkeypatch.setenv("TELVEGUARD_CONTEXTFORGE_TOKEN", "yanlis")
    plugin = _plugin(dictionary_gateway_url=gateway.url)
    await plugin.initialize()
    assert await _post(plugin, "Mavi Kartal") == "Mavi Kartal"


def test_plugin_rejects_non_http_gateway_url():
    with pytest.raises(ValueError):
        _plugin(dictionary_gateway_url="file:///etc/passwd")
