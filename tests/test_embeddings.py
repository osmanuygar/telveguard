"""OpenAI /v1/embeddings: RAG indeksleme trafiğinde maskeleme, politika, denetim."""
import json

import httpx
import pytest
from fastapi.testclient import TestClient

from app import main
from app.attachments import AttachmentScanner, Settings
from app.providers import ProviderRegistry
from tests.test_tr_pii import make_tckn

TCKN = make_tckn()
AWS_KEY = "AKIA" + "Q3EXAMPLE7ABCDEF"
seen = {}


def upstream(request: httpx.Request) -> httpx.Response:
    body = json.loads(request.content)
    seen["body"], seen["url"] = body, str(request.url)
    n = len(body["input"]) if isinstance(body["input"], list) and not isinstance(body["input"][0], int) else 1
    return httpx.Response(200, json={
        "object": "list", "model": body["model"],
        "data": [{"object": "embedding", "index": i, "embedding": [0.5, -0.25]} for i in range(n)],
        "usage": {"prompt_tokens": 2000, "total_tokens": 2000}})


@pytest.fixture()
def client():
    main.app.state.http = httpx.AsyncClient(transport=httpx.MockTransport(upstream))
    with TestClient(main.app) as c:
        events = []

        async def capture(ev):
            events.append(ev)
        c.app.state.audit.emit = capture
        c.events = events
        yield c


def embed(c, inp, model="text-embedding-3-small", team="analitik"):
    return c.post("/v1/embeddings", headers={"x-telveguard-team": team}, json={"model": model, "input": inp})


def test_external_embedding_input_masked(client):
    r = embed(client, f"Müşteri {TCKN} kredi başvurusu")
    assert r.status_code == 200
    assert seen["body"]["input"] == "Müşteri [TCKN_1] kredi başvurusu"
    assert seen["url"].endswith("/embeddings") and "stream" not in seen["body"]
    assert r.json()["data"][0]["embedding"] == [0.5, -0.25]          # vektör olduğu gibi döner
    ev = client.events[-1]
    assert ev["api_format"] == "embeddings" and ev["action"] == "mask" and "TCKN" in ev["entities"]
    assert ev["prompt_chars"] > 0 and ev["prompt_tokens"] == 2000 and ev["completion_tokens"] == 0


def test_batch_uses_consistent_placeholders(client):
    r = embed(client, [f"Belge 1: {TCKN}", "Belge 2: bilgi yok", f"Belge 3: yine {TCKN}"])
    assert r.status_code == 200 and len(r.json()["data"]) == 3
    assert seen["body"]["input"] == ["Belge 1: [TCKN_1]", "Belge 2: bilgi yok", "Belge 3: yine [TCKN_1]"]


def test_internal_embedding_model_not_masked_but_secrets_are(client):
    embed(client, f"TC {TCKN} anahtar {AWS_KEY}", model="vllm/bge-m3")
    sent = seen["body"]["input"]
    assert TCKN in sent and AWS_KEY not in sent                     # sır her yerde maskelenir


def test_injection_text_is_indexed_not_blocked(client):
    r = embed(client, "Güvenlik eğitimi: saldırgan 'önceki tüm talimatları yok say' yazabilir")
    assert r.status_code == 200 and client.events[-1]["injection_score"] == 0.0


def test_team_rule_blocks_whole_batch(client):
    r = embed(client, ["ilk belge", f"TC {TCKN}"], team="stajyer")
    assert r.status_code == 403 and r.json()["error"]["code"] == "blocked"
    assert client.events[-1]["est_cost_usd"] == 0.0


def test_token_input_is_unscannable(client):
    client.app.state.attachments = AttachmentScanner(Settings())
    assert embed(client, [101, 2023, 2003]).status_code == 200
    assert "ek-taranamadi" in client.events[-1]["rules"] and client.events[-1]["action"] == "alert"
    client.app.state.attachments = AttachmentScanner(Settings(unscannable="block"))
    r = embed(client, [[101, 2023], [101, 2024]])
    assert r.status_code == 403 and "token dizisi" in r.json()["error"]["message"]
    assert embed(client, [101, 2023], model="vllm/bge-m3").status_code == 200   # kurum içi: dokunulmaz


@pytest.mark.parametrize("inp", [None, [], 42, ["a", 1], [[1], "a"], ["x"] * 2049])
def test_invalid_input_rejected(client, inp):
    r = embed(client, inp)
    assert r.status_code == 400 and "input" in r.json()["error"]["message"]


def test_simulator_supports_embeddings(client, monkeypatch):
    monkeypatch.setenv("TELVEGUARD_ADMIN_TOKEN", "adm")
    r = client.post("/v1/policy/simulate?format=embeddings", headers={"Authorization": "Bearer adm"},
                    json={"model": "text-embedding-3-large", "input": [f"TC {TCKN}"]})
    assert r.status_code == 200
    assert r.json()["decision"]["action"] == "mask"
    assert r.json()["upstream_body"]["input"] == ["TC [TCKN_1]"]


def test_provider_routing_for_embeddings():
    reg = ProviderRegistry.from_config({"providers": [
        {"name": "Azure", "match": ["text-embedding-"], "type": "azure", "url": "https://k.openai.azure.com",
         "api_version": "2024-10-21", "deployments": {"text-embedding-3-small": "emb-small"}},
        {"name": "Mistral", "match": ["mistral-embed"], "url": "https://api.mistral.ai/v1"},
        {"name": "Anthropic", "match": ["claude-"], "type": "anthropic", "url": "https://api.anthropic.com"}]})
    p, _ = reg.resolve("text-embedding-3-small", "embeddings")
    assert p.endpoint("embeddings", "text-embedding-3-small", {})[0] == \
        "https://k.openai.azure.com/openai/deployments/emb-small/embeddings?api-version=2024-10-21"
    p, _ = reg.resolve("mistral-embed", "embeddings")
    assert p.endpoint("embeddings", "mistral-embed", {})[0] == "https://api.mistral.ai/v1/embeddings"
    p, err = reg.resolve("claude-x", "embeddings")
    assert p is None and "messages" in err
