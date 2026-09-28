"""Çıktı koruması: modelin cevabında ürettiği (girdide olmayan) PII / sırlar."""
import json

import httpx
import pytest
import yaml
from fastapi.testclient import TestClient

from app import main
from telveguard_core.policy import PolicyEngine
from tests.test_tr_pii import make_tckn

AWS_KEY = "AKIA" + "Q3EXAMPLE7ABCDEF"
reply = {"content": ""}
sent = {}


def upstream(request: httpx.Request) -> httpx.Response:
    body = json.loads(request.content)
    sent["body"] = body
    # "{echo}" yer tutucusu: modele giden son mesajı cevaba koy (maskeli / maskesiz)
    content = reply["content"].replace("{echo}", body["messages"][-1]["content"])
    if body.get("stream"):
        # Gerçek akış: MockTransport senkron cevabı önceden okur, pass-through'u taklit edemez
        async def sse():
            chunk = {"choices": [{"index": 0, "delta": {"content": content}}]}
            yield f"data: {json.dumps(chunk, ensure_ascii=False)}\n\n".encode()
            yield b"data: [DONE]\n\n"
        return httpx.Response(200, content=sse(), headers={"content-type": "text/event-stream"})
    return httpx.Response(200, json={
        "id": "x", "created": 0, "model": body["model"],
        "choices": [{"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": content}}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 10},
    })


@pytest.fixture()
def c():
    main.app.state.http = httpx.AsyncClient(transport=httpx.MockTransport(upstream))
    with TestClient(main.app) as client:
        client.events = []

        async def capture(ev):
            client.events.append(ev)
        client.app.state.audit.emit = capture
        yield client


def ask(c, content, model="gpt-4o", **extra):
    return c.post("/v1/chat/completions", json={"model": model, "messages": [{"role": "user", "content": content},
                                                                              ], **extra})


def text(r):
    return r.json()["choices"][0]["message"]["content"]


def test_secret_generated_by_model_is_redacted(c):
    reply["content"] = f"Örnek yapılandırma: key={AWS_KEY}"
    r = ask(c, "Bir S3 yapılandırma örneği yaz")
    assert r.status_code == 200
    assert AWS_KEY not in text(r) and "[GİZLENDİ:SECRET_AWS_KEY]" in text(r)
    ev = c.events[-1]
    assert ev["output_leaked"] == ["SECRET_AWS_KEY"] and ev["output_action"] == "mask"
    assert ev["output_rules"] == ["cikti-sir-gizle"]


def test_new_tckn_in_answer_is_redacted_but_users_own_is_not(c):
    own, other = make_tckn(seed=1), make_tckn(seed=2)
    reply["content"] = f"Sizin kaydınız {{echo}}; benzer müşteri: {other}"
    r = ask(c, f"TC {own} kimdir", model="vllm/qwen3")   # iç model: maskelenmeden gider
    assert own in text(r)                                 # kullanıcının kendi verisi sızıntı değil
    assert other not in text(r) and "[GİZLENDİ:TCKN]" in text(r)
    assert c.events[-1]["output_leaked"] == ["TCKN"]


def test_masked_roundtrip_is_not_a_leak(c):
    tckn = make_tckn()
    reply["content"] = "Özet: {echo}"                     # model yer tutucuyu geri döndürür
    r = ask(c, f"TC {tckn} özetle")
    assert "[TCKN_1]" in sent["body"]["messages"][-1]["content"]
    assert tckn in text(r) and "GİZLENDİ" not in text(r)
    assert c.events[-1]["output_leaked"] == [] and c.events[-1]["output_action"] == ""


def test_monitor_output_rule_records_but_does_not_redact(c):
    reply["content"] = "Bize 0532 999 88 77 numarasından ulaşın"
    r = ask(c, "İletişim bilgisi öner")
    assert "0532 999 88 77" in text(r)
    ev = c.events[-1]
    assert ev["output_action"] == "allow" and "cikti-iletisim-gizle" in ev["monitored_rules"]


def test_output_block_rule(c, tmp_path):
    cfg = yaml.safe_load(open("policies/default.yaml", encoding="utf-8"))
    cfg["output_rules"] = [{"name": "cikti-kart-engel", "when": {"entity_in": ["CREDIT_CARD"]},
                            "action": "block", "message": "kart numarası üretildi"}]
    p = tmp_path / "p.yaml"
    p.write_text(yaml.safe_dump(cfg, allow_unicode=True), encoding="utf-8")
    c.app.state.policy = PolicyEngine(str(p))
    reply["content"] = "Test kartı: 4111 1111 1111 1111"
    r = ask(c, "Örnek ödeme verisi")
    assert r.status_code == 403 and r.json()["error"]["code"] == "output_blocked"
    assert "4111" not in r.text
    assert c.events[-1]["output_action"] == "block"


def test_stream_is_buffered_and_redacted_when_output_rules_exist(c):
    reply["content"] = f"key={AWS_KEY}"
    r = ask(c, "anahtar örneği", stream=True)
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/event-stream")
    assert sent["body"]["stream"] is False                # tamponlandı (pass-through değil)
    assert AWS_KEY not in r.text and "GİZLENDİ" in r.text


def test_stream_passthrough_without_output_rules(c, tmp_path):
    cfg = yaml.safe_load(open("policies/default.yaml", encoding="utf-8"))
    cfg.pop("output_rules")
    p = tmp_path / "p.yaml"
    p.write_text(yaml.safe_dump(cfg, allow_unicode=True), encoding="utf-8")
    c.app.state.policy = PolicyEngine(str(p))
    reply["content"] = f"key={AWS_KEY}"
    r = ask(c, "selam", model="vllm/qwen3", stream=True)
    assert sent["body"]["stream"] is True                 # gerçek pass-through
    # Bilinen ödünleşim: çıktı kuralı yoksa stream'deki cevap taranmaz
    assert AWS_KEY in r.text and c.events[-1]["output_scan"] == "skipped_stream"
