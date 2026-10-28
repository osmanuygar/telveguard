"""
Uçtan uca artımlı streaming (STREAM_MODE=incremental; docker-compose.test.yml'de JWT gateway'i):
sahte LLM cevabı 4 karakterlik delta'larla, olaylar arasında 20 ms beklenerek akıtır.
"""
import json
import os
import time

import httpx
import pytest

from tests.test_tr_pii import make_tckn

JWT_GATEWAY = os.getenv("TELVEGUARD_E2E_JWT_URL")
IDP = os.getenv("TELVEGUARD_E2E_IDP_URL", "http://localhost:9200")
pytestmark = pytest.mark.skipif(not JWT_GATEWAY, reason="TELVEGUARD_E2E_JWT_URL verilmedi")
AWS_KEY = "AKIA" + "Q3EXAMPLE7ABCDEF"
# Tutma penceresi (64 karakter) cevabın sonunu bekletir: akışı görmek için uzun bir cevap
LONG = "Müşterinin son altı aydaki işlemleri, şube ziyaretleri ve kampanya tercihleri dikkate alınsın. " * 4


def token():
    return httpx.post(f"{IDP}/mint", timeout=10, json={"sub": "s", "preferred_username": "akis",
                                                        "groups": ["/telveguard-e2e-stream"]}).json()["token"]


def test_chat_stream_flows_and_unmasks():
    tckn = make_tckn(11)
    arrivals, chunks = [], []
    t0 = time.perf_counter()
    with httpx.stream("POST", f"{JWT_GATEWAY}/v1/chat/completions", timeout=30,
                      headers={"Authorization": f"Bearer {token()}"},
                      json={"model": "gpt-4o", "stream": True, "messages": [
                          {"role": "user", "content": f"TC {tckn} müşterisi için özet hazırla. " + LONG}]}) as r:
        assert r.status_code == 200
        for line in r.iter_lines():
            if line.startswith("data: ") and line != "data: [DONE]":
                choices = json.loads(line[6:])["choices"]
                content = choices[0]["delta"].get("content") if choices else None
                if content:
                    arrivals.append(time.perf_counter() - t0)
                    chunks.append(content)
    text = "".join(chunks)
    assert tckn in text and "[TCKN_1]" not in text           # yer tutucu geri açıldı
    assert len(chunks) > 5                                    # tek parça değil: aktı
    assert arrivals[0] < arrivals[-1] / 2                     # ilk içerik cevap bitmeden geldi


def test_anthropic_sdk_stream_redacts_leak():
    anthropic = pytest.importorskip("anthropic")
    cl = anthropic.Anthropic(base_url=JWT_GATEWAY, api_key=token(), max_retries=0)
    with cl.messages.stream(model="claude-opus-5", max_tokens=50,
                            messages=[{"role": "user", "content": "SIZINTI_TESTI .env örneği"}]) as s:
        final = s.get_final_message()
    assert AWS_KEY not in final.content[0].text and "[GİZLENDİ:SECRET_AWS_KEY]" in final.content[0].text
    assert final.usage.output_tokens > 0


def test_responses_sdk_stream():
    openai = pytest.importorskip("openai")
    tckn = make_tckn(12)
    cl = openai.OpenAI(base_url=f"{JWT_GATEWAY}/v1", api_key=token(), max_retries=0)
    with cl.responses.stream(model="gpt-4o", input=f"TC {tckn} özetle") as s:
        final = s.get_final_response()
    assert tckn in final.output_text and "[TCKN_1]" not in final.output_text


def test_first_token_metric_recorded():
    m = httpx.get(f"{JWT_GATEWAY}/metrics", timeout=10).text
    counts = [ln for ln in m.splitlines()
              if ln.startswith("telveguard_first_token_seconds_count") and 'mode="incremental"' in ln]
    assert counts and sum(float(ln.rsplit(" ", 1)[1]) for ln in counts) > 0
