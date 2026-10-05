"""Uçtan uca kurumsal sözlük: varsayılan politikadaki örnek terimler (compose ortamı)."""
import os

import httpx
import pytest

GATEWAY = os.getenv("TELVEGUARD_E2E_URL")
pytestmark = pytest.mark.skipif(not GATEWAY, reason="TELVEGUARD_E2E_URL verilmedi")


def test_dictionary_terms_masked_and_restored():
    r = httpx.post(f"{GATEWAY}/v1/chat/completions", timeout=30, headers={"x-telveguard-team": "e2e-sozluk"},
                   json={"model": "gpt-4o", "messages": [
                       {"role": "user", "content": "PROJE ANKA için db01.sirket.local raporu"}]})
    assert r.status_code == 200
    body = r.json()
    assert body["mock_received_messages"][-1] == "[KURUM_PROJE_1] için [KURUM_SUNUCU_1] raporu"
    assert "PROJE ANKA" in body["choices"][0]["message"]["content"]
