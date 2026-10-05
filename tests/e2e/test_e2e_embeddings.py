"""Uçtan uca /v1/embeddings: maskeleme ve denetim (compose ortamı)."""
import os

import httpx
import pytest

from tests.test_tr_pii import make_tckn

GATEWAY = os.getenv("TELVEGUARD_E2E_URL")
pytestmark = pytest.mark.skipif(not GATEWAY, reason="TELVEGUARD_E2E_URL verilmedi")


def test_embeddings_masked_end_to_end():
    tckn = make_tckn(11)
    r = httpx.post(f"{GATEWAY}/v1/embeddings", timeout=30, headers={"x-telveguard-team": "e2e-rag"},
                   json={"model": "text-embedding-3-small", "input": [f"Sözleşme: {tckn}", "Ek belge"]})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["mock_received_input"] == ["Sözleşme: [TCKN_1]", "Ek belge"]
    assert "stream" not in body["mock_received_keys"]
    assert len(body["data"]) == 2
