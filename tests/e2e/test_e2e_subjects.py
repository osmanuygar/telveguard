"""Uçtan uca ilgili kişi araması: istek -> Kafka -> ClickHouse -> /v1/subjects/search."""
import os
import random
import time

import httpx
import pytest

from tests.test_tr_pii import make_tckn

GATEWAY = os.getenv("TELVEGUARD_E2E_URL")
pytestmark = pytest.mark.skipif(not GATEWAY, reason="TELVEGUARD_E2E_URL verilmedi")
ADMIN = {"Authorization": "Bearer " + os.getenv("TELVEGUARD_E2E_ADMIN_TOKEN", "e2e-admin-token")}


def test_subject_found_after_request():
    tckn = make_tckn(random.randint(1000, 10**6))          # her koşuda yeni kişi
    r = httpx.post(f"{GATEWAY}/v1/chat/completions", timeout=30, headers={"x-telveguard-team": "e2e-basvuru"},
                   json={"model": "gpt-4o", "messages": [{"role": "user", "content": f"TC {tckn} müşteriyi özetle"}]})
    assert r.status_code == 200
    body = {}
    for _ in range(30):                                     # Kafka -> ClickHouse birkaç saniye sürer
        body = httpx.post(f"{GATEWAY}/v1/subjects/search", headers=ADMIN, timeout=30,
                          json={"values": [tckn, "0555 000 00 00"]}).json()
        if body["summary"][0]["events"]:
            break
        time.sleep(1)
    tckn_summary, phone_summary = body["summary"]
    assert tckn_summary["events"] == 1 and tckn_summary["masked"] == 1 and tckn_summary["unmasked"] == 0
    assert phone_summary["events"] == 0
    assert body["events"][0]["team"] == "e2e-basvuru" and tckn not in str(body)
