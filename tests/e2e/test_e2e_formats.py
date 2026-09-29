"""
Uçtan uca: gerçek resmi SDK'lar (anthropic, openai) -> gerçek gateway container'ı -> sahte LLM.
Denetim kaydında API biçimi (api_format) ClickHouse'a ulaşmalı.
"""
import json
import os
import time
import uuid

import httpx
import pytest

from tests.test_tr_pii import make_tckn

anthropic = pytest.importorskip("anthropic")
openai = pytest.importorskip("openai")

GATEWAY = os.getenv("TELVEGUARD_E2E_URL")
JWT_GATEWAY = os.getenv("TELVEGUARD_E2E_JWT_URL")
IDP = os.getenv("TELVEGUARD_E2E_IDP_URL", "http://localhost:9200")
CLICKHOUSE = os.getenv("TELVEGUARD_E2E_CLICKHOUSE", "http://localhost:8123")
pytestmark = pytest.mark.skipif(not GATEWAY, reason="TELVEGUARD_E2E_URL verilmedi")
TEAM = f"fmt{uuid.uuid4().hex[:8]}"
AWS_KEY = "AKIA" + "Q3EXAMPLE7ABCDEF"


def claude(**kw):
    return anthropic.Anthropic(base_url=GATEWAY, api_key="kullanilmiyor", max_retries=0,
                               default_headers={"x-telveguard-team": TEAM}, **kw)


def test_anthropic_sdk_masks_and_restores():
    tckn = make_tckn()
    msg = claude().messages.create(model="claude-opus-5", max_tokens=50, system=f"Müşteri {tckn}",
                                   messages=[{"role": "user", "content": f"Anahtar {AWS_KEY} ve TC {tckn}"}])
    raw = msg.model_extra  # sahte LLM'in gördükleri
    assert tckn not in raw["mock_received_system"] and "[TCKN_1]" in raw["mock_received_system"]
    assert AWS_KEY not in raw["mock_received_last"]
    assert AWS_KEY in msg.content[0].text and tckn in msg.content[0].text


def test_anthropic_sdk_stream_and_output_leak_redaction():
    with claude().messages.stream(model="claude-opus-5", max_tokens=50,
                                  messages=[{"role": "user", "content": "SIZINTI_TESTI .env örneği"}]) as s:
        final = s.get_final_message()
    assert AWS_KEY not in final.content[0].text and "[GİZLENDİ:SECRET_AWS_KEY]" in final.content[0].text


def test_anthropic_sdk_count_tokens():
    assert claude().messages.count_tokens(model="claude-opus-5",
                                          messages=[{"role": "user", "content": "merhaba"}]).input_tokens > 0


def test_openai_responses_sdk_stream():
    tckn = make_tckn()
    client = openai.OpenAI(base_url=f"{GATEWAY}/v1", api_key="x", max_retries=0,
                           default_headers={"x-telveguard-team": TEAM})
    with client.responses.stream(model="gpt-4o", instructions=f"TC {tckn}", input=f"TC {tckn} özetle") as s:
        final = s.get_final_response()
    assert tckn in final.output_text
    assert "[TCKN_1]" in final.model_extra["mock_received_instructions"]


@pytest.mark.skipif(not JWT_GATEWAY, reason="TELVEGUARD_E2E_JWT_URL verilmedi")
def test_claude_code_style_jwt_via_x_api_key():
    token = httpx.post(f"{IDP}/mint", timeout=10, json={"sub": "u", "preferred_username": "gelistirici",
                                                        "groups": [f"/telveguard-{TEAM}"]}).json()["token"]
    msg = anthropic.Anthropic(base_url=JWT_GATEWAY, api_key=token, max_retries=0).messages.create(
        model="claude-opus-5", max_tokens=10, messages=[{"role": "user", "content": "merhaba"}])
    assert msg.content[0].text.startswith("MODEL GÖRDÜ")


def test_api_format_reaches_clickhouse():
    q = (f"SELECT api_format, count() AS n FROM telveguard.audit WHERE team = '{TEAM}' "
         f"GROUP BY api_format ORDER BY api_format FORMAT JSONEachRow")
    rows = {}
    for _ in range(30):
        rows = {r["api_format"]: int(r["n"]) for r in map(json.loads, httpx.post(
            CLICKHOUSE, content=q, auth=("telveguard", "telveguard"), timeout=10).text.splitlines())}
        if rows.get("messages", 0) >= 3 and rows.get("responses", 0) >= 1:
            break
        time.sleep(2)
    assert rows.get("messages", 0) >= 3 and rows.get("responses", 0) >= 1, rows
