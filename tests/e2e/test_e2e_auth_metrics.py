"""
Uçtan uca: OIDC / JWT kimlik (gateway-jwt + sahte IdP), çıktı koruması ve Prometheus metrikleri.

    docker compose -f docker-compose.yml -f docker-compose.test.yml up -d --build
    TELVEGUARD_E2E_URL=http://localhost:8080 TELVEGUARD_E2E_JWT_URL=http://localhost:8081 pytest tests/e2e -v
"""
import json
import os
import re
import time
import uuid

import httpx
import pytest

from tests.test_tr_pii import make_tckn

GATEWAY = os.getenv("TELVEGUARD_E2E_URL")
JWT_GATEWAY = os.getenv("TELVEGUARD_E2E_JWT_URL")
IDP = os.getenv("TELVEGUARD_E2E_IDP_URL", "http://localhost:9200")
CLICKHOUSE = os.getenv("TELVEGUARD_E2E_CLICKHOUSE", "http://localhost:8123")
TEAM = f"e2e{uuid.uuid4().hex[:8]}"  # bu koşunun ekibi (token grubundan: telveguard-<TEAM>)
AWS_KEY = "AKIA" + "Q3EXAMPLE7ABCDEF"


def mint(**claims):
    claims = {"sub": "u-1", "preferred_username": "ayse", "groups": [f"/telveguard-{TEAM}"], **claims}
    return httpx.post(f"{IDP}/mint", json=claims, timeout=10).json()["token"]


def chat(base, content, headers=None, model="gpt-4o"):
    return httpx.post(f"{base}/v1/chat/completions", headers=headers or {}, timeout=30,
                      json={"model": model, "messages": [{"role": "user", "content": content}]})


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


# ---------------- JWT ----------------

jwt_only = pytest.mark.skipif(not JWT_GATEWAY, reason="TELVEGUARD_E2E_JWT_URL verilmedi")


@jwt_only
def test_jwt_valid_token_identity_reaches_audit():
    r = chat(JWT_GATEWAY, "merhaba", {**bearer(mint()),
                                      "x-telveguard-user": "sahte", "x-telveguard-team": "yonetim"})
    assert r.status_code == 200
    query = (f"SELECT user, team, teams, auth_source FROM telveguard.audit WHERE team = '{TEAM}' "
             f"FORMAT JSONEachRow")
    rows = []
    for _ in range(30):
        rows = [json.loads(x) for x in httpx.post(CLICKHOUSE, content=query, auth=("telveguard", "telveguard"),
                                                  timeout=10).text.splitlines()]
        if rows:
            break
        time.sleep(2)
    assert rows and rows[0] == {"user": "ayse", "team": TEAM, "teams": [TEAM], "auth_source": "jwt"}


@jwt_only
@pytest.mark.parametrize("claims,code", [({"exp_in": -3600}, "expired"), ({"aud": "baska"}, "bad_audience")])
def test_jwt_invalid_tokens_rejected(claims, code):
    r = chat(JWT_GATEWAY, "merhaba", bearer(mint(**claims)))
    assert r.status_code == 401 and r.json()["error"]["code"] == code


@jwt_only
def test_jwt_missing_token_and_header_spoofing_rejected():
    r = chat(JWT_GATEWAY, "merhaba", {"x-telveguard-user": "ayse", "x-telveguard-team": "analitik"})
    assert r.status_code == 401 and r.headers["www-authenticate"].startswith("Bearer")


@jwt_only
def test_jwt_multi_group_cannot_escape_intern_rule():
    tok = mint(groups=[f"/telveguard-{TEAM}", "/telveguard-stajyer"])
    r = chat(JWT_GATEWAY, f"TC {make_tckn()}", bearer(tok))
    assert r.status_code == 403 and r.json()["error"]["code"] == "blocked"


# ---------------- çıktı koruması ----------------

gw_only = pytest.mark.skipif(not GATEWAY, reason="TELVEGUARD_E2E_URL verilmedi")


@gw_only
def test_model_generated_secret_is_redacted():
    r = chat(GATEWAY, "SIZINTI_TESTI bir yapılandırma örneği ver")
    content = r.json()["choices"][0]["message"]["content"]
    assert AWS_KEY not in content and "[GİZLENDİ:SECRET_AWS_KEY]" in content


# ---------------- metrikler ----------------

def _counter(text, name, **labels):
    want = ",".join(f'{k}="{v}"' for k, v in sorted(labels.items()))
    total = 0.0
    for line in text.splitlines():
        m = re.match(rf'^{name}\{{(.*)\}} ([0-9.e+]+)$', line)
        if m and ",".join(sorted(m.group(1).split(","))) == want:
            total += float(m.group(2))
    return total


@gw_only
def test_metrics_aggregate_across_workers():
    """Gateway 2 worker'la çalışır; /metrics hangi worker'a düşerse düşsün toplamı göstermeli."""
    def scrape():
        return httpx.get(f"{GATEWAY}/metrics", timeout=10).text
    before = _counter(scrape(), "telveguard_requests_total", action="allow", destination="internal", api_format="chat")
    for _ in range(20):
        assert chat(GATEWAY, "merhaba", model="vllm/qwen3").status_code == 200
    after = [_counter(scrape(), "telveguard_requests_total", action="allow", destination="internal", api_format="chat")
             for _ in range(5)]  # farklı worker'lara düşen birkaç okuma
    assert all(a - before == 20 for a in after), (before, after)
