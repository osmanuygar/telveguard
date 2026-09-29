"""Yönetim uçlarına OIDC grubuyla erişim (statik token'a ek / yerine)."""
import logging
import time

import pytest

from tests.test_auth import AUDIENCE, ISSUER, FakeIdP
from tests.test_gateway import client  # noqa: F401  (fixture)
from tests.test_xray import FakeClickHouse
from app.auth import Authenticator

import httpx


@pytest.fixture()
def idp():
    return FakeIdP()


@pytest.fixture()
def admin_client(client, idp, monkeypatch):  # noqa: F811
    monkeypatch.delenv("TELVEGUARD_ADMIN_TOKEN", raising=False)
    http = httpx.AsyncClient(transport=httpx.MockTransport(idp.handler))
    client.app.state.auth = Authenticator("jwt", http, issuer=ISSUER, audience=AUDIENCE,
                                          team_prefix="telveguard-", admin_group="telveguard-admin")
    # KVKK sorgusu için boş sonuç (varsayılan sahte satır [{}] rapor alanlarını içermez)
    client.app.state.ch = FakeClickHouse({"ARRAY JOIN entities AS entity\n    WHERE destination": []})
    return client


def xray(c, token):
    return c.get("/v1/xray", headers={"Authorization": f"Bearer {token}"})


def test_admin_group_member_can_access(admin_client, idp, caplog):
    tok = idp.token(preferred_username="denetci", groups=["/telveguard-analitik", "/telveguard-admin"])
    with caplog.at_level(logging.INFO, logger="telveguard.admin"):
        assert xray(admin_client, tok).status_code == 200
    assert any("admin_access via=oidc user=denetci path=/v1/xray" in m for m in caplog.messages)


def test_non_admin_forbidden_and_logged(admin_client, idp, caplog):
    tok = idp.token(preferred_username="ayse", groups=["/telveguard-analitik"])
    with caplog.at_level(logging.INFO, logger="telveguard.admin"):
        r = xray(admin_client, tok)
    assert r.status_code == 403 and r.json()["error"]["code"] == "forbidden"
    assert any("admin_denied user=ayse" in m for m in caplog.messages)


def test_admin_group_does_not_come_from_team_prefix(admin_client, idp):
    """Önekle süzülen ekipler değil, ham gruplar kontrol edilir; 'admin' adlı bir ekip yetmez."""
    tok = idp.token(groups=["/telveguard-telveguard-admin-degil", "/admin"])
    assert xray(admin_client, tok).status_code == 403


@pytest.mark.parametrize("claims,status", [({"exp": int(time.time()) - 3600}, 401), ({"aud": "baska"}, 401)])
def test_invalid_admin_tokens_rejected(admin_client, idp, claims, status):
    tok = idp.token(groups=["/telveguard-admin"], **claims)
    assert xray(admin_client, tok).status_code == status


def test_garbage_token_is_401_not_500(admin_client):
    assert xray(admin_client, "rastgele-metin").status_code == 401


def test_static_token_still_works_alongside_oidc(admin_client, monkeypatch):
    monkeypatch.setenv("TELVEGUARD_ADMIN_TOKEN", "otomasyon-token")
    assert xray(admin_client, "otomasyon-token").status_code == 200


def test_all_admin_endpoints_accept_oidc(admin_client, idp):
    tok = idp.token(groups=["/telveguard-admin"])
    h = {"Authorization": f"Bearer {tok}"}
    assert admin_client.get("/v1/reports/kvkk-transfer?month=2026-09&format=json", headers=h).status_code == 200
    r = admin_client.post("/v1/policy/simulate", headers=h,
                          json={"model": "gpt-4o", "messages": [{"role": "user", "content": "x"}]})
    assert r.status_code == 200


def test_admin_group_ignored_in_header_mode(client, monkeypatch):  # noqa: F811
    monkeypatch.delenv("TELVEGUARD_ADMIN_TOKEN", raising=False)
    client.app.state.auth = Authenticator("header", None, admin_group="telveguard-admin")
    assert client.get("/v1/xray").status_code == 404   # header modunda kimlik doğrulanamaz: kapalı
