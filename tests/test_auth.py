"""
OIDC / JWT kimlik doğrulama. Gerçek RSA / EC anahtarları + sahte kimlik sağlayıcı (JWKS).
Saldırılar: alg=none, HS256 sahteciliği (public key'i HMAC sırrı olarak), yanlış aud/iss,
süresi dolmuş token, header ile kimlik taklidi, çoklu grupla kısıtlayıcı kuraldan kaçma.
"""
import base64
import json
import time

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from app.auth import AuthError, Authenticator
from tests.test_gateway import captured, client  # noqa: F401  (fixture)
from tests.test_tr_pii import make_tckn

ISSUER = "https://sso.sirket.local/realms/ai"
AUDIENCE = "telveguard"


class FakeIdP:
    """Discovery + JWKS sunan sahte kimlik sağlayıcı; anahtar rotasyonu ve kesinti simüle edilir."""

    def __init__(self):
        self.keys = {}          # kid -> private key
        self.published = []     # JWKS'te yayınlanan kid'ler
        self.jwks_calls = 0
        self.down = False
        self.add_key("k1")

    def add_key(self, kid, kind="rsa", publish=True):
        self.keys[kid] = (rsa.generate_private_key(public_exponent=65537, key_size=2048) if kind == "rsa"
                          else ec.generate_private_key(ec.SECP256R1()))
        if publish:
            self.published.append(kid)

    def jwk(self, kid):
        pub = self.keys[kid].public_key()
        alg = "RS256" if isinstance(pub, rsa.RSAPublicKey) else "ES256"
        algo = jwt.algorithms.RSAAlgorithm if alg == "RS256" else jwt.algorithms.ECAlgorithm
        return {**json.loads(algo.to_jwk(pub)), "kid": kid, "alg": alg, "use": "sig"}

    def handler(self, request: httpx.Request) -> httpx.Response:
        if self.down:
            raise httpx.ConnectError("IdP yok")
        if request.url.path.endswith("/.well-known/openid-configuration"):
            return httpx.Response(200, json={"issuer": ISSUER, "jwks_uri": f"{ISSUER}/certs"})
        if request.url.path.endswith("/certs"):
            self.jwks_calls += 1
            return httpx.Response(200, json={"keys": [self.jwk(k) for k in self.published]})
        return httpx.Response(404)

    def token(self, kid="k1", alg=None, **overrides):
        key = self.keys[kid]
        alg = alg or ("RS256" if isinstance(key, rsa.RSAPrivateKey) else "ES256")
        now = int(time.time())
        claims = {"iss": ISSUER, "aud": AUDIENCE, "sub": "u-1", "preferred_username": "ayse",
                  "groups": ["/telveguard-analitik"], "iat": now, "exp": now + 300, **overrides}
        claims = {k: v for k, v in claims.items() if v is not None}
        return jwt.encode(claims, key, algorithm=alg, headers={"kid": kid})


@pytest.fixture()
def idp():
    return FakeIdP()


def make_auth(idp, **kw):
    http = httpx.AsyncClient(transport=httpx.MockTransport(idp.handler))
    return Authenticator("jwt", http, issuer=ISSUER, audience=AUDIENCE, team_prefix="telveguard-", **kw)


def bearer(token):
    return {"authorization": f"Bearer {token}"}


# ---------------- doğrulama ----------------

async def test_valid_token_gives_user_and_teams(idp):
    ident = await make_auth(idp).authenticate(bearer(idp.token(groups=["/telveguard-analitik", "/baska-grup",
                                                                       "telveguard-stajyer"])))
    assert (ident.user, ident.teams, ident.source) == ("ayse", ["analitik", "stajyer"], "jwt")


async def test_ec_keys_supported(idp):
    idp.add_key("ec1", kind="ec")
    assert (await make_auth(idp).authenticate(bearer(idp.token(kid="ec1")))).user == "ayse"


@pytest.mark.parametrize("claims,reason", [
    ({"aud": "baska-servis"}, "bad_audience"),
    ({"iss": "https://kotu.example"}, "bad_issuer"),
    ({"exp": int(time.time()) - 3600}, "expired"),
    ({"exp": None}, "invalid"),                         # exp zorunlu
    ({"preferred_username": None, "sub": None}, "no_user"),
])
async def test_invalid_claims_rejected(idp, claims, reason):
    with pytest.raises(AuthError) as e:
        await make_auth(idp).authenticate(bearer(idp.token(**claims)))
    assert e.value.reason == reason and e.value.status == 401


async def test_missing_or_malformed_token(idp):
    auth = make_auth(idp)
    for headers in ({}, {"authorization": "Basic eDp5"}, bearer("")):
        with pytest.raises(AuthError, match="Bearer"):
            await auth.authenticate(headers)
    with pytest.raises(AuthError) as e:
        await auth.authenticate(bearer("abc.def"))
    assert e.value.reason == "malformed"


async def test_alg_none_rejected(idp):
    def b64(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    forged = f'{b64({"alg": "none", "kid": "k1"})}.{b64({"iss": ISSUER, "aud": AUDIENCE, "sub": "x", "exp": 2**31})}.'
    with pytest.raises(AuthError) as e:
        await make_auth(idp).authenticate(bearer(forged))
    assert e.value.reason == "bad_algorithm"


async def test_hs256_forgery_with_public_key_rejected(idp):
    """Klasik algoritma karıştırma saldırısı: public key'i HMAC sırrı yap, kendi token'ını imzala."""
    pem = idp.keys["k1"].public_key().public_bytes(serialization.Encoding.PEM,
                                                   serialization.PublicFormat.SubjectPublicKeyInfo)
    # PyJWT bu anahtarla imzalamayı reddeder; saldırgan elle imzalar
    import hashlib
    import hmac

    def b64(raw: bytes) -> str:
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    head = b64(json.dumps({"alg": "HS256", "typ": "JWT", "kid": "k1"}).encode())
    body = b64(json.dumps({"iss": ISSUER, "aud": AUDIENCE, "sub": "admin", "exp": int(time.time()) + 300}).encode())
    sig = b64(hmac.new(pem, f"{head}.{body}".encode(), hashlib.sha256).digest())
    forged = f"{head}.{body}.{sig}"
    with pytest.raises(AuthError) as e:
        await make_auth(idp).authenticate(bearer(forged))
    assert e.value.reason == "bad_algorithm"


async def test_token_signed_by_unknown_key_rejected(idp):
    idp.add_key("saldirgan", publish=False)  # IdP'nin yayınlamadığı anahtar
    with pytest.raises(AuthError) as e:
        await make_auth(idp).authenticate(bearer(idp.token(kid="saldirgan")))
    assert e.value.reason == "unknown_key"


# ---------------- JWKS önbelleği / rotasyon / kesinti ----------------

async def test_jwks_cached_and_rotation_refetched(idp):
    auth = make_auth(idp, jwks_min_refresh=0)
    for _ in range(5):
        await auth.authenticate(bearer(idp.token()))
    assert idp.jwks_calls == 1                      # önbellekten
    idp.add_key("k2")                               # IdP anahtar döndürdü
    assert (await auth.authenticate(bearer(idp.token(kid="k2")))).user == "ayse"
    assert idp.jwks_calls == 2


async def test_unknown_kid_flood_does_not_hammer_idp(idp):
    auth = make_auth(idp)  # varsayılan: en fazla 30 sn'de bir yeniden çekim
    await auth.authenticate(bearer(idp.token()))
    idp.add_key("sahte", publish=False)
    for _ in range(20):
        with pytest.raises(AuthError):
            await auth.authenticate(bearer(idp.token(kid="sahte")))
    assert idp.jwks_calls == 1


async def test_idp_down_at_start_is_503_and_not_hammered(idp):
    idp.down = True
    auth = make_auth(idp)
    for _ in range(5):
        with pytest.raises(AuthError) as e:
            await auth.authenticate(bearer(idp.token()))
        assert e.value.status == 503


async def test_idp_down_later_keeps_cached_keys(idp):
    auth = make_auth(idp, jwks_ttl=0, jwks_min_refresh=0)
    await auth.authenticate(bearer(idp.token()))
    idp.down = True
    assert (await auth.authenticate(bearer(idp.token()))).user == "ayse"


def test_jwt_mode_requires_issuer_and_audience():
    with pytest.raises(ValueError, match="OIDC_ISSUER"):
        Authenticator("jwt", None, issuer=ISSUER)
    with pytest.raises(ValueError, match="AUTH_MODE"):
        Authenticator("ldap", None)


# ---------------- gateway entegrasyonu ----------------

@pytest.fixture()
def jwt_client(client, idp):  # noqa: F811
    client.app.state.auth = make_auth(idp)
    return client


def chat(c, headers, content="merhaba", model="gpt-4o"):
    return c.post("/v1/chat/completions", headers=headers,
                  json={"model": model, "messages": [{"role": "user", "content": content}]})


def test_gateway_rejects_missing_token_with_401(jwt_client):
    r = chat(jwt_client, {"x-telveguard-user": "ayse", "x-telveguard-team": "analitik"})
    assert r.status_code == 401 and r.json()["error"]["code"] == "missing_token"
    assert r.headers["www-authenticate"].startswith("Bearer")


def test_gateway_ignores_spoofed_headers_in_jwt_mode(jwt_client, idp):
    events = []

    async def capture(ev):
        events.append(ev)
    jwt_client.app.state.audit.emit = capture
    headers = {**bearer(idp.token()), "x-telveguard-user": "genel-mudur", "x-telveguard-team": "yonetim"}
    assert chat(jwt_client, headers).status_code == 200
    assert (events[-1]["user"], events[-1]["team"], events[-1]["auth_source"]) == ("ayse", "analitik", "jwt")


def test_gateway_multi_group_user_cannot_escape_restrictive_rule(jwt_client, idp):
    """stajyer + analitik grubundaki kullanıcı: 'analitik' ilk sırada olsa da stajyer kuralı uygulanır."""
    tok = idp.token(groups=["/telveguard-analitik", "/telveguard-stajyer"])
    r = chat(jwt_client, bearer(tok), content=f"TC {make_tckn()}")
    assert r.status_code == 403 and r.json()["error"]["code"] == "blocked"


def test_gateway_client_token_never_forwarded_upstream(jwt_client, idp):
    tok = idp.token()
    captured.clear()
    import app.main as m
    sent_headers = {}
    orig = jwt_client.app.state.http

    class Spy:
        async def post(self, url, json, headers):
            sent_headers.update(headers)
            return await orig.post(url, json=json, headers=headers)
    jwt_client.app.state.http = Spy()
    try:
        assert chat(jwt_client, bearer(tok)).status_code == 200
    finally:
        jwt_client.app.state.http = orig
    assert tok not in json.dumps(sent_headers)
    assert sent_headers.get("Authorization", "") == (f"Bearer {m.UPSTREAM_KEYS['external']}"
                                                     if m.UPSTREAM_KEYS["external"] else "")


def test_simulator_uses_explicit_headers_with_multiple_teams(client, monkeypatch):  # noqa: F811
    monkeypatch.setenv("TELVEGUARD_ADMIN_TOKEN", "t")
    r = client.post("/v1/policy/simulate", headers={"Authorization": "Bearer t", "x-telveguard-team": "analitik, stajyer"},
                    json={"model": "gpt-4o", "messages": [{"role": "user", "content": f"TC {make_tckn()}"}]})
    assert r.json()["teams"] == ["analitik", "stajyer"] and r.json()["decision"]["action"] == "block"
