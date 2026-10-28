"""ContextForge eklentisi: araç çağrıları arası kalıcı yer tutucu vault'u (Redis, kullanıcı kapsamı)."""
import pytest

pytest.importorskip("cpex.framework")
fakeredis = pytest.importorskip("fakeredis")

from cpex.framework import (GlobalContext, PluginConfig, PluginContext, ToolPostInvokePayload,
                            ToolPreInvokePayload)
from cpex.framework.models import UserContext

from telveguard_contextforge import TelveguardPlugin
from telveguard_contextforge.vault import RedisVault, VaultError
from tests.test_tr_pii import make_iban, make_tckn

KEY = "vault-anahtari-yalnizca-test-0123456789abcdef"


@pytest.fixture()
def redis_server():
    return fakeredis.FakeServer()


@pytest.fixture()
def plugin(redis_server, monkeypatch):
    """Her test yeni bir eklenti örneği; aynı sahte Redis (ContextForge'un birden fazla worker'ı gibi)."""
    def make(**config):
        monkeypatch.setenv("TELVEGUARD_VAULT_REDIS_URL", "redis://sahte")
        monkeypatch.setenv("TELVEGUARD_VAULT_KEY", KEY)
        monkeypatch.setattr("redis.Redis.from_url",
                            lambda *a, **k: fakeredis.FakeRedis(server=redis_server))
        cfg = PluginConfig(name="Telveguard", kind="telveguard_contextforge.TelveguardPlugin",
                           hooks=["tool_pre_invoke", "tool_post_invoke"], config=config)
        return TelveguardPlugin(cfg)
    return make


def ctx(user="ayse@sirket.com", tenant="t1"):
    uc = UserContext(user_id=user, teams=[]) if user else None
    return PluginContext(global_context=GlobalContext(request_id="r", user_context=uc, tenant_id=tenant))


async def post(p, text, c=None, tool="crm_lookup"):
    r = await p.tool_post_invoke(ToolPostInvokePayload(
        name=tool, result={"content": [{"type": "text", "text": text}]}), c or ctx())
    return r.modified_payload.result["content"][0]["text"] if r.modified_payload else text


async def pre(p, args, c=None, tool="crm_update"):
    return await p.tool_pre_invoke(ToolPreInvokePayload(name=tool, args=args), c or ctx())


async def test_placeholders_consistent_across_calls_and_workers(plugin):
    t1, t2 = make_tckn(1), make_tckn(2)
    worker_a, worker_b = plugin(), plugin()
    assert await post(worker_a, f"Müşteri {t1}") == "Müşteri [TCKN_1]"
    assert await post(worker_b, f"Müşteri {t2}") == "Müşteri [TCKN_2]"     # numara çakışmaz
    # Ayrı çağrıda, farklı yazımla bile aynı değer aynı yer tutucu
    spaced = f"{t1[:3]} {t1[3:6]} {t1[6:9]} {t1[9:]}"
    assert await post(worker_b, f"Tekrar {spaced} ve {t2}") == "Tekrar [TCKN_1] ve [TCKN_2]"


async def test_internal_tool_gets_real_value_from_previous_call(plugin):
    p = plugin()
    tckn, iban = make_tckn(), make_iban()
    masked = await post(p, f"TCKN {tckn}, IBAN {iban}")
    assert masked == "TCKN [TCKN_1], IBAN [IBAN_TR_1]"
    r = await pre(plugin(), {"musteri": {"tckn": "[TCKN_1]", "not": "IBAN [IBAN_TR_1], bilinmeyen [TCKN_9]"}})
    assert r.modified_payload.args == {"musteri": {"tckn": tckn, "not": f"IBAN {iban}, bilinmeyen [TCKN_9]"}}
    assert r.metadata["telveguard"]["unmasked"] == 2


async def test_external_tool_never_gets_real_value(plugin):
    p = plugin()
    await post(p, f"TCKN {make_tckn()}")
    r = await pre(p, {"text": "Müşteri [TCKN_1] hakkında"}, tool="slack_post")
    assert r.continue_processing is True and r.modified_payload is None    # yer tutucu olduğu gibi gider


async def test_users_cannot_unmask_each_other(plugin):
    p = plugin()
    tckn = make_tckn()
    assert await post(p, f"TCKN {tckn}", ctx("ayse@sirket.com")) == "TCKN [TCKN_1]"
    r = await pre(p, {"tckn": "[TCKN_1]"}, ctx("mehmet@sirket.com"))
    assert r.modified_payload is None
    # Aynı kullanıcı başka tenant'ta da ayrı kapsam
    assert (await pre(p, {"tckn": "[TCKN_1]"}, ctx("ayse@sirket.com", tenant="t2"))).modified_payload is None
    # Mehmet'in ilk değeri de [TCKN_1] olur: numaralar kullanıcıya özgü
    assert await post(p, f"TCKN {make_tckn(5)}", ctx("mehmet@sirket.com")) == "TCKN [TCKN_1]"


async def test_anonymous_caller_gets_per_call_vault_only(plugin):
    p = plugin()
    assert await post(p, f"TCKN {make_tckn(1)}", ctx(user=None)) == "TCKN [TCKN_1]"
    assert await post(p, f"TCKN {make_tckn(2)}", ctx(user=None)) == "TCKN [TCKN_1]"   # kalıcı değil
    assert (await pre(p, {"tckn": "[TCKN_1]"}, ctx(user=None))).modified_payload is None


async def test_redis_holds_no_raw_values_or_user_names(plugin, redis_server):
    p = plugin()
    tckn = make_tckn()
    await post(p, f"TCKN {tckn}")
    r = fakeredis.FakeRedis(server=redis_server)
    dump = b"".join(k + b"".join(f + v for f, v in r.hgetall(k).items()) for k in r.keys("*"))
    assert tckn.encode() not in dump and b"ayse" not in dump
    assert all(0 < r.ttl(k) <= 8 * 3600 for k in r.keys("*"))


async def test_redis_down_blocks_masking_but_not_unmasking(plugin, monkeypatch):
    import redis
    p = plugin()

    def down(*_a, **_k):
        raise redis.exceptions.ConnectionError("yok")
    monkeypatch.setattr(p._store, "assign_many", down)
    monkeypatch.setattr(p._store, "lookup_many", down)
    r = await p.tool_post_invoke(ToolPostInvokePayload(
        name="crm_lookup", result={"content": [{"type": "text", "text": f"TCKN {make_tckn()}"}]}), ctx())
    assert r.continue_processing is False and r.violation.code == "TELVEGUARD_VAULT_UNAVAILABLE"
    r = await pre(p, {"tckn": "[TCKN_1]"})
    assert r.continue_processing is True and r.metadata["telveguard"]["unmask"] == "vault_unavailable"


async def test_unmask_can_be_disabled(plugin):
    p = plugin(unmask_tool_args=False)
    await post(p, f"TCKN {make_tckn()}")
    assert (await pre(p, {"tckn": "[TCKN_1]"})).modified_payload is None


def test_vault_requires_key_when_redis_configured(monkeypatch):
    monkeypatch.setenv("TELVEGUARD_VAULT_REDIS_URL", "redis://sahte")
    monkeypatch.delenv("TELVEGUARD_VAULT_KEY", raising=False)
    with pytest.raises(VaultError):
        RedisVault.from_env("TELVEGUARD_VAULT_REDIS_URL", "TELVEGUARD_VAULT_KEY", 60)
    monkeypatch.setenv("TELVEGUARD_VAULT_KEY", "kisa")
    with pytest.raises(VaultError):
        RedisVault.from_env("TELVEGUARD_VAULT_REDIS_URL", "TELVEGUARD_VAULT_KEY", 60)
    monkeypatch.delenv("TELVEGUARD_VAULT_REDIS_URL")
    assert RedisVault.from_env("TELVEGUARD_VAULT_REDIS_URL", "TELVEGUARD_VAULT_KEY", 60) is None


def test_ciphertext_bound_to_scope_and_placeholder():
    v = RedisVault(fakeredis.FakeRedis(), KEY.encode(), 60)
    a, b = v.scope("t1", "ayse"), v.scope("t1", "mehmet")
    ph = v.assign(a, "TCKN", make_tckn())
    blob = v._r.hget(f"tv:cf:{a}:v", ph)
    # Başka kullanıcının kaydına kopyalanan şifreli değer açılmaz
    v._r.hset(f"tv:cf:{b}:v", ph, blob)
    assert v.lookup(b, ph) is None and v.lookup(a, ph) == make_tckn()


class _CountingRedis:
    """Redis'e giden gidiş-dönüş sayısı (pipeline.execute ya da tek komut = 1)."""

    def __init__(self, inner):
        self.inner, self.round_trips = inner, 0

    def pipeline(self, **kw):
        outer, pipe = self, self.inner.pipeline(**kw)
        real = pipe.execute

        def execute(*a, **k):
            outer.round_trips += 1
            return real(*a, **k)
        pipe.execute = execute
        return pipe

    def __getattr__(self, name):
        attr = getattr(self.inner, name)
        if not callable(attr):
            return attr

        def call(*a, **k):
            self.round_trips += 1
            return attr(*a, **k)
        return call


async def test_many_values_use_few_round_trips(plugin):
    p = plugin()
    counting = _CountingRedis(p._store._r)
    p._store._r = counting
    tcknler = [make_tckn(i) for i in range(1, 51)]
    text = "\n".join(f"Müşteri {t}" for t in tcknler)
    masked = await post(p, text)
    assert counting.round_trips <= 3                       # 50 yeni değer: oku + numara + yaz
    assert masked.splitlines()[0] == "Müşteri [TCKN_1]" and masked.splitlines()[-1] == "Müşteri [TCKN_50]"
    counting.round_trips = 0
    assert await post(p, text) == masked                   # hepsi biliniyor
    assert counting.round_trips == 1
    counting.round_trips = 0
    args = {"liste": [f"[TCKN_{i}]" for i in range(1, 51)]}
    r = await pre(p, args)
    assert r.modified_payload.args == {"liste": tcknler} and counting.round_trips == 1
