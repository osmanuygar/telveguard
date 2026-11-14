"""Sahte değerle maskeleme (masking.style: synthetic): model geçerli görünen sahte değer görür,
kullanıcıya gerçek değer döner."""
import json
import random
import re

import httpx
import pytest
import yaml
from fastapi.testclient import TestClient

from app import main
from telveguard_core.pii.engine import KnownValues, TrPiiEngine, is_placeholder
from telveguard_core.pii.synthetic import make_surrogate
from telveguard_core.pii.tr_recognizers import is_valid_luhn, is_valid_tckn, is_valid_tr_iban, is_valid_vkn
from telveguard_core.policy import PolicyEngine
from tests.test_guardrail import H, LITELLM, TOKEN
from tests.test_tr_pii import make_iban, make_tckn

TCKN = make_tckn(3)
IBAN = make_iban()
SAMPLE = (f"TC {TCKN}, IBAN {IBAN}, kart 4111 1111 1111 1111, tel 0532 123 45 67, "
          "e-posta ali@firma.com.tr, plaka 34 ABC 123, vergi no 1234567890")


@pytest.fixture()
def engine(monkeypatch):
    monkeypatch.setenv("TELVEGUARD_SYNTHETIC_KEY", "k" * 32)
    return TrPiiEngine()


# ---------------- motor ----------------

def test_surrogates_are_valid_and_keep_layout(engine):
    r = engine.mask(SAMPLE, style="synthetic")
    assert not any(is_placeholder(k) for k in r.vault)
    fake = {v: k for k, v in r.vault.items()}
    assert is_valid_tckn(fake[TCKN]) and fake[TCKN] != TCKN
    assert is_valid_tr_iban(fake[IBAN]) and fake[IBAN] != IBAN
    assert is_valid_luhn(fake["4111 1111 1111 1111"]) and fake["4111 1111 1111 1111"][0] == "4"
    for value in r.vault:   # aynı ayraçlar aynı yerde
        assert re.sub(r"[0-9A-Za-z]", "x", value) == re.sub(r"[0-9A-Za-z]", "x", r.vault[value]) or "@" in value
    vkn = next(k for k, v in r.vault.items() if v == "1234567890")
    assert is_valid_vkn(vkn)
    assert re.fullmatch(r"05\d{2} \d{3} \d{2} \d{2}", next(k for k, v in r.vault.items() if v.startswith("0532")))
    assert next(k for k, v in r.vault.items() if "@" in v).endswith("@example.com")
    # Sahteler yeniden taramada aynı türden tanınır (artımlı akışta bölünmesin, sızıntı sanılmasın)
    assert {f.entity for f in engine.analyze(r.text)} == {f.entity for f in r.findings}


def test_roundtrip_and_reformatted_surrogate(engine):
    r = engine.mask(SAMPLE, style="synthetic")
    assert engine.unmask(r.text, r.vault) == SAMPLE
    fake = next(k for k, v in r.vault.items() if v == TCKN)
    spaced = f"{fake[:3]} {fake[3:6]} {fake[6:9]} {fake[9:]}"
    assert engine.unmask(f"Kayıt: {spaced}.", r.vault) == f"Kayıt: {TCKN}."
    plate = next(k for k, v in r.vault.items() if v == "34 ABC 123")
    assert engine.unmask(plate.replace(" ", "").lower(), r.vault) == "34 ABC 123"
    # Daha uzun bir sayının parçası değiştirilmez
    assert engine.unmask("9" + fake + "9", r.vault) == "9" + fake + "9"


def test_deterministic_per_key_and_consistent_across_spellings(engine, monkeypatch):
    a = engine.mask(f"TC {TCKN}", style="synthetic").text
    assert engine.mask(f"TC {TCKN}", style="synthetic").text == a      # prompt önbelleği bozulmaz
    split = f"{TCKN[:3]} {TCKN[3:6]} {TCKN[6:9]} {TCKN[9:]}"
    r = engine.mask(f"TC {TCKN} ve TC {split}", style="synthetic")
    assert len(r.vault) == 1
    monkeypatch.setenv("TELVEGUARD_SYNTHETIC_KEY", "z" * 32)
    assert TrPiiEngine().mask(f"TC {TCKN}", style="synthetic").text != a   # anahtarsız tahmin edilemez


def test_unsupported_entities_keep_placeholders(engine):
    aws = "AKIA" + "Q3EXAMPLE7ABCDEF"
    r = engine.mask(f"TC {TCKN} key={aws}", style="synthetic")
    assert "[SECRET_AWS_KEY_1]" in r.text and TCKN not in r.text
    assert engine.unmask(r.text, r.vault) == f"TC {TCKN} key={aws}"


def test_shared_vault_mixes_styles(engine):
    vault = {}
    engine.mask(f"TC {TCKN}", vault=vault)                        # önce yer tutucu
    r = engine.mask(f"TC {TCKN} ve {make_tckn(4)}", vault=vault, style="synthetic")
    assert r.text.startswith("TC [TCKN_1] ve ") and "[TCKN_2]" not in r.text


def test_known_values_cover_surrogates(engine):
    r = engine.mask(SAMPLE, style="synthetic")
    kv = KnownValues(r.vault)
    fake = next(k for k, v in r.vault.items() if v == TCKN)
    assert fake in kv and TCKN in kv and f"{fake[:5]} {fake[5:]}" in kv
    assert make_tckn(9) not in kv


def test_surrogate_never_equals_original():
    for seed in range(200):
        original = make_tckn(seed + 10)
        s = make_surrogate("TCKN", original, original, bytes([seed]) * 32)
        assert is_valid_tckn(s)


def test_invalid_style_and_policy_validation(engine, tmp_path):
    with pytest.raises(ValueError):
        engine.mask("x", style="sahte")
    assert PolicyEngine(config={}).mask_style == "placeholder"
    assert PolicyEngine(config={"masking": {"style": "synthetic"}}).mask_style == "synthetic"
    for bad in ({"style": "sahte"}, {"stil": "synthetic"}, "synthetic"):
        with pytest.raises(ValueError):
            PolicyEngine(config={"masking": bad})


def test_short_key_rejected(monkeypatch):
    monkeypatch.setenv("TELVEGUARD_SYNTHETIC_KEY", "kisa")
    with pytest.raises(ValueError):
        TrPiiEngine().mask(f"TC {TCKN}", style="synthetic")


# ---------------- gateway ----------------

state = {"reply": "{echo}", "body": None, "seed": 0}


def _upstream(request: httpx.Request) -> httpx.Response:
    body = json.loads(request.content)
    state["body"] = body
    content = state["reply"].replace("{echo}", body["messages"][-1]["content"])
    if not body.get("stream"):
        return httpx.Response(200, json={
            "id": "x", "created": 0, "model": body["model"],
            "choices": [{"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": content}}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 10}})
    rnd = random.Random(state["seed"])
    pieces, i = [], 0
    while i < len(content):
        n = rnd.randint(1, 6)
        pieces.append(content[i:i + n])
        i += n

    async def sse():
        for p in pieces:
            chunk = {"id": "x", "object": "chat.completion.chunk", "created": 0, "model": body["model"],
                     "choices": [{"index": 0, "delta": {"content": p}, "finish_reason": None}]}
            yield f"data: {json.dumps(chunk, ensure_ascii=False)}\n\n".encode()
        end = {"id": "x", "object": "chat.completion.chunk", "created": 0, "model": body["model"],
               "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]}
        yield f"data: {json.dumps(end)}\n\n".encode()
        yield b"data: [DONE]\n\n"
    return httpx.Response(200, content=sse(), headers={"content-type": "text/event-stream"})


@pytest.fixture()
def c(monkeypatch, tmp_path):
    monkeypatch.setenv("TELVEGUARD_SYNTHETIC_KEY", "k" * 32)
    monkeypatch.setenv("GUARDRAIL_TOKEN", TOKEN)
    state["reply"] = "{echo}"
    main.app.state.http = httpx.AsyncClient(transport=httpx.MockTransport(_upstream))
    with TestClient(main.app) as client:
        cfg = yaml.safe_load(open("policies/default.yaml", encoding="utf-8"))
        cfg["masking"] = {"style": "synthetic"}
        p = tmp_path / "p.yaml"
        p.write_text(yaml.safe_dump(cfg, allow_unicode=True), encoding="utf-8")
        client.app.state.policy = PolicyEngine(str(p))
        client.events = []

        async def capture(ev):
            client.events.append(ev)
        client.app.state.audit.emit = capture
        yield client


def ask(c, content, **extra):
    return c.post("/v1/chat/completions", json={"model": "gpt-4o", "messages": [{"role": "user", "content": content}],
                                                **extra})


def test_model_sees_surrogate_user_gets_original(c):
    r = ask(c, f"TC {TCKN} olan müşteriyi özetle")
    sent = state["body"]["messages"][-1]["content"]
    assert TCKN not in sent and "[TCKN" not in sent
    fake = re.search(r"\d{11}", sent).group(0)
    assert is_valid_tckn(fake)
    assert r.json()["choices"][0]["message"]["content"] == f"TC {TCKN} olan müşteriyi özetle"
    ev = c.events[-1]
    assert ev["action"] == "mask" and ev["masked_count"] == 1
    assert ev["output_leaked"] == []                  # modelin tekrarladığı sahte değer sızıntı değil


def test_reformatted_surrogate_in_answer_is_restored(c):
    state["reply"] = "{echo}"
    ask(c, f"TC {TCKN}")
    fake = re.search(r"\d{11}", state["body"]["messages"][-1]["content"]).group(0)
    state["reply"] = f"Kimlik: {fake[:3]} {fake[3:6]} {fake[6:9]} {fake[9:]}"
    r = ask(c, f"TC {TCKN}")
    assert r.json()["choices"][0]["message"]["content"] == f"Kimlik: {TCKN}"
    assert c.events[-1]["output_leaked"] == []


def test_new_value_from_model_is_still_a_leak(c):
    other = make_tckn(8)
    state["reply"] = f"{{echo}} benzer: {other}"
    r = ask(c, f"TC {TCKN}")
    assert other not in r.text and "[GİZLENDİ:TCKN]" in r.text
    assert c.events[-1]["output_leaked"] == ["TCKN"]


@pytest.mark.parametrize("seed", range(6))
def test_incremental_stream_restores_split_surrogate(c, monkeypatch, seed):
    monkeypatch.setenv("STREAM_MODE", "incremental")
    state["seed"] = seed
    state["reply"] = "Özet: {echo} tamam"
    r = ask(c, f"TC {TCKN}, IBAN {IBAN}", stream=True)
    out = "".join(json.loads(ln[6:])["choices"][0]["delta"].get("content", "")
                  for ln in r.text.split("\n") if ln.startswith("data: {") and json.loads(ln[6:])["choices"])
    assert out == f"Özet: TC {TCKN}, IBAN {IBAN} tamam"


def test_simulator_shows_surrogate(c, monkeypatch):
    monkeypatch.setenv("TELVEGUARD_ADMIN_TOKEN", "adm")
    r = c.post("/v1/policy/simulate", headers={"Authorization": "Bearer adm"},
               json={"model": "gpt-4o", "messages": [{"role": "user", "content": f"TC {TCKN}"}]})
    assert r.status_code == 200, r.text
    sent = r.json()["upstream_messages"][-1]["content"]
    assert TCKN not in sent and is_valid_tckn(re.search(r"\d{11}", sent).group(0))


def test_guardrail_roundtrip(c):
    def call(phase, texts):
        r = c.post(LITELLM, headers=H, json={"input_type": phase, "texts": texts, "litellm_call_id": "call-sahte-1",
                                             "model": "gpt-4o"})
        assert r.status_code == 200, r.text
        return r.json()
    r = call("request", [f"TC {TCKN} özetle"])
    masked = r["texts"][0]
    assert TCKN not in masked and "[TCKN" not in masked
    fake = re.search(r"\d{11}", masked).group(0)
    r = call("response", [f"Özet: {fake} numaralı müşteri"])
    assert r["texts"] == [f"Özet: {TCKN} numaralı müşteri"]
    # Stream'de yarım sahte numara sonraki tura bekletilir (yarısı gönderilirse geri açılamaz)
    r = call("response", [f"Özet: {fake[:6]}"])
    assert r["stream_holdback_chars"] == [6]
