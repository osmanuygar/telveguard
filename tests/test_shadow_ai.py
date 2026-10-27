"""Gölge AI olay toplama ucu (tarayıcı eklentisi)."""
import pytest

from tests.test_gateway import client  # noqa: F401  (fixture)

TOKEN = "eklenti-token"
H = {"Authorization": f"Bearer {TOKEN}"}


@pytest.fixture()
def events(client, monkeypatch):  # noqa: F811
    monkeypatch.setenv("SHADOW_AI_TOKEN", TOKEN)
    out = []

    async def capture(ev):
        out.append(ev)
    client.app.state.audit.emit = capture
    return out


def post(c, events_, headers=H):
    return c.post("/v1/shadow-ai/events", headers=headers, json={"events": events_})


def test_events_written_to_audit_without_content(client, events):  # noqa: F811
    r = post(client, [
        {"site": "ChatGPT.com", "action": "masked", "entities": {"TCKN": 2, "IBAN_TR": 1}, "chars": 540,
         "user": "ayse@sirket.com", "team": "finans", "extension_version": "0.1.0"},
        {"site": "claude.ai", "action": "allowed_override", "entities": {"SECRET_AWS_KEY": 1}},
    ])
    assert r.status_code == 200 and r.json() == {"accepted": 2}
    a, b = events
    assert (a["model"], a["action"], a["api_format"], a["destination"]) == ("chatgpt.com", "mask", "browser", "external")
    assert a["entities"] == a["masked_entities"] == ["IBAN_TR", "TCKN"] and a["masked_count"] == 3
    assert a["rules"] == ["golge-ai:masked"] and a["auth_source"] == "browser_extension"
    assert b["action"] == "alert" and b["masked_entities"] == []          # uyarıya rağmen olduğu gibi
    assert all(ev["masked_prompt"] == "" for ev in events)                 # içerik yok


def test_trigger_recorded_as_reason(client, events):  # noqa: F811
    r = post(client, [{"site": "claude.ai", "action": "masked", "entities": {"TCKN": 1}, "trigger": "send"},
                      {"site": "claude.ai", "action": "blocked", "entities": {"TCKN": 1}, "trigger": "paste"},
                      {"site": "claude.ai", "action": "blocked", "entities": {"TCKN": 1}}])   # eski eklenti
    assert r.status_code == 200
    assert [e["reason"] for e in events] == ["Tarayıcı: gönderim sırasında", "Tarayıcı: yapıştırma sırasında", ""]
    assert post(client, [{"site": "claude.ai", "action": "blocked", "trigger": "drop"}]).status_code == 400


def test_disabled_without_token(client, monkeypatch):  # noqa: F811
    monkeypatch.delenv("SHADOW_AI_TOKEN", raising=False)
    assert post(client, []).status_code == 404


def test_wrong_token(client, events):  # noqa: F811
    assert post(client, [], headers={"Authorization": "Bearer yanlis"}).status_code == 401
    assert post(client, [], headers={}).status_code == 401


@pytest.mark.parametrize("bad", [
    {"site": "chatgpt.com", "action": "sil"},                                    # bilinmeyen aksiyon
    {"site": "<script>", "action": "blocked"},                                   # site alan adı değil
    {"site": "chatgpt.com", "action": "blocked", "entities": {"TCKN_DEGERI": 1}},  # bilinmeyen tür
    {"site": "chatgpt.com", "action": "blocked", "entities": {"TCKN": -1}},
    {"site": "chatgpt.com", "action": "blocked", "user": "a'; DROP TABLE audit --"},
    {"site": "chatgpt.com", "action": "blocked", "raw_text": "TC 10000000146"},  # fazladan alan yok sayılır
])
def test_strict_validation(client, events, bad):  # noqa: F811
    r = post(client, [bad])
    if "raw_text" in bad:
        assert r.status_code == 200 and "10000000146" not in str(events)   # metin kaydedilmez
    else:
        assert r.status_code == 400 and events == []


def test_batch_size_limit(client, events):  # noqa: F811
    assert post(client, [{"site": "claude.ai", "action": "visit"}] * 101).status_code == 400


def test_dictionary_entities_and_file_trigger(client, events):  # noqa: F811
    r = post(client, [{"site": "chatgpt.com", "action": "masked", "trigger": "file",
                       "entities": {"KURUM_PROJE": 2, "TCKN": 1}}])
    assert r.status_code == 200
    assert events[0]["entities"] == ["KURUM_PROJE", "TCKN"] and events[0]["reason"] == "Tarayıcı: dosya eklerken"
    assert post(client, [{"site": "chatgpt.com", "action": "blocked", "entities": {"KURUM_": 1}}]).status_code == 400
    assert post(client, [{"site": "chatgpt.com", "action": "blocked", "entities": {"kurum_proje": 1}}]).status_code == 400


# ---------------- kurumsal sözlük (tarayıcı sürümü) ----------------

def get_dictionary(c, headers=H):
    return c.get("/v1/shadow-ai/dictionary", headers=headers)


def test_dictionary_endpoint_sends_hashes_not_terms(client, events):  # noqa: F811
    from app.dictionary import Dictionary, term_hash
    client.app.state.dictionary = Dictionary.from_config({"dictionary": [
        {"entity": "KURUM_MUSTERI", "label": "Müşteri", "terms": ["Işık Lojistik", "Akdeniz Holding"]},
        {"entity": "KURUM_SUNUCU", "patterns": [r"[a-z0-9-]+\.sirket\.local"]},
        {"entity": "KURUM_KOD", "terms": ["PRJX"], "whole_word": False},
    ]})
    r = get_dictionary(client)
    assert r.status_code == 200
    body = r.json()
    assert "lojistik" not in r.text.lower() and "akdeniz" not in r.text.lower()
    (terms,) = body["terms"]
    assert terms["entity"] == "KURUM_MUSTERI" and terms["max_words"] == 2 and terms["lengths"] == [13, 15]
    assert term_hash(body["salt"], "ışık lojistik") in terms["hashes"]       # Türkçe küçük harf
    assert body["patterns"] == [{"entity": "KURUM_SUNUCU", "pattern": r"[a-z0-9-]+\.sirket\.local",
                                 "case_sensitive": False, "whole_word": True}]
    assert body["skipped_terms"] == 1 and body["labels"] == {"KURUM_MUSTERI": "Müşteri"}
    # Değişmediyse 304: eklenti saatlik kontrolde yeniden indirmez
    etag = r.headers["etag"]
    assert get_dictionary(client, {**H, "If-None-Match": etag}).status_code == 304


def test_dictionary_endpoint_sends_exceptions_as_hashes(client, events):  # noqa: F811
    from app.dictionary import term_hash
    from app.exemptions import Exemptions
    from tests.test_tr_pii import make_iban
    iban = make_iban(account="0000000999999999")
    before = get_dictionary(client).headers["etag"]
    client.app.state.exemptions = Exemptions.from_config({"exceptions": [
        {"entity": "IBAN_TR", "values": [iban]}, {"entity": "EMAIL_ADDRESS", "patterns": [r"[\w.]+@sirket\.com\.tr"]}]})
    r = get_dictionary(client)
    body = r.json()
    assert iban not in r.text and iban[4:] not in r.text
    assert body["exceptions"]["values"] == [{"entity": "IBAN_TR", "hashes": [term_hash(body["salt"], iban)]}]
    assert body["exceptions"]["patterns"] == [{"entity": "EMAIL_ADDRESS", "pattern": r"[\w.]+@sirket\.com\.tr"}]
    # Yalnızca istisna değişse de sürüm değişir: eklenti yeniden indirir
    assert r.headers["etag"] != before


def test_dictionary_endpoint_requires_token(client, monkeypatch):  # noqa: F811
    monkeypatch.delenv("SHADOW_AI_TOKEN", raising=False)
    assert get_dictionary(client).status_code == 404
    monkeypatch.setenv("SHADOW_AI_TOKEN", TOKEN)
    assert get_dictionary(client, {"Authorization": "Bearer yanlis"}).status_code == 401


def test_dictionary_version_changes_with_terms():
    from app.dictionary import Dictionary
    a = Dictionary.from_config({"dictionary": [{"entity": "KURUM_P", "terms": ["Anka"]}]}).browser()
    b = Dictionary.from_config({"dictionary": [{"entity": "KURUM_P", "terms": ["Anka", "Turna"]}]}).browser()
    assert a["version"] != b["version"] and a["salt"] != b["salt"]
    assert Dictionary.from_config({}).browser()["terms"] == []


def test_redirect_and_justification(client, events):  # noqa: F811
    r = post(client, [
        {"site": "chatgpt.com", "action": "allowed_override", "trigger": "send", "entities": {"TCKN": 1},
         "justification": "false_positive"},
        {"site": "chatgpt.com", "action": "redirected", "trigger": "paste", "entities": {"TCKN": 1}},
        {"site": "chatgpt.com", "action": "redirected", "trigger": "banner"},
        {"site": "chatgpt.com", "action": "masked", "entities": {"TCKN": 1}, "justification": "consent"},
    ])
    assert r.status_code == 200
    override, redirected, banner, masked = events
    assert override["rules"] == ["golge-ai:allowed_override", "golge-ai:gerekce:false_positive"]
    assert override["reason"] == "Tarayıcı: gönderim sırasında · Gerekçe: Yanlış alarm" and override["action"] == "alert"
    assert redirected["action"] == "block" and redirected["rules"] == ["golge-ai:redirected"]
    assert banner["reason"] == "Tarayıcı: bilgilendirme bandından"
    assert masked["rules"] == ["golge-ai:masked"]                       # gerekçe yalnızca "yine de" için
    bad = {"site": "chatgpt.com", "action": "allowed_override", "justification": "keyfime göre"}
    assert post(client, [bad]).status_code == 400                       # serbest metin kabul edilmez


# ---------------- hız sınırı (token herkeste: sahte olay seli) ----------------

def test_rate_limited_per_declared_user(client, events):  # noqa: F811
    from app.shadow_ai import RateLimiter
    client.app.state.shadow_limiter = RateLimiter(per_user=3, total=100)
    ev = {"site": "chatgpt.com", "action": "blocked", "user": "ayse@sirket.com"}
    assert post(client, [ev, ev]).status_code == 200
    r = post(client, [ev, ev])                       # parti sığmıyor: hiçbiri yazılmaz
    assert r.status_code == 429 and r.headers["Retry-After"] == "60" and len(events) == 2
    assert post(client, [{**ev, "user": "mehmet@sirket.com"}]).status_code == 200


def test_rate_limit_total_and_window_reset():
    from app.shadow_ai import RateLimiter, ShadowEvent
    now = [0.0]
    limiter = RateLimiter(per_user=1000, total=5, clock=lambda: now[0])
    batch = [ShadowEvent(site="claude.ai", action="visit", user=f"u{i}") for i in range(3)]
    assert limiter.allow(batch) and not limiter.allow(batch)
    now[0] = 61.0                                    # yeni dakika
    assert limiter.allow(batch)
