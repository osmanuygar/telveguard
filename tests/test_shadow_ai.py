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
