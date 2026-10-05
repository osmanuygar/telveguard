"""KVKK md. 11 ilgili kişi başvurusu: anahtarlı özetlerin kaydı ve arama (sahte ClickHouse)."""
import json
import logging

import pytest

from app.providers import ProviderRegistry
from app.subjects import SubjectIndex, mask_label, normalize
from tests.test_gateway import client  # noqa: F401  (fixture)
from tests.test_tr_pii import make_iban, make_tckn
from tests.test_xray import AUTH, FakeClickHouse, admin  # noqa: F401  (fixture)

KEY = "k" * 40
TCKN = make_tckn()


@pytest.fixture()
def index(client):  # noqa: F811
    client.app.state.subjects = SubjectIndex(KEY)
    events = []

    async def capture(ev):
        events.append(ev)
    client.app.state.audit.emit = capture
    client.events = events
    return client.app.state.subjects


def chat(c, content, model="gpt-4o", team="analitik"):
    return c.post("/v1/chat/completions", headers={"x-telveguard-team": team},
                  json={"model": model, "messages": [{"role": "user", "content": content}]})


def search(c, values, days=730):
    return c.post("/v1/subjects/search", headers=AUTH, json={"values": values, "days": days})


# ---------------- normalize ve özet ----------------

@pytest.mark.parametrize("entity, a, b", [
    ("PHONE_TR", "0532 123 45 67", "+90 (532) 123-4567"),
    ("IBAN_TR", "TR33 0006 1005 1978 6457 8413 26", "tr330006100519786457841326"),
    ("EMAIL_ADDRESS", "Ayse.Yilmaz@Ornek.com ", "ayse.yilmaz@ornek.com"),
    ("PLATE_TR", "34 abc 123", "34ABC123"),
    ("CREDIT_CARD", "4111 1111 1111 1111", "4111-1111-1111-1111"),
])
def test_normalize_matches_formats(entity, a, b):
    assert normalize(entity, a) == normalize(entity, b)
    assert SubjectIndex(KEY).hash(entity, a) == SubjectIndex(KEY).hash(entity, b)


def test_hash_is_keyed_and_typed():
    a, b = SubjectIndex(KEY), SubjectIndex("z" * 40)
    assert a.hash("TCKN", TCKN) != b.hash("TCKN", TCKN)          # anahtarsız geri çevrilemez
    assert a.hash("VKN", "1234567890") != a.hash("PHONE_TR", "1234567890")
    assert len(a.hash("TCKN", TCKN)) == 32


def test_short_key_rejected():
    with pytest.raises(ValueError, match="32"):
        SubjectIndex("kisa")


def test_mask_label():
    assert mask_label(TCKN, "TCKN") == "*******" + TCKN[-4:]
    assert mask_label("ayse@ornek.com", "EMAIL_ADDRESS") == "a***@ornek.com"


# ---------------- kayıt ----------------

def test_event_records_hashes_not_values(client, index):  # noqa: F811
    iban = make_iban()
    chat(client, f"TC {TCKN}, IBAN {iban}, tel 0532 123 45 67, anahtar AKIA{'Q3EXAMPLE7ABCDEF'}")
    ev = client.events[-1]
    assert set(ev["subject_hashes"]) == {index.hash("TCKN", TCKN), index.hash("IBAN_TR", iban),
                                         index.hash("PHONE_TR", "05321234567")}   # sır kişiyi tanımlamaz
    dumped = json.dumps(ev, ensure_ascii=False)
    assert TCKN not in dumped and iban not in dumped


def test_blocked_request_also_recorded(client, index):  # noqa: F811
    chat(client, f"TC {TCKN}", team="stajyer")                    # engellendi
    assert client.events[-1]["action"] == "block" and client.events[-1]["subject_hashes"]


def test_disabled_without_key(client):  # noqa: F811
    client.app.state.subjects = SubjectIndex(None)
    events = []

    async def capture(ev):
        events.append(ev)
    client.app.state.audit.emit = capture
    chat(client, f"TC {TCKN}")
    assert events[-1]["subject_hashes"] == []


# ---------------- arama ----------------

def row(index, **kw):
    base = {"event_id": "00000000-0000-0000-0000-000000000001", "event_time": "2026-09-10 10:00:00.000",
            "team": "analitik", "user": "ayse", "model": "gpt-4o", "destination": "external",
            "api_format": "chat", "action": "mask", "rules": [], "entities": ["TCKN"],
            "masked_entities": ["TCKN"], "matched": [index.hash("TCKN", TCKN)]}
    return {**base, **kw}


def test_search_requires_admin_and_key(client, index, monkeypatch):  # noqa: F811
    monkeypatch.delenv("TELVEGUARD_ADMIN_TOKEN", raising=False)
    assert search(client, [TCKN]).status_code == 404
    monkeypatch.setenv("TELVEGUARD_ADMIN_TOKEN", "test-admin-token")
    client.app.state.subjects = SubjectIndex(None)
    r = search(client, [TCKN])
    assert r.status_code == 404 and r.json()["error"]["code"] == "subjects_disabled"


@pytest.mark.parametrize("body", [{}, {"values": []}, {"values": "x"}, {"values": ["1"] * 21},
                                  {"values": [TCKN], "days": 0}, {"values": [TCKN], "days": "730"}])
def test_search_validation(client, index, admin, body):  # noqa: F811
    client.app.state.ch = FakeClickHouse()
    assert client.post("/v1/subjects/search", headers=AUTH, json=body).status_code == 400


def test_search_summary_and_statuses(client, index, admin):  # noqa: F811
    client.app.state.providers = ProviderRegistry.from_config({"providers": [
        {"name": "OpenAI", "match": ["gpt-"], "url": "https://api.openai.com/v1", "country": "ABD"}]})
    phone_hash = index.hash("PHONE_TR", "5321234567")
    fake = FakeClickHouse({"FROM audit": [
        row(index, event_id="e1", event_time="2026-10-01 09:00:00.000", masked_entities=[]),     # maskesiz
        row(index, event_id="e2", event_time="2026-09-10 10:00:00.000"),                        # maskeli
        row(index, event_id="e3", event_time="2026-08-01 08:00:00.000", destination="internal", model="vllm/qwen3"),
        row(index, event_id="e4", event_time="2026-07-01 08:00:00.000", action="block",
            matched=[index.hash("TCKN", TCKN), phone_hash]),
    ]})
    client.app.state.ch = fake
    r = search(client, [f"TC {TCKN}", "0532 123 45 67", "merhaba", {"entity": "VKN", "value": "1234567890"}])
    assert r.status_code == 200
    body = r.json()
    tckn, phone, vkn = body["summary"]
    assert tckn["label"] == "*******" + TCKN[-4:] and tckn["events"] == 4
    assert (tckn["unmasked"], tckn["masked"], tckn["internal"], tckn["blocked"]) == (1, 1, 1, 1)
    assert tckn["recipients"] == {"OpenAI (ABD)": 1}
    assert tckn["first_seen"].startswith("2026-07-01") and tckn["last_seen"].startswith("2026-10-01")
    assert phone["events"] == 1 and phone["blocked"] == 1 and vkn["events"] == 0
    assert len(body["errors"]) == 1 and body["errors"][0]["label"] == mask_label("merhaba")
    e4 = next(e for e in body["events"] if e["event_id"] == "e4")
    assert {s["entity"] for s in e4["subjects"]} == {"TCKN", "PHONE_TR"}
    # Değerler SQL'e gömülmez, parametre olarak gider; cevapta ham değer yok
    sql, params = fake.calls[0]
    assert TCKN not in sql and index.hash("TCKN", TCKN) in params["hashes"]
    assert TCKN not in r.text


def test_search_logs_without_values(client, index, admin, caplog):  # noqa: F811
    client.app.state.ch = FakeClickHouse({"FROM audit": []})
    with caplog.at_level(logging.INFO, logger="telveguard.admin"):
        search(client, [TCKN])
    assert "subject_search values=1 types=TCKN" in caplog.text and TCKN not in caplog.text


def test_search_old_key_also_searched(client, admin):  # noqa: F811
    old = "o" * 40
    client.app.state.subjects = SubjectIndex(KEY, old)
    fake = FakeClickHouse({"FROM audit": []})
    client.app.state.ch = fake
    search(client, [TCKN])
    assert set(fake.calls[0][1]["hashes"]) == {SubjectIndex(KEY).hash("TCKN", TCKN), SubjectIndex(old).hash("TCKN", TCKN)}


def test_search_missing_column_hint(client, index, admin):  # noqa: F811
    from app import xray as xray_mod

    class Broken(FakeClickHouse):
        async def query(self, sql, params):
            raise xray_mod.ClickHouseError("ClickHouse hatası (400): Missing columns: 'subject_hashes'")
    client.app.state.ch = Broken()
    r = search(client, [TCKN])
    assert r.status_code == 502 and "0.3.0-subject-hashes.sql" in r.json()["error"]["message"]
