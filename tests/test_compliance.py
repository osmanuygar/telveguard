"""AI envanteri, EU AI Act sınıflandırması ve VERBİS taslağı."""
import csv
import io
import re
from datetime import date

import pytest

from app import compliance as c
from tests.test_gateway import client  # noqa: F401  (fixture)
from tests.test_xray import FakeClickHouse

TODAY = date(2026, 9, 29)


# ---------------- katalog: kaynaklarla tutarlılık ----------------

def test_article_5_all_points_present():
    refs = {u["ref"].split()[1].replace("(Omnibus)", "") for u in c.USE_CASES.values() if u["risk"] == "prohibited"}
    points = {re.search(r"5\(1\)\((\w+)\)", r).group(1) for r in refs}
    assert points == {"a", "b", "ba", "bb", "c", "d", "e", "f", "g", "h"}


def test_annex_iii_all_areas_covered():
    areas = {re.match(r"Ek III (\d)", u["ref"]).group(1) for u in c.USE_CASES.values() if u["risk"] == "high"}
    assert areas == set("12345678")


def test_omnibus_dates():
    by = {k: u["applies_from"] for k, u in c.USE_CASES.items()}
    assert {by[k] for k, u in c.USE_CASES.items() if u["risk"] == "high"} == {"2027-12-02"}   # Ek III
    assert by["intimate_imagery"] == by["csam"] == "2026-12-02"                               # yeni yasaklar
    assert by["social_scoring"] == "2025-02-02"
    assert {by[k] for k, u in c.USE_CASES.items() if u["risk"] == "limited"} == {"2026-08-02"}  # md. 50


def test_obligations_by_risk():
    assert "yasaktır" in c.obligations("social_scoring")[0]
    high = " ".join(c.obligations("recruitment"))
    assert "md. 26/6" in high and "2027-12-02" in high and c.AI_LITERACY in c.obligations("recruitment")
    assert any("md. 50/1" in o for o in c.obligations("chatbot_public"))
    assert c.obligations("code_assistant") == [c.AI_LITERACY]


# ---------------- beyan doğrulama ----------------

def test_shipped_inventory_is_valid():
    inv = c.load_inventory("policies/inventory.yaml")
    assert len(inv["systems"]) == 3


def test_missing_inventory_file_is_empty():
    assert c.load_inventory("/yok/inventory.yaml") == {"systems": []}


@pytest.mark.parametrize("system,msg", [
    ({"id": "x", "name": "X", "owner_team": "t", "models": ["*"], "use_case": "cv_filtreleme", "purpose": "p"},
     "bilinmeyen use_case"),
    ({"id": "x", "name": "X", "owner_team": "t", "models": ["*"], "use_case": "recruitment"}, "eksik alan"),
])
def test_invalid_declarations_rejected(system, msg):
    with pytest.raises(ValueError, match=msg):
        c.validate_inventory({"systems": [system]})


def test_duplicate_ids_rejected():
    s = {"id": "x", "name": "X", "owner_team": "t", "models": ["*"], "use_case": "code_assistant", "purpose": "p"}
    with pytest.raises(ValueError, match="iki kez"):
        c.validate_inventory({"systems": [s, dict(s)]})


# ---------------- envanter ----------------

INV = {"systems": [
    {"id": "ik", "name": "CV ön eleme", "owner_team": "ik", "models": ["gpt-*"], "use_case": "recruitment",
     "purpose": "Başvuru ön değerlendirme", "data_subjects": ["Çalışan adayı"], "decides_about_people": True},
    {"id": "kod", "name": "Kod asistanı", "owner_team": ["yazilim", "platform"], "models": ["claude-*"],
     "use_case": "code_assistant", "purpose": "Yazılım geliştirme"},
    {"id": "fiyat", "name": "Kampanya fiyatlama", "owner_team": "pazarlama", "models": ["gpt-*"],
     "use_case": "data_analysis", "purpose": "Fiyat analizi", "decides_about_people": True},
    {"id": "eski", "name": "Eski bot", "owner_team": "destek", "models": ["gpt-3*"],
     "use_case": "chatbot_public", "purpose": "SSS"},
]}
USAGE = [
    {"team": "ik", "model": "gpt-4o", "destination": "external", "requests": 40, "users": 3,
     "entities": ["TCKN", "EMAIL_ADDRESS"], "external_with_pii": 12},
    {"team": "platform", "model": "claude-opus-5", "destination": "external", "requests": 90, "users": 7,
     "entities": ["SECRET_AWS_KEY"], "external_with_pii": 0},
    {"team": "pazarlama", "model": "gpt-4o", "destination": "external", "requests": 5, "users": 1,
     "entities": [], "external_with_pii": 0},
    {"team": "finans", "model": "gemini-2.5-pro", "destination": "external", "requests": 17, "users": 2,
     "entities": ["IBAN_TR"], "external_with_pii": 17},
]


def test_inventory_classification_matching_and_undeclared():
    inv = c.build_inventory(INV, USAGE, TODAY)
    by = {s["id"]: s for s in inv["systems"]}
    assert by["ik"]["risk"] == "high" and by["ik"]["legal_ref"] == "Ek III 4(a)"
    assert by["ik"]["in_force"] is False                       # 2.12.2027'den itibaren
    assert by["ik"]["observed"]["requests"] == 40 and by["ik"]["observed"]["entities"] == ["EMAIL_ADDRESS", "TCKN"]
    assert any("KVKK md. 9" in w for w in by["ik"]["warnings"])
    assert by["kod"]["observed"]["requests"] == 90             # çoklu ekip beyanı
    assert any("Ek III" in w for w in by["fiyat"]["warnings"])  # kişiler hakkında karar + minimal
    assert any("trafik görülmedi" in w for w in by["eski"]["warnings"])
    assert by["eski"]["risk"] == "limited" and by["eski"]["in_force"] is True
    assert [(u["team"], u["model"]) for u in inv["undeclared"]] == [("finans", "gemini-2.5-pro")]
    assert inv["summary"] == {"prohibited": 0, "high": 1, "limited": 1, "minimal": 2, "unclassified": 1}
    assert [s["risk"] for s in inv["systems"]][0] == "high"     # en riskli önce
    assert inv["disclaimer"].startswith("TASLAK")


# ---------------- VERBİS ----------------

VERBIS_ROWS = [
    {"entity": "TCKN", "destination": "external", "model": "gpt-4o", "team": "ik", "requests": 12, "provider": "OpenAI"},
    {"entity": "TCKN", "destination": "internal", "model": "vllm/qwen3", "team": "ik", "requests": 30, "provider": "Diğer / bilinmiyor"},
    {"entity": "IBAN_TR", "destination": "internal", "model": "vllm/qwen3", "team": "finans", "requests": 3, "provider": "Diğer / bilinmiyor"},
    {"entity": "SECRET_AWS_KEY", "destination": "external", "model": "claude-opus-5", "team": "platform", "requests": 9, "provider": "Anthropic"},
    {"entity": "SECRET_PASSWORD", "destination": "external", "model": "claude-opus-5", "team": "platform", "requests": 2, "provider": "Anthropic"},
]


def test_verbis_mapping():
    rep = c.build_verbis(INV, VERBIS_ROWS, "2 yıl")
    by = {r["veri_kategorisi"]: r for r in rep["rows"]}
    assert set(by) == {"Kimlik", "Finans", "İşlem Güvenliği"}          # API anahtarı kişisel veri değil
    k = by["Kimlik"]
    assert k["yurt_disina_aktarim"] == "Evet" and k["aktarilan_ulkeler"] == ["ABD"] and k["saglayicilar"] == ["OpenAI"]
    assert k["isleme_amaclari"] == ["Başvuru ön değerlendirme"] and k["veri_konusu_kisi_gruplari"] == ["Çalışan adayı"]
    assert "5 iş günü" in k["aktarim_dayanagi_kvkk_9"] and k["gozlenen_istek"] == 42
    f = by["Finans"]
    assert f["yurt_disina_aktarim"] == "Hayır" and f["alici_gruplari"] == ["Kurum içi"]
    assert f["isleme_amaclari"] == [c.TO_LEGAL]                         # beyan yok -> hukuk doldurur
    assert by["İşlem Güvenliği"]["tespit_edilen_turler"] == ["SECRET_PASSWORD"]


def test_verbis_csv():
    text = c.verbis_csv(c.build_verbis(INV, VERBIS_ROWS, "2 yıl"))
    assert text.startswith("\ufeff")
    rows = list(csv.reader(io.StringIO(text.lstrip("\ufeff")), delimiter=";"))
    assert rows[0][0].startswith("TASLAK") and rows[1][0] == "Veri kategorisi"
    assert any(r[0] == "Kimlik" and "ABD" in r[6] for r in rows[2:])


# ---------------- uçlar ----------------

def test_inventory_and_verbis_endpoints(client, monkeypatch):  # noqa: F811
    monkeypatch.setenv("TELVEGUARD_ADMIN_TOKEN", "t")
    h = {"Authorization": "Bearer t"}
    client.app.state.inventory = INV
    client.app.state.ch = FakeClickHouse({"GROUP BY team, model": USAGE,
                                          "GROUP BY entity, destination, model, team": [
                                              {k: v for k, v in r.items() if k != "provider"} for r in VERBIS_ROWS]})
    inv = client.get("/v1/inventory?days=90", headers=h).json()
    assert inv["summary"]["unclassified"] == 1
    rep = client.get("/v1/reports/verbis", headers=h).json()
    assert {r["veri_kategorisi"] for r in rep["rows"]} == {"Kimlik", "Finans", "İşlem Güvenliği"}
    r = client.get("/v1/reports/verbis?format=csv", headers=h)
    assert r.headers["content-disposition"].endswith('verbis-taslak.csv"')
    assert client.get("/v1/inventory").status_code == 401             # yönetici değil
