"""POC değerlendirme raporu: akıbet hesabı, KVKK tablosu, öneriler ve uç (sahte ClickHouse).
Gerçek SQL e2e'de ClickHouse'a karşı koşar (tests/e2e/test_e2e_poc_report.py)."""
import pytest

from app import poc_report as pr
from tests.test_gateway import client  # noqa: F401  (fixture)
from tests.test_xray import AUTH, FakeClickHouse, admin  # noqa: F401  (fixture)

SUMMARY = {"requests": 100, "users": 9, "teams": 3, "external_requests": 70, "monitored_requests": 40,
           "first_seen": "2026-09-25 09:00:00.000", "last_seen": "2026-10-08 17:00:00.000",
           "risky_total": 30, "risky_exposed": 6, "risky_would": 14,
           "pii_external_total": 20, "pii_external_protected": 5, "pii_external_would": 12,
           "secrets_total": 4, "secrets_protected": 4, "secrets_would": 0,
           "injection_total": 5, "injection_protected": 1, "injection_would": 2}


def test_summarize_splits_outcomes():
    s = pr.summarize(SUMMARY)
    assert s["risky"] == {"total": 30, "protected": 10, "would": 14, "exposed": 6}
    assert s["risks"]["pii_external"] == {"label": pr.RISK_LABELS["pii_external"], "total": 20, "protected": 5,
                                          "would": 12, "exposed": 3}
    assert s["risks"]["injection"]["exposed"] == 2 and s["risks"]["output_leak"]["total"] == 0


def test_summarize_empty_window():
    s = pr.summarize({})
    assert s["requests"] == 0 and s["first_seen"] is None and s["risky"]["total"] == 0


ENTITY_ROWS = [
    {"entity": "TCKN", "model": "gpt-4o", "destination": "external", "requests": 10, "protected": 2, "would": 6},
    {"entity": "TCKN", "model": "gpt-4o-mini", "destination": "external", "requests": 2, "protected": 0, "would": 0},
    {"entity": "TCKN", "model": "vllm/qwen3", "destination": "internal", "requests": 50, "protected": 0, "would": 0},
    {"entity": "PHONE_TR", "model": "gemini-2.5-pro", "destination": "external", "requests": 3, "protected": 0, "would": 0},
    {"entity": "SECRET_AWS_KEY", "model": "vllm/qwen3", "destination": "internal", "requests": 2, "protected": 0, "would": 0},
    {"entity": "KURUM_PROJE", "model": "gpt-4o", "destination": "external", "requests": 4, "protected": 4, "would": 0},
]


def test_entity_tables_kvkk_by_provider_and_internal_excluded():
    kvkk, entities = pr.entity_tables(ENTITY_ROWS, None, {"OpenAI": "ABD", "Google": "ABD"}, {"KURUM_PROJE": "Proje"})
    by = {(k["entity"], k["provider"]): k for k in kvkk}
    assert by[("TCKN", "OpenAI")] == {"entity": "TCKN", "label": "T.C. kimlik no", "provider": "OpenAI",
                                      "country": "ABD", "total": 12, "protected": 2, "would": 6, "exposed": 4}
    assert by[("PHONE_TR", "Google")]["exposed"] == 3
    assert all(k["entity"] != "SECRET_AWS_KEY" for k in kvkk)              # sır KVKK tablosunda değil
    e = {x["entity"]: x for x in entities}
    assert e["TCKN"]["total"] == 12                                        # kurum içi TCKN risk değil
    assert e["SECRET_AWS_KEY"]["exposed"] == 2 and e["SECRET_AWS_KEY"]["kind"] == "secret"   # sır her yerde
    assert e["KURUM_PROJE"]["label"] == "Proje" and e["KURUM_PROJE"]["exposed"] == 0
    assert entities[0]["entity"] == "TCKN"                                 # en çok korumasız önce


def recs(summary=SUMMARY, rows=ENTITY_ROWS, rules=(), shadow=None, undeclared=0):
    s = pr.summarize(summary)
    _k, entities = pr.entity_tables(rows, None, {}, {})
    shadow = shadow or {"sites": [], "totals": {}}
    return pr.recommendations(s, entities, list(rules), shadow, {"undeclared": undeclared})


def test_recommendations_cover_gaps_with_policy():
    out = recs(rules=[{"rule": "kvkk-yurtdisi-maskele", "mode": "monitor", "hits": 12},
                      {"rule": "x", "mode": "enforce", "hits": 3}], undeclared=2)
    titles = [r["title"] for r in out]
    assert titles[0] == "Yurt dışı modele giden kişisel veriyi maskeleyin"
    assert "entity_in: [TCKN, PHONE_TR]" in out[0]["policy"] and out[0]["priority"] == "high"
    assert "Sırları her hedefte maskeleyin" in titles                     # kurum içinde korumasız AWS anahtarı
    assert "Prompt injection girişimlerini engelleyin" in titles
    monitor = next(r for r in out if r["title"] == "Gözlemdeki kuralları uygulamaya alın")
    assert "kvkk-yurtdisi-maskele (12)" in monitor["detail"] and "x (" not in monitor["detail"]
    assert "Tarayıcı eklentisini dağıtın" in titles
    assert out[-1]["priority"] == "low" and "declared: false" in out[-1]["policy"]
    import yaml
    for r in out:   # YAML parçaları geçerli olmalı
        if r["policy"]:
            yaml.safe_load(r["policy"])


def test_recommendations_shadow_override_and_quiet_when_clean():
    shadow = {"sites": [{"site": "chatgpt.com"}],
              "totals": {"masked": 4, "cancelled": 1, "blocked": 0, "overridden": 5}}
    clean = {"requests": 50, "risky_total": 0}
    out = recs(summary=clean, rows=[], shadow=shadow)
    assert [r["title"] for r in out] == ["Tarayıcı eklentisini engelleme moduna alın"]
    shadow["totals"]["overridden"] = 1
    assert recs(summary=clean, rows=[], shadow=shadow) == []


def test_sql_keeps_browser_events_out_of_gateway_numbers():
    for name in ("summary", "entities", "teams", "examples"):
        assert "api_format != 'browser'" in pr.QUERIES[name]
    assert "api_format = 'browser'" in pr.QUERIES["shadow_sites"]
    assert "LIMIT 1 BY team, outcome" in pr.QUERIES["examples"] and "LIMIT 3 BY outcome" in pr.QUERIES["examples"]


# ---------------- uç ----------------

def test_report_endpoint_assembles_sections(client, admin):  # noqa: F811
    fake = FakeClickHouse({
        "risky_total": [SUMMARY],
        "ARRAY JOIN entities AS entity WHERE event_time >= now() - INTERVAL {days:UInt32} DAY AND api_format != 'browser'": ENTITY_ROWS,
        "GROUP BY team ORDER BY exposed": [{"team": "finans", "requests": 40, "risky": 9, "exposed": 2, "would": 5}],
        "AS site": [{"site": "chatgpt.com", "users": 3, "visits": 0, "with_data": 7, "masked": 4, "cancelled": 1,
                     "blocked": 0, "overridden": 2}],
        "AS events": [{"entity": "TCKN", "events": 5}],
        "AS outcome": [{"event_id": "e1", "event_time": "2026-10-08 10:00:00.000", "team": "finans", "model": "gpt-4o",
                        "destination": "external", "api_format": "chat", "action": "allow", "would_action": "mask",
                        "entities": ["TCKN"], "masked_entities": [], "rules": [], "monitored_rules": ["k"],
                        "injection_score": 0.0, "output_leaked": [], "output_action": "", "outcome": "would"}],
        "SELECT rule, mode, hits": [{"rule": "kvkk-yurtdisi-maskele", "mode": "monitor", "hits": 14}],
        "GROUP BY team, model": [{"team": "finans", "model": "gemini-2.5-pro", "destination": "external",
                                  "requests": 3, "users": 1, "entities": [], "external_with_pii": 0}],
    })
    client.app.state.ch = fake
    r = client.get("/v1/reports/poc?days=14", headers=AUTH)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["summary"]["risky"]["exposed"] == 6 and body["window"] == {"days": 14}
    assert body["kvkk"][0]["provider"] == "OpenAI" and body["kvkk"][0]["country"] == "ABD"
    assert body["shadow"]["totals"]["with_data"] == 7 and body["shadow"]["entities"][0]["label"] == "T.C. kimlik no"
    assert body["examples"][0]["labels"] == ["T.C. kimlik no"] and "user" not in body["examples"][0]
    assert body["inventory"]["undeclared"] == 1                           # envanterde finans x gemini yok
    assert body["recommendations"] and all(p == {"days": 14} or p == {"days": 14, "team": ""} for _s, p in fake.calls)


def test_report_endpoint_validation_and_auth(client, admin, monkeypatch):  # noqa: F811
    client.app.state.ch = FakeClickHouse()
    assert client.get("/v1/reports/poc?days=0", headers=AUTH).status_code == 400
    assert client.get("/v1/reports/poc").status_code == 401
    client.app.state.ch = None
    assert client.get("/v1/reports/poc", headers=AUTH).status_code == 503


def test_poc_policy_starts_in_monitor_mode_except_secrets():
    from telveguard_core.policy import Context, PolicyEngine
    poc = PolicyEngine("policies/poc.yaml")
    assert poc.mode == "monitor"
    d = poc.evaluate(Context("analitik", "gpt-4o", "external", {"TCKN", "SECRET_AWS_KEY"}, 0.0))
    assert d.action == "mask" and d.mask_entities == {"SECRET_AWS_KEY"}   # sır uygulanır, TCKN gözlemde
    assert "kvkk-yurtdisi-maskele" in d.monitored_rules and d.would_action == "mask"
    default = PolicyEngine("policies/default.yaml")
    assert [r["name"] for r in poc.rules] == [r["name"] for r in default.rules]   # aynı kurallar
