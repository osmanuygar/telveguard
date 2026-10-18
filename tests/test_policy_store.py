"""Konsoldan politika yönetimi: sürümler, dört göz, yayına alma, geri alma, etki analizi."""
import pytest

from app import policy_store as ps
from tests.test_gateway import client  # noqa: F401  (fixture)
from tests.test_tr_pii import make_tckn
from tests.test_xray import ADMIN, AUTH, FakeClickHouse

BASE = open("policies/default.yaml", encoding="utf-8").read()


class MemoryClickHouse:
    """policy_store'un kullandığı birkaç sorgunun bellek içi karşılığı."""

    def __init__(self):
        self.versions, self.events, self.fail = [], [], False

    async def insert(self, table, rows, settings=None):
        if self.fail:
            raise ps.ClickHouseError("ClickHouse'a ulaşılamadı: ConnectError")
        (self.versions if table == "policy_versions" else self.events).extend(rows)

    async def query(self, sql, params, settings=None):
        if self.fail:
            raise ps.ClickHouseError("ClickHouse'a ulaşılamadı: ConnectError")
        if "max(version)" in sql:
            return [{"v": max((v["version"] for v in self.versions), default=0)}]
        if "event IN ('approved', 'applied', 'emergency')" in sql:
            act = [e for e in self.events if e["event"] in ps.ACTIVATING]
            return [{"version": act[-1]["version"]}] if act else []
        if "FROM policy_versions WHERE version" in sql:
            return [{**v, "created_at": str(v["created_at"])} for v in self.versions if v["version"] == params["v"]]
        if "FROM policy_versions ORDER BY" in sql:
            return [{**v, "created_at": str(v["created_at"])} for v in sorted(self.versions, key=lambda v: -v["version"])]
        if "FROM policy_events" in sql:
            rows = [e for e in self.events if "v" not in params or e["version"] == params["v"]]
            return [{**e, "ts": str(e["ts"])} for e in rows]
        raise AssertionError(sql)


@pytest.fixture()
def store(client, monkeypatch):  # noqa: F811
    monkeypatch.setenv("TELVEGUARD_ADMIN_TOKEN", ADMIN)
    ch = MemoryClickHouse()
    rt = client.app.state.policy_runtime
    old = (rt.store, rt.version, rt.content, client.app.state.policy)
    rt.store = ps.PolicyStore(ch, ps.Lock())
    yield ch
    rt.store, rt.version, rt.content, client.app.state.policy = old


def as_(name):
    return {**AUTH, "x-telveguard-actor": name}



def draft(rt_content: str) -> str:
    """Yayındaki kurallara: finans ekibi dış modele hiç kişisel veri göndermesin."""
    return rt_content.replace("rules:\n", """rules:
  - name: finans-dis-model-engel
    when: { teams: [finans], destination: external, entity_in: [TCKN] }
    action: block
    message: "Finans ekibi dış modellere kimlik numarası gönderemez."
""", 1)


def chat(client, team):  # noqa: F811
    return client.post("/v1/chat/completions", headers={"x-telveguard-team": team},
                       json={"model": "gpt-4o", "messages": [{"role": "user", "content": f"TC {make_tckn()}"}]})


def test_initial_content_keeps_comments_and_only_rules(client, store):  # noqa: F811
    r = client.get("/v1/policy/store", headers=as_("ayse")).json()
    assert r["runtime"]["source"] == "ConfigMap" and r["runtime"]["enabled"] and r["versions"] == []
    assert "# Kimlik/finans verisi yurt dışı modele" in r["content"]
    assert "providers" not in r["content"] and "pricing" not in r["content"]
    assert r["actor"] == {"name": "ayse", "via": "static_token"}


def test_four_eyes_flow_and_hot_reload(client, store):  # noqa: F811
    content = client.get("/v1/policy/store", headers=as_("ayse")).json()["content"]
    assert chat(client, "finans").status_code == 200          # bugün: maskelenir

    r = client.post("/v1/policy/versions", headers=as_("ayse"), json={"content": draft(content), "comment": "BDDK denetimi"})
    assert r.status_code == 200 and r.json() == {"version": 1, "status": "pending"}
    assert chat(client, "finans").status_code == 200          # bekleyen sürüm etkilemez

    r = client.post("/v1/policy/versions/1/approve", headers=as_("ayse"), json={})
    assert r.status_code == 403 and "Dört göz" in r.json()["error"]["message"]

    r = client.post("/v1/policy/versions/1/approve", headers=as_("mehmet"), json={"comment": "uygun"})
    assert r.status_code == 200 and r.json()["runtime"]["version"] == 1
    assert chat(client, "finans").status_code == 403          # yeniden başlatmadan yürürlükte
    assert chat(client, "pazarlama").status_code == 200

    v = client.get("/v1/policy/store", headers=as_("ayse")).json()
    assert v["runtime"]["source"] == "sürüm 1" and v["content"] == draft(content)
    assert [(x["version"], x["status"], [e["event"] for e in x["events"]]) for x in v["versions"]] == \
        [(1, "approved", ["created", "approved"])]
    assert [e["actor"] for e in v["versions"][0]["events"]] == ["ayse", "mehmet"]


def test_rollback_to_previous_version(client, store):  # noqa: F811
    content = client.get("/v1/policy/store", headers=as_("ayse")).json()["content"]
    for i, text in enumerate([content.replace("default_action: allow", "default_action: alert"), draft(content)], 1):
        client.post("/v1/policy/versions", headers=as_("ayse"), json={"content": text, "comment": f"değişiklik {i}"})
        client.post(f"/v1/policy/versions/{i}/approve", headers=as_("mehmet"), json={})
    assert chat(client, "finans").status_code == 403
    r = client.post("/v1/policy/versions/1/apply", headers=as_("ayse"), json={"comment": "finans şikayet etti"})
    assert r.status_code == 200 and r.json()["event"] == "applied" and r.json()["runtime"]["version"] == 1
    assert chat(client, "finans").status_code == 200
    assert client.app.state.policy.default_action == "alert"


def test_emergency_by_author_requires_reason(client, store):  # noqa: F811
    content = client.get("/v1/policy/store", headers=as_("ayse")).json()["content"]
    client.post("/v1/policy/versions", headers=as_("ayse"), json={"content": draft(content), "comment": "sızıntı"})
    r = client.post("/v1/policy/versions/1/approve", headers=as_("ayse"), json={"emergency": True, "comment": "kısa"})
    assert r.status_code == 400
    r = client.post("/v1/policy/versions/1/approve", headers=as_("ayse"),
                    json={"emergency": True, "comment": "Finans'tan canlı TCKN sızıntısı, SOME-123"})
    assert r.json()["event"] == "emergency"


def test_reject_and_state_errors(client, store):  # noqa: F811
    content = client.get("/v1/policy/store", headers=as_("ayse")).json()["content"]
    client.post("/v1/policy/versions", headers=as_("ayse"), json={"content": draft(content), "comment": "deneme"})
    assert client.post("/v1/policy/versions/1/apply", headers=as_("mehmet"), json={"comment": "x" * 5}).status_code == 409
    assert client.post("/v1/policy/versions/1/reject", headers=as_("mehmet"), json={"comment": "geniş"}).json()["event"] == "rejected"
    assert client.post("/v1/policy/versions/1/approve", headers=as_("can"), json={}).status_code == 409
    assert client.post("/v1/policy/versions/9/approve", headers=as_("can"), json={}).status_code == 404


def test_invalid_drafts_rejected_with_reason(client, store):  # noqa: F811
    cases = {
        "rules: [\n": "YAML okunamadı",
        "providers: []\n": "ConfigMap",
        "rules:\n  - name: a\n    when: { team: [x] }\n    action: block\n": "bilinmeyen koşul",
        "rules:\n  - name: a\n    action: blok\n": "geçersiz action",
        "rules:\n  - name: a\n    action: block\n  - name: a\n    action: mask\n": "aynı adlı",
    }
    for text, msg in cases.items():
        v = client.post("/v1/policy/validate", headers=AUTH, json={"content": text}).json()
        assert not v["ok"] and msg in v["error"], (text, v)
        r = client.post("/v1/policy/versions", headers=as_("ayse"), json={"content": text, "comment": "deneme"})
        assert r.status_code == 400
    assert store.versions == []


def test_create_requires_actor_comment_and_change(client, store):  # noqa: F811
    content = client.get("/v1/policy/store", headers=AUTH).json()["content"]
    assert client.post("/v1/policy/versions", headers=AUTH, json={"content": draft(content), "comment": "abc"}).json()["error"]["code"] == "actor_required"
    assert client.post("/v1/policy/versions", headers=as_("ayse"), json={"content": draft(content)}).status_code == 400
    r = client.post("/v1/policy/versions", headers=as_("ayse"), json={"content": content + "\n# yorum\n", "comment": "aynı"})
    assert r.json()["error"]["code"] == "unchanged"


def test_store_down_keeps_running_policy(client, store):  # noqa: F811
    store.fail = True
    rt = client.app.state.policy_runtime
    assert __import__("asyncio").run(rt.refresh()) is False and "ulaşılamadı" in rt.last_error
    assert chat(client, "default").status_code == 200
    r = client.get("/v1/policy/store", headers=AUTH).json()
    assert r["versions"] == [] and "ulaşılamadı" in r["error"]


def test_disabled_store_is_read_only(client, monkeypatch):  # noqa: F811
    monkeypatch.setenv("TELVEGUARD_ADMIN_TOKEN", ADMIN)
    r = client.get("/v1/policy/store", headers=AUTH).json()
    assert r["runtime"]["enabled"] is False and "rules:" in r["content"]
    assert client.post("/v1/policy/versions", headers=as_("ayse"), json={"content": "x", "comment": "abc"}).status_code == 404


def test_impact_replays_recorded_contexts(client, monkeypatch):  # noqa: F811
    monkeypatch.setenv("TELVEGUARD_ADMIN_TOKEN", ADMIN)
    rows = [
        {"team": "finans", "teams": ["finans"], "model": "gpt-4o", "destination": "external",
         "entities": ["TCKN"], "score": 0.0, "n": 40, "users": 6},
        {"team": "finans", "teams": ["finans"], "model": "vllm/qwen3", "destination": "internal",
         "entities": ["TCKN"], "score": 0.0, "n": 9, "users": 2},
        {"team": "pazarlama", "teams": ["pazarlama"], "model": "gpt-4o", "destination": "external",
         "entities": ["TCKN"], "score": 0.0, "n": 25, "users": 4},
    ]
    client.app.state.ch = FakeClickHouse({"GROUP BY team, teams, model": rows})
    content = client.get("/v1/policy/store", headers=AUTH).json()["content"]
    r = client.post("/v1/policy/impact", headers=AUTH, json={"content": draft(content), "days": 14})
    assert r.status_code == 200, r.text
    b = r.json()
    assert b["requests"] == 74 and b["changed"] == 40 and b["days"] == 14
    assert b["transitions"] == [{"from": "mask", "to": "block", "requests": 40}]
    assert b["teams"] == [{"team": "finans", "requests": 40}]
    assert b["rules_added"] == [{"rule": "finans-dis-model-engel", "requests": 40}]
    assert b["examples"][0]["users"] == 6 and b["examples"][0]["reason"].startswith("Finans")
    sql, params = client.app.state.ch.calls[0]
    assert "api_format != 'browser'" in sql and params == {"days": 14}


def test_editable_text_falls_back_when_structure_unusual():
    raw = "rules: [{name: a, action: block}]\nproviders: []\n"
    assert ps.editable_text(raw) == "rules: [{name: a, action: block}]\n"
    assert ps.parse(ps.editable_text(BASE), {})[0] == ps.editable_part(__import__("yaml").safe_load(BASE))


def test_rules_diff_for_console(client, store):  # noqa: F811
    content = client.get("/v1/policy/store", headers=AUTH).json()["content"]
    text = draft(content).replace("default_action: allow", "default_action: alert")
    text = text.replace("    when: { injection_score_gte: 0.5 }\n    action: alert", "    when: { injection_score_gte: 0.6 }\n    action: alert")
    c = client.post("/v1/policy/validate", headers=AUTH, json={"content": text}).json()["changes"]
    by = {r["name"]: r for r in c["rules"]}
    assert by["finans-dis-model-engel"]["status"] == "added" and by["finans-dis-model-engel"]["action"] == "block"
    assert by["prompt-injection-alert"]["status"] == "changed"
    assert by["prompt-injection-alert"]["before"]["when"] == {"injection_score_gte": 0.5}
    assert by["kvkk-yurtdisi-maskele"]["status"] == "same" and by["kvkk-yurtdisi-maskele"]["mode"] == "enforce"
    assert c["settings"]["default_action"] == {"before": "allow", "after": "alert"}
    assert c["counts"] == {"added": 1, "changed": 1, "removed": 0}
    removed = ps.rules_diff({"rules": [{"name": "a", "action": "block"}]}, {"rules": []})
    assert removed["rules"][0]["status"] == "removed"
