"""Model izin listesi: model_in / model_not_in ve envanter beyanı (declared) koşulları."""
import pytest

from app import compliance
from telveguard_core.policy import Context, PolicyEngine
from tests.test_gateway import client  # noqa: F401  (fixture)
from tests.test_policy_monitor import ADMIN, simulate, write_policy

RULES = [
    {"name": "stajyer-sadece-kurum-ici", "when": {"teams": ["stajyer"], "model_not_in": ["vllm/*", "qwen*"]},
     "action": "block", "message": "Ekibiniz yalnızca kurum içi modelleri kullanabilir."},
    {"name": "pahali-model-uyar", "when": {"model_in": ["o3*", "claude-opus-*"]}, "action": "alert"},
    {"name": "beyansiz-engel", "when": {"declared": False}, "action": "block"},
]

INV = {"systems": [{"id": "kod", "name": "Kod asistanı", "owner_team": ["yazilim", "ar-ge"],
                    "models": ["claude-*", "gpt-*"], "use_case": "code_assistant", "purpose": "Yazılım"}]}


def ctx(model, team="yazilim", declared=None, teams=()):
    return Context(team, model, "external", set(), 0.0, frozenset(teams), declared)


@pytest.fixture()
def policy(tmp_path):
    return PolicyEngine(write_policy(tmp_path, {"rules": RULES}))


def test_model_not_in_blocks_team_outside_allowlist(policy):
    d = policy.evaluate(ctx("gpt-4o", team="stajyer"))
    assert d.action == "block" and d.rules == ["stajyer-sadece-kurum-ici"]
    assert d.reason == "Ekibiniz yalnızca kurum içi modelleri kullanabilir."
    assert policy.evaluate(ctx("vllm/qwen3", team="stajyer")).action == "allow"
    assert policy.evaluate(ctx("gpt-4o", team="analitik")).action == "allow"


def test_model_in_matches_wildcards(policy):
    assert policy.evaluate(ctx("claude-opus-4")).rules == ["pahali-model-uyar"]
    assert policy.evaluate(ctx("o3-mini")).action == "alert"
    assert policy.evaluate(ctx("claude-sonnet-4")).rules == []


def test_empty_model_is_outside_every_allowlist(policy):
    assert policy.evaluate(ctx("", team="stajyer")).action == "block"


def test_declared_condition(policy):
    assert policy.evaluate(ctx("gemini-2.5-pro", declared=False)).rules == ["beyansiz-engel"]
    assert policy.evaluate(ctx("gpt-4o", declared=True)).action == "allow"
    # Envanter yok: koşul eşleşmez, tüm trafik engellenmez
    assert policy.evaluate(ctx("gemini-2.5-pro", declared=None)).action == "allow"


def test_output_rules_see_model_and_declared(tmp_path):
    out = [{"name": "opus-sir", "when": {"model_in": ["claude-opus-*"], "entity_in": ["SECRET_*"]},
            "action": "block"}]
    policy = PolicyEngine(write_policy(tmp_path, {"output_rules": out}))
    assert policy.evaluate_output(ctx("claude-opus-4"), {"SECRET_AWS_KEY"}).action == "block"
    assert policy.evaluate_output(ctx("gpt-4o"), {"SECRET_AWS_KEY"}).action == "allow"


@pytest.mark.parametrize("when", [
    {"model_notin": ["gpt-*"]},          # yazım hatası: sessizce yok sayılsa kural herkesi engellerdi
    {"model_in": "gpt-*"},               # liste değil
    {"model_not_in": []},
    {"model_in": [""]},
    {"declared": "hayır"},
])
def test_invalid_when_rejected_at_load(tmp_path, when):
    with pytest.raises(ValueError):
        PolicyEngine(write_policy(tmp_path, {"rules": [{"name": "x", "when": when, "action": "block"}]}))


def test_shipped_policy_still_valid():
    PolicyEngine("policies/default.yaml")


# ---------------- envanter ----------------

def test_is_declared_any_team_matches():
    assert compliance.is_declared(INV, {"ar-ge"}, "claude-sonnet-4") is True
    assert compliance.is_declared(INV, {"stajyer", "yazilim"}, "gpt-4o") is True
    assert compliance.is_declared(INV, {"yazilim"}, "gemini-2.5-pro") is False
    assert compliance.is_declared(INV, {"analitik"}, "gpt-4o") is False
    assert compliance.is_declared({"systems": []}, {"yazilim"}, "gpt-4o") is None


# ---------------- gateway ----------------

def test_gateway_blocks_undeclared_model(client, tmp_path):  # noqa: F811
    client.app.state.policy = PolicyEngine(write_policy(tmp_path, {"rules": RULES}))
    client.app.state.inventory = INV
    events = []

    async def capture(ev):
        events.append(ev)
    client.app.state.audit.emit = capture

    def post(model, team):
        return client.post("/v1/chat/completions", headers={"x-telveguard-team": team},
                           json={"model": model, "messages": [{"role": "user", "content": "merhaba"}]})

    assert post("gpt-4o", "yazilim").status_code == 200
    r = post("gemini-2.5-pro", "yazilim")
    assert r.status_code == 403 and "beyansiz-engel" in r.text
    assert events[-1]["action"] == "block" and events[-1]["rules"] == ["beyansiz-engel"]
    r = post("gpt-4o", "stajyer")
    assert r.status_code == 403 and "yalnızca kurum içi" in r.text


def test_simulate_shows_declared(client, tmp_path, monkeypatch):  # noqa: F811
    monkeypatch.setenv("TELVEGUARD_ADMIN_TOKEN", ADMIN)
    client.app.state.policy = PolicyEngine(write_policy(tmp_path, {"rules": RULES}))
    client.app.state.inventory = INV
    body = simulate(client, "merhaba", model="gemini-2.5-pro", team="yazilim").json()
    assert body["declared"] is False and body["decision"]["action"] == "block"
    assert simulate(client, "merhaba", model="gpt-4o", team="yazilim").json()["declared"] is True
