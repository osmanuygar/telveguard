"""Onaylanan politika sürümünü Bitbucket Data Center'a yansıtma."""
import json
import time
from email.parser import BytesParser
from email.policy import HTTP
from urllib.parse import parse_qs, unquote, urlsplit

import httpx
import pytest
import yaml

from app import policy_git as pg
from app import policy_store as ps
from tests.test_gateway import client  # noqa: F401  (fixture)
from tests.test_policy_store import AUTH, as_, draft, store  # noqa: F401  (fixture)

BASE = "/rest/api/1.0/projects/SEC/repos/telveguard-config"


class FakeBitbucket:
    """Bitbucket DC'nin kullandığımız uçları: depo, dallar, commit geçmişi, dosya düzenleme, PR."""

    def __init__(self, path="policies/policy.yaml"):
        self.path = path
        self.branches = {"main": {path: ("c0", "eski: içerik\n")}}   # dal -> dosya -> (commit, içerik)
        self.commits, self.prs, self.down, self.token = [], [], False, "tg-token"

    def __call__(self, req: httpx.Request) -> httpx.Response:
        if self.down:
            raise httpx.ConnectError("bağlantı reddedildi")
        if req.headers.get("authorization") != f"Bearer {self.token}":
            return httpx.Response(401, json={"errors": [{"message": "Authentication failed"}]})
        url = urlsplit(str(req.url))
        path, q = unquote(url.path), {k: v[0] for k, v in parse_qs(url.query).items()}
        assert path.startswith(BASE), path
        path = path[len(BASE):]
        if req.method == "GET" and path == "":
            return httpx.Response(200, json={"name": "telveguard-config", "slug": "telveguard-config"})
        if req.method == "GET" and path == "/branches":
            return httpx.Response(200, json={"values": [{"displayId": b} for b in self.branches if q["filterText"] in b]})
        if req.method == "GET" and path == "/commits":
            branch = q["until"].removeprefix("refs/heads/")
            if branch not in self.branches:
                return httpx.Response(404, json={"errors": [{"message": "no branch"}]})
            f = self.branches[branch].get(q["path"])
            return httpx.Response(200, json={"values": [{"id": f[0]}] if f else []})
        if req.method == "PUT" and path == f"/browse/{self.path}":
            msg = BytesParser(policy=HTTP).parsebytes(
                b"content-type: " + req.headers["content-type"].encode() + b"\r\n\r\n" + req.read())
            form = {p.get_param("name", header="content-disposition"): p.get_payload(decode=True) for p in msg.iter_parts()}
            branch = form["branch"].decode()
            if branch not in self.branches:
                self.branches[branch] = dict(self.branches[form["sourceBranch"].decode()])
            current = self.branches[branch].get(self.path)
            if current and (form.get("sourceCommitId") or b"").decode() != current[0]:
                return httpx.Response(409, json={"errors": [{"message": "file was modified"}]})
            commit = f"c{len(self.commits) + 1}"
            self.commits.append({"id": commit, "branch": branch, "message": form["message"].decode(),
                                 "content": form["content"].decode()})
            self.branches[branch][self.path] = (commit, form["content"].decode())
            return httpx.Response(200, json={"id": commit})
        if req.method == "POST" and path == "/pull-requests":
            body = json.loads(req.content)
            self.prs.append(body)
            return httpx.Response(201, json={"id": len(self.prs), "links": {"self": [
                {"href": f"https://bb.example/projects/SEC/repos/telveguard-config/pull-requests/{len(self.prs)}"}]}})
        return httpx.Response(404, json={"errors": [{"message": f"{req.method} {path}"}]})


def config(**kw):
    return pg.GitConfig(**{"url": "https://bb.example", "project": "SEC", "repo": "telveguard-config",
                           "token": "tg-token", **kw})


@pytest.fixture()
def bb(client, store):  # noqa: F811
    fake = FakeBitbucket()

    def install(**kw):
        cfg = config(**kw)
        mirror = pg.Mirror(cfg, pg.BitbucketDC(cfg, transport=httpx.MockTransport(fake)))
        mirror.RETRIES = (0, 0)
        client.app.state.policy_git = mirror
        return mirror
    install()
    yield fake, install
    client.app.state.policy_git = None


def submit(client, text, comment="BDDK bulgusu"):  # noqa: F811
    return client.post("/v1/policy/versions", headers=as_("ayse"), json={"content": text, "comment": comment}).json()["version"]


def events(client, version):  # noqa: F811
    """Arka plandaki yazma bitene kadar (en fazla 3 sn) sürümün olayları."""
    for _ in range(60):
        evs = [e["event"] for e in client.get(f"/v1/policy/versions/{version}", headers=AUTH).json()["events"]]
        if any(e.startswith("mirror") for e in evs):
            return evs
        time.sleep(0.05)
    return evs


def current(client):  # noqa: F811
    return client.get("/v1/policy/store", headers=AUTH).json()["content"]


def test_approved_version_committed_with_full_policy_and_audit_message(client, bb):  # noqa: F811
    fake, _ = bb
    v = submit(client, draft(current(client)), "BDDK bulgusu: finans TCKN engeli (SOME-1182)")
    r = client.post(f"/v1/policy/versions/{v}/approve", headers=as_("mehmet"), json={"comment": "etki uygun"}).json()
    assert r["git"] == {"status": "pending"}
    assert events(client, v) == ["created", "approved", "mirrored"]
    commit, = fake.commits
    assert commit["branch"] == "main"
    msg = commit["message"]
    assert msg.startswith("Telveguard politika sürüm 1: BDDK bulgusu: finans TCKN engeli (SOME-1182)")
    assert "Yazan: ayse" in msg and "Yayına alan: mehmet (beyan)" in msg and "Not: etki uygun" in msg
    assert "Telveguard-Policy-Version: 1" in msg
    # Dağıtılabilir tam politika: ConfigMap'teki diğer bölümler de var, kurallar sürümden
    stored = yaml.safe_load(commit["content"])
    base = yaml.safe_load(open("policies/default.yaml", encoding="utf-8"))
    assert stored["rules"][0]["name"] == "finans-dis-model-engel"
    assert {k: v for k, v in stored.items() if k not in ps.EDITABLE_KEYS} == \
        {k: v for k, v in base.items() if k not in ps.EDITABLE_KEYS}
    ev = client.get(f"/v1/policy/versions/{v}", headers=AUTH).json()["events"][-1]
    assert ev["comment"] == "https://bb.example/projects/SEC/repos/telveguard-config/commits/c1"


def test_existing_file_updated_with_its_last_commit(client, bb):  # noqa: F811
    fake, _ = bb
    text = draft(current(client))
    for i, t in enumerate([text, text.replace("default_action: allow", "default_action: alert")], 1):
        submit(client, t, f"değişiklik {i}")
        client.post(f"/v1/policy/versions/{i}/approve", headers=as_("mehmet"), json={})
        events(client, i)
    assert [c["id"] for c in fake.commits] == ["c1", "c2"]
    assert yaml.safe_load(fake.branches["main"]["policies/policy.yaml"][1])["default_action"] == "alert"


def test_rules_only_content(client, bb):  # noqa: F811
    fake, install = bb
    install(content="rules")
    text = draft(current(client))
    v = submit(client, text)
    client.post(f"/v1/policy/versions/{v}/approve", headers=as_("mehmet"), json={})
    events(client, v)
    assert fake.commits[0]["content"] == text


def test_pull_request_mode_for_protected_branch(client, bb):  # noqa: F811
    fake, install = bb
    install(mode="pull_request", reviewers=["guvenlik.lead", "uyum"])
    v = submit(client, draft(current(client)))
    client.post(f"/v1/policy/versions/{v}/approve", headers=as_("mehmet"), json={})
    assert events(client, v)[-1] == "mirrored"
    assert fake.commits[0]["branch"] == "telveguard/politika-v1"
    assert fake.branches["main"]["policies/policy.yaml"][0] == "c0"   # ana dal PR ile değişir
    pr, = fake.prs
    assert pr["fromRef"]["id"] == "refs/heads/telveguard/politika-v1" and pr["toRef"]["id"] == "refs/heads/main"
    assert pr["reviewers"] == [{"user": {"name": "guvenlik.lead"}}, {"user": {"name": "uyum"}}]
    ev = client.get(f"/v1/policy/versions/{v}", headers=AUTH).json()["events"][-1]
    assert ev["comment"].endswith("/pull-requests/1")


def test_strict_mode_blocks_publish_when_git_unreachable(client, bb):  # noqa: F811
    fake, install = bb
    install(strict=True)
    fake.down = True
    v = submit(client, draft(current(client)))
    r = client.post(f"/v1/policy/versions/{v}/approve", headers=as_("mehmet"), json={})
    assert r.status_code == 502 and "yayına alınmadı" in r.json()["error"]["message"]
    s = client.get("/v1/policy/store", headers=AUTH).json()
    assert s["runtime"]["version"] is None and s["versions"][0]["status"] == "pending"
    fake.down = False
    r = client.post(f"/v1/policy/versions/{v}/approve", headers=as_("mehmet"), json={}).json()
    assert r["git"]["status"] == "mirrored" and r["runtime"]["version"] == v
    assert [e["event"] for e in client.get(f"/v1/policy/versions/{v}", headers=AUTH).json()["events"]] == \
        ["created", "approved", "mirrored"]


def test_non_strict_failure_recorded_and_retry_from_console(client, bb):  # noqa: F811
    fake, _ = bb
    fake.down = True
    v = submit(client, draft(current(client)))
    r = client.post(f"/v1/policy/versions/{v}/approve", headers=as_("mehmet"), json={})
    assert r.status_code == 200 and r.json()["runtime"]["version"] == v   # yayın Git'i beklemez
    assert events(client, v)[-1] == "mirror_failed"
    fake.down = False
    r = client.post(f"/v1/policy/versions/{v}/mirror", headers=as_("mehmet"), json={})
    assert r.status_code == 200 and r.json()["git"]["commit"] == "c1"
    assert "Yayına alan: mehmet" in fake.commits[0]["message"]


def test_older_version_never_overwrites_newer_in_repo(client, bb):  # noqa: F811
    fake, _ = bb
    text = draft(current(client))
    for i, t in enumerate([text, text.replace("default_action: allow", "default_action: alert")], 1):
        submit(client, t, f"değişiklik {i}")
    fake.down = True
    client.post("/v1/policy/versions/1/approve", headers=as_("mehmet"), json={})
    assert events(client, 1)[-1] == "mirror_failed"
    fake.down = False
    client.post("/v1/policy/versions/2/approve", headers=as_("mehmet"), json={})
    events(client, 2)
    r = client.post("/v1/policy/versions/1/mirror", headers=as_("mehmet"), json={})
    assert r.status_code == 409
    assert [c["id"] for c in fake.commits] == ["c1"] and "default_action: alert" in fake.commits[0]["content"]


def test_rejected_version_not_mirrored(client, bb):  # noqa: F811
    fake, _ = bb
    v = submit(client, draft(current(client)))
    assert client.post(f"/v1/policy/versions/{v}/reject", headers=as_("mehmet"), json={"comment": "geniş"}).json()["git"] is None
    time.sleep(0.1)
    assert fake.commits == []


def test_connection_check(client, bb):  # noqa: F811
    fake, install = bb
    r = client.get("/v1/policy/git", headers=AUTH).json()
    assert r["enabled"] and r["check"] == {"ok": True, "repository": "telveguard-config", "branch": "main",
                                           "file_exists": True, "last_commit": "c0"}
    assert "token" not in json.dumps(r) and r["browse_url"].startswith("https://bb.example/projects/SEC/repos/telveguard-config/browse/")
    install(branch="release")
    assert "dalı bulunamadı" in client.get("/v1/policy/git", headers=AUTH).json()["check"]["error"]
    fake.token = "baska"
    install()
    assert "yazma yetkisi" in client.get("/v1/policy/git", headers=AUTH).json()["check"]["error"]


def test_config_from_env(monkeypatch):
    assert pg.GitConfig.from_env() is None
    for k, v in {"POLICY_GIT_PROVIDER": "bitbucket-dc", "POLICY_GIT_URL": "https://bb.sirket.local/bitbucket/",
                 "POLICY_GIT_PROJECT": "SEC", "POLICY_GIT_REPO": "tg", "POLICY_GIT_TOKEN": "t",
                 "POLICY_GIT_MODE": "pull_request", "POLICY_GIT_PR_REVIEWERS": "a, b"}.items():
        monkeypatch.setenv(k, v)
    cfg = pg.GitConfig.from_env()
    assert cfg.url == "https://bb.sirket.local/bitbucket" and cfg.reviewers == ["a", "b"] and not cfg.strict
    monkeypatch.setenv("POLICY_GIT_MESSAGE", "Sürüm {surum}")
    monkeypatch.setenv("POLICY_GIT_MODE", "push")
    monkeypatch.delenv("POLICY_GIT_TOKEN")
    with pytest.raises(RuntimeError) as e:
        pg.GitConfig.from_env()
    assert all(s in str(e.value) for s in ("POLICY_GIT_MODE", "POLICY_GIT_TOKEN", "POLICY_GIT_MESSAGE"))
    monkeypatch.setenv("POLICY_GIT_PROVIDER", "gitlab")
    with pytest.raises(RuntimeError, match="desteklenmiyor"):
        pg.GitConfig.from_env()


def test_custom_message_template():
    cfg = config(message="[{version}] {comment} ({actor}{actor_note})")
    assert cfg.render_message({"version": 4, "event": "applied", "author": "a", "actor": "b",
                               "actor_via": "static_token", "comment": "geri al\nikinci satır", "note": ""}) == \
        "[4] geri al (b (beyan))"


def test_personal_repo_paths():
    cfg = config(project="~ayse")
    assert cfg.describe()["browse_url"].startswith("https://bb.example/users/ayse/repos/telveguard-config/browse/")
    assert str(pg.BitbucketDC(cfg).http.base_url) == "https://bb.example/rest/api/1.0/users/ayse/repos/telveguard-config/"


def test_full_content_carries_routing_section():
    """Konsolda düzenlenen yönlendirme (routing) depoya yazılan tam politikada yer alır; diğer
    bölümler (sağlayıcılar, sözlük, fiyatlar) ve yorumları olduğu gibi kalır."""
    from telveguard_core.policy import PolicyEngine
    base = open("policies/default.yaml", encoding="utf-8").read()
    content = ps.editable_text(base).replace("rules:\n", (
        "routing:\n  - name: kimlik-kurum-ici\n    when: { destination: external, entity_in: [TCKN] }\n"
        "    to: vllm/qwen3\nrules:\n"), 1)
    text = ps.with_rules(base, content)
    cfg = yaml.safe_load(text)
    assert cfg["routing"] == [{"name": "kimlik-kurum-ici", "when": {"destination": "external", "entity_in": ["TCKN"]},
                               "to": "vllm/qwen3"}]
    assert cfg["pricing"] == yaml.safe_load(base)["pricing"] and "# Kurumsal sözlük" in text
    assert PolicyEngine(config=cfg).routing[0]["to"] == "vllm/qwen3"
