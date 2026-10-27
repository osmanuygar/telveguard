"""
Onaylanan politika sürümünü Git'e yansıtma (Bitbucket Data Center).

Konsolda yayına alınan her sürüm (onay, acil yayın, geri alma) kurumun Git deposuna da yazılır:
denetçi değişikliği alışık olduğu yerde, kim yazdı / kim onayladı / gerekçe commit mesajında
görür; ConfigMap'i depodan dağıtan (GitOps) kurulumda depo ile canlı politika ayrışmaz.

Yapılandırma (hepsi ortam değişkeni; Helm policy.git.*):
  POLICY_GIT_PROVIDER     bitbucket-dc (boşsa kapalı)
  POLICY_GIT_URL          https://bitbucket.sirket.local (bağlam yolu varsa dahil: .../bitbucket)
  POLICY_GIT_WEB_URL      konsoldaki bağlantılar için tarayıcı adresi (API adresinden farklıysa)
  POLICY_GIT_PROJECT      proje anahtarı (ör. SEC); kişisel depo için ~kullanici
  POLICY_GIT_REPO         depo adı (slug)
  POLICY_GIT_BRANCH       hedef dal (main)
  POLICY_GIT_PATH         dosya yolu (policies/policy.yaml)
  POLICY_GIT_MODE         commit (doğrudan dala) | pull_request (dal + PR; dal korumalıysa)
  POLICY_GIT_PR_REVIEWERS PR gözden geçirenleri (kullanıcı adları, virgülle)
  POLICY_GIT_CONTENT      full (ConfigMap dosyası + kurallar: dağıtılabilir) | rules (yalnızca kurallar)
  POLICY_GIT_STRICT       1: Git'e yazılamazsa yayına alma reddedilir (değişiklik kaydı zorunlu)
  POLICY_GIT_MESSAGE      commit mesajı şablonu ({version} {event} {author} {actor} {comment} ...)
  POLICY_GIT_TOKEN        HTTP erişim token'ı (proje / depo token'ı, yazma yetkili) — Secret'tan
  POLICY_GIT_CA_FILE      kurum içi CA (PEM)
  POLICY_GIT_ALLOW_HTTP   1: düz http adresine izin (token şifresiz gider; yalnızca yerel test)
  POLICY_GIT_TIMEOUT      saniye (10)

Strict değilse yazma arka planda, birkaç denemeyle yapılır; sonuç sürümün geçmişine
"mirrored" / "mirror_failed" olayı olarak düşer, konsoldan yeniden denenebilir.
"""
import asyncio
import logging
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import quote

import httpx

from .policy_store import StoreError, with_rules

log = logging.getLogger("telveguard.policy_git")

EVENT_TEXT = {"approved": "onaylandı", "emergency": "acil yayına alındı (dört göz atlandı)",
              "applied": "yeniden yayına alındı (geri alma)"}
DEFAULT_MESSAGE = ("Telveguard politika sürüm {version}: {comment}\n\n"
                   "Sürüm {version} {event_text}.\n"
                   "Yazan: {author}\n"
                   "Yayına alan: {actor}{actor_note}\n"
                   "Not: {note}\n\n"
                   "Telveguard-Policy-Version: {version}\n"
                   "Telveguard-Event: {event}")
_SLUG = re.compile(r"^~?[\w.-]{1,128}$")


class GitError(Exception):
    pass


@dataclass
class GitConfig:
    url: str
    project: str
    repo: str
    branch: str = "main"
    path: str = "policies/policy.yaml"
    mode: str = "commit"
    reviewers: List[str] = field(default_factory=list)
    content: str = "full"
    strict: bool = False
    message: str = DEFAULT_MESSAGE
    token: str = field(default="", repr=False)   # loglara / hata çıktısına düşmesin
    allow_http: bool = False
    ca_file: str = ""
    timeout: float = 10.0
    web_url: str = ""

    @classmethod
    def from_env(cls) -> Optional["GitConfig"]:
        provider = os.getenv("POLICY_GIT_PROVIDER", "")
        if not provider:
            return None
        if provider != "bitbucket-dc":
            raise RuntimeError(f"POLICY_GIT_PROVIDER '{provider}' desteklenmiyor (bitbucket-dc)")
        e = os.getenv
        cfg = cls(url=e("POLICY_GIT_URL", "").rstrip("/"), project=e("POLICY_GIT_PROJECT", ""),
                  web_url=e("POLICY_GIT_WEB_URL", "").rstrip("/"),
                  repo=e("POLICY_GIT_REPO", ""), branch=e("POLICY_GIT_BRANCH", "main"),
                  path=e("POLICY_GIT_PATH", "policies/policy.yaml").strip("/"),
                  mode=e("POLICY_GIT_MODE", "commit"),
                  reviewers=[r.strip() for r in e("POLICY_GIT_PR_REVIEWERS", "").split(",") if r.strip()],
                  content=e("POLICY_GIT_CONTENT", "full"), strict=e("POLICY_GIT_STRICT", "0") == "1",
                  message=e("POLICY_GIT_MESSAGE", "") or DEFAULT_MESSAGE, token=e("POLICY_GIT_TOKEN", ""),
                  allow_http=e("POLICY_GIT_ALLOW_HTTP", "0") == "1",
                  ca_file=e("POLICY_GIT_CA_FILE", ""), timeout=float(e("POLICY_GIT_TIMEOUT", "10")))
        cfg.validate()
        return cfg

    def validate(self) -> None:
        problems = []
        if not (self.url.startswith("https://") or (self.allow_http and self.url.startswith("http://"))):
            # Token her istekte gider: düz http yalnızca bilinçli istisnayla (ör. yerel test)
            problems.append("POLICY_GIT_URL https:// olmalı (düz http için POLICY_GIT_ALLOW_HTTP=1)")
        if not _SLUG.match(self.project) or not _SLUG.match(self.repo):
            problems.append("POLICY_GIT_PROJECT / POLICY_GIT_REPO geçersiz")
        if self.mode not in ("commit", "pull_request"):
            problems.append("POLICY_GIT_MODE commit ya da pull_request olmalı")
        if self.content not in ("full", "rules"):
            problems.append("POLICY_GIT_CONTENT full ya da rules olmalı")
        if not self.path or ".." in self.path.split("/"):
            problems.append("POLICY_GIT_PATH geçersiz")
        if not self.token:
            problems.append("POLICY_GIT_TOKEN tanımlı değil")
        try:
            self.render_message({"version": 1, "event": "approved", "author": "a", "actor": "b",
                                 "actor_via": "oidc", "comment": "c", "note": ""})
        except (KeyError, IndexError, ValueError) as ex:
            problems.append(f"POLICY_GIT_MESSAGE şablonu geçersiz: {ex}")
        if problems:
            raise RuntimeError("Git yansıtma yapılandırması: " + "; ".join(problems))

    def describe(self) -> Dict[str, Any]:
        """Konsol için (token yok)."""
        return {"provider": "bitbucket-dc", "url": self.url, "project": self.project, "repo": self.repo,
                "branch": self.branch, "path": self.path, "mode": self.mode, "reviewers": self.reviewers,
                "content": self.content, "strict": self.strict,
                "browse_url": f"{self.web()}/{self._repo_web()}/browse/{quote(self.path)}?at={quote('refs/heads/' + self.branch, safe='')}"}

    def web(self) -> str:
        return self.web_url or self.url

    def _repo_web(self) -> str:
        if self.project.startswith("~"):
            return f"users/{quote(self.project[1:])}/repos/{quote(self.repo)}"
        return f"projects/{quote(self.project)}/repos/{quote(self.repo)}"

    def render_message(self, f: Dict[str, Any]) -> str:
        def line(v, n):   # tek satır: notla sahte "Telveguard-Policy-Version:" satırı eklenemesin
            return " ".join(str(v or "").split())[:n] or "–"
        values = {**f, "event_text": EVENT_TEXT.get(f["event"], f["event"]),
                  "actor_note": " (beyan)" if f.get("actor_via") == "static_token" else "",
                  "note": line(f.get("note"), 500), "comment": line(f.get("comment"), 200),
                  "author": line(f.get("author"), 100), "actor": line(f.get("actor"), 100)}
        return self.message.format(**values)


class BitbucketDC:
    """Bitbucket Data Center REST API 1.0: dosya düzenleme (browse PUT) ve PR."""

    def __init__(self, cfg: GitConfig, transport: Optional[httpx.AsyncBaseTransport] = None):
        self.cfg = cfg
        self.http = httpx.AsyncClient(
            base_url=f"{cfg.url}/rest/api/1.0/{'users/' + quote(cfg.project[1:]) if cfg.project.startswith('~') else 'projects/' + quote(cfg.project)}/repos/{quote(cfg.repo)}",
            headers={"Authorization": f"Bearer {cfg.token}", "Accept": "application/json",
                     "X-Atlassian-Token": "no-check"},
            verify=cfg.ca_file or True, timeout=cfg.timeout, transport=transport)

    async def close(self):
        await self.http.aclose()

    async def _req(self, method: str, url: str, **kw) -> httpx.Response:
        try:
            r = await self.http.request(method, url, **kw)
        except httpx.HTTPError as e:
            raise GitError(f"Bitbucket'a ulaşılamadı: {type(e).__name__}")
        if r.status_code in (401, 403):
            raise GitError(f"Bitbucket yetki hatası ({r.status_code}): token'ın bu depoya yazma yetkisi var mı?")
        return r

    @staticmethod
    def _error(r: httpx.Response) -> str:
        try:
            errs = r.json().get("errors") or []
            return "; ".join(e.get("message", "") for e in errs) or r.text[:200]
        except ValueError:
            return r.text[:200]

    async def check(self) -> Dict[str, Any]:
        """Bağlantı denemesi: depo, dal ve dosya var mı (yazmadan)."""
        # Depo kaydı: sondaki "/" olmadan (httpx base_url'e ekler)
        r = await self._req("GET", str(self.http.base_url).rstrip("/"))
        if r.status_code == 404:
            raise GitError("Depo bulunamadı (POLICY_GIT_PROJECT / POLICY_GIT_REPO)")
        if r.status_code != 200:
            raise GitError(f"Depo okunamadı ({r.status_code}): {self._error(r)}")
        b = await self._req("GET", "/branches", params={"filterText": self.cfg.branch, "limit": 25})
        branches = [x.get("displayId") for x in (b.json().get("values") or [])] if b.status_code == 200 else []
        if self.cfg.branch not in branches:
            raise GitError(f"'{self.cfg.branch}' dalı bulunamadı")
        last = await self.last_commit(self.cfg.branch)
        return {"repository": r.json().get("name"), "branch": self.cfg.branch, "file_exists": bool(last),
                "last_commit": last}

    async def last_commit(self, branch: str) -> Optional[str]:
        """Dosyayı en son değiştiren commit (düzenleme için sourceCommitId); dosya yoksa None."""
        r = await self._req("GET", "/commits", params={"path": self.cfg.path, "until": f"refs/heads/{branch}", "limit": 1})
        if r.status_code == 404:
            raise GitError(f"'{branch}' dalı bulunamadı")
        if r.status_code != 200:
            raise GitError(f"Commit geçmişi okunamadı ({r.status_code}): {self._error(r)}")
        values = r.json().get("values") or []
        return values[0]["id"] if values else None

    async def _put_file(self, content: str, message: str, branch: str, source_branch: Optional[str] = None) -> str:
        for attempt in range(2):   # 409: arada başka biri değiştirdi -> güncel commit'le bir kez daha
            data = {"branch": branch, "message": message}
            if source_branch:   # dal yok: source_branch'ten açılır
                data["sourceBranch"] = source_branch
            # Var olan dosya düzenlenirken son commit'i verilmeli (yoksa yeni dosya sayılır, reddedilir)
            last = await self.last_commit(source_branch or branch)
            if last:
                data["sourceCommitId"] = last
            r = await self._req("PUT", f"/browse/{quote(self.cfg.path)}", data=data,
                                files={"content": (self.cfg.path.rsplit("/", 1)[-1], content.encode("utf-8"), "text/yaml")})
            if r.status_code in (200, 201):
                return r.json().get("id", "")
            if r.status_code == 409 and attempt == 0 and not source_branch:
                continue
            msg = self._error(r)
            if "identical" in msg.lower() or "same as" in msg.lower():
                return ""   # depodaki dosya zaten bu içerikte
            raise GitError(f"Dosya yazılamadı ({r.status_code}): {msg}")
        raise GitError("Dosya yazılamadı: depo eşzamanlı değişiyor")

    async def publish(self, version: int, content: str, message: str, title: str) -> Dict[str, Any]:
        cfg = self.cfg
        if cfg.mode == "commit":
            commit = await self._put_file(content, message, cfg.branch)
            return {"commit": commit, "url": f"{cfg.web()}/{cfg._repo_web()}/commits/{commit}" if commit else cfg.describe()["browse_url"]}
        branch = f"telveguard/politika-v{version}"
        exists = await self._req("GET", "/branches", params={"filterText": branch, "limit": 5})
        on_branch = exists.status_code == 200 and any(x.get("displayId") == branch for x in exists.json().get("values") or [])
        commit = await self._put_file(content, message, branch, None if on_branch else cfg.branch)
        repo = {"slug": cfg.repo, "project": {"key": cfg.project}}
        r = await self._req("POST", "/pull-requests", json={
            "title": title, "description": message,
            "fromRef": {"id": f"refs/heads/{branch}", "repository": repo},
            "toRef": {"id": f"refs/heads/{cfg.branch}", "repository": repo},
            "reviewers": [{"user": {"name": n}} for n in cfg.reviewers]})
        if r.status_code in (200, 201):
            pr = r.json()
            return {"commit": commit, "pull_request": pr.get("id"),
                    "url": ((pr.get("links") or {}).get("self") or [{}])[0].get("href", "")}
        if r.status_code == 409:   # bu daldan açık PR zaten var (yeniden deneme)
            return {"commit": commit, "pull_request": None, "url": cfg.describe()["browse_url"],
                    "note": "Bu dal için açık bir PR zaten var"}
        raise GitError(f"PR açılamadı ({r.status_code}): {self._error(r)}")


class Mirror:
    """Sürümü Git'e yazar; sonucu politika olaylarına işler (mirrored / mirror_failed)."""

    RETRIES = (2, 10, 30)

    def __init__(self, cfg: GitConfig, client: Optional[BitbucketDC] = None):
        self.cfg = cfg
        self.client = client or BitbucketDC(cfg)
        self._tasks: set = set()

    def file_content(self, runtime, version_content: str) -> str:
        return version_content if self.cfg.content == "rules" else with_rules(runtime.base_text, version_content)

    async def publish(self, runtime, version: Dict[str, Any], event: str, actor: str, via: str, note: str) -> Dict[str, Any]:
        fields = {"version": version["version"], "event": event, "author": version["author"], "actor": actor,
                  "actor_via": via, "comment": version.get("comment", ""), "note": note}
        message = self.cfg.render_message(fields)
        title = f"Telveguard politika sürüm {version['version']}: {' '.join((version.get('comment') or '').split())[:80]}".rstrip(": ")
        return await self.client.publish(version["version"], self.file_content(runtime, version["content"]), message, title)

    async def record(self, store, version: int, result: Optional[Dict[str, Any]], error: str = "") -> None:
        if result is not None:
            ref = result.get("url") or result.get("commit") or ""
            await store.event(version, "mirrored", "telveguard", "system", ref)
        else:
            await store.event(version, "mirror_failed", "telveguard", "system", error[:500])

    def schedule(self, runtime, store, version: Dict[str, Any], event: str, actor: str, via: str, note: str) -> None:
        """Arka planda, birkaç denemeyle (strict değilse)."""
        async def run():
            error = ""
            for delay in (0,) + self.RETRIES:
                await asyncio.sleep(delay)
                try:
                    # Bu arada daha yeni bir sürüm yayına girdiyse eskisi depoya yazılmasın
                    active = await store.active()
                    if active and active["version"] != version["version"]:
                        await store.event(version["version"], "mirror_skipped", "telveguard", "system",
                                          f"Sürüm {active['version']} yayına girdi; depoya o yazılır")
                        return
                    result = await self.publish(runtime, version, event, actor, via, note)
                    await self.record(store, version["version"], result)
                    return
                except (GitError, StoreError) as e:
                    error = str(e)
                    log.warning("politika Git'e yazılamadı (sürüm %s): %s", version["version"], error)
                except Exception as e:   # noqa: BLE001  arka plan görevi ölmesin
                    error = f"{type(e).__name__}: {e}"
                    log.exception("politika Git yansıtma hatası")
            try:
                await self.record(store, version["version"], None, error)
            except Exception:   # noqa: BLE001
                log.exception("mirror_failed kaydedilemedi")
        task = asyncio.create_task(run())
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def close(self):
        for t in list(self._tasks):
            t.cancel()
        await self.client.close()
