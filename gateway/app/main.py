"""
Telveguard Gateway - LLM güvenlik proxy'si (OpenAI ve Anthropic uyumlu).

Akış:  istemci -> [kimlik] -> [PII + sır + injection tarama] -> [politika] ->
       (engelle | maskele | geçir) -> upstream LLM -> [çıktı koruması + maskeyi geri aç]
       -> istemci ;  her istek -> audit olayı (Kafka)

Desteklenen biçimler (formats.py): OpenAI /v1/chat/completions ve /v1/responses,
Anthropic /v1/messages (Claude Code dahil). İstemciler yalnızca taban adresi değiştirir:
    OpenAI(base_url="http://telveguard:8080/v1", ...)
    Anthropic(base_url="http://telveguard:8080", ...)   /  ANTHROPIC_BASE_URL=http://telveguard:8080
"""
import asyncio
import copy
import dataclasses
import hmac
import logging
import os
import re
import sys
import time
import uuid
from collections import Counter
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import date
from typing import Any, Dict, List, Optional, Set

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse

from . import agent as agent_mod
from . import attachments as attachments_mod
from . import compliance
from . import dictionary as dictionary_mod
from . import exemptions as exemptions_mod
from . import guardrail as guardrail_mod
from . import icap as icap_mod
from . import shadow_ai
from . import streaming
from . import subjects as subjects_mod
from . import metrics
from . import notify as notify_mod
from . import policy_git as policy_git_mod
from . import policy_store as policy_store_mod
from . import poc_report as poc_report_mod
from . import providers as providers_mod
from . import risk as risk_mod
from . import xray as xray_mod
from .audit import AuditSink
from .auth import AuthError, Authenticator, Identity
from .quota import QuotaBackendError, QuotaManager
from .formats import CHAT, EMBEDDINGS, FORMATS, MESSAGES, RESPONSES, UPSTREAM_KEYS, UPSTREAMS, ApiFormat, Part  # noqa: F401
from telveguard_core.detectors.injection import InjectionDetector, InjectionResult
from telveguard_core.pii.engine import KnownValues, TrPiiEngine, is_placeholder
from telveguard_core.policy import Context, Decision, PolicyEngine


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.pii = TrPiiEngine(enable_ner=os.getenv("ENABLE_TR_NER") == "1")
    app.state.injection = InjectionDetector()
    policy_path = os.getenv("POLICY_PATH", "policies/default.yaml")
    app.state.policy = PolicyEngine(policy_path)
    app.state.providers = providers_mod.load(policy_path)
    app.state.attachments = attachments_mod.load(policy_path)
    # Kurumsal sözlük (proje adları, müşteri unvanları ...): PII motoruna tanıyıcı olarak eklenir
    app.state.dictionary = dictionary_mod.load(policy_path)
    app.state.dictionary.install(app.state.pii)
    # İstisnalar (kurumun kamuya açık IBAN'ı, destek e-postası ...): bulunmamış sayılır
    app.state.exemptions = exemptions_mod.load(policy_path)
    app.state.exemptions.install(app.state.pii)
    app.state.audit = AuditSink()
    await app.state.audit.start()
    if not hasattr(app.state, "http"):  # testlerde MockTransport enjekte edilebilir
        app.state.http = httpx.AsyncClient(timeout=httpx.Timeout(120, connect=5))
    app.state.notifier = notify_mod.load(policy_path)
    app.state.notifier.start(app.state.http)
    if not hasattr(app.state, "ch"):  # testlerde sahte ClickHouse enjekte edilebilir
        app.state.ch = xray_mod.ClickHouse.from_env(app.state.http)
    app.state.auth = Authenticator.from_env(app.state.http)
    app.state.subjects = subjects_mod.SubjectIndex.from_env()
    app.state.shadow_limiter = shadow_ai.RateLimiter.from_env()
    app.state.quota = QuotaManager.from_env(app.state.policy.quotas)
    # Anlık anomali (politikadaki `anomaly`): sayaç kota ile aynı yerde (REDIS_URL; yoksa worker belleği)
    app.state.anomaly = risk_mod.AnomalyDetector(app.state.quota.backend)
    # Guardrail servisi (LiteLLM, agentgateway): istek ile cevap arasında maske eşleşmesi
    app.state.guardrail_sessions = guardrail_mod.Sessions.from_env()
    # AI sistem beyanları (EU AI Act envanteri); yoksa tüm kullanımlar "beyan edilmemiş"
    app.state.inventory = compliance.load_inventory(os.getenv("INVENTORY_PATH", "policies/inventory.yaml"))
    # Konsoldan politika yönetimi (POLICY_STORE=clickhouse): yayındaki sürüm pod'lara yeniden başlatmadan yayılır
    with open(policy_path, encoding="utf-8") as f:
        app.state.policy_runtime = policy_store_mod.Runtime(
            app.state, f.read(), policy_store_mod.PolicyStore.from_env(app.state.http))
    await app.state.policy_runtime.start(float(os.getenv("POLICY_STORE_POLL_SECONDS", "5")))
    # Onaylanan sürümü Git'e (Bitbucket Data Center) yansıtma; POLICY_GIT_PROVIDER yoksa kapalı
    app.state.policy_git = None
    if git_cfg := policy_git_mod.GitConfig.from_env():
        if not app.state.policy_runtime.store:
            raise RuntimeError("POLICY_GIT_* için POLICY_STORE=clickhouse gerekli (Git'e onaylanan sürüm yazılır)")
        app.state.policy_git = policy_git_mod.Mirror(git_cfg)
    # Ağ tarafı (ICAP): kurum proxy'si masaüstü uygulamalarının AI trafiğini sorar; ICAP_PORT yoksa kapalı
    app.state.icap = None
    if settings := icap_mod.Settings.from_env(app.version):
        app.state.icap = icap_mod.IcapServer(settings, lambda *a: icap_check(app.state, *a))
        await app.state.icap.start()
    yield
    if app.state.icap:
        await app.state.icap.stop()
    await app.state.policy_runtime.stop()
    if app.state.policy_git:
        await app.state.policy_git.close()
    await app.state.notifier.stop()
    await app.state.audit.stop()
    await app.state.http.aclose()


def _setup_logging():
    """telveguard.* logları stdout'a (varsayılan INFO, LOG_LEVEL ile). uvicorn kök logger'a handler koymaz;
    olmasa INFO logları (yönetici erişimi, KVKK başvuru araması, politika sürümleri) hiçbir yere yazılmazdı."""
    root = logging.getLogger("telveguard")
    if root.handlers:
        return
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("%(levelname)s %(name)s %(message)s"))
    root.addHandler(handler)
    root.setLevel(os.getenv("LOG_LEVEL", "INFO").upper())


_setup_logging()
admin_log = logging.getLogger("telveguard.admin")
log = logging.getLogger("telveguard.gateway")
app = FastAPI(title="Telveguard Gateway", version="0.7.1", lifespan=lifespan)

DEFAULT_MAX_REQUEST_BYTES = 32_000_000   # Anthropic API'nin istek sınırı; ekler base64 olarak gövdede


class BodyLimit:
    """İstek gövdesi sınırı (MAX_REQUEST_BYTES): gövde uygulamaya verilmeden önce sayılır, aşan
    istek 413 ile reddedilir. Sınırsız gövde kimliği doğrulanmış tek bir istemcinin belleği
    doldurmasına izin verirdi. Content-Length yoksa (chunked) okunan baytlar sayılır."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["method"] not in ("POST", "PUT", "PATCH"):
            return await self.app(scope, receive, send)
        limit = int(os.getenv("MAX_REQUEST_BYTES", DEFAULT_MAX_REQUEST_BYTES))
        length = dict(scope["headers"]).get(b"content-length", b"")
        if length.isdigit() and int(length) > limit:
            return await self._reject(scope, receive, send, limit)
        messages, size = [], 0
        while True:
            message = await receive()
            messages.append(message)
            if message["type"] != "http.request":
                break
            size += len(message.get("body", b""))
            if size > limit:
                return await self._reject(scope, receive, send, limit)
            if not message.get("more_body"):
                break
        pending = iter(messages)

        async def replay():
            return next(pending, None) or await receive()
        return await self.app(scope, replay, send)

    @staticmethod
    async def _reject(scope, receive, send, limit: int):
        fmt = MESSAGES if scope["path"].startswith("/v1/messages") else CHAT
        resp = fmt.error(413, f"Telveguard: istek gövdesi çok büyük (sınır {limit} bayt).",
                         "request_too_large", "invalid_request_error")
        await resp(scope, receive, send)


app.add_middleware(BodyLimit)


class SecurityHeaders:
    """Tüm cevaplara içerik türü koklama ve referrer kısıtı; HTML sayfalarına ayrıca CSP ve çerçeve
    yasağı (_html_page)."""

    HEADERS = [(b"x-content-type-options", b"nosniff"), (b"referrer-policy", b"no-referrer")]

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                names = {k.lower() for k, _ in message.get("headers", [])}
                message["headers"] = list(message.get("headers", [])) + [h for h in self.HEADERS if h[0] not in names]
            await send(message)
        return await self.app(scope, receive, send_with_headers)


app.add_middleware(SecurityHeaders)


# ---------------- yardımcılar ----------------

def _openai_error(status: int, message: str, code: str,
                  type_: str = "telveguard_policy_violation") -> JSONResponse:
    return CHAT.error(status, message, code, type_)


def _upstream_error(fmt: ApiFormat, resp: httpx.Response) -> JSONResponse:
    """Upstream hatası JSON ise olduğu gibi (zaten o biçimde); değilse (ör. proxy'nin HTML
    502 sayfası) istemcinin biçiminde hata."""
    try:
        return JSONResponse(status_code=resp.status_code, content=resp.json())
    except ValueError:
        return fmt.error(resp.status_code, f"Upstream hata döndü ({resp.status_code}).",
                         "upstream_error", "upstream_error")


async def _require_admin(request: Request) -> Optional[JSONResponse]:
    err, _ = await _admin(request)
    return err


_ACTOR = re.compile(r"^[\w.@+ -]{2,100}$", re.UNICODE)


async def _admin(request: Request):
    """(hata, (kim, nasıl)). Politika değişikliklerinin kaydı için kişi: OIDC'de token'dan
    (doğrulanmış), statik token'da X-Telveguard-Actor başlığından (beyan)."""
    """Yönetim uçları (simülatör, Röntgen, raporlar) iki yoldan biriyle açılır:
      * OIDC_ADMIN_GROUP (AUTH_MODE=jwt): bu gruptaki kullanıcının kendi JWT'si (önerilen)
      * TELVEGUARD_ADMIN_TOKEN: statik token (ör. otomasyon / geçiş dönemi)
    İkisi de yoksa uçlar kapalıdır: simülatör açık kalırsa saldırgan injection skorunu
    yoklayarak tespiti atlatmayı deneyebilir. Her başarılı erişim kimliğiyle loglanır."""
    expected = os.getenv("TELVEGUARD_ADMIN_TOKEN", "")
    auth = request.app.state.auth
    if not expected and not auth.admin_group:
        return _openai_error(404, "Yönetim uçları kapalı (OIDC_ADMIN_GROUP ya da TELVEGUARD_ADMIN_TOKEN "
                                  "tanımlı değil).", "admin_disabled", "admin_error"), None
    header = request.headers.get("authorization", "")
    given = header[7:].strip() if header.lower().startswith("bearer ") \
        else request.headers.get("x-telveguard-admin-token", "")
    if expected and given and hmac.compare_digest(given.encode(), expected.encode()):
        admin_log.info("admin_access via=static_token path=%s", request.url.path)
        actor = request.headers.get("x-telveguard-actor", "").strip()
        return None, (actor if _ACTOR.match(actor) else "", "static_token")
    if auth.admin_group and given.count(".") == 2:  # JWT biçimi
        try:
            identity = await auth.verify_token(given)
        except AuthError as e:
            return _openai_error(e.status, f"Telveguard: {e.message}", e.reason, "admin_error"), None
        if not auth.is_admin(identity):
            admin_log.warning("admin_denied user=%s path=%s", identity.user, request.url.path)
            return _openai_error(403, f"'{auth.admin_group}' grubunda değilsiniz.", "forbidden", "admin_error"), None
        admin_log.info("admin_access via=oidc user=%s path=%s", identity.user, request.url.path)
        return None, (identity.user, "oidc")
    return _openai_error(401, "Geçersiz yönetici kimliği.", "unauthorized", "admin_error"), None


@dataclass
class Analysis:
    identity: Identity
    fmt: ApiFormat
    model: str
    destination: str
    body: Dict[str, Any]
    parts: List[Part]
    full_text: str                  # injection için taranan roller (kullanıcı + araç sonuçları)
    all_text: str                   # maskelemeden ÖNCEKİ tüm metin (çıktı sızıntısı karşılaştırması)
    entity_counts: Counter          # tüm rollerdeki PII/sır türleri ve adetleri
    injection: InjectionResult
    ctx: Context
    decision: Decision
    provider: Optional[providers_mod.Provider] = None
    provider_error: Optional[str] = None
    scans: List[attachments_mod.Scan] = field(default_factory=list)   # görsel / PDF ekleri
    subject_hashes: List[str] = field(default_factory=list)          # ilgili kişi araması (subjects.py)
    part_findings: List[List[Any]] = field(default_factory=list)     # parça başına bulgular (maskeleme yeniden taramaz)
    routed_from: str = ""                                            # yönlendirildiyse istenen model

    @property
    def user(self) -> str:
        return self.identity.user

    @property
    def team(self) -> str:
        return self.identity.team

    @property
    def entities(self) -> Set[str]:
        return set(self.entity_counts)

    @property
    def messages(self) -> Any:  # geriye uyumluluk (chat)
        return self.body.get("messages", [])


# Bu boyutun üstündeki istekler (bayt) thread'de taranır: tarama CPU'da ~1 ms/KB ve event loop'u
# bloklar (o worker'daki diğer istekler ve akan stream'ler bekler). GIL nedeniyle throughput artmaz;
# event loop GIL'i aralıklarla geri alır, diğer istekler donmaz. Asıl ölçek: worker / pod sayısı.
SCAN_THREAD_MIN_BYTES = int(os.getenv("SCAN_THREAD_MIN_BYTES", "65536"))


async def _scan_analyze(st, body: Dict[str, Any], identity: Identity, fmt: ApiFormat = CHAT,
                        size: int = 0) -> Analysis:
    """Ekleri (görsel / PDF) tarar, sonra metinle birlikte politikadan geçirir."""
    scans = await st.attachments.scan(fmt.request_attachments(body))
    if size >= SCAN_THREAD_MIN_BYTES:
        return await asyncio.to_thread(_analyze, st, body, identity, fmt, scans)
    return _analyze(st, body, identity, fmt, scans)


def _analyze(st, body: Dict[str, Any], identity: Identity, fmt: ApiFormat = CHAT,
             scans: List[attachments_mod.Scan] = (), destination: Optional[str] = None) -> Analysis:
    """Tarama + politika. Gerçek istek, simülatör ve ajan kontrolü aynı yolu kullanır.
    destination: verinin gerçekte gittiği yer modelden çıkarılamıyorsa (ör. Cursor: istek
    önce Cursor'un sunucularına gider) çağıran verir."""
    model = body.get("model", "") if isinstance(body.get("model"), str) else ""
    parts = fmt.request_parts(body)
    # Eklerden okunan metin de taranır: görsele gömülü injection ("visual prompt injection") dahil
    inj_texts = ([p.text for p in parts if p.role in fmt.injection_roles]
                 + [s.text for s in scans if s.text and s.att.role in fmt.injection_roles])
    texts = [p.text for p in parts] + [s.text for s in scans if s.text]
    full_text = "\n".join(inj_texts)
    all_text = "\n".join(texts)
    # Parça parça ve önbellekli: değişmeyen parçalar (önceki turlar, sistem istemi, araç tanımları)
    # yeniden taranmaz. Sonuç tüm metni tek seferde taramakla aynı (sınır pencereleri dahil)
    per_text, findings = st.pii.analyze_parts(texts)
    entity_counts = Counter(f.entity for f in findings)
    injection = st.injection.scan_parts(inj_texts)
    provider, provider_error, destination, ctx, decision = _decide(
        st, identity, fmt, model, set(entity_counts), injection.score, scans, destination)
    return Analysis(identity, fmt, model, destination, body, parts, full_text, all_text,
                    entity_counts, injection, ctx, decision, provider, provider_error, list(scans),
                    st.subjects.event_hashes(all_text, findings), part_findings=per_text[:len(parts)])


def _decide(st, identity: Identity, fmt: ApiFormat, model: str, entities: Set[str], injection_score: float,
            scans: List[attachments_mod.Scan], destination: Optional[str] = None):
    """Taranmış isteğin hedefi ve politika kararı -> (sağlayıcı, sağlayıcı hatası, hedef, bağlam, karar)."""
    # Eşleşen sağlayıcının hedefi önce gelir: veri gerçekte nereye gidiyorsa karar ona göre
    provider, provider_error = st.providers.resolve(model, fmt.name)
    routed = provider or st.providers.first(model)
    destination = destination or (routed.destination if routed else st.policy.destination_of(model))
    teams = frozenset(identity.teams)
    ctx = Context(identity.team, model, destination, entities, injection_score, teams,
                  compliance.is_declared(st.inventory, teams | {identity.team}, model))
    decision = st.policy.evaluate(ctx)
    st.attachments.apply_unscannable(decision, list(scans), destination)
    return provider, provider_error, destination, ctx, decision


ROUTE_MARK = "yonlendirme:"


def _route(st, a: Analysis, headers, kind: Optional[str] = None) -> Analysis:
    """Politikadaki `routing`: eşleşen istek kurum içi modele gider; kurallar yeni hedefe göre
    yeniden değerlendirilir (metin yeniden taranmaz). Hedef kurum içi değilse ya da bu API biçimine
    upstream'i yoksa yönlendirilmez: istek olduğu gibi kurallardan geçer (maskele / engelle korur).
    Kayıtta kural adı "yonlendirme:<ad>" olarak görünür (gözlemdekiler monitored_rules'ta)."""
    rule, monitored = st.policy.route(a.ctx)
    a.decision.monitored_rules += [ROUTE_MARK + n for n in monitored]
    if rule is None:
        return a
    target, kind = rule["to"], kind or a.fmt.name
    if not _routable(st, target, a.fmt, kind, headers):
        log.warning("routing_skipped rule=%s to=%s format=%s", rule["name"], target, kind)
        return a
    provider, provider_error, destination, ctx, decision = _decide(
        st, a.identity, a.fmt, target, a.entities, a.injection.score, a.scans)
    decision.rules.insert(0, ROUTE_MARK + rule["name"])
    decision.monitored_rules = a.decision.monitored_rules + decision.monitored_rules
    a.body["model"] = target
    return dataclasses.replace(a, model=target, destination=destination, ctx=ctx, decision=decision,
                               provider=provider, provider_error=provider_error, routed_from=a.model)


def _routable(st, target: str, fmt: ApiFormat, kind: str, headers) -> bool:
    """Yönlendirme hedefi kullanılabilir mi: kurum içi ve bu API biçimi için upstream'i var."""
    provider, provider_error = st.providers.resolve(target, fmt.name)
    routed = provider or st.providers.first(target)
    if provider_error or (routed.destination if routed else st.policy.destination_of(target)) != "internal":
        return False
    if provider:
        return provider.supports(kind)
    if kind == "count_tokens":
        return MESSAGES.upstream("internal", headers, path="/v1/messages/count_tokens") is not None
    return fmt.upstream("internal", headers) is not None


def _impact_outcome(st, pol: PolicyEngine, ctx: Context, api_format: str):
    """Etki analizi: kayıttaki bağlamın sonucu, yönlendirme dahil -> (sonuç, karar). Sonuç karar
    işlemidir; kurum içine yönlendirilip orada engellenmeyen istek için "route". Yönlendirme yalnızca
    gateway'den geçen biçimlerde olur (hook / ICAP olayları yönlendirilemez)."""
    fmt = FORMATS.get(api_format)
    rule = pol.route(ctx)[0] if fmt else None
    if rule and _routable(st, rule["to"], fmt, fmt.name, {}):
        target = rule["to"]
        d = pol.evaluate(dataclasses.replace(
            ctx, model=target, destination="internal",
            declared=compliance.is_declared(st.inventory, ctx.all_teams, target)))
        d.rules.insert(0, ROUTE_MARK + rule["name"])
        return ("block" if d.action == "block" else "route"), d
    d = pol.evaluate(ctx)
    return d.action, d


def _routed_headers(a: Analysis) -> Dict[str, str]:
    """İstemci cevabı hangi modelin verdiğini bilsin (cevaptaki model adı da değişir)."""
    return {"X-Telveguard-Routed-To": a.model} if a.routed_from else {}


async def _emit(st, ev: dict):
    """Denetim kaydı + (eşleşen kanal varsa) arka planda Slack / Teams / webhook bildirimi."""
    await st.audit.emit(ev)
    st.notifier.submit(ev)
    if st.policy.anomaly:
        for alert in await st.anomaly.observe(st.policy.anomaly, ev):
            st.notifier.submit(alert)      # denetim kaydına yazılmaz (istek sayıları şişmesin)


def _auth_error(e: AuthError, fmt: ApiFormat = CHAT) -> JSONResponse:
    metrics.AUTH_FAILURES.labels(e.reason).inc()
    resp = fmt.error(e.status, f"Telveguard: {e.message}", e.reason, "authentication_error")
    if e.status == 401:
        resp.headers["WWW-Authenticate"] = f'Bearer error="invalid_token", error_description="{e.reason}"'
    return resp


def _find_output_leaks(st, text: str, known: str, vault: Dict[str, str]):
    """Cevaptaki PII / sırlardan GİRDİDE OLMAYANLAR. Kullanıcının kendi verisinin cevapta
    geri gelmesi (iç model, maskesiz) sızıntı değildir; modelin ürettiği yeni değer sızıntıdır."""
    findings = st.pii.analyze(text)
    known_values = KnownValues(vault)   # gerçek değerler ve sahte değerler (masking.style: synthetic)
    leaks = [f for f in findings
             if text[f.start:f.end] not in known and text[f.start:f.end] not in known_values]
    return findings, leaks


def _redact(text: str, leaks, entities: Set[str]) -> str:
    """Sızıntıyı geri çevrilemez biçimde gizle (kullanıcı da görmemeli)."""
    for f in sorted((f for f in leaks if f.entity in entities), key=lambda f: f.start, reverse=True):
        text = text[:f.start] + f"[GİZLENDİ:{f.entity}]" + text[f.end:]
    return text


def _usage_fields(st, fmt: ApiFormat, model: str, resp: Optional[dict]) -> Dict[str, Any]:
    """Röntgen için token + tahmini maliyet. usage yoksa (maskesiz stream, upstream hatası)
    token 0 ve maliyet None yazılır: "bilinmiyor", "bedava" değil."""
    pt, ct, effective_pt, known = fmt.usage(resp)
    return {"prompt_tokens": pt, "completion_tokens": ct, "usage_known": int(known),
            "est_cost_usd": st.policy.estimate_cost_usd(model, effective_pt, ct) if known else None}


def _mask_parts(st, parts: List[Part], decision: Decision, vault: Dict[str, str],
                scans: List[attachments_mod.Scan] = (), part_findings: Optional[List[List[Any]]] = None) -> Optional[str]:
    """Karar maskeleme gerektiriyorsa tüm parçaları (system ve araç argümanları dahil) ve ekleri
    (görsel karartma, PDF -> maskeli metin) yerinde maskeler; denetim için maskeli metni döndürür.
    part_findings: _analyze'ın parça başına bulguları (verilirse parçalar yeniden taranmaz)."""
    if decision.action != "mask" or not decision.mask_entities:
        return None
    if part_findings is None or len(part_findings) != len(parts):
        part_findings = [None] * len(parts)
    for p, found in zip(parts, part_findings):
        p.set(st.pii.mask(p.text, list(decision.mask_entities), vault, findings=found,
                          style=st.policy.mask_style).text)
    notes = st.attachments.mask(st.pii, list(scans), decision.mask_entities, vault, st.policy.mask_style)
    return "\n".join([p.text for p in parts] + notes)


async def _read_body(request: Request, fmt: ApiFormat):
    try:
        body = await request.json()
    except ValueError:
        return None, fmt.error(400, "Geçersiz JSON gövdesi.", "invalid_request", "invalid_request_error")
    if not isinstance(body, dict):
        return None, fmt.error(400, "Gövde bir JSON nesnesi olmalı.", "invalid_request", "invalid_request_error")
    if err := fmt.validate(body):
        return None, fmt.error(400, err, "invalid_request", "invalid_request_error")
    return body, None


# ---------------- endpoint'ler ----------------

@app.get("/healthz")
async def healthz():
    return {"status": "ok"}


@app.get("/metrics", include_in_schema=False)
async def metrics_endpoint(request: Request):
    """METRICS_TOKEN tanımlıysa yalnızca o token'la (Prometheus / ServiceMonitor). Metriklerde kişisel
    veri yoktur ama kural adları, ekip dışı trafik hacmi ve hata oranları kuruma özgüdür."""
    expected = os.getenv("METRICS_TOKEN", "")
    # Token zorunlu (Helm metrics.requireToken) ama Secret'ta yoksa uç açık kalmasın, kapansın
    if not expected and os.getenv("METRICS_REQUIRE_TOKEN") == "1":
        return Response("metrics token tanımlı değil\n", status_code=503, media_type="text/plain")
    if expected:
        header = request.headers.get("authorization", "")
        given = header[7:].strip() if header.lower().startswith("bearer ") else ""
        if not (given and hmac.compare_digest(given.encode(), expected.encode())):
            return Response("unauthorized\n", status_code=401, media_type="text/plain",
                            headers={"WWW-Authenticate": "Bearer"})
    body, content_type = metrics.render()
    return Response(body, media_type=content_type)


@app.post("/v1/chat/completions")
async def chat_completions(request: Request):
    return await _timed(request, CHAT)


@app.post("/v1/responses")
async def responses(request: Request):
    return await _timed(request, RESPONSES)


@app.post("/v1/messages")
async def messages(request: Request):
    return await _timed(request, MESSAGES)


@app.post("/v1/embeddings")
async def embeddings(request: Request):
    return await _timed(request, EMBEDDINGS)


async def _timed(request: Request, fmt: ApiFormat):
    t0 = time.perf_counter()
    request.state.destination = "none"  # kimlik / gövde hatasında (sınırlı etiket)
    try:
        return await _proxy(request, t0, fmt)
    finally:
        metrics.REQUEST_SECONDS.labels(request.state.destination).observe(time.perf_counter() - t0)


async def _proxy(request: Request, t0: float, fmt: ApiFormat):
    st = request.app.state
    # Kimlik gövdeden ÖNCE: doğrulanmamış isteğin gövdesi işlenmez
    try:
        identity = await st.auth.authenticate(request.headers)
    except AuthError as e:
        return _auth_error(e, fmt)
    body, err = await _read_body(request, fmt)
    if err:
        return err

    # 1-2) Tarama + politika
    t_scan = time.perf_counter()
    a = _route(st, await _scan_analyze(st, body, identity, fmt, len(await request.body())), request.headers)
    metrics.SCAN_SECONDS.observe(time.perf_counter() - t_scan)
    model, destination, decision = a.model, a.destination, a.decision
    request.state.destination = destination
    metrics.REQUESTS.labels(decision.action, destination, fmt.name).inc()
    for entity in a.entities:
        metrics.ENTITIES.labels(entity, "input").inc()
    if a.injection.score >= 0.5:
        metrics.INJECTIONS.inc()

    async def audit(masked_prompt=None, upstream_status=None, **extra):
        ev = st.audit.build_event(
            user=a.user, team=a.team, model=model, destination=destination, decision=decision,
            entities=a.entities, injection=a.injection,
            prompt=a.full_text if fmt.injection_roles else a.all_text,   # embeddings: tüm girdi
            masked_prompt=masked_prompt, latency_ms=(time.perf_counter() - t0) * 1000,
            upstream_status=upstream_status,
        )
        ev.update(teams=a.identity.teams, auth_source=a.identity.source, api_format=fmt.name,
                  subject_hashes=a.subject_hashes)
        ev.update(extra)
        await _emit(st, ev)

    if decision.action == "block":
        # Upstream'e hiçbir şey gitmedi: maliyet kesin olarak 0
        await audit(prompt_tokens=0, completion_tokens=0, usage_known=1, est_cost_usd=0.0)
        return fmt.error(403, f"Telveguard: {decision.reason}", "blocked")

    # Kota (engellenen istek kotadan yemez): politika SONRASI, upstream ÖNCESİ
    try:
        exceeded = await st.quota.check(a.team)
    except QuotaBackendError:
        await audit(prompt_tokens=0, completion_tokens=0, usage_known=1, est_cost_usd=0.0,
                    upstream_status=503, quota="backend_unavailable")
        return fmt.error(503, "Telveguard: kota sayacına ulaşılamadı.", "quota_unavailable", "api_error")
    if exceeded:
        metrics.QUOTA_EXCEEDED.labels(exceeded.kind).inc()
        await audit(prompt_tokens=0, completion_tokens=0, usage_known=1, est_cost_usd=0.0,
                    upstream_status=429, quota=exceeded.kind, action="block",
                    rules=decision.rules + [f"kota:{exceeded.kind}"], reason=exceeded.message)
        resp = fmt.error(429, f"Telveguard: {exceeded.message}", "quota_exceeded", "rate_limit_error")
        resp.headers["Retry-After"] = str(exceeded.retry_after)
        return resp

    if a.provider_error:
        await audit(prompt_tokens=0, completion_tokens=0, usage_known=1, est_cost_usd=0.0,
                    upstream_status=400)
        return fmt.error(400, f"Telveguard: {a.provider_error}", "no_upstream", "invalid_request_error")
    upstream = (a.provider.endpoint(fmt.name, model, request.headers) if a.provider
                else fmt.upstream(destination, request.headers))
    if upstream is None:
        await audit(prompt_tokens=0, completion_tokens=0, usage_known=1, est_cost_usd=0.0,
                    upstream_status=400)
        return fmt.error(400, f"Telveguard: '{model}' kurum içi bir model; bu API biçimi için kurum içi "
                              "upstream tanımlı değil.", "no_upstream", "invalid_request_error")
    url, headers = upstream

    # 3) Maskeleme (tüm konuşma boyunca ortak vault -> tutarlı yer tutucular)
    vault: Dict[str, str] = {}
    masked_prompt = _mask_parts(st, a.parts, decision, vault, a.scans, a.part_findings)

    wants_stream = bool(body.get("stream"))
    # STREAM_MODE=incremental: cevap akarken taranır (streaming.py). Uygulanan bir `block` çıktı
    # kuralı varsa tamponlanır: akmaya başlamış cevap geri alınamaz
    if wants_stream and fmt.streams and streaming.incremental_enabled() \
            and not streaming.has_block_output_rule(st.policy):
        return await _stream_incremental(st, a, fmt, url, headers, body, vault, masked_prompt, audit, t0)

    # Maskeleme ya da çıktı kuralı varsa stream tamponlanır: yer tutucular parça sınırında
    # bölünmesin ve cevap müşteriye gitmeden taransın
    must_buffer = bool(vault) or bool(st.policy.output_rules)

    if wants_stream and not must_buffer:
        # Maskeleme ve çıktı kuralı yoksa gerçek pass-through streaming
        req = st.http.build_request("POST", url, json=body, headers=headers)
        try:
            resp = await st.http.send(req, stream=True)
        except httpx.HTTPError:
            metrics.UPSTREAM_ERRORS.labels(destination, "unreachable").inc()
            await audit(masked_prompt, 502, output_scan="skipped_stream", **_usage_fields(st, fmt, model, None))
            return fmt.error(502, "Upstream'e ulaşılamadı.", "upstream_unreachable", "upstream_error")
        await audit(masked_prompt, resp.status_code, output_scan="skipped_stream",
                    **_usage_fields(st, fmt, model, None))

        async def relay():
            async for chunk in resp.aiter_raw():
                yield chunk
            await resp.aclose()
        return StreamingResponse(relay(), status_code=resp.status_code, headers=_routed_headers(a),
                                 media_type=resp.headers.get("content-type", "text/event-stream"))

    if fmt.streams:
        body["stream"] = False
    t_up = time.perf_counter()
    try:
        resp = await st.http.post(url, json=body, headers=headers)
    except httpx.HTTPError:
        metrics.UPSTREAM_ERRORS.labels(destination, "unreachable").inc()
        await audit(masked_prompt, 502, **_usage_fields(st, fmt, model, None))
        return fmt.error(502, "Upstream'e ulaşılamadı.", "upstream_unreachable", "upstream_error")
    metrics.UPSTREAM_SECONDS.labels(destination).observe(time.perf_counter() - t_up)
    if resp.status_code >= 400:
        metrics.UPSTREAM_ERRORS.labels(destination, metrics.upstream_error_kind(resp.status_code)).inc()
        await audit(masked_prompt, resp.status_code, **_usage_fields(st, fmt, model, None))
        return _upstream_error(fmt, resp)

    result = resp.json()

    # 5) Çıktı: sızıntı taraması (maske geri açılmadan ÖNCE) -> çıktı politikası -> maskeyi geri aç.
    # Araç çağrıları dahil: Claude Code'un yazdığı dosya içeriği de çıktıdır.
    output_entities: Set[str] = set()
    scanned = []
    for part in fmt.response_parts(result):
        findings, leaks = _find_output_leaks(st, part.text, a.all_text, vault)
        output_entities |= {f.entity for f in findings}
        scanned.append((part, leaks))
    leaked = {f.entity for _, leaks in scanned for f in leaks}
    out = st.policy.evaluate_output(a.ctx, leaked)
    for entity in leaked:
        metrics.ENTITIES.labels(entity, "output_leak").inc()
    if leaked:
        metrics.OUTPUT_ACTIONS.labels(out.action).inc()
    output_audit = dict(output_entities=sorted(output_entities), output_leaked=sorted(leaked),
                        output_action=out.action if leaked else "",
                        output_rules=out.rules,
                        monitored_rules=decision.monitored_rules + out.monitored_rules)

    usage = _usage_fields(st, fmt, model, result)
    # Upstream çağrıldı: çıktı engellense de token / maliyet kotadan düşer
    await st.quota.record(a.team, usage["prompt_tokens"] + usage["completion_tokens"], usage["est_cost_usd"])

    if out.action == "block":
        await audit(masked_prompt, resp.status_code, masked_count=len(vault), **output_audit, **usage)
        return fmt.error(403, f"Telveguard: model cevabı engellendi ({out.reason}).", "output_blocked")

    for part, leaks in scanned:
        text = part.text
        if out.action == "mask":
            text = _redact(text, leaks, out.mask_entities)
        # Yer tutucular araç argümanlarında da geri açılır: model maskeli sırrı bir dosyaya
        # yazıyorsa diske [SECRET_..._1] değil gerçek değer gitmeli
        part.set(st.pii.unmask(text, vault))

    await audit(masked_prompt, resp.status_code, masked_count=len(vault), **output_audit, **usage)

    if wants_stream:
        metrics.FIRST_TOKEN_SECONDS.labels(destination, "buffered").observe(time.perf_counter() - t0)
        return StreamingResponse(fmt.buffered_sse(result), media_type="text/event-stream",
                                 headers=_routed_headers(a))
    return JSONResponse(result, headers=_routed_headers(a))


_STREAM_TASKS: Set[asyncio.Task] = set()   # istemci koptuğunda arka planda biten denetim kayıtları


async def _stream_incremental(st, a: Analysis, fmt: ApiFormat, url: str, headers: Dict[str, str],
                              body: Dict[str, Any], vault: Dict[str, str], masked_prompt, audit, t0: float):
    """Artımlı streaming: upstream'in SSE'si olay olay çıktı korumasından geçer (streaming.py).
    Denetim kaydı, kota ve metrikler akış bitince (istemci koparsa da) yazılır."""
    destination, model = a.destination, a.model
    strip_usage = False
    if fmt is CHAT and not (body.get("stream_options") or {}).get("include_usage"):
        # Röntgen / kota için usage gerekli; istemci istemediyse son usage parçası ona gitmez
        body["stream_options"] = {**(body.get("stream_options") or {}), "include_usage": True}
        strip_usage = True
    req = st.http.build_request("POST", url, json=body, headers=headers)
    try:
        resp = await st.http.send(req, stream=True)
    except httpx.HTTPError:
        metrics.UPSTREAM_ERRORS.labels(destination, "unreachable").inc()
        await audit(masked_prompt, 502, **_usage_fields(st, fmt, model, None))
        return fmt.error(502, "Upstream'e ulaşılamadı.", "upstream_unreachable", "upstream_error")
    if resp.status_code >= 400:
        await resp.aread()
        await resp.aclose()
        metrics.UPSTREAM_ERRORS.labels(destination, metrics.upstream_error_kind(resp.status_code)).inc()
        await audit(masked_prompt, resp.status_code, **_usage_fields(st, fmt, model, None))
        return _upstream_error(fmt, resp)

    guard = streaming.OutputGuard(st.pii, st.policy, a.ctx, a.all_text, vault,
                                  extra_holdback=st.dictionary.max_term_length() + 8)
    stream = streaming.Stream(guard, on_first=lambda: metrics.FIRST_TOKEN_SECONDS.labels(
        destination, "incremental").observe(time.perf_counter() - t0))
    events = streaming.sse_events(resp.aiter_bytes())
    if fmt is MESSAGES:
        source = streaming.anthropic_messages(stream, events)
    elif fmt is RESPONSES:
        source = streaming.openai_responses(stream, events)
    else:
        source = streaming.openai_chat(stream, events, strip_usage)

    async def finalize(aborted: bool):
        await resp.aclose()
        usage = _usage_fields(st, fmt, model, stream.usage)
        await st.quota.record(a.team, usage["prompt_tokens"] + usage["completion_tokens"], usage["est_cost_usd"])
        out = st.policy.evaluate_output(a.ctx, guard.leaked)
        for entity in guard.leaked:
            metrics.ENTITIES.labels(entity, "output_leak").inc()
        if guard.leaked:
            metrics.OUTPUT_ACTIONS.labels(out.action).inc()
        await audit(masked_prompt, resp.status_code, masked_count=len(vault), stream_aborted=int(aborted),
                    output_entities=sorted(guard.entities), output_leaked=sorted(guard.leaked),
                    output_action=out.action if guard.leaked else "", output_rules=out.rules,
                    monitored_rules=a.decision.monitored_rules + out.monitored_rules, **usage)

    async def relay():
        done = False
        try:
            async for chunk in source:
                yield chunk
            done = True
        finally:
            if done:
                await finalize(False)
            else:   # istemci koptu / iptal: bu görev iptal edildiği için kayıt ayrı görevde
                task = asyncio.get_running_loop().create_task(finalize(True))
                _STREAM_TASKS.add(task)
                task.add_done_callback(_STREAM_TASKS.discard)

    return StreamingResponse(relay(), status_code=resp.status_code, headers=_routed_headers(a),
                             media_type="text/event-stream")


@app.post("/v1/messages/count_tokens")
async def messages_count_tokens(request: Request):
    """Claude Code bağlam boyutunu ölçmek için çağırır. Metin upstream'e gittiği için aynı
    kimlik / politika / maskeleme uygulanır; model çağrısı olmadığından denetime yazılmaz."""
    st = request.app.state
    try:
        identity = await st.auth.authenticate(request.headers)
    except AuthError as e:
        return _auth_error(e, MESSAGES)
    body, err = await _read_body(request, MESSAGES)
    if err:
        return err
    a = _route(st, await _scan_analyze(st, body, identity, MESSAGES), request.headers, "count_tokens")
    if a.decision.action == "block":
        return MESSAGES.error(403, f"Telveguard: {a.decision.reason}", "blocked")
    if a.provider_error:
        return MESSAGES.error(400, f"Telveguard: {a.provider_error}", "no_upstream")
    upstream = (a.provider.endpoint("count_tokens", a.model, request.headers) if a.provider
                else MESSAGES.upstream(a.destination, request.headers, path="/v1/messages/count_tokens"))
    if upstream is None:
        return MESSAGES.error(400, "Bu model için Anthropic upstream'i tanımlı değil.", "no_upstream")
    _mask_parts(st, a.parts, a.decision, {}, a.scans, a.part_findings)
    try:
        resp = await st.http.post(upstream[0], json=body, headers=upstream[1])
    except httpx.HTTPError:
        return MESSAGES.error(502, "Upstream'e ulaşılamadı.", "upstream_unreachable")
    if resp.status_code >= 400:
        return _upstream_error(MESSAGES, resp)
    return JSONResponse(resp.json())


@app.post("/v1/policy/simulate")
async def policy_simulate(request: Request, format: str = "chat"):
    """Bir isteğin politikadan nasıl geçeceğini gösterir; upstream'e gitmez, denetime yazılmaz.
    Gövde ilgili API'ninkiyle aynıdır (?format=chat|responses|messages|embeddings)."""
    if err := await _require_admin(request):
        return err
    fmt = FORMATS.get(format)
    if fmt is None:
        return _openai_error(400, "format chat, responses, messages ya da embeddings olmalı.", "invalid_request",
                             "invalid_request_error")
    body, err = await _read_body(request, fmt)
    if err:
        return err

    body = copy.deepcopy(body)
    # Yönetici aracı: Authorization yönetici token'ını taşır; simüle edilecek kimlik
    # açıkça header'dan verilir (AUTH_MODE'dan bağımsız)
    h = request.headers
    teams = [t.strip() for t in h.get("x-telveguard-team", "default").split(",") if t.strip()]
    identity = Identity(h.get("x-telveguard-user", "simulate"), teams or ["default"], "simulate")
    a = _route(request.app.state, await _scan_analyze(request.app.state, body, identity, fmt), request.headers)
    d = a.decision
    originals = [p.text for p in a.parts]
    _mask_parts(request.app.state, a.parts, d, {}, a.scans, a.part_findings)
    blocked = d.action == "block"
    parts = [{"role": p.role, "segments": _segments(request.app.state, text),
              "sent": None if blocked else p.text}
             for p, text in zip(a.parts, originals) if text.strip()]
    return {
        "format": fmt.name,
        "team": a.team,
        "teams": a.identity.teams,
        "model": a.model,
        "routed_from": a.routed_from or None,
        "destination": a.destination,
        "declared": a.ctx.declared,
        "provider": a.provider.name if a.provider else None,
        "provider_error": a.provider_error,
        "entities": dict(sorted(a.entity_counts.items())),
        "injection": {"score": a.injection.score, "engine": a.injection.engine,
                      "matched_rules": len(a.injection.matched)},
        "decision": {
            "action": d.action, "reason": d.reason, "rules": d.rules,
            "mask_entities": sorted(d.mask_entities),
            "monitored_rules": d.monitored_rules, "would_action": d.would_action,
        },
        # Engellenecekse upstream'e hiçbir şey gitmez
        "upstream_messages": None if blocked else body.get("messages"),
        "upstream_body": None if blocked else body,
        # Arayüz için: metin, tespit edilen değerler ayrı bölüm olarak (offset yok: JS UTF-16 sayar)
        "parts": parts,
        # Ekler: okunan metin (işaretli), taranamayanların nedeni, maskelendiyse nasıl
        "attachments": [{**sc.summary(), "redacted": sc.redacted,
                         "segments": _segments(request.app.state, sc.text) if sc.text else []}
                        for sc in a.scans],
    }


def _segments(st, text: str) -> List[Dict[str, str]]:
    out, pos = [], 0
    for f in sorted(st.pii.analyze(text), key=lambda f: f.start):
        if f.start < pos:
            continue
        if f.start > pos:
            out.append({"text": text[pos:f.start]})
        out.append({"text": text[f.start:f.end], "entity": f.entity})
        pos = f.end
    if pos < len(text):
        out.append({"text": text[pos:]})
    return out


@app.get("/v1/policy/info")
async def policy_info(request: Request):
    """Arayüz için politika özeti: hedef önekleri ve kurallar (simülatör, olay ayrıntısı)."""
    if err := await _require_admin(request):
        return err
    pol = request.app.state.policy

    def rules(items):
        return [{"name": r.get("name", ""), "action": r.get("action"), "mode": r.get("mode", pol.mode),
                 "when": r.get("when", {}), "message": r.get("message", "")} for r in items]
    teams = sorted({t for r in pol.rules + pol.output_rules + pol.routing for t in (r.get("when") or {}).get("teams", [])})
    return {"default_action": pol.default_action, "mode": pol.mode, "destinations": pol.destinations,
            "runtime": request.app.state.policy_runtime.describe(),
            "rules": rules(pol.rules), "output_rules": rules(pol.output_rules), "teams": teams,
            "routing": [{"name": r["name"], "to": r["to"], "mode": r.get("mode", pol.mode),
                         "when": r.get("when", {})} for r in pol.routing],
            "providers": request.app.state.providers.describe(),
            "notify": request.app.state.notifier.describe(),
            "dictionary": request.app.state.dictionary.describe(),
            "exceptions": request.app.state.exemptions.describe()}


@app.post("/v1/notify/test")
async def notify_test(request: Request, channel: Optional[str] = None):
    """Kurulum denetimi: kanallara (?channel=ad ile tek kanala) örnek bir bildirim gönderir.
    Koşullara ve tekrar bastırmaya bakılmaz; denetim kaydına yazılmaz."""
    if err := await _require_admin(request):
        return err
    notifier = request.app.state.notifier
    channels = [c for c in notifier.channels if channel in (None, c.name)]
    if not channels:
        return _openai_error(404, "Bildirim kanalı bulunamadı (politikadaki notify.channels).",
                             "not_found", "admin_error")
    ev = {"event_id": str(uuid.uuid4()), "ts": int(time.time() * 1000), "user": "deneme.kullanici",
          "team": "deneme", "teams": ["deneme"], "model": "gpt-4o", "destination": "external",
          "action": "block", "rules": ["bildirim-denemesi"], "entities": ["TCKN"], "output_leaked": [],
          "reason": "Bu bir deneme bildirimidir; gerçek bir olay değildir.", "api_format": "chat"}
    results = []
    for c in channels:
        ok, detail = await notifier.send(c, ev)
        results.append({"name": c.name, "type": c.type, "ok": ok, "detail": detail})
    return {"results": results}


# ---------------- ilgili kişi başvurusu (KVKK md. 11) ----------------

@app.post("/v1/subjects/search")
async def subjects_search(request: Request):
    """Verilen kimlik / iletişim değerlerinin geçtiği istekler ve verinin akıbeti. Değerler
    URL'de değil gövdede gelir (erişim loglarına düşmesin); cevapta ve logda maskelidir.
    Gövde: {"values": ["10000000146", {"entity": "VKN", "value": "1234567890"}], "days": 730}"""
    if err := await _require_admin(request):
        return err
    index = request.app.state.subjects
    if not index.enabled:
        return _openai_error(404, "İlgili kişi araması kapalı (TELVEGUARD_SUBJECT_HASH_KEY tanımlı değil).",
                             "subjects_disabled", "admin_error")
    try:
        body = await request.json()
    except ValueError:
        body = None
    values = body.get("values") if isinstance(body, dict) else None
    days = body.get("days", 730) if isinstance(body, dict) else None
    if not isinstance(values, list) or not 1 <= len(values) <= subjects_mod.MAX_SEARCH_VALUES:
        return _openai_error(400, f"values 1-{subjects_mod.MAX_SEARCH_VALUES} değerlik bir liste olmalı.",
                             "invalid_request", "invalid_request_error")
    if not isinstance(days, int) or isinstance(days, bool) or not 1 <= days <= 3650:
        return _openai_error(400, "days 1-3650 arası bir tamsayı olmalı.", "invalid_request", "invalid_request_error")
    ch, err = _require_clickhouse(request)
    if err:
        return err
    resolved = index.resolve(request.app.state.pii, values)
    found = [s for s in resolved if "error" not in s]
    errors = [{"label": s["label"], "error": s["error"]} for s in resolved if "error" in s]
    result = {"summary": [], "events": [], "truncated": False, "statuses": xray_mod.SUBJECT_STATUS}
    if found:
        try:
            result = await xray_mod.subject_search(ch, found, days, request.app.state.providers)
        except xray_mod.ClickHouseError as e:
            hint = (" Şema güncel değil: clickhouse/migrations/0.3.0-subject-hashes.sql çalıştırılmalı."
                    if "subject_hashes" in str(e) else "")
            return _openai_error(502, str(e)[:200] + hint, "clickhouse_error", "admin_error")
    # Kim, ne zaman, kaç değer aradı (değerler loglanmaz)
    admin_log.info("subject_search values=%d types=%s events=%d", len(values),
                   ",".join(sorted({s["entity"] for s in found})), len(result["events"]))
    return {**result, "errors": errors, "days": days}


# ---------------- Röntgen + KVKK raporu ----------------

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")


def _require_clickhouse(request: Request):
    ch = getattr(request.app.state, "ch", None)
    if ch is None:
        return None, _openai_error(503, "ClickHouse yapılandırılmamış (CLICKHOUSE_URL).",
                                   "clickhouse_disabled", "admin_error")
    return ch, None


_PAGES: Dict[str, Response] = {}


def _html_page(name: str) -> Response:
    """Statik sayfa + CSP: yalnızca sayfanın kendi satır içi betiği (özetiyle) çalışır, istekler yalnızca
    gateway'e gider, sayfa başka bir siteye çerçevelenemez. Yönetici token'ı sayfadadır: araya
    sızan bir betik (ör. kayıttaki bir model adı yoluyla) token'ı dışarı gönderemesin."""
    if name not in _PAGES:
        import base64
        import hashlib
        with open(os.path.join(STATIC_DIR, name), encoding="utf-8") as f:
            html = f.read()
        scripts = re.findall(r"<script>(.*?)</script>", html, re.S)
        hashes = " ".join("'sha256-%s'" % base64.b64encode(hashlib.sha256(s.encode()).digest()).decode()
                          for s in scripts)
        csp = (f"default-src 'none'; script-src {hashes}; style-src 'unsafe-inline'; img-src 'self' data: blob:; "
               "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
        _PAGES[name] = Response(html, media_type="text/html; charset=utf-8", headers={
            "Content-Security-Policy": csp, "X-Frame-Options": "DENY", "Cache-Control": "no-cache"})
    page = _PAGES[name]
    return Response(page.body, media_type=page.media_type, headers=dict(page.headers))


@app.get("/xray", include_in_schema=False)
async def xray_page():
    """Dashboard sayfası veri içermez; veriyi yönetici token'ıyla /v1/xray'den çeker.
    Harici CDN yok (air-gapped)."""
    return _html_page("xray.html")


@app.get("/asistan")
async def demo_assistant():
    """Demo: tarayıcı eklentisinin yönlendirdiği "Kurum Asistanı" sohbet sayfası. Kimliği header'dan
    verdiği için yalnızca DEMO_ASSISTANT=1 ve AUTH_MODE=header (yerel test ortamı) iken açılır."""
    if os.getenv("DEMO_ASSISTANT") != "1" or os.getenv("AUTH_MODE", "header") != "header":
        return _openai_error(404, "Bulunamadı.", "not_found", "invalid_request_error")
    return _html_page("asistan.html")


@app.get("/v1/xray")
async def xray_api(request: Request, days: int = 30, team: str = ""):
    if err := await _require_admin(request):
        return err
    if not 1 <= days <= 366:
        return _openai_error(400, "days 1 ile 366 arasında olmalı.", "invalid_request", "invalid_request_error")
    ch, err = _require_clickhouse(request)
    if err:
        return err
    try:
        return await xray_mod.xray(ch, days, team)
    except xray_mod.ClickHouseError as e:
        return _openai_error(502, str(e), "clickhouse_error", "admin_error")


@app.get("/v1/events")
async def events_api(request: Request, days: int = 30, flag: str = "", limit: int = 50,
                     before_ts: int = 0, before_id: str = ""):
    """Denetim kayıtları, en yeni önce. Filtreler: team, user, model, action, destination,
    api_format, entity, rule, day (YYYY-MM-DD); flag Röntgen kutucuklarının görünümleri."""
    if err := await _require_admin(request):
        return err
    q = request.query_params
    filters = {k: q.get(k, "").strip() for k in xray_mod.EVENT_FILTERS}
    filters["days"] = str(days)
    problem = None
    if not 1 <= days <= 366:
        problem = "days 1 ile 366 arasında olmalı."
    elif not 1 <= limit <= xray_mod.EVENTS_MAX_LIMIT:
        problem = f"limit 1 ile {xray_mod.EVENTS_MAX_LIMIT} arasında olmalı."
    elif flag and flag not in xray_mod.EVENT_FLAGS:
        problem = "flag şunlardan biri olmalı: " + ", ".join(xray_mod.EVENT_FLAGS)
    elif filters["day"] and not _is_date(filters["day"]):
        problem = "day YYYY-MM-DD biçiminde olmalı."
    elif before_ts and not _is_uuid(before_id):
        problem = "before_id geçerli bir olay kimliği olmalı."
    if problem:
        return _openai_error(400, problem, "invalid_request", "invalid_request_error")
    ch, err = _require_clickhouse(request)
    if err:
        return err
    try:
        return await xray_mod.events(ch, filters, flag, before_ts, before_id, limit)
    except xray_mod.ClickHouseError as e:
        return _openai_error(502, str(e), "clickhouse_error", "admin_error")


@app.get("/v1/events/{event_id}")
async def event_detail_api(request: Request, event_id: str):
    """Tek olay: tüm alanlar + (AUDIT_STORE_MASKED=1 ise) maskeli metin + aynı prompt'un tekrarı."""
    if err := await _require_admin(request):
        return err
    if not _is_uuid(event_id):
        return _openai_error(400, "Geçersiz olay kimliği.", "invalid_request", "invalid_request_error")
    ch, err = _require_clickhouse(request)
    if err:
        return err
    try:
        ev = await xray_mod.event_detail(ch, event_id)
    except xray_mod.ClickHouseError as e:
        return _openai_error(502, str(e), "clickhouse_error", "admin_error")
    if ev is None:
        return _openai_error(404, "Olay bulunamadı.", "not_found", "admin_error")
    return ev


def _is_uuid(value: str) -> bool:
    try:
        uuid.UUID(value)
        return True
    except ValueError:
        return False


def _is_date(value: str) -> bool:
    try:
        date.fromisoformat(value)
        return len(value) == 10
    except ValueError:
        return False


@app.get("/v1/reports/kvkk-transfer")
async def kvkk_transfer_report(request: Request, month: str, format: str = "csv"):
    """Aylık KVKK md. 9 yurt dışı aktarım raporu: ekip x sağlayıcı x kişisel veri türü."""
    if err := await _require_admin(request):
        return err
    try:
        xray_mod.month_range(month)
    except (ValueError, TypeError):
        return _openai_error(400, "month YYYY-MM biçiminde olmalı (ör. 2026-09).",
                             "invalid_request", "invalid_request_error")
    if format not in ("csv", "json"):
        return _openai_error(400, "format csv ya da json olmalı.", "invalid_request", "invalid_request_error")
    ch, err = _require_clickhouse(request)
    if err:
        return err
    try:
        rows = await xray_mod.kvkk_transfer(ch, month, request.app.state.providers)
    except xray_mod.ClickHouseError as e:
        return _openai_error(502, str(e), "clickhouse_error", "admin_error")
    if format == "json":
        return {"month": month, "rows": rows}
    return Response(xray_mod.kvkk_csv(rows), media_type="text/csv; charset=utf-8", headers={
        "Content-Disposition": f'attachment; filename="kvkk-yurtdisi-aktarim-{month}.csv"'})


@app.get("/v1/reports/poc")
async def poc_report(request: Request, days: int = 14):
    """POC değerlendirme raporu: riskli istekler korundu / gözlemde korunurdu / korumasız,
    KVKK md. 9 maruziyeti, gölge AI, örnek olaylar (kullanıcı adı yok) ve politika önerileri."""
    if err := await _require_admin(request):
        return err
    if not 1 <= days <= 366:
        return _openai_error(400, "days 1 ile 366 arasında olmalı.", "invalid_request", "invalid_request_error")
    ch, err = _require_clickhouse(request)
    if err:
        return err
    st = request.app.state
    try:
        return await poc_report_mod.build(
            ch, days, registry=st.providers, inventory_cfg=st.inventory, policy_mode=st.policy.mode,
            dictionary_labels={e["entity"]: e["label"] for e in st.dictionary.describe() if e["label"]})
    except xray_mod.ClickHouseError as e:
        return _openai_error(502, str(e), "clickhouse_error", "admin_error")


@app.get("/v1/reports/risk")
async def risk_report(request: Request, days: int = 30, team: str = "", limit: int = risk_mod.RISK_LIMIT):
    """Kullanıcı başına risk skoru (0-100), sinyallerin katkısı ve son 24 saatteki ani artış.
    Kullanıcı adı içerir: yönetici ucu, erişim loglanır."""
    if err := await _require_admin(request):
        return err
    if not 2 <= days <= 366:
        return _openai_error(400, "days 2 ile 366 arasında olmalı.", "invalid_request", "invalid_request_error")
    if not 1 <= limit <= 500:
        return _openai_error(400, "limit 1 ile 500 arasında olmalı.", "invalid_request", "invalid_request_error")
    ch, err = _require_clickhouse(request)
    if err:
        return err
    try:
        result = await risk_mod.report(ch, days, team.strip(), limit)
    except xray_mod.ClickHouseError as e:
        return _openai_error(502, str(e), "clickhouse_error", "admin_error")
    result["anomaly"] = request.app.state.policy.anomaly or None
    return result


# ---------------- AI envanteri (EU AI Act) + VERBİS taslağı ----------------

@app.get("/v1/inventory")
async def ai_inventory(request: Request, days: int = 90):
    """Beyan edilen AI sistemleri + risk sınıfı + yükümlülükler; beyan edilmemiş kullanımlar. TASLAK."""
    if err := await _require_admin(request):
        return err
    if not 1 <= days <= 730:
        return _openai_error(400, "days 1 ile 730 arasında olmalı.", "invalid_request", "invalid_request_error")
    ch, err = _require_clickhouse(request)
    if err:
        return err
    try:
        usage = await xray_mod.inventory_usage(ch, days)
    except xray_mod.ClickHouseError as e:
        return _openai_error(502, str(e), "clickhouse_error", "admin_error")
    return compliance.build_inventory(request.app.state.inventory, usage)


@app.get("/v1/reports/verbis")
async def verbis_report(request: Request, days: int = 365, format: str = "json"):
    """VERBİS başlıklarına eşlenmiş taslak (veri kategorisi, amaç, alıcı, yurt dışı aktarım, saklama)."""
    if err := await _require_admin(request):
        return err
    if not 1 <= days <= 730 or format not in ("json", "csv"):
        return _openai_error(400, "days 1-730, format json ya da csv olmalı.", "invalid_request",
                             "invalid_request_error")
    ch, err = _require_clickhouse(request)
    if err:
        return err
    try:
        rows = await xray_mod.verbis_rows(ch, days, request.app.state.providers)
    except xray_mod.ClickHouseError as e:
        return _openai_error(502, str(e), "clickhouse_error", "admin_error")
    report = compliance.build_verbis(request.app.state.inventory, rows,
                                     provider_countries=request.app.state.providers.countries(),
                                     retention=os.getenv("AUDIT_RETENTION",
                                                         "2 yıl (denetim kaydı saklama süresi)"))
    if format == "json":
        return report
    return Response(compliance.verbis_csv(report), media_type="text/csv; charset=utf-8", headers={
        "Content-Disposition": 'attachment; filename="verbis-taslak.csv"'})


# ---------------- gölge AI (tarayıcı eklentisi) ----------------

def _require_extension(request: Request) -> Optional[JSONResponse]:
    """SHADOW_AI_TOKEN (MDM ile eklentiye dağıtılır); tanımlı değilse gölge AI uçları kapalı."""
    expected = os.getenv("SHADOW_AI_TOKEN", "")
    if not expected:
        return _openai_error(404, "Gölge AI toplama kapalı (SHADOW_AI_TOKEN tanımlı değil).",
                             "shadow_ai_disabled", "admin_error")
    header = request.headers.get("authorization", "")
    if not shadow_ai.check_token(header[7:].strip() if header.lower().startswith("bearer ") else None, expected):
        return _openai_error(401, "Geçersiz eklenti token'ı.", "unauthorized", "authentication_error")
    return None


@app.post("/v1/shadow-ai/events")
async def shadow_ai_events(request: Request):
    """Tarayıcı eklentisinden olay toplu gönderimi. Metin YOK: site, veri türleri, karar."""
    if err := _require_extension(request):
        return err
    try:
        batch = shadow_ai.ShadowBatch.model_validate(await request.json())
    except ValueError as e:
        return _openai_error(400, f"Geçersiz olay: {str(e)[:300]}", "invalid_request", "invalid_request_error")
    if not request.app.state.shadow_limiter.allow(batch.events):
        metrics.SHADOW_AI_EVENTS.labels("rate_limited").inc()
        resp = _openai_error(429, "Çok fazla gölge AI olayı; bir dakika sonra yeniden deneyin.", "rate_limited",
                             "rate_limit_error")
        resp.headers["Retry-After"] = "60"
        return resp
    for event in batch.events:
        await _emit(request.app.state, shadow_ai.to_audit_event(event))
        metrics.SHADOW_AI_EVENTS.labels(event.action).inc()
    return {"accepted": len(batch.events)}


@app.get("/v1/shadow-ai/dictionary")
async def shadow_ai_dictionary(request: Request):
    """Kurumsal sözlüğün ve istisnaların tarayıcı sürümü: terimler / değerler tuzlu özet, düzenli
    ifadeler olduğu gibi (dictionary.browser_payload, exemptions.browser_payload). ETag = sürüm;
    değişmediyse 304, eklenti yeniden indirmez."""
    if err := _require_extension(request):
        return err
    st = request.app.state
    payload = exemptions_mod.browser_payload(st.dictionary.browser(), st.exemptions)
    etag = f'"{payload["version"]}"'
    if request.headers.get("if-none-match") == etag:
        return Response(status_code=304, headers={"ETag": etag})
    return JSONResponse(payload, headers={"ETag": etag, "Cache-Control": "no-cache"})


@app.get("/v1/contextforge/dictionary")
async def contextforge_dictionary(request: Request):
    """Kurumsal sözlük ContextForge eklentisine: terimler düz metin (sunucudan sunucuya, güvenilen
    bileşen; tarayıcıdaki gibi özet değil). CONTEXTFORGE_TOKEN tanımlı değilse kapalı. ETag = sürüm."""
    expected = os.getenv("CONTEXTFORGE_TOKEN", "")
    if not expected:
        return _openai_error(404, "ContextForge sözlük ucu kapalı (CONTEXTFORGE_TOKEN tanımlı değil).",
                             "contextforge_disabled", "admin_error")
    header = request.headers.get("authorization", "")
    if not shadow_ai.check_token(header[7:].strip() if header.lower().startswith("bearer ") else None, expected):
        return _openai_error(401, "Geçersiz ContextForge token'ı.", "unauthorized", "authentication_error")
    payload = request.app.state.dictionary.server_payload()
    etag = f'"{payload["version"]}"'
    if request.headers.get("if-none-match") == etag:
        return Response(status_code=304, headers={"ETag": etag})
    return JSONResponse(payload, headers={"ETag": etag, "Cache-Control": "no-store"})


# ---------------- kod asistanı hook'ları (telve: Cursor, Claude Code) ----------------

@app.get("/v1/agent/config")
async def agent_config(request: Request):
    """`telve setup` için kurulum bilgisi: kimlik modu ve (jwt) cihaz akışıyla giriş için
    OIDC adresi ve public istemci kimliği. Sır içermez; kimlik doğrulamasız açıktır."""
    auth = request.app.state.auth
    oidc = None
    if auth.mode == "jwt":
        oidc = {"issuer": auth.issuer, "client_id": os.getenv("OIDC_AGENT_CLIENT_ID", ""),
                "scope": os.getenv("OIDC_AGENT_SCOPE", "openid offline_access")}
    return {"auth_mode": auth.mode, "oidc": oidc, "version": app.version}


@app.post("/v1/agent/check")
async def agent_check(request: Request):
    """Cursor / Claude Code hook'u: prompt, okunacak dosya, komut ya da araç çıktısı politikadan
    geçer. Kimlik proxy'dekiyle aynıdır (kullanıcının kendi token'ı). Upstream'e hiçbir şey gitmez.
    Cevap: action = allow | warn | mask | block; mask ise masked_text (yalnızca tool_output)."""
    st = request.app.state
    t0 = time.perf_counter()
    try:
        identity = await st.auth.authenticate(request.headers)
    except AuthError as e:
        return _auth_error(e)
    try:
        req = agent_mod.AgentCheck.model_validate(await request.json())
    except ValueError as e:
        return _openai_error(400, f"Geçersiz istek: {str(e)[:300]}", "invalid_request", "invalid_request_error")

    role = "user" if req.event in ("prompt", "shell") else "tool"
    body = {"model": req.model or req.client,
            "messages": [{"role": role, "content": req.text, "tool_call_id": "telve"}]}
    a = _analyze(st, body, identity, CHAT, destination=agent_mod.destination(req))
    d = a.decision
    action, audited_action = agent_mod.resolve(d, req)
    entities = dict(sorted(a.entity_counts.items()))
    masked_text, vault = None, {}
    if action == "mask":
        masked_text = st.pii.mask(req.text, list(d.mask_entities), vault).text
    elif action == "block" and req.event == "tool_output" and a.entities:
        # Araç zaten çalıştı, çıktısı hook'ta: hook en azından bulunan her şeyi maskeli koysun
        masked_text = st.pii.mask(req.text, list(a.entities), vault).text
    metrics.AGENT_CHECKS.labels(req.client, req.event, action).inc()
    for entity in a.entities:
        metrics.ENTITIES.labels(entity, "input").inc()

    event_id = None
    if agent_mod.should_audit(req, action, entities, d, a.injection.score):
        recorded = Decision(audited_action, d.mask_entities if audited_action == "mask" else set(),
                            agent_mod.audit_rules(d, req), d.reason, d.monitored_rules, d.would_action)
        ev = st.audit.build_event(
            user=a.user, team=a.team, model=a.model, destination=a.destination, decision=recorded,
            entities=a.entities, injection=a.injection, prompt=req.text, masked_prompt=None,
            latency_ms=(time.perf_counter() - t0) * 1000, upstream_status=0)
        ev.update(teams=a.identity.teams, auth_source=identity.source, api_format=req.client,
                  subject_hashes=a.subject_hashes, prompt_tokens=0, completion_tokens=0,
                  usage_known=1, est_cost_usd=0.0, masked_count=len(vault))
        await _emit(st, ev)
        event_id = ev["event_id"]

    return {
        "action": action,
        "message": agent_mod.message(action, d, req, entities),
        "masked_text": masked_text,
        "entities": entities,
        "destination": a.destination,
        # Kayda kim olarak geçtiği: kullanıcı görebilsin (telve doctor)
        "identity": {"user": a.user, "teams": a.identity.teams, "source": identity.source},
        # Gözlemdeki kurallar (monitored_rules / would_action) dönmez: her kullanıcı bu uçla hangi
        # kuralın henüz uygulanmadığını yoklayabilirdi (simülatör bu yüzden yalnızca yöneticiye açık)
        "policy": {"action": d.action, "rules": d.rules, "reason": d.reason},
        "event_id": event_id,
    }


# ---------------- politika yönetimi (konsol: sürüm, onay, geri alma, etki) ----------------

def _store_error(e: "policy_store_mod.StoreError") -> JSONResponse:
    return _openai_error(e.status, e.message, "policy_store", "admin_error")


async def _policy_admin(request: Request, write: bool = False):
    """(hata, runtime, (kişi, nasıl)). Yazma işlemleri depo açık ve kişi belliyse."""
    err, actor = await _admin(request)
    if err:
        return err, None, None
    rt = request.app.state.policy_runtime
    if write and not rt.store:
        return _openai_error(404, "Konsoldan politika düzenleme kapalı (POLICY_STORE=clickhouse).",
                             "policy_store_disabled", "admin_error"), None, None
    if write and actor[1] == "static_token" and request.app.state.auth.admin_group \
            and os.getenv("POLICY_STATIC_TOKEN_WRITES", "0") != "1":
        # OIDC varken statik token'daki ad beyandır: token sahibi başkası adına onaylayıp dört gözü
        # atlatabilir. Politika değişikliği kurum hesabıyla (doğrulanmış kişi) yapılır.
        return _openai_error(403, "Politika değişikliği için kurum hesabıyla (OIDC) giriş yapın; statik yönetici "
                                  "token'ı yalnızca okuma içindir.", "oidc_required", "admin_error"), None, None
    if write and not actor[0]:
        return _openai_error(400, "Kayıt için adınızı girin (statik token ile: X-Telveguard-Actor başlığı).",
                             "actor_required", "admin_error"), None, None
    return None, rt, actor


async def _json_body(request: Request) -> Dict[str, Any]:
    try:
        body = await request.json()
    except ValueError:
        body = None
    return body if isinstance(body, dict) else {}


@app.get("/v1/policy/store")
async def policy_store_overview(request: Request):
    """Konsolun Politika sekmesi: yayındaki kurallar (metin), sürümler ve durumları."""
    err, rt, actor = await _policy_admin(request)
    if err:
        return err
    versions, error = [], ""
    if rt.store:
        try:
            versions = await rt.store.list()
        except policy_store_mod.StoreError as e:
            error = e.message
    pol = request.app.state.policy
    rules = pol.rules + pol.output_rules
    counts = {"rules": len(pol.rules), "output_rules": len(pol.output_rules),
              "monitor": sum(1 for r in rules if r.get("mode", pol.mode) == "monitor")}
    git = request.app.state.policy_git
    return {"runtime": rt.describe(), "content": rt.content, "editable_keys": list(policy_store_mod.EDITABLE_KEYS),
            "counts": counts, "git": git.cfg.describe() if git else None,
            "versions": versions, "error": error, "actor": {"name": actor[0], "via": actor[1]}}


@app.get("/v1/policy/versions/{version}")
async def policy_version(request: Request, version: int):
    err, rt, _ = await _policy_admin(request, write=False)
    if err:
        return err
    if not rt.store:
        return _openai_error(404, "Politika deposu kapalı.", "policy_store_disabled", "admin_error")
    try:
        v = await rt.store.get(version)
    except policy_store_mod.StoreError as e:
        return _store_error(e)
    v["diff"] = policy_store_mod.diff(rt.content, v["content"], f"yayında ({rt.describe()['source']})",
                                      f"sürüm {version}")
    try:
        v["changes"] = policy_store_mod.rules_diff(policy_store_mod.parse(rt.content, rt.base)[0],
                                                   policy_store_mod.parse(v["content"], rt.base)[0])
    except policy_store_mod.StoreError:
        v["changes"] = None   # bu pod'un tabanıyla kurulamıyor (ör. ConfigMap değişti)
    return v


@app.post("/v1/policy/validate")
async def policy_validate(request: Request):
    """Taslak: geçerli mi, yayındakinden farkı ne, kaç kural."""
    err, rt, _ = await _policy_admin(request)
    if err:
        return err
    content = (await _json_body(request)).get("content")
    if not isinstance(content, str):
        return _openai_error(400, "content (YAML metni) gerekli.", "invalid_request", "invalid_request_error")
    try:
        data, engine = policy_store_mod.parse(content, rt.base)
    except policy_store_mod.StoreError as e:
        return {"ok": False, "error": e.message}
    active, _ = policy_store_mod.parse(rt.content, rt.base)
    return {"ok": True, "error": "", "rules": len(engine.rules), "output_rules": len(engine.output_rules),
            "unchanged": active == data, "changes": policy_store_mod.rules_diff(active, data),
            "diff": policy_store_mod.diff(rt.content, content, "yayında", "taslak")}


@app.post("/v1/policy/versions")
async def policy_version_create(request: Request):
    err, rt, who = await _policy_admin(request, write=True)
    if err:
        return err
    actor, via = who
    body = await _json_body(request)
    content, comment = body.get("content"), str(body.get("comment") or "").strip()
    if not isinstance(content, str):
        return _openai_error(400, "content (YAML metni) gerekli.", "invalid_request", "invalid_request_error")
    if len(comment) < 3:
        return _openai_error(400, "Değişikliğin gerekçesini yazın (en az 3 karakter).", "comment_required",
                             "invalid_request_error")
    try:
        data, _ = policy_store_mod.parse(content, rt.base)
        if data == policy_store_mod.parse(rt.content, rt.base)[0]:
            return _openai_error(400, "Taslak yayındaki politikayla aynı.", "unchanged", "invalid_request_error")
        version = await rt.store.create(content, actor, via, comment[:1000], rt.version or 0)
    except policy_store_mod.StoreError as e:
        return _store_error(e)
    admin_log.info("policy_version_created version=%s author=%s via=%s", version, actor, via)
    return {"version": version, "status": "pending"}


@app.post("/v1/policy/versions/{version}/{action}")
async def policy_version_transition(request: Request, version: int, action: str):
    """approve (başka bir yönetici; emergency=true ile yazanın kendisi, gerekçeyle) |
    reject | apply (onaylı eski sürüme geri dönüş) | mirror (yayındaki sürümü Git'e yeniden yaz).
    Yayına alınan sürüm bu pod'da hemen, diğerlerinde POLICY_STORE_POLL_SECONDS içinde yüklenir;
    Git yansıtma açıksa depoya da yazılır (strict: önce depoya, yazılamazsa yayına girmez)."""
    if action not in ("approve", "reject", "apply", "mirror"):
        return _openai_error(404, "İşlem approve, reject, apply ya da mirror olmalı.", "not_found", "admin_error")
    err, rt, actor = await _policy_admin(request, write=True)
    if err:
        return err
    st = request.app.state
    git = st.policy_git
    body = await _json_body(request)
    comment = str(body.get("comment") or "").strip()[:1000]
    if action == "mirror":
        return await _policy_mirror_now(rt, git, version, actor)
    published = {}

    async def strict_publish(v, event):
        if event == "rejected":
            return
        try:
            published["result"] = await git.publish(rt, v, event, actor[0], actor[1], comment)
        except policy_git_mod.GitError as e:
            raise policy_store_mod.StoreError(502, f"Git'e yazılamadığı için yayına alınmadı (POLICY_GIT_STRICT): {e}")
    try:
        target = await rt.store.get(version)
        if action in ("approve", "apply"):
            # Yayına almadan önce bu pod'un tabanıyla kurulabildiğini doğrula
            policy_store_mod.parse(target["content"], rt.base)
        result = await rt.store.transition(version, action, actor[0], actor[1], comment,
                                           emergency=bool(body.get("emergency")),
                                           before_commit=strict_publish if git and git.cfg.strict else None)
    except policy_store_mod.StoreError as e:
        return _store_error(e)
    admin_log.info("policy_version_%s version=%s actor=%s via=%s", result["event"], version, *actor)
    if result["event"] in POLICY_SOLO_EVENTS:
        _notify_policy_event(st, version, result["event"], actor, comment)
    git_state = None
    if result["event"] != "rejected":
        await rt.refresh()
        if git and "result" in published:
            await git.record(rt.store, version, published["result"])
            git_state = {"status": "mirrored", **published["result"]}
        elif git:
            git.schedule(rt, rt.store, target, result["event"], actor[0], actor[1], comment)
            git_state = {"status": "pending"}
    return {**result, "runtime": rt.describe(), "git": git_state}


# Tek kişinin yayına aldığı sürüm (dört göz yok): bildirim kanallarına da düşer
POLICY_SOLO_EVENTS = {"emergency": "politika:acil-yayin", "applied": "politika:geri-alma"}


def _notify_policy_event(st, version: int, event: str, actor, comment: str) -> None:
    """Acil yayın / geri alma: kanallarda `rules: ["politika:*"]` ile eşleşir. Denetim kaydına yazılmaz
    (Röntgen istek saymasın); kayıt policy_events'te."""
    label = "acil yayına alındı (dört göz atlandı)" if event == "emergency" else "yeniden yayına alındı (geri alma)"
    st.notifier.submit({
        "event_id": str(uuid.uuid4()), "ts": int(time.time() * 1000), "user": actor[0], "team": "politika",
        "teams": ["politika"], "model": f"politika sürüm {version}", "destination": "", "action": "alert",
        "rules": [POLICY_SOLO_EVENTS[event]], "entities": [], "output_leaked": [], "api_format": "policy",
        "reason": f"Sürüm {version} {label} · {actor[1]} · gerekçe: {comment[:300]}"})


async def _policy_mirror_now(rt, git, version: int, actor):
    """Konsoldaki "Yeniden dene": yalnızca yayındaki sürüm (eskisi depodaki yeniyi ezmesin)."""
    if not git:
        return _openai_error(404, "Git yansıtma kapalı (POLICY_GIT_PROVIDER).", "git_disabled", "admin_error")
    if rt.version != version:
        return _openai_error(409, "Yalnızca yayındaki sürüm depoya yeniden yazılabilir.", "not_active", "admin_error")
    try:
        v = await rt.store.get(version)
        act = [e for e in v["events"] if e["event"] in policy_store_mod.ACTIVATING][-1]
        result = await git.publish(rt, v, act["event"], act["actor"], act["actor_via"], act["comment"])
        await git.record(rt.store, version, result)
    except policy_git_mod.GitError as e:
        try:
            await git.record(rt.store, version, None, str(e))
        except policy_store_mod.StoreError:
            pass
        return _openai_error(502, str(e), "git_error", "admin_error")
    except policy_store_mod.StoreError as e:
        return _store_error(e)
    admin_log.info("policy_version_mirrored version=%s actor=%s", version, actor[0])
    return {"version": version, "event": "mirrored", "git": {"status": "mirrored", **result}}


@app.get("/v1/policy/git")
async def policy_git_check(request: Request):
    """Git yansıtma ayarları (token yok) ve bağlantı denemesi: depo, dal, dosya (yazmadan)."""
    err, _, _ = await _policy_admin(request)
    if err:
        return err
    git = request.app.state.policy_git
    if not git:
        return {"enabled": False}
    try:
        check = {"ok": True, **(await git.client.check())}
    except policy_git_mod.GitError as e:
        check = {"ok": False, "error": str(e)}
    return {"enabled": True, **git.cfg.describe(), "check": check}


IMPACT_GROUPS = 20000


@app.post("/v1/policy/impact")
async def policy_impact(request: Request):
    """Taslağın son N günün gerçek trafiğine etkisi. Ham prompt saklanmadığı için metin yeniden
    taranmaz: kayıttaki bağlam (ekip, model, hedef, bulunan veri türleri, injection skoru)
    yayındaki ve taslak politikadan geçirilir. Tarayıcı eklentisi olayları (karar eklentide)
    hariç. Aynı bağlamdaki istekler gruplanır."""
    err, rt, _ = await _policy_admin(request)
    if err:
        return err
    st = request.app.state
    if st.ch is None:
        return _openai_error(404, "Etki analizi için CLICKHOUSE_URL gerekli.", "xray_disabled", "admin_error")
    body = await _json_body(request)
    try:
        days = max(1, min(int(body.get("days") or 7), 90))
    except (TypeError, ValueError):
        days = 7
    try:
        _, candidate = policy_store_mod.parse(str(body.get("content") or ""), rt.base)
    except policy_store_mod.StoreError as e:
        return _store_error(e)
    try:
        rows = await st.ch.query(f"""
            SELECT team, teams, model, destination, entities, round(injection_score, 2) AS score,
                   api_format, count() AS n, uniqExact(user) AS users
            FROM audit WHERE event_time >= now() - INTERVAL {{days:UInt32}} DAY AND api_format != 'browser'
            GROUP BY team, teams, model, destination, entities, score, api_format
            ORDER BY n DESC LIMIT {IMPACT_GROUPS}""", {"days": days})
    except xray_mod.ClickHouseError as e:
        return _openai_error(502, str(e), "clickhouse_error", "admin_error")

    current = st.policy
    before, after = Counter(), Counter()
    transitions, teams, rules_added, rules_removed = Counter(), Counter(), Counter(), Counter()
    examples = []
    for r in rows:
        n = int(r["n"])
        team_set = frozenset(r.get("teams") or []) | {r["team"]}
        ctx = Context(r["team"], r["model"], r["destination"], set(r.get("entities") or []),
                      float(r.get("score") or 0), frozenset(r.get("teams") or []),
                      compliance.is_declared(st.inventory, team_set, r["model"]))
        fmt_name = r.get("api_format") or ""
        (old_action, old), (new_action, new) = (_impact_outcome(st, current, ctx, fmt_name),
                                                _impact_outcome(st, candidate, ctx, fmt_name))
        before[old_action] += n
        after[new_action] += n
        for name in set(new.rules) - set(old.rules):
            rules_added[name] += n
        for name in set(old.rules) - set(new.rules):
            rules_removed[name] += n
        if old_action != new_action:
            transitions[(old_action, new_action)] += n
            teams[r["team"]] += n
            if len(examples) < 12:
                examples.append({"team": r["team"], "model": r["model"], "destination": r["destination"],
                                 "entities": r.get("entities") or [], "injection_score": r.get("score"),
                                 "requests": n, "users": int(r.get("users") or 0),
                                 "from": old_action, "to": new_action, "rules": new.rules, "reason": new.reason})
    total = sum(before.values())
    return {
        "days": days, "requests": total, "groups": len(rows), "truncated": len(rows) >= IMPACT_GROUPS,
        "changed": sum(transitions.values()),
        "before": dict(before), "after": dict(after),
        "transitions": [{"from": a, "to": b, "requests": n} for (a, b), n in transitions.most_common()],
        "teams": [{"team": t, "requests": n} for t, n in teams.most_common(10)],
        "rules_added": [{"rule": k, "requests": n} for k, n in rules_added.most_common(10)],
        "rules_removed": [{"rule": k, "requests": n} for k, n in rules_removed.most_common(10)],
        "examples": examples,
    }


# ---------------- guardrail servisi (LiteLLM, agentgateway; bkz. guardrail.py) ----------------

def _require_guardrail(request: Request) -> Optional[JSONResponse]:
    """GUARDRAIL_TOKEN: çağıran gateway'e verilen güven (kimlik başlıklarını o beyan eder).
    LiteLLM api_key'i x-api-key ile gönderir; agentgateway başlığı yapılandırmada verilir."""
    expected = os.getenv("GUARDRAIL_TOKEN", "")
    if not expected:
        return _openai_error(404, "Guardrail servisi kapalı (GUARDRAIL_TOKEN tanımlı değil).",
                             "guardrail_disabled", "admin_error")
    header = request.headers.get("authorization", "")
    given = header[7:].strip() if header.lower().startswith("bearer ") else request.headers.get("x-api-key", "")
    if not given or not hmac.compare_digest(given.encode(), expected.encode()):
        return _openai_error(401, "Geçersiz guardrail token'ı.", "unauthorized", "authentication_error")
    return None


async def _guardrail_body(request: Request):
    try:
        body = await request.json()
    except ValueError:
        body = None
    if not isinstance(body, dict):
        return None, _openai_error(400, "Gövde bir JSON nesnesi olmalı.", "invalid_request", "invalid_request_error")
    return body, None


def _guardrail_destination(call: guardrail_mod.Call) -> Optional[str]:
    """Çağıranın bildirdiği hedef yalnızca daha SIKI olabilir (external). "internal" bildirimi
    maskelemeyi kapatır: istemci bu alanı istek bazında verebiliyorsa (ör. gateway'in istek
    düzeyindeki guardrail parametreleri) yurt dışı modele maskesiz veri gider. Kurum içi takma
    adlar politikadaki destinations.internal'a yazılır; bildirime güvenmek için
    GUARDRAIL_TRUST_DESTINATION=1. None: modelden çıkar (model de yoksa yurt dışı)."""
    if call.destination == "internal" and os.getenv("GUARDRAIL_TRUST_DESTINATION", "0") != "1":
        log.warning("guardrail_destination_ignored source=%s model=%s (GUARDRAIL_TRUST_DESTINATION)",
                    call.source, call.model[:80])
        return None if call.model else "external"
    return call.destination or (None if call.model else "external")


async def guardrail_input(st, call: guardrail_mod.Call) -> guardrail_mod.Verdict:
    """İstek fazı: gateway'in kendi yoluyla aynı tarama, politika, istisnalar ve maskeleme.
    Model bilinmiyorsa hedef yurt dışı (güvenli varsayılan). Yönlendirme yok: modeli çağıran seçer."""
    t0 = time.perf_counter()
    identity = Identity(call.user or "unknown", call.teams or ["default"], "guardrail")
    body = {"model": call.model, "messages": [{"role": r, "content": t} for r, t in zip(call.roles, call.texts)]}
    a = _analyze(st, body, identity, CHAT, destination=_guardrail_destination(call))
    d = a.decision
    vault: Dict[str, str] = {}
    masked_prompt = _mask_parts(st, a.parts, d, vault, part_findings=a.part_findings)
    action = "block" if d.action == "block" else "mask" if vault else "pass"
    metrics.GUARDRAIL_CHECKS.labels(call.source, "request", action).inc()
    for entity in a.entities:
        metrics.ENTITIES.labels(entity, "input").inc()
    if a.injection.score >= 0.5:
        metrics.INJECTIONS.inc()

    ev = st.audit.build_event(
        user=a.user, team=a.team, model=call.model, destination=a.destination, decision=d,
        entities=a.entities, injection=a.injection, prompt=a.full_text, masked_prompt=masked_prompt,
        latency_ms=(time.perf_counter() - t0) * 1000, upstream_status=0)
    # Upstream'i çağıran gateway: token / maliyet burada bilinmez ("bedava" değil)
    ev.update(teams=a.identity.teams, auth_source="guardrail", api_format="guardrail",
              rules=d.rules + [f"guardrail:{call.source}"], subject_hashes=a.subject_hashes,
              prompt_tokens=0, completion_tokens=0, usage_known=0, est_cost_usd=None, masked_count=len(vault))
    await _emit(st, ev)
    if action == "block":
        return guardrail_mod.Verdict("block", call.texts, d.reason or "engellendi")

    if call.session_id:
        # Sızıntı karşılaştırması için girdide bulunan değerler (yalnızca çıktı kuralı varsa)
        known = sorted({a.all_text[f.start:f.end] for f in st.pii.analyze(a.all_text)}) \
            if st.policy.output_rules else []
        await st.guardrail_sessions.put(call.source, call.session_id, guardrail_mod.Session(
            vault, known, {"user": a.user, "teams": a.identity.teams, "model": call.model,
                           "destination": a.destination, "declared": a.ctx.declared}))
    texts = [m["content"] for m in body["messages"]]
    return guardrail_mod.Verdict(action, texts, "Kişisel veri / sır maskelendi." if vault else "")


async def guardrail_output(st, call: guardrail_mod.Call) -> guardrail_mod.Verdict:
    """Cevap fazı: sızıntı (girdide olmayan PII / sır) -> çıktı kuralları -> maskeyi geri aç.
    Stream'de (LiteLLM) her tur birikmiş metinle gelir: sızıntı bir kez kayda yazılır."""
    session = await st.guardrail_sessions.get(call.source, call.session_id) if call.session_id else None
    if session is None:
        metrics.GUARDRAIL_SESSION_MISSES.labels(call.source).inc()
        session = guardrail_mod.Session(ctx={"user": call.user, "teams": call.teams, "model": call.model,
                                             "destination": _guardrail_destination(call) or "external"})
    c = session.ctx
    teams = list(c.get("teams") or []) or ["default"]
    ctx = Context(teams[0], c.get("model") or "", c.get("destination") or "external", set(), 0.0,
                  frozenset(teams), c.get("declared"))
    known, known_values = set(session.known), KnownValues(session.vault)
    scanned, output_entities = [], set()
    for text in call.texts:
        findings = st.pii.analyze(text)
        output_entities |= {f.entity for f in findings}
        scanned.append((text, [f for f in findings
                               if text[f.start:f.end] not in known and text[f.start:f.end] not in known_values]))
    leaked = {f.entity for _, leaks in scanned for f in leaks}
    out = st.policy.evaluate_output(ctx, leaked)

    if leaked and not session.leak_reported:
        for entity in leaked:
            metrics.ENTITIES.labels(entity, "output_leak").inc()
        metrics.OUTPUT_ACTIONS.labels(out.action).inc()
        recorded = Decision("block" if out.action == "block" else "allow", set(),
                            [f"guardrail:{call.source}", "guardrail:cevap"], out.reason or "")
        ev = st.audit.build_event(
            user=c.get("user") or "unknown", team=teams[0], model=ctx.model, destination=ctx.destination,
            decision=recorded, entities=set(), injection=InjectionResult(0.0, engine=""), prompt="",
            masked_prompt=None, latency_ms=0, upstream_status=0)
        ev.update(teams=teams, auth_source="guardrail", api_format="guardrail",
                  output_entities=sorted(output_entities), output_leaked=sorted(leaked),
                  output_action=out.action, output_rules=out.rules, monitored_rules=out.monitored_rules,
                  prompt_tokens=0, completion_tokens=0, usage_known=0, est_cost_usd=None, masked_count=0)
        await _emit(st, ev)
        if call.session_id:
            session.leak_reported = True
            await st.guardrail_sessions.put(call.source, call.session_id, session)

    if out.action == "block":
        metrics.GUARDRAIL_CHECKS.labels(call.source, "response", "block").inc()
        return guardrail_mod.Verdict("block", call.texts, f"model cevabı engellendi ({out.reason})")
    texts = [st.pii.unmask(_redact(text, leaks, out.mask_entities) if out.action == "mask" else text,
                           session.vault) for text, leaks in scanned]
    changed = texts != call.texts
    # Stream: yarım yer tutucu ve (çıktı kuralı ya da sahte değer varsa) yarım değer sonraki tura beklesin:
    # yarısı gönderilmiş sahte numara geri açılamaz
    synthetic = any(not is_placeholder(k) for k in session.vault)
    hold = [guardrail_mod.holdback(t, placeholders=bool(session.vault),
                                   tokens=bool(st.policy.output_rules) or synthetic)
            for t in texts]
    action = "mask" if changed else "pass"
    metrics.GUARDRAIL_CHECKS.labels(call.source, "response", action).inc()
    return guardrail_mod.Verdict(action, texts, "Telveguard" if changed else "", hold)


@app.post("/beta/litellm_basic_guardrail_api")
async def guardrail_litellm(request: Request):
    """LiteLLM Generic Guardrail API (guardrail: generic_guardrail_api). Örnek: deploy/guardrail/litellm.yaml"""
    if err := _require_guardrail(request):
        return err
    body, err = await _guardrail_body(request)
    if err:
        return err
    try:
        call = guardrail_mod.parse_litellm(body)
    except guardrail_mod.GuardrailInputError as e:
        return _openai_error(400, str(e), "invalid_request", "invalid_request_error")
    st = request.app.state
    verdict = await (guardrail_input(st, call) if call.phase == "request" else guardrail_output(st, call))
    return guardrail_mod.format_litellm(verdict)


@app.post("/v1/guardrail/agentgateway/{phase}")
async def guardrail_agentgateway(request: Request, phase: str):
    """agentgateway Guardrail Webhook API (promptGuard webhook). Örnek: deploy/guardrail/agentgateway.yaml"""
    if phase not in ("request", "response"):
        return _openai_error(404, "Bilinmeyen faz (request | response).", "not_found", "invalid_request_error")
    if err := _require_guardrail(request):
        return err
    body, err = await _guardrail_body(request)
    if err:
        return err
    try:
        call = guardrail_mod.parse_agentgateway(phase, body, request.headers)
    except guardrail_mod.GuardrailInputError as e:
        return _openai_error(400, str(e), "invalid_request", "invalid_request_error")
    st = request.app.state
    verdict = await (guardrail_input(st, call) if phase == "request" else guardrail_output(st, call))
    return guardrail_mod.format_agentgateway(phase, verdict, call.roles)


# ---------------- ağ tarafı (ICAP: kurum proxy'si, masaüstü uygulamaları) ----------------

def _icap_identity(req: icap_mod.IcapRequest) -> Identity:
    """Proxy'nin doğruladığı kullanıcı. Gruplar OIDC'deki gibi önekle ekibe çevrilir."""
    user = icap_mod.proxy_user(req.headers)
    if not user:
        ip = req.headers.get("x-client-ip", "")
        user = f"ip:{ip}" if ip and len(ip) <= 45 else "unknown"
    prefix = os.getenv("ICAP_TEAM_PREFIX", os.getenv("OIDC_TEAM_PREFIX", ""))
    groups = icap_mod.proxy_groups(req.headers)
    teams = [g[len(prefix):] for g in groups if g.startswith(prefix) and len(g) > len(prefix)] if prefix else groups
    return Identity(user=user, teams=teams, source="icap", groups=groups)


async def icap_check(st, req: icap_mod.IcapRequest, http: icap_mod.HttpRequest, site: icap_mod.Site,
                     text: str, unscannable: bool):
    """Proxy'den gelen bir AI isteği: geçir ya da durdur. Maskeleme yok (bkz. icap.py); politika
    "maskele" diyorsa durdurulur. Prompt gönderimleri her zaman, diğer istekler yalnızca bir şey
    bulunursa kayda geçer. Dönen: (durdur mu, kullanıcıya mesaj)."""
    t0 = time.perf_counter()
    identity = _icap_identity(req)
    body = {"model": site.host, "messages": [{"role": "user", "content": text}]}
    a = _analyze(st, body, identity, CHAT, destination="external")
    d = a.decision
    rules = list(d.rules)
    if d.action in ("block", "mask"):
        action = "block"
    elif req.body_truncated and os.getenv("ICAP_OVERSIZE", "block") == "block":
        # Sınırın ötesi taranmadı: sona eklenen veri gözden kaçmasın (ICAP_OVERSIZE=allow ile geçer)
        action = "block"
        rules.append("ag:boyut-siniri")
    elif unscannable and os.getenv("ICAP_UNSCANNABLE", "allow") == "block":
        action = "block"
        rules.append("ag:okunamadi")
    else:
        action = "alert" if d.action == "alert" else "allow"
    entities = sorted(a.entities)
    if action == "block":
        found = ", ".join(entities) or d.reason or ("taranabilir boyutu aşan içerik" if "ag:boyut-siniri" in rules
                                                    else "okunamayan içerik")
        message = (f"Telveguard: {site.name} isteği {found} içerdiği için gönderilmedi. "
                   "Veriyi çıkarın ya da kurumun onaylı yapay zekâ aracını kullanın.")
    else:
        message = ""
    metrics.ICAP_CHECKS.labels(action).inc()
    for entity in entities:
        metrics.ENTITIES.labels(entity, "input").inc()
    if site.prompt or action != "allow" or entities or d.monitored_rules or a.injection.score >= 0.5:
        # Gölge AI bölümleri (Röntgen, POC raporu) "golge-ai:" kurallarını sayar
        rules += ["ag:icap", "golge-ai:blocked" if action == "block" else "golge-ai:network"]
        recorded = Decision(action, set(), rules, d.reason or (message if action == "block" else ""),
                            d.monitored_rules, d.would_action)
        ev = st.audit.build_event(
            user=a.user, team=a.team, model=site.host, destination="external", decision=recorded,
            entities=a.entities, injection=a.injection, prompt=text, masked_prompt=None,
            latency_ms=(time.perf_counter() - t0) * 1000, upstream_status=0)
        ev.update(teams=a.identity.teams, auth_source="icap", api_format="icap",
                  subject_hashes=a.subject_hashes, prompt_tokens=0, completion_tokens=0,
                  usage_known=0, est_cost_usd=None, masked_count=0)
        await _emit(st, ev)
    return action == "block", message
