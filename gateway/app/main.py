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
import copy
import hmac
import logging
import os
import time
import uuid
from collections import Counter
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import date
from typing import Any, Dict, List, Optional, Set

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse

from . import attachments as attachments_mod
from . import compliance
from . import shadow_ai
from . import metrics
from . import notify as notify_mod
from . import providers as providers_mod
from . import xray as xray_mod
from .audit import AuditSink
from .auth import AuthError, Authenticator, Identity
from .quota import QuotaBackendError, QuotaManager
from .formats import CHAT, EMBEDDINGS, FORMATS, MESSAGES, RESPONSES, UPSTREAM_KEYS, UPSTREAMS, ApiFormat, Part  # noqa: F401
from telveguard_core.detectors.injection import InjectionDetector, InjectionResult
from telveguard_core.pii.engine import TrPiiEngine
from telveguard_core.policy import Context, Decision, PolicyEngine


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.pii = TrPiiEngine(enable_ner=os.getenv("ENABLE_TR_NER") == "1")
    app.state.injection = InjectionDetector()
    policy_path = os.getenv("POLICY_PATH", "policies/default.yaml")
    app.state.policy = PolicyEngine(policy_path)
    app.state.providers = providers_mod.load(policy_path)
    app.state.attachments = attachments_mod.load(policy_path)
    app.state.audit = AuditSink()
    await app.state.audit.start()
    if not hasattr(app.state, "http"):  # testlerde MockTransport enjekte edilebilir
        app.state.http = httpx.AsyncClient(timeout=httpx.Timeout(120, connect=5))
    app.state.notifier = notify_mod.load(policy_path)
    app.state.notifier.start(app.state.http)
    if not hasattr(app.state, "ch"):  # testlerde sahte ClickHouse enjekte edilebilir
        app.state.ch = xray_mod.ClickHouse.from_env(app.state.http)
    app.state.auth = Authenticator.from_env(app.state.http)
    app.state.quota = QuotaManager.from_env(app.state.policy.quotas)
    # AI sistem beyanları (EU AI Act envanteri); yoksa tüm kullanımlar "beyan edilmemiş"
    app.state.inventory = compliance.load_inventory(os.getenv("INVENTORY_PATH", "policies/inventory.yaml"))
    yield
    await app.state.notifier.stop()
    await app.state.audit.stop()
    await app.state.http.aclose()


admin_log = logging.getLogger("telveguard.admin")
app = FastAPI(title="Telveguard Gateway", version="0.2.1", lifespan=lifespan)


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
    """Yönetim uçları (simülatör, Röntgen, raporlar) iki yoldan biriyle açılır:
      * OIDC_ADMIN_GROUP (AUTH_MODE=jwt): bu gruptaki kullanıcının kendi JWT'si (önerilen)
      * TELVEGUARD_ADMIN_TOKEN: statik token (ör. otomasyon / geçiş dönemi)
    İkisi de yoksa uçlar kapalıdır: simülatör açık kalırsa saldırgan injection skorunu
    yoklayarak tespiti atlatmayı deneyebilir. Her başarılı erişim kimliğiyle loglanır."""
    expected = os.getenv("TELVEGUARD_ADMIN_TOKEN", "")
    auth = request.app.state.auth
    if not expected and not auth.admin_group:
        return _openai_error(404, "Yönetim uçları kapalı (OIDC_ADMIN_GROUP ya da TELVEGUARD_ADMIN_TOKEN "
                                  "tanımlı değil).", "admin_disabled", "admin_error")
    header = request.headers.get("authorization", "")
    given = header[7:].strip() if header.lower().startswith("bearer ") \
        else request.headers.get("x-telveguard-admin-token", "")
    if expected and given and hmac.compare_digest(given.encode(), expected.encode()):
        admin_log.info("admin_access via=static_token path=%s", request.url.path)
        return None
    if auth.admin_group and given.count(".") == 2:  # JWT biçimi
        try:
            identity = await auth.verify_token(given)
        except AuthError as e:
            return _openai_error(e.status, f"Telveguard: {e.message}", e.reason, "admin_error")
        if not auth.is_admin(identity):
            admin_log.warning("admin_denied user=%s path=%s", identity.user, request.url.path)
            return _openai_error(403, f"'{auth.admin_group}' grubunda değilsiniz.", "forbidden", "admin_error")
        admin_log.info("admin_access via=oidc user=%s path=%s", identity.user, request.url.path)
        return None
    return _openai_error(401, "Geçersiz yönetici kimliği.", "unauthorized", "admin_error")


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


async def _scan_analyze(st, body: Dict[str, Any], identity: Identity, fmt: ApiFormat = CHAT) -> Analysis:
    """Ekleri (görsel / PDF) tarar, sonra metinle birlikte politikadan geçirir."""
    scans = await st.attachments.scan(fmt.request_attachments(body))
    return _analyze(st, body, identity, fmt, scans)


def _analyze(st, body: Dict[str, Any], identity: Identity, fmt: ApiFormat = CHAT,
             scans: List[attachments_mod.Scan] = ()) -> Analysis:
    """Tarama + politika. Gerçek istek ve simülatör aynı yolu kullanır."""
    model = body.get("model", "") if isinstance(body.get("model"), str) else ""
    # Eşleşen sağlayıcının hedefi önce gelir: veri gerçekte nereye gidiyorsa karar ona göre
    provider, provider_error = st.providers.resolve(model, fmt.name)
    routed = provider or st.providers.first(model)
    destination = routed.destination if routed else st.policy.destination_of(model)
    parts = fmt.request_parts(body)
    # Eklerden okunan metin de taranır: görsele gömülü injection ("visual prompt injection") dahil
    full_text = "\n".join([p.text for p in parts if p.role in fmt.injection_roles]
                          + [s.text for s in scans if s.text and s.att.role in fmt.injection_roles])
    all_text = "\n".join([p.text for p in parts] + [s.text for s in scans if s.text])
    entity_counts = Counter(f.entity for f in st.pii.analyze(all_text))
    injection = st.injection.scan(full_text)
    ctx = Context(identity.team, model, destination, set(entity_counts), injection.score,
                  frozenset(identity.teams))
    decision = st.policy.evaluate(ctx)
    st.attachments.apply_unscannable(decision, list(scans), destination)
    return Analysis(identity, fmt, model, destination, body, parts, full_text, all_text,
                    entity_counts, injection, ctx, decision, provider, provider_error, list(scans))


async def _emit(st, ev: dict):
    """Denetim kaydı + (eşleşen kanal varsa) arka planda Slack / Teams / webhook bildirimi."""
    await st.audit.emit(ev)
    st.notifier.submit(ev)


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
    known_values = set(vault.values())
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
                scans: List[attachments_mod.Scan] = ()) -> Optional[str]:
    """Karar maskeleme gerektiriyorsa tüm parçaları (system ve araç argümanları dahil) ve ekleri
    (görsel karartma, PDF -> maskeli metin) yerinde maskeler; denetim için maskeli metni döndürür."""
    if decision.action != "mask" or not decision.mask_entities:
        return None
    for p in parts:
        p.set(st.pii.mask(p.text, list(decision.mask_entities), vault).text)
    notes = st.attachments.mask(st.pii, list(scans), decision.mask_entities, vault)
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
async def metrics_endpoint():
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
    a = await _scan_analyze(st, body, identity, fmt)
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
        ev.update(teams=a.identity.teams, auth_source=a.identity.source, api_format=fmt.name)
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
    masked_prompt = _mask_parts(st, a.parts, decision, vault, a.scans)

    wants_stream = bool(body.get("stream"))
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
        return StreamingResponse(relay(), status_code=resp.status_code,
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
        return StreamingResponse(fmt.buffered_sse(result), media_type="text/event-stream")
    return JSONResponse(result)


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
    a = await _scan_analyze(st, body, identity, MESSAGES)
    if a.decision.action == "block":
        return MESSAGES.error(403, f"Telveguard: {a.decision.reason}", "blocked")
    if a.provider_error:
        return MESSAGES.error(400, f"Telveguard: {a.provider_error}", "no_upstream")
    upstream = (a.provider.endpoint("count_tokens", a.model, request.headers) if a.provider
                else MESSAGES.upstream(a.destination, request.headers, path="/v1/messages/count_tokens"))
    if upstream is None:
        return MESSAGES.error(400, "Bu model için Anthropic upstream'i tanımlı değil.", "no_upstream")
    _mask_parts(st, a.parts, a.decision, {}, a.scans)
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
    a = await _scan_analyze(request.app.state, body, identity, fmt)
    d = a.decision
    originals = [p.text for p in a.parts]
    _mask_parts(request.app.state, a.parts, d, {}, a.scans)
    blocked = d.action == "block"
    parts = [{"role": p.role, "segments": _segments(request.app.state, text),
              "sent": None if blocked else p.text}
             for p, text in zip(a.parts, originals) if text.strip()]
    return {
        "format": fmt.name,
        "team": a.team,
        "teams": a.identity.teams,
        "model": a.model,
        "destination": a.destination,
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
    teams = sorted({t for r in pol.rules + pol.output_rules for t in (r.get("when") or {}).get("teams", [])})
    return {"default_action": pol.default_action, "mode": pol.mode, "destinations": pol.destinations,
            "rules": rules(pol.rules), "output_rules": rules(pol.output_rules), "teams": teams,
            "providers": request.app.state.providers.describe(),
            "notify": request.app.state.notifier.describe()}


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


# ---------------- Röntgen + KVKK raporu ----------------

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")


def _require_clickhouse(request: Request):
    ch = getattr(request.app.state, "ch", None)
    if ch is None:
        return None, _openai_error(503, "ClickHouse yapılandırılmamış (CLICKHOUSE_URL).",
                                   "clickhouse_disabled", "admin_error")
    return ch, None


@app.get("/xray", include_in_schema=False)
async def xray_page():
    """Dashboard sayfası veri içermez; veriyi yönetici token'ıyla /v1/xray'den çeker.
    Harici CDN yok (air-gapped)."""
    return FileResponse(os.path.join(STATIC_DIR, "xray.html"), media_type="text/html")


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

@app.post("/v1/shadow-ai/events")
async def shadow_ai_events(request: Request):
    """Tarayıcı eklentisinden olay toplu gönderimi. Metin YOK: site, veri türleri, karar.
    SHADOW_AI_TOKEN (MDM ile eklentiye dağıtılır) ile korunur; tanımlı değilse kapalı."""
    expected = os.getenv("SHADOW_AI_TOKEN", "")
    if not expected:
        return _openai_error(404, "Gölge AI toplama kapalı (SHADOW_AI_TOKEN tanımlı değil).",
                             "shadow_ai_disabled", "admin_error")
    header = request.headers.get("authorization", "")
    if not shadow_ai.check_token(header[7:].strip() if header.lower().startswith("bearer ") else None, expected):
        return _openai_error(401, "Geçersiz eklenti token'ı.", "unauthorized", "authentication_error")
    try:
        batch = shadow_ai.ShadowBatch.model_validate(await request.json())
    except ValueError as e:
        return _openai_error(400, f"Geçersiz olay: {str(e)[:300]}", "invalid_request", "invalid_request_error")
    for event in batch.events:
        await _emit(request.app.state, shadow_ai.to_audit_event(event))
        metrics.SHADOW_AI_EVENTS.labels(event.action).inc()
    return {"accepted": len(batch.events)}
