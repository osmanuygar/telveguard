"""
Telveguard Gateway - OpenAI uyumlu LLM güvenlik proxy'si.

Akış:  istemci -> [kimlik] -> [PII + injection tarama] -> [politika] ->
       (engelle | maskele | geçir) -> upstream LLM -> [maskeyi geri aç + çıktı tarama]
       -> istemci ;  her istek -> audit olayı (Kafka)

İstemciler sadece base_url değiştirerek bağlanır:
    OpenAI(base_url="http://telveguard-gateway:8080/v1", api_key="...")
"""
import copy
import hmac
import json
import os
import time
from collections import Counter
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse

from . import metrics
from . import xray as xray_mod
from .audit import AuditSink
from .auth import AuthError, Authenticator, Identity
from telveguard_core.detectors.injection import InjectionDetector
from telveguard_core.pii.engine import TrPiiEngine
from telveguard_core.detectors.injection import InjectionResult
from telveguard_core.policy import Context, Decision, PolicyEngine

UPSTREAMS = {
    "internal": os.getenv("UPSTREAM_INTERNAL_URL", "http://vllm:8000/v1"),
    "external": os.getenv("UPSTREAM_EXTERNAL_URL", "https://api.openai.com/v1"),
}
UPSTREAM_KEYS = {
    "internal": os.getenv("UPSTREAM_INTERNAL_KEY", ""),
    "external": os.getenv("UPSTREAM_EXTERNAL_KEY", ""),
}

# Injection taraması: dolaylı vektörler dahil (tool çıktıları, RAG içeriği).
# system/assistant uygulamanın kendi metni sayılır, injection için taranmaz.
SCANNED_ROLES = {"user", "tool", "function"}
# PII taraması TÜM rollerde yapılır: system prompt'a veya konuşma geçmişine
# gömülü kişisel veri de dışarı gider.


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.pii = TrPiiEngine(enable_ner=os.getenv("ENABLE_TR_NER") == "1")
    app.state.injection = InjectionDetector()
    app.state.policy = PolicyEngine(os.getenv("POLICY_PATH", "policies/default.yaml"))
    app.state.audit = AuditSink()
    await app.state.audit.start()
    if not hasattr(app.state, "http"):  # testlerde MockTransport enjekte edilebilir
        app.state.http = httpx.AsyncClient(timeout=httpx.Timeout(120, connect=5))
    if not hasattr(app.state, "ch"):  # testlerde sahte ClickHouse enjekte edilebilir
        app.state.ch = xray_mod.ClickHouse.from_env(app.state.http)
    app.state.auth = Authenticator.from_env(app.state.http)
    yield
    await app.state.audit.stop()
    await app.state.http.aclose()


app = FastAPI(title="Telveguard Gateway", version="0.1.0", lifespan=lifespan)


# ---------------- yardımcılar ----------------

def _iter_text_parts(messages: List[Dict[str, Any]]):
    """(mesaj, anahtar/indeks, metin) üçlüleri: hem düz string hem çok parçalı içerik."""
    for msg in messages:
        content = msg.get("content")
        if isinstance(content, str):
            yield msg, None, content
        elif isinstance(content, list):
            for i, part in enumerate(content):
                if isinstance(part, dict) and part.get("type") == "text":
                    yield msg, i, part.get("text", "")


def _set_text(msg, idx, text):
    if idx is None:
        msg["content"] = text
    else:
        msg["content"][idx]["text"] = text


def _openai_error(status: int, message: str, code: str,
                  type_: str = "telveguard_policy_violation") -> JSONResponse:
    return JSONResponse(status_code=status, content={
        "error": {"message": message, "type": type_, "code": code}
    })


def _upstream_error(resp: httpx.Response) -> JSONResponse:
    """Upstream hatası JSON değilse (ör. proxy'nin HTML 502 sayfası) OpenAI formatına sar."""
    try:
        return JSONResponse(status_code=resp.status_code, content=resp.json())
    except ValueError:
        return _openai_error(resp.status_code, f"Upstream hata döndü ({resp.status_code}).",
                             "upstream_error", "upstream_error")


def _as_sse(completion: dict):
    """Maskeleme yapıldığında stream'i tamponlayıp tek parça SSE olarak döndürür
    (yer tutucuların parça sınırında bölünmesini önlemek için)."""
    choice = completion["choices"][0]
    chunk = {
        "id": completion.get("id"), "object": "chat.completion.chunk",
        "created": completion.get("created"), "model": completion.get("model"),
        "choices": [{"index": 0, "delta": {"role": "assistant",
                     "content": choice["message"].get("content", "")},
                     "finish_reason": choice.get("finish_reason")}],
    }

    async def gen():
        yield f"data: {json.dumps(chunk, ensure_ascii=False)}\n\n"
        yield "data: [DONE]\n\n"
    return gen()


def _require_admin(request: Request) -> Optional[JSONResponse]:
    """Yönetim uçları (simülatör, Röntgen, raporlar) TELVEGUARD_ADMIN_TOKEN ile korunur.
    Token tanımlı değilse uçlar kapalıdır: simülatör açık kalırsa saldırgan injection
    skorunu yoklayarak tespiti atlatmayı deneyebilir."""
    expected = os.getenv("TELVEGUARD_ADMIN_TOKEN", "")
    if not expected:
        return _openai_error(404, "Yönetim uçları kapalı (TELVEGUARD_ADMIN_TOKEN tanımlı değil).",
                             "admin_disabled", "admin_error")
    auth = request.headers.get("authorization", "")
    given = auth[7:] if auth.lower().startswith("bearer ") else request.headers.get("x-telveguard-admin-token", "")
    if not hmac.compare_digest(given.encode(), expected.encode()):
        return _openai_error(401, "Geçersiz yönetici token'ı.", "unauthorized", "admin_error")
    return None


@dataclass
class Analysis:
    identity: Identity
    model: str
    destination: str
    messages: List[Dict[str, Any]]
    full_text: str                  # injection için taranan roller
    all_text: str                   # maskelemeden ÖNCEKİ tüm metin (çıktı sızıntısı karşılaştırması)
    entity_counts: Counter          # tüm rollerdeki PII/sır türleri ve adetleri
    injection: InjectionResult
    ctx: Context
    decision: Decision

    @property
    def user(self) -> str:
        return self.identity.user

    @property
    def team(self) -> str:
        return self.identity.team

    @property
    def entities(self) -> Set[str]:
        return set(self.entity_counts)


def _analyze(st, body: Dict[str, Any], identity: Identity) -> Analysis:
    """Tarama + politika. Gerçek istek ve simülatör aynı yolu kullanır."""
    model = body.get("model", "")
    destination = st.policy.destination_of(model)
    messages = body.get("messages", [])

    scanned = [t for m, _, t in _iter_text_parts(messages) if m.get("role") in SCANNED_ROLES]
    full_text = "\n".join(scanned)
    all_text = "\n".join(t for _, _, t in _iter_text_parts(messages))
    entity_counts = Counter(f.entity for f in st.pii.analyze(all_text))
    injection = st.injection.scan(full_text)
    ctx = Context(identity.team, model, destination, set(entity_counts), injection.score,
                  frozenset(identity.teams))
    decision = st.policy.evaluate(ctx)
    return Analysis(identity, model, destination, messages, full_text, all_text, entity_counts,
                    injection, ctx, decision)


def _auth_error(e: AuthError) -> JSONResponse:
    metrics.AUTH_FAILURES.labels(e.reason).inc()
    resp = _openai_error(e.status, f"Telveguard: {e.message}", e.reason, "authentication_error")
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


def _usage_fields(st, model: str, completion: Optional[dict]) -> Dict[str, Any]:
    """Röntgen için token + tahmini maliyet. usage yoksa (maskesiz stream, upstream hatası)
    token 0 ve maliyet None yazılır: "bilinmiyor", "bedava" değil."""
    usage = (completion or {}).get("usage") or {}
    pt, ct = int(usage.get("prompt_tokens") or 0), int(usage.get("completion_tokens") or 0)
    known = bool(usage)
    return {"prompt_tokens": pt, "completion_tokens": ct, "usage_known": int(known),
            "est_cost_usd": st.policy.estimate_cost_usd(model, pt, ct) if known else None}


def _mask_messages(st, messages, decision: Decision, vault: Dict[str, str]) -> Optional[str]:
    """Karar maskeleme gerektiriyorsa mesajları yerinde maskeler; denetim metnini döndürür."""
    if decision.action != "mask" or not decision.mask_entities:
        return None
    for msg, idx, text in list(_iter_text_parts(messages)):
        _set_text(msg, idx, st.pii.mask(text, list(decision.mask_entities), vault).text)
    # Maskeleme tüm rollere uygulandığı için denetim kaydı da hepsini içerir (system dahil)
    return "\n".join(t for _, _, t in _iter_text_parts(messages))


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
    t0 = time.perf_counter()
    request.state.destination = "none"  # kimlik / gövde hatasında (sınırlı etiket)
    try:
        return await _chat_completions(request, t0)
    finally:
        metrics.REQUEST_SECONDS.labels(request.state.destination).observe(time.perf_counter() - t0)


async def _chat_completions(request: Request, t0: float):
    st = request.app.state
    # Kimlik gövdeden ÖNCE: doğrulanmamış isteğin gövdesi işlenmez
    try:
        identity = await st.auth.authenticate(request.headers)
    except AuthError as e:
        return _auth_error(e)
    try:
        body = await request.json()
    except ValueError:
        return _openai_error(400, "Geçersiz JSON gövdesi.", "invalid_request", "invalid_request_error")
    if not isinstance(body, dict) or not isinstance(body.get("messages", []), list):
        return _openai_error(400, "Gövde bir nesne, 'messages' bir liste olmalı.",
                             "invalid_request", "invalid_request_error")

    # 1-2) Tarama + politika
    t_scan = time.perf_counter()
    a = _analyze(st, body, identity)
    metrics.SCAN_SECONDS.observe(time.perf_counter() - t_scan)
    model, destination, decision, messages = a.model, a.destination, a.decision, a.messages
    request.state.destination = destination
    metrics.REQUESTS.labels(decision.action, destination).inc()
    for entity in a.entities:
        metrics.ENTITIES.labels(entity, "input").inc()
    if a.injection.score >= 0.5:
        metrics.INJECTIONS.inc()

    async def audit(masked_prompt=None, upstream_status=None, **extra):
        ev = st.audit.build_event(
            user=a.user, team=a.team, model=model, destination=destination, decision=decision,
            entities=a.entities, injection=a.injection, prompt=a.full_text,
            masked_prompt=masked_prompt, latency_ms=(time.perf_counter() - t0) * 1000,
            upstream_status=upstream_status,
        )
        ev.update(teams=a.identity.teams, auth_source=a.identity.source)
        ev.update(extra)
        await st.audit.emit(ev)

    if decision.action == "block":
        # Upstream'e hiçbir şey gitmedi: maliyet kesin olarak 0
        await audit(prompt_tokens=0, completion_tokens=0, usage_known=1, est_cost_usd=0.0)
        return _openai_error(403, f"Telveguard: {decision.reason}", "blocked")

    # 3) Maskeleme (tüm konuşma boyunca ortak vault -> tutarlı yer tutucular)
    vault: Dict[str, str] = {}
    masked_prompt = _mask_messages(st, messages, decision, vault)

    # 4) Upstream'e ilet
    url = f"{UPSTREAMS[destination]}/chat/completions"
    headers = {"Content-Type": "application/json"}
    if UPSTREAM_KEYS[destination]:
        headers["Authorization"] = f"Bearer {UPSTREAM_KEYS[destination]}"

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
            await audit(masked_prompt, 502, output_scan="skipped_stream", **_usage_fields(st, model, None))
            return _openai_error(502, "Upstream'e ulaşılamadı.", "upstream_unreachable", "upstream_error")
        await audit(masked_prompt, resp.status_code, output_scan="skipped_stream", **_usage_fields(st, model, None))

        async def relay():
            async for chunk in resp.aiter_raw():
                yield chunk
            await resp.aclose()
        return StreamingResponse(relay(), status_code=resp.status_code,
                                 media_type="text/event-stream")

    body["stream"] = False
    t_up = time.perf_counter()
    try:
        resp = await st.http.post(url, json=body, headers=headers)
    except httpx.HTTPError:
        metrics.UPSTREAM_ERRORS.labels(destination, "unreachable").inc()
        await audit(masked_prompt, 502, **_usage_fields(st, model, None))
        return _openai_error(502, "Upstream'e ulaşılamadı.", "upstream_unreachable", "upstream_error")
    metrics.UPSTREAM_SECONDS.labels(destination).observe(time.perf_counter() - t_up)
    if resp.status_code >= 400:
        metrics.UPSTREAM_ERRORS.labels(destination, metrics.upstream_error_kind(resp.status_code)).inc()
        await audit(masked_prompt, resp.status_code, **_usage_fields(st, model, None))
        return _upstream_error(resp)

    completion = resp.json()

    # 5) Çıktı: sızıntı taraması (maske geri açılmadan ÖNCE) -> çıktı politikası -> maskeyi geri aç
    output_entities: Set[str] = set()
    scanned_outputs = []
    for choice in completion.get("choices", []):
        msg = choice.get("message", {})
        if isinstance(msg.get("content"), str):
            findings, leaks = _find_output_leaks(st, msg["content"], a.all_text, vault)
            output_entities |= {f.entity for f in findings}
            scanned_outputs.append((msg, leaks))
    leaked = {f.entity for _, leaks in scanned_outputs for f in leaks}
    out = st.policy.evaluate_output(a.ctx, leaked)
    for entity in leaked:
        metrics.ENTITIES.labels(entity, "output_leak").inc()
    if leaked:
        metrics.OUTPUT_ACTIONS.labels(out.action).inc()
    output_audit = dict(output_entities=sorted(output_entities), output_leaked=sorted(leaked),
                        output_action=out.action if leaked else "",
                        output_rules=out.rules,
                        monitored_rules=decision.monitored_rules + out.monitored_rules)

    if out.action == "block":
        await audit(masked_prompt, resp.status_code, masked_count=len(vault), **output_audit,
                    **_usage_fields(st, model, completion))
        return _openai_error(403, f"Telveguard: model cevabı engellendi ({out.reason}).", "output_blocked")

    for msg, leaks in scanned_outputs:
        if out.action == "mask":
            msg["content"] = _redact(msg["content"], leaks, out.mask_entities)
        msg["content"] = st.pii.unmask(msg["content"], vault)

    await audit(masked_prompt, resp.status_code, masked_count=len(vault), **output_audit,
                **_usage_fields(st, model, completion))

    if wants_stream:
        return StreamingResponse(_as_sse(completion), media_type="text/event-stream")
    return JSONResponse(completion)


@app.post("/v1/policy/simulate")
async def policy_simulate(request: Request):
    """Bir isteğin politikadan nasıl geçeceğini gösterir; upstream'e gitmez, denetime yazılmaz.
    Gövde /v1/chat/completions ile aynıdır; ekip/kullanıcı aynı header'lardan okunur."""
    if err := _require_admin(request):
        return err
    try:
        body = await request.json()
    except ValueError:
        return _openai_error(400, "Geçersiz JSON gövdesi.", "invalid_request", "invalid_request_error")
    if not isinstance(body, dict) or not isinstance(body.get("messages", []), list):
        return _openai_error(400, "Gövde bir nesne, 'messages' bir liste olmalı.",
                             "invalid_request", "invalid_request_error")

    body = copy.deepcopy(body)
    # Yönetici aracı: Authorization yönetici token'ını taşır; simüle edilecek kimlik
    # açıkça header'dan verilir (AUTH_MODE'dan bağımsız)
    h = request.headers
    teams = [t.strip() for t in h.get("x-telveguard-team", "default").split(",") if t.strip()]
    identity = Identity(h.get("x-telveguard-user", "simulate"), teams or ["default"], "simulate")
    a = _analyze(request.app.state, body, identity)
    d = a.decision
    vault: Dict[str, str] = {}
    _mask_messages(request.app.state, a.messages, d, vault)
    return {
        "team": a.team,
        "teams": a.identity.teams,
        "model": a.model,
        "destination": a.destination,
        "entities": dict(sorted(a.entity_counts.items())),
        "injection": {"score": a.injection.score, "engine": a.injection.engine,
                      "matched_rules": len(a.injection.matched)},
        "decision": {
            "action": d.action, "reason": d.reason, "rules": d.rules,
            "mask_entities": sorted(d.mask_entities),
            "monitored_rules": d.monitored_rules, "would_action": d.would_action,
        },
        # Engellenecekse upstream'e hiçbir şey gitmez
        "upstream_messages": None if d.action == "block" else a.messages,
    }


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
    if err := _require_admin(request):
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


@app.get("/v1/reports/kvkk-transfer")
async def kvkk_transfer_report(request: Request, month: str, format: str = "csv"):
    """Aylık KVKK md. 9 yurt dışı aktarım raporu: ekip x sağlayıcı x kişisel veri türü."""
    if err := _require_admin(request):
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
        rows = await xray_mod.kvkk_transfer(ch, month)
    except xray_mod.ClickHouseError as e:
        return _openai_error(502, str(e), "clickhouse_error", "admin_error")
    if format == "json":
        return {"month": month, "rows": rows}
    return Response(xray_mod.kvkk_csv(rows), media_type="text/csv; charset=utf-8", headers={
        "Content-Disposition": f'attachment; filename="kvkk-yurtdisi-aktarim-{month}.csv"'})
