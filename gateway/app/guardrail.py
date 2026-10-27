"""
Guardrail servisi: başka bir AI gateway'i (LiteLLM, agentgateway) isteği modele göndermeden önce
Telveguard'a sorar, cevabı istemciye vermeden önce yine sorar. Karar, maskeleme, kayıt ve raporlar
Telveguard'da; yönlendirme, yük dengeleme, önbellek o gateway'de kalır.

    istemci -> LiteLLM / agentgateway --(istek)--> Telveguard: tara, politika, maskele -> karar
                         |                         (maske eşleşmesi oturumda saklanır)
                         v
                        model -> LiteLLM / agentgateway --(cevap)--> Telveguard: sızıntı, maskeyi aç

Uçlar (GUARDRAIL_TOKEN ile; Authorization: Bearer ya da x-api-key):
  POST /beta/litellm_basic_guardrail_api        LiteLLM Generic Guardrail API (istek + cevap)
  POST /v1/guardrail/agentgateway/request       agentgateway Guardrail Webhook API
  POST /v1/guardrail/agentgateway/response

İstek ile cevap OTURUMLA eşleşir: LiteLLM'de `litellm_call_id`, agentgateway'de yapılandırmanın
eklediği `x-telveguard-id` başlığı (transformation: `uuid()`). Oturumda maske eşleşmesi (vault),
girdide bulunan değerler (sızıntı karşılaştırması) ve bağlam (ekip, model, hedef) GUARDRAIL_SESSION_TTL
saniye (varsayılan 600) tutulur: REDIS_URL varsa Redis (tüm pod'lar), yoksa süreç belleği (tek pod).
Oturumda ham kişisel veri vardır: Redis erişimini kısıtlayın. Eşleşme yoksa maske kalıcıdır
(kullanıcı [TCKN_1] görür) ve sızıntı taraması girdiyi bilmeden yapılır.

Stream: LiteLLM `streaming_transform_mode: incremental_diff` ile cevabı birikmiş metin olarak
tekrar tekrar sorar; maske geri açılır, sızıntı istemciye gitmeden engellenir. Yarım kalan yer
tutucu ("[TCK") ve sondaki yarım kelime `stream_holdback_chars` ile bekletilir. agentgateway
stream'de yalnızca engelleyebilir (değiştirilen metni uygulamaz): kullanıcı yer tutucu görür.

Kimlik çağıran gateway'den gelir; GUARDRAIL_TOKEN o gateway'e verilen güvendir (ICAP'teki
ICAP_ALLOWED_CLIENTS gibi). Kota ve maliyet o gateway'de: kayıtta token / maliyet "bilinmiyor".
"""
import json
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger("telveguard.guardrail")

SOURCES = ("litellm", "agentgateway")
SESSION_ID_RX = re.compile(r"^[A-Za-z0-9._:-]{8,128}$")
MAX_TEXTS = 2000
MAX_CHARS = 2_000_000
# Akışın sonunda yarım kalabilecek parça: yer tutucu ("... [TCKN_") ya da sayı grupları / kelime
# ("TC 1000000", "TR33 0006 10", "ali@orn"): tamamlanmadan tanınamaz, gönderilirse geri alınamaz
_PARTIAL_PLACEHOLDER = re.compile(r"\[[A-Z0-9_]*$")
_PARTIAL_TOKEN = re.compile(r"(?:(?:\+?\d+|TR\d*)[ -])*\S*$", re.IGNORECASE)
MAX_HOLDBACK = 64
MEMORY_MAX_SESSIONS = 50_000   # REDIS_URL yokken süreç belleğindeki en fazla oturum


class GuardrailInputError(ValueError):
    pass


def holdback(text: str, placeholders: bool, tokens: bool) -> int:
    """Stream'de bir sonraki tura bekletilecek karakter sayısı."""
    n = 0
    if placeholders and (m := _PARTIAL_PLACEHOLDER.search(text)):
        n = len(m.group(0))
    if tokens and (m := _PARTIAL_TOKEN.search(text)):
        n = max(n, len(m.group(0)))
    return min(n, MAX_HOLDBACK)


# ---------------- oturum ----------------

@dataclass
class Session:
    vault: Dict[str, str] = field(default_factory=dict)   # yer tutucu -> gerçek değer
    known: List[str] = field(default_factory=list)        # girdide bulunan değerler (sızıntı değil)
    ctx: Dict[str, Any] = field(default_factory=dict)     # user, team, teams, model, destination, declared
    leak_reported: bool = False                           # stream'de her tur kayda yazılmasın

    def dumps(self) -> str:
        return json.dumps({"vault": self.vault, "known": self.known, "ctx": self.ctx,
                           "leak_reported": self.leak_reported}, ensure_ascii=False)

    @classmethod
    def loads(cls, raw: str) -> "Session":
        d = json.loads(raw)
        return cls(d.get("vault") or {}, d.get("known") or [], d.get("ctx") or {}, bool(d.get("leak_reported")))


class MemoryStore:
    """Tek süreç (geliştirme / tek pod)."""

    def __init__(self, ttl: int):
        self.ttl = ttl
        self._data: Dict[str, Tuple[float, str]] = {}

    async def get(self, key: str) -> Optional[Session]:
        item = self._data.get(key)
        if not item or item[0] < time.time():
            self._data.pop(key, None)
            return None
        return Session.loads(item[1])

    async def put(self, key: str, session: Session) -> None:
        now = time.time()
        if len(self._data) > 10_000:    # süresi geçenleri ara sıra temizle
            self._data = {k: v for k, v in self._data.items() if v[0] >= now}
            # Hâlâ çoksa (hepsi süresi içinde) en eskiler düşer: bellek sınırsız büyümesin
            while len(self._data) > MEMORY_MAX_SESSIONS:
                self._data.pop(next(iter(self._data)))
        self._data[key] = (now + self.ttl, session.dumps())


class RedisStore:
    def __init__(self, url: str, ttl: int, password: Optional[str] = None):
        import redis.asyncio as aioredis
        self.ttl = ttl
        # Kısa zaman aşımı: oturum deposu yavaşlarsa LLM isteği beklemesin (maske kalıcı olur)
        self.r = aioredis.from_url(url, password=password or None, socket_timeout=0.5,
                                   socket_connect_timeout=0.5, decode_responses=True)

    async def get(self, key: str) -> Optional[Session]:
        raw = await self.r.get(key)
        return Session.loads(raw) if raw else None

    async def put(self, key: str, session: Session) -> None:
        await self.r.set(key, session.dumps(), ex=self.ttl)


class Sessions:
    """Depo hatası isteği bozmaz: maske kalıcı olur, sızıntı girdiyi bilmeden taranır."""

    def __init__(self, store):
        self.store = store

    @classmethod
    def from_env(cls) -> "Sessions":
        import os
        ttl = int(os.getenv("GUARDRAIL_SESSION_TTL", "600"))
        url = os.getenv("REDIS_URL", "")
        return cls(RedisStore(url, ttl, os.getenv("REDIS_PASSWORD")) if url else MemoryStore(ttl))

    @staticmethod
    def key(source: str, session_id: str) -> str:
        return f"telveguard:guardrail:{source}:{session_id}"

    async def get(self, source: str, session_id: str) -> Optional[Session]:
        try:
            return await self.store.get(self.key(source, session_id))
        except Exception as e:  # redis.exceptions.* + zaman aşımı
            log.error("guardrail_session_get_failed source=%s error=%s", source, type(e).__name__)
            return None

    async def put(self, source: str, session_id: str, session: Session) -> bool:
        try:
            await self.store.put(self.key(source, session_id), session)
            return True
        except Exception as e:
            log.error("guardrail_session_put_failed source=%s error=%s", source, type(e).__name__)
            return False


# ---------------- gateway biçimleri ----------------

@dataclass
class Call:
    """Bir guardrail çağrısı, gateway'den bağımsız."""
    source: str                         # litellm | agentgateway
    phase: str                          # request | response
    roles: List[str]                    # metin başına rol (istek fazında)
    texts: List[str]
    session_id: str = ""
    model: str = ""
    destination: str = ""               # "" = modelden çıkar (model de yoksa yurt dışı)
    user: str = ""
    teams: List[str] = field(default_factory=list)


@dataclass
class Verdict:
    action: str                         # pass | mask | block
    texts: List[str]
    reason: str = ""
    holdback: List[int] = field(default_factory=list)


def _str_list(value: Any, where: str) -> List[str]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise GuardrailInputError(f"{where} bir metin listesi olmalı")
    if len(value) > MAX_TEXTS or sum(len(v) for v in value) > MAX_CHARS:
        raise GuardrailInputError(f"{where} çok büyük")
    return value


def _session_id(value: Any) -> str:
    return value if isinstance(value, str) and SESSION_ID_RX.match(value) else ""


def _destination(value: Any) -> str:
    return value if value in ("internal", "external") else ""


def parse_litellm(body: Dict[str, Any]) -> Call:
    """LiteLLM Generic Guardrail API isteği. Kimlik sanal anahtarın bilgilerinden; hedef
    additional_provider_specific_params.destination ile zorlanabilir (takma ad kurum içi modelse)."""
    phase = body.get("input_type")
    if phase not in ("request", "response"):
        raise GuardrailInputError("input_type request ya da response olmalı")
    texts = _str_list(body.get("texts") or [], "texts")
    roles = ["user"] * len(texts)
    msgs = body.get("structured_messages")
    # Rol yalnızca metinler mesajlarla birebir eşleşiyorsa alınır (injection taraması role bakar)
    if isinstance(msgs, list) and len(msgs) == len(texts) and all(
            isinstance(m, dict) and m.get("content") == t for m, t in zip(msgs, texts)):
        roles = ["tool" if m.get("role") in ("tool", "function") else str(m.get("role") or "user") for m in msgs]
    rd = body.get("request_data") if isinstance(body.get("request_data"), dict) else {}
    user = next((str(rd[k]) for k in ("user_api_key_user_email", "user_api_key_user_id", "user_api_key_end_user_id")
                 if rd.get(k)), "")
    team = next((str(rd[k]) for k in ("user_api_key_team_alias", "user_api_key_team_id") if rd.get(k)), "")
    params = body.get("additional_provider_specific_params")
    params = params if isinstance(params, dict) else {}
    return Call("litellm", phase, roles, texts, _session_id(body.get("litellm_call_id")),
                body.get("model") if isinstance(body.get("model"), str) else "",
                _destination(params.get("destination")), user, [team] if team else [])


def format_litellm(v: Verdict) -> Dict[str, Any]:
    if v.action == "block":
        return {"action": "BLOCKED", "blocked_reason": f"Telveguard: {v.reason}"}
    if v.action == "mask" or any(v.holdback):
        out: Dict[str, Any] = {"action": "GUARDRAIL_INTERVENED", "texts": v.texts}
        if any(v.holdback):
            out["stream_holdback_chars"] = v.holdback
        return out
    return {"action": "NONE"}


def parse_agentgateway(phase: str, body: Dict[str, Any], headers) -> Call:
    """agentgateway Guardrail Webhook API: istek fazında body.messages, cevapta body.choices.
    Oturum, model ve kimlik yapılandırmadaki CEL başlıklarından (bkz. deploy/guardrail/)."""
    inner = body.get("body") if isinstance(body.get("body"), dict) else {}
    if phase == "request":
        items = inner.get("messages")
        if not isinstance(items, list) or not all(isinstance(m, dict) for m in items):
            raise GuardrailInputError("body.messages bir mesaj listesi olmalı")
        texts = _str_list([m.get("content") if isinstance(m.get("content"), str) else "" for m in items],
                          "body.messages")
        roles = ["tool" if m.get("role") in ("tool", "function") else str(m.get("role") or "user") for m in items]
    else:
        items = inner.get("choices")
        if not isinstance(items, list) or not all(isinstance(c, dict) for c in items):
            raise GuardrailInputError("body.choices bir liste olmalı")
        texts = _str_list([(c.get("message") or {}).get("content") or "" for c in items], "body.choices")
        roles = ["assistant"] * len(texts)
    teams = [t.strip() for t in headers.get("x-telveguard-teams", "").split(",") if t.strip()]
    return Call("agentgateway", phase, roles, texts, _session_id(headers.get("x-telveguard-id")),
                headers.get("x-telveguard-model", ""), _destination(headers.get("x-telveguard-destination")),
                headers.get("x-telveguard-user", "").strip(), teams)


def format_agentgateway(phase: str, v: Verdict, roles: List[str]) -> Dict[str, Any]:
    if v.action == "block":
        error = json.dumps({"error": {"message": f"Telveguard: {v.reason}", "type": "telveguard_policy_violation",
                                      "code": "blocked"}}, ensure_ascii=False)
        return {"action": {"body": error, "status_code": 403, "reason": v.reason}}
    if v.action == "mask":
        if phase == "request":
            body = {"messages": [{"role": r, "content": t} for r, t in zip(roles, v.texts)]}
        else:
            body = {"choices": [{"message": {"role": "assistant", "content": t}} for t in v.texts]}
        return {"action": {"body": body, "reason": v.reason or "Telveguard"}}
    return {"action": {}}
