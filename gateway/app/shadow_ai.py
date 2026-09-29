"""
Gölge AI: tarayıcı eklentisinden (extension/) gelen olaylar.

Eklenti ChatGPT, Claude.ai, Gemini gibi sitelere yapıştırılan metni tarayıcıda tarar; bu uca
yalnızca olay bilgisi gönderir: site, veri TÜRLERİ, kullanıcının kararı. Metnin kendisi
ASLA gönderilmez. Olaylar normal denetim hattına (Kafka -> ClickHouse) api_format=browser
olarak yazılır; Röntgen'de kendiliğinden görünür.

Kimlik: eklenti kurumun MDM'i ile dağıtılır; kullanıcı / ekip MDM yapılandırmasından gelir
(kendi beyanıdır, JWT gibi doğrulanmaz). Uç SHADOW_AI_TOKEN ile korunur; tanımlı değilse kapalı.
Tüm alanlar sıkı doğrulanır: bu uç kimliği doğrulanmamış tarayıcılardan veri kabul eder.
"""
import re
import time
import uuid
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field, field_validator

from telveguard_core.pii.secret_recognizers import SECRET_RECOGNIZERS
from telveguard_core.pii.tr_recognizers import TR_RECOGNIZERS

KNOWN_ENTITIES = {r.entity for r in TR_RECOGNIZERS + SECRET_RECOGNIZERS} | {"PERSON", "LOCATION", "ORGANIZATION"}
_SITE = re.compile(r"^[a-z0-9.-]{3,100}$")
_IDENT = re.compile(r"^[\w.@+-]{1,200}$", re.UNICODE)

# Eklentideki kullanıcı kararı -> denetim kaydındaki politika aksiyonu
ACTIONS = {
    "blocked": "block",           # engelleme modu: yapıştırma engellendi
    "masked": "mask",             # kullanıcı "maskeleyerek yapıştır"ı seçti
    "cancelled": "block",         # kullanıcı vazgeçti
    "allowed_override": "alert",  # kullanıcı uyarıya rağmen olduğu gibi yapıştırdı
    "visit": "allow",             # (opsiyonel) AI sitesi ziyareti; KVKK: çalışan bilgilendirilmeli
}


TRIGGERS = {"paste": "Tarayıcı: yapıştırma sırasında", "send": "Tarayıcı: gönderim sırasında"}


class ShadowEvent(BaseModel):
    site: str
    action: Literal["blocked", "masked", "cancelled", "allowed_override", "visit"]
    # Nerede yakalandı: yapıştırma ya da gönderim (Enter / gönder düğmesi). Eski eklentiler göndermez.
    trigger: Optional[Literal["paste", "send"]] = None
    entities: Dict[str, int] = Field(default_factory=dict)   # tür -> adet (değer YOK)
    chars: int = Field(0, ge=0, le=10_000_000)
    user: str = "unknown"
    team: str = "default"
    extension_version: str = ""

    @field_validator("site")
    @classmethod
    def _site(cls, v: str) -> str:
        v = v.lower()
        if not _SITE.match(v):
            raise ValueError("site bir alan adı olmalı")
        return v

    @field_validator("entities")
    @classmethod
    def _entities(cls, v: Dict[str, int]) -> Dict[str, int]:
        unknown = set(v) - KNOWN_ENTITIES
        if unknown:
            raise ValueError(f"bilinmeyen veri türü: {', '.join(sorted(unknown))}")
        if any(not isinstance(n, int) or n < 0 or n > 100_000 for n in v.values()):
            raise ValueError("adetler 0-100000 arası tamsayı olmalı")
        return v

    @field_validator("user", "team")
    @classmethod
    def _ident(cls, v: str) -> str:
        if not _IDENT.match(v):
            raise ValueError("kullanıcı / ekip adı geçersiz karakter içeriyor")
        return v

    @field_validator("extension_version")
    @classmethod
    def _version(cls, v: str) -> str:
        if v and not re.fullmatch(r"[0-9.]{1,20}", v):
            raise ValueError("sürüm biçimi geçersiz")
        return v


class ShadowBatch(BaseModel):
    events: List[ShadowEvent] = Field(max_length=100)


def to_audit_event(e: ShadowEvent) -> Dict[str, Any]:
    """Denetim şemasıyla aynı alanlar: Röntgen / KVKK / envanter sorguları değişmeden çalışır."""
    entities = sorted(e.entities)
    action = ACTIONS[e.action]
    return {
        "event_id": str(uuid.uuid4()), "ts": int(time.time() * 1000),
        "user": e.user, "team": e.team, "model": e.site, "destination": "external",
        "action": action, "rules": [f"golge-ai:{e.action}"], "reason": TRIGGERS.get(e.trigger, ""),
        "entities": entities, "injection_score": 0.0, "injection_engine": "browser",
        "prompt_sha256": "0" * 64, "prompt_chars": e.chars, "masked_prompt": "",
        "latency_ms": 0.0, "upstream_status": 0,
        "monitored_rules": [], "would_action": action,
        # "masked": kullanıcı maskeli yapıştırdı -> türler maskelenerek gitti
        "masked_entities": entities if e.action == "masked" else [],
        "prompt_tokens": 0, "completion_tokens": 0, "usage_known": 0, "est_cost_usd": None,
        "teams": [e.team], "auth_source": "browser_extension", "api_format": "browser",
        "output_entities": [], "output_leaked": [], "output_action": "", "output_rules": [],
        "masked_count": sum(e.entities.values()) if e.action == "masked" else 0,
        "output_scan": "", "quota": "",
    }


def check_token(given: Optional[str], expected: str) -> bool:
    import hmac
    return bool(expected) and bool(given) and hmac.compare_digest(given.encode(), expected.encode())
