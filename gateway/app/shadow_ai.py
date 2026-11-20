"""
Gölge AI: tarayıcı eklentisinden (extension/) gelen olaylar.

Eklenti ChatGPT, Claude.ai, Gemini gibi sitelere yapıştırılan metni tarayıcıda tarar; bu uca
yalnızca olay bilgisi gönderir: site, veri TÜRLERİ, kullanıcının kararı. Metnin kendisi
ASLA gönderilmez. Olaylar normal denetim hattına (Kafka -> ClickHouse) api_format=browser
olarak yazılır; Röntgen'de kendiliğinden görünür.

Kimlik: eklenti kurumun MDM'i ile dağıtılır; kullanıcı / ekip MDM yapılandırmasından gelir
(kendi beyanıdır, JWT gibi doğrulanmaz). Uç SHADOW_AI_TOKEN ile korunur; tanımlı değilse kapalı.
Tüm alanlar sıkı doğrulanır: bu uç kimliği doğrulanmamış tarayıcılardan veri kabul eder.

Token MDM ile her tarayıcıya dağıtıldığı için fiilen herkestedir: ele geçiren biri başkası adına
olay yazabilir. Bu yüzden kayıtta kaynak `browser_extension` (beyan) olarak işaretlidir ve uç hız
sınırlıdır (RateLimiter): beyan edilen kullanıcı başına ve worker genelinde dakikalık olay sayısı.
Eklenti 429'da olayları kuyrukta tutar, sonra yeniden dener.
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
    "redirected": "block",        # kullanıcı kurumun onaylı AI aracına geçti; dış siteye gitmedi
}
# "Yine de" gerekçesi (kullanıcının seçimi; serbest metin yok)
JUSTIFICATIONS = {"consent": "Müşteri / ilgili kişi onayı", "test_data": "Test / sahte veri",
                  "false_positive": "Yanlış alarm", "other": "Diğer"}


TRIGGERS = {"paste": "Tarayıcı: yapıştırma sırasında", "send": "Tarayıcı: gönderim sırasında",
            "file": "Tarayıcı: dosya eklerken", "banner": "Tarayıcı: bilgilendirme bandından",
            "live": "Tarayıcı: yazarken (canlı uyarı)"}
# Kurumsal sözlük türleri (dictionary.py ile aynı biçim): politikaya göre değişir, adla doğrulanır
_DICT_ENTITY = re.compile(r"^KURUM_[A-Z0-9_]{1,40}$")


class ShadowEvent(BaseModel):
    site: str
    action: Literal["blocked", "masked", "cancelled", "allowed_override", "visit", "redirected"]
    # Nerede yakalandı: yapıştırma, gönderim (Enter / gönder düğmesi) ya da dosya ekleme
    # (sürükle-bırak / dosya seçme), bilgilendirme bandı ya da yazarken uyarı. Eski eklentiler göndermez.
    trigger: Optional[Literal["paste", "send", "file", "banner", "live"]] = None
    justification: Optional[Literal["consent", "test_data", "false_positive", "other"]] = None
    preview_unavailable: bool = False   # eklentinin önizleme çerçevesi bu sitede açılamadı (sitenin CSP'si)
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
        unknown = {e for e in v if e not in KNOWN_ENTITIES and not _DICT_ENTITY.match(e)}
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
    rules = [f"golge-ai:{e.action}"]
    reason = TRIGGERS.get(e.trigger, "")
    if e.justification and e.action == "allowed_override":
        rules.append(f"golge-ai:gerekce:{e.justification}")
        reason = " · ".join(x for x in (reason, "Gerekçe: " + JUSTIFICATIONS[e.justification]) if x)
    if e.preview_unavailable:
        rules.append("golge-ai:onizleme-acilamadi")
    return {
        "event_id": str(uuid.uuid4()), "ts": int(time.time() * 1000),
        "user": e.user, "team": e.team, "model": e.site, "destination": "external",
        "action": action, "rules": rules, "reason": reason,
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


class RateLimiter:
    """Dakikalık sabit pencere: kullanıcı başına (SHADOW_AI_USER_PER_MIN, 300) ve toplam
    (SHADOW_AI_GLOBAL_PER_MIN, 20000) olay. Sayaç worker içidir; amaç sahte olay seline karşı
    bir tavan (denetim kaydı, ClickHouse, bildirim kanalları), muhasebe değil."""

    def __init__(self, per_user: int, total: int, clock=time.monotonic):
        self.per_user, self.total, self.clock = per_user, total, clock
        self._window, self._users, self._all = -1, {}, 0

    @classmethod
    def from_env(cls) -> "RateLimiter":
        import os
        return cls(int(os.getenv("SHADOW_AI_USER_PER_MIN", "300")), int(os.getenv("SHADOW_AI_GLOBAL_PER_MIN", "20000")))

    def allow(self, events: List[ShadowEvent]) -> bool:
        """Tüm parti sığıyorsa sayar ve True; sığmıyorsa hiçbirini saymaz (eklenti partiyi yeniden dener)."""
        window = int(self.clock() // 60)
        if window != self._window:
            self._window, self._users, self._all = window, {}, 0
        counts: Dict[str, int] = {}
        for e in events:
            counts[e.user] = counts.get(e.user, 0) + 1
        if self._all + len(events) > self.total or \
                any(self._users.get(u, 0) + n > self.per_user for u, n in counts.items()):
            return False
        self._all += len(events)
        for u, n in counts.items():
            self._users[u] = self._users.get(u, 0) + n
        return True


def check_token(given: Optional[str], expected: str) -> bool:
    import hmac
    return bool(expected) and bool(given) and hmac.compare_digest(given.encode(), expected.encode())
