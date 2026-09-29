"""
Ekip kota / hız sınırı. Politika dosyasındaki `quotas` bölümü:

    quotas:
      on_backend_error: open          # open: sayaç (Redis) çökerse istekleri geçir | closed: 503
      default:                        # tüm ekipler
        requests_per_minute: 300
      teams:                          # ekip bazında üzerine yazar
        stajyer: { requests_per_minute: 30, monthly_cost_usd: 25 }
        analitik: { monthly_tokens: 20000000 }

Limitler: requests_per_minute, monthly_tokens, monthly_cost_usd. Ay İstanbul saatine göre.
Kota, kullanıcının BİRİNCİL ekibine (token'daki ilk grup / x-telveguard-team) uygulanır.

Sayaç Redis'te (REDIS_URL): tüm pod ve worker'lar aynı sayacı görür. REDIS_URL yoksa
süreç içi bellek kullanılır; birden fazla worker/pod varken limitler worker başına olur
(yalnızca geliştirme). Aylık limit istek ÖNCESİ kontrol edilir, kullanım cevap SONRASI
eklenir: limitin aşıldığı istek tamamlanır, sonrakiler reddedilir (en fazla bir istek taşma).
"""
import logging
import os
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, Optional, Tuple
from zoneinfo import ZoneInfo

from .metrics import QUOTA_BACKEND_ERRORS

log = logging.getLogger("telveguard.quota")
TZ = ZoneInfo("Europe/Istanbul")
LIMIT_KEYS = ("requests_per_minute", "monthly_tokens", "monthly_cost_usd")
MONTH_TTL = 40 * 24 * 3600


class QuotaBackendError(Exception):
    pass


@dataclass
class QuotaExceeded:
    kind: str           # requests_per_minute | monthly_tokens | monthly_cost_usd
    limit: float
    used: float
    retry_after: int    # saniye

    @property
    def message(self) -> str:
        what = {"requests_per_minute": "dakikalık istek", "monthly_tokens": "aylık token",
                "monthly_cost_usd": "aylık maliyet (USD)"}[self.kind]
        return f"Ekip {what} kotası aşıldı ({self.used:g} / {self.limit:g})."


class MemoryBackend:
    """Tek süreç için (geliştirme / test)."""

    def __init__(self):
        self._counters: Dict[str, Tuple[int, float]] = {}
        self._usage: Dict[str, Dict[str, int]] = {}

    async def incr_window(self, key: str, ttl: int) -> int:
        now = time.time()
        count, expires = self._counters.get(key, (0, now + ttl))
        if expires < now:
            count, expires = 0, now + ttl
        self._counters[key] = (count + 1, expires)
        return count + 1

    async def get_usage(self, key: str) -> Tuple[int, int]:
        u = self._usage.get(key, {})
        return u.get("tokens", 0), u.get("cost_micro", 0)

    async def add_usage(self, key: str, tokens: int, cost_micro: int, ttl: int) -> None:
        u = self._usage.setdefault(key, {"tokens": 0, "cost_micro": 0})
        u["tokens"] += tokens
        u["cost_micro"] += cost_micro


class RedisBackend:
    def __init__(self, url: str, password: Optional[str] = None):
        import redis.asyncio as aioredis
        # Kısa zaman aşımı: sayaç yavaşlarsa LLM isteği beklemesin (on_backend_error devreye girer)
        self.r = aioredis.from_url(url, password=password or None, socket_timeout=0.5,
                                   socket_connect_timeout=0.5, decode_responses=True)

    async def _run(self, coro):
        try:
            return await coro
        except Exception as e:  # redis.exceptions.* + zaman aşımı
            raise QuotaBackendError(type(e).__name__) from e

    async def incr_window(self, key: str, ttl: int) -> int:
        async def go():
            async with self.r.pipeline(transaction=True) as p:
                p.incr(key)
                p.expire(key, ttl)
                count, _ = await p.execute()
                return int(count)
        return await self._run(go())

    async def get_usage(self, key: str) -> Tuple[int, int]:
        async def go():
            tokens, cost = await self.r.hmget(key, "tokens", "cost_micro")
            return int(tokens or 0), int(cost or 0)
        return await self._run(go())

    async def add_usage(self, key: str, tokens: int, cost_micro: int, ttl: int) -> None:
        async def go():
            async with self.r.pipeline(transaction=True) as p:
                p.hincrby(key, "tokens", tokens)
                p.hincrby(key, "cost_micro", cost_micro)
                p.expire(key, ttl)
                await p.execute()
        await self._run(go())


def validate_quotas(cfg: Dict[str, Any]) -> None:
    """Politika yüklenirken: yazım hatası sessizce 'limitsiz' olmasın."""
    if not cfg:
        return
    unknown = set(cfg) - {"on_backend_error", "default", "teams"}
    if unknown:
        raise ValueError(f"quotas: bilinmeyen alan(lar): {', '.join(sorted(unknown))}")
    if cfg.get("on_backend_error", "open") not in ("open", "closed"):
        raise ValueError("quotas.on_backend_error: open ya da closed olmalı")
    for where, limits in [("default", cfg.get("default") or {})] + \
            [(f"teams.{t}", v or {}) for t, v in (cfg.get("teams") or {}).items()]:
        bad = set(limits) - set(LIMIT_KEYS)
        if bad:
            raise ValueError(f"quotas.{where}: bilinmeyen limit(ler): {', '.join(sorted(bad))} "
                             f"(geçerli: {', '.join(LIMIT_KEYS)})")
        for k, v in limits.items():
            if not isinstance(v, (int, float)) or v < 0:
                raise ValueError(f"quotas.{where}.{k}: sıfır ya da pozitif bir sayı olmalı")


class QuotaManager:
    def __init__(self, cfg: Dict[str, Any], backend):
        validate_quotas(cfg)
        self.cfg = cfg or {}
        self.backend = backend
        self.fail_open = self.cfg.get("on_backend_error", "open") == "open"

    @classmethod
    def from_env(cls, cfg: Dict[str, Any]) -> "QuotaManager":
        url = os.getenv("REDIS_URL")
        if url:
            backend = RedisBackend(url, os.getenv("REDIS_PASSWORD"))
        else:
            backend = MemoryBackend()
            if cfg:
                log.warning("quotas tanımlı ama REDIS_URL yok: sayaç süreç içi bellekte; birden fazla "
                            "worker / pod varken limitler worker başına uygulanır (yalnızca geliştirme)")
        return cls(cfg, backend)

    @property
    def enabled(self) -> bool:
        return bool(self.cfg.get("default") or self.cfg.get("teams"))

    def limits_for(self, team: str) -> Dict[str, float]:
        limits = dict(self.cfg.get("default") or {})
        limits.update((self.cfg.get("teams") or {}).get(team) or {})
        return limits

    @staticmethod
    def _now() -> datetime:
        return datetime.now(TZ)

    def _month_key(self, team: str) -> Tuple[str, int]:
        now = self._now()
        nxt = (now.replace(day=1) + timedelta(days=32)).replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        return f"tg:q:m:{team}:{now:%Y-%m}", max(1, int((nxt - now).total_seconds()))

    async def check(self, team: str) -> Optional[QuotaExceeded]:
        """İstek ÖNCESİ. Dakikalık sayaç burada artar. Arka uç hatasında on_backend_error."""
        limits = self.limits_for(team)
        if not limits:
            return None
        try:
            rpm = limits.get("requests_per_minute")
            if rpm is not None:
                now = time.time()
                count = await self.backend.incr_window(f"tg:q:rpm:{team}:{int(now // 60)}", 120)
                if count > rpm:
                    return QuotaExceeded("requests_per_minute", rpm, count, max(1, 60 - int(now % 60)))
            if "monthly_tokens" in limits or "monthly_cost_usd" in limits:
                key, until_next = self._month_key(team)
                tokens, cost_micro = await self.backend.get_usage(key)
                if "monthly_tokens" in limits and tokens >= limits["monthly_tokens"]:
                    return QuotaExceeded("monthly_tokens", limits["monthly_tokens"], tokens, until_next)
                cost = cost_micro / 1_000_000
                if "monthly_cost_usd" in limits and cost >= limits["monthly_cost_usd"]:
                    return QuotaExceeded("monthly_cost_usd", limits["monthly_cost_usd"], round(cost, 4), until_next)
        except QuotaBackendError as e:
            QUOTA_BACKEND_ERRORS.inc()
            log.error("quota_backend_error error=%s fail_open=%s", e, self.fail_open)
            if self.fail_open:
                return None
            raise
        return None

    async def record(self, team: str, tokens: int, cost_usd: Optional[float]) -> None:
        """Cevap SONRASI: aylık kullanım. Hata isteği bozmaz (yalnızca loglanır)."""
        limits = self.limits_for(team)
        if not ("monthly_tokens" in limits or "monthly_cost_usd" in limits):
            return
        key, _ = self._month_key(team)
        try:
            await self.backend.add_usage(key, int(tokens), int(round((cost_usd or 0) * 1_000_000)), MONTH_TTL)
        except QuotaBackendError as e:
            QUOTA_BACKEND_ERRORS.inc()
            log.error("quota_record_failed error=%s", e)
