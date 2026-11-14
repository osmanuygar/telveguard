"""
Kullanıcı riski: anlık anomali uyarısı ve risk skoru raporu.

Anlık anomali (politikadaki `anomaly` bölümü): her denetim olayı kullanıcı başına sabit pencerede
sayılır; bir sinyal eşiğe ulaşınca pencerede BİR KEZ bildirim olayı üretilir (`anomali:<sinyal>`
kuralı). Olay denetim kaydına yazılmaz (Röntgen istek sayıları şişmesin), bildirim kanallarına gider:

    anomaly:
      window_minutes: 60
      thresholds:             # kullanıcı başına, pencere içinde
        subjects: 100         # yurt dışı modele giden farklı kişi tanımlayıcısı (TCKN, telefon, e-posta ...)
        blocked: 10           # engellenen istek
        overrides: 5          # tarayıcı eklentisinde uyarıya rağmen gönderim ("yine de")
        secrets: 3            # sır içeren istek
        injection: 3          # injection denemesi (skor >= 0,5)

    notify:
      channels:
        - { name: anomali, type: slack, url_env: SLACK_SECURITY_WEBHOOK_URL,
            when: { rules: ["anomali:*"] }, cooldown_seconds: 0 }

`subjects` farklı DEĞER sayar (Claude Code her turda tüm konuşmayı yeniden gönderir; aynı TCKN bir
kez sayılır) ve ilgili kişi özetlerini kullanır: `TELVEGUARD_SUBJECT_HASH_KEY` yoksa çalışmaz.
Sayaç kota ile aynı yerde (REDIS_URL; yoksa worker başına bellek). Sayaç hatası isteği bozmaz.

Risk skoru (`GET /v1/reports/risk`): ClickHouse kayıtlarından kullanıcı başına sinyaller, ağırlıklı
toplam ve 0-100 skor; her sinyalin katkısı ayrı döner ("neden riskli"). Son 24 saatteki riskli
istek kullanıcının kendi ortalamasının çok üstündeyse "ani artış" işaretlenir.

KVKK: bu bir çalışan izleme özelliğidir; aydınlatma metninde yer almalı. Ham metin kullanılmaz,
yalnızca denetim kaydındaki türler, kararlar ve özetler.
"""
import logging
import math
import time
import uuid
from typing import Any, Dict, List

from . import metrics
from .notify import effective_action
from .quota import QuotaBackendError
from .xray import _UNMASKED_PII, ClickHouse

from telveguard_core.policy import ANOMALY_SIGNALS

log = logging.getLogger("telveguard.risk")

SIGNALS = {   # sıra ve adlar telveguard_core.policy.ANOMALY_SIGNALS ile aynı
    "subjects": "farklı kişinin kimlik / iletişim bilgisi yurt dışı modele gitti",
    "blocked": "istek engellendi",
    "overrides": "uyarıya rağmen gönderim (tarayıcı eklentisi)",
    "secrets": "sır içeren istek",
    "injection": "injection denemesi",
}
assert tuple(SIGNALS) == ANOMALY_SIGNALS
RULE_PREFIX = "anomali:"
OVERRIDE_RULE = "golge-ai:allowed_override"
# Kimliği bilinmeyen istekler tek bir "kullanıcı"da toplanır: sayılmaz, sıralanmaz (header modunda
# kullanıcı başlığı yoksa "anonymous", guardrail / eklentide "unknown")
ANONYMOUS = ("", "unknown", "anonymous")


def _signals(ev: Dict[str, Any]) -> Dict[str, Any]:
    """Olayın tetiklediği sinyaller: sayaçlar için 1, subjects için özet listesi."""
    out: Dict[str, Any] = {}
    if effective_action(ev) == "block":
        out["blocked"] = 1
    if OVERRIDE_RULE in (ev.get("rules") or []):
        out["overrides"] = 1
    if any(e.startswith("SECRET_") for e in list(ev.get("entities") or []) + list(ev.get("output_leaked") or [])):
        out["secrets"] = 1
    if (ev.get("injection_score") or 0) >= 0.5:
        out["injection"] = 1
    if ev.get("subject_hashes") and ev.get("destination") == "external" and ev.get("action") != "block":
        out["subjects"] = list(ev["subject_hashes"])
    return out


def anomaly_event(ev: Dict[str, Any], signal: str, count: int, threshold: int, window: int) -> Dict[str, Any]:
    """Bildirim olayı (denetim kaydına yazılmaz). Alanlar bildirim biçimlerinin beklediği gibi."""
    return {
        "event_id": str(uuid.uuid4()), "ts": int(time.time() * 1000),
        "user": ev.get("user") or "unknown", "team": ev.get("team") or "default",
        "teams": list(ev.get("teams") or [ev.get("team") or "default"]),
        "model": ev.get("model") or "", "destination": ev.get("destination") or "",
        "action": "alert", "rules": [RULE_PREFIX + signal],
        "reason": f"Anomali: son {window} dakikada {count} kez {SIGNALS[signal]} (eşik {threshold})",
        "entities": [], "output_leaked": [], "output_action": "", "output_rules": [],
        "injection_score": 0.0, "api_format": "anomaly", "quota": "",
    }


class AnomalyDetector:
    def __init__(self, backend, clock=time.time):
        self.backend, self.clock = backend, clock

    async def observe(self, cfg: Dict[str, Any], ev: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Olayı say; eşiğe ulaşan sinyaller için bildirim olayları."""
        thresholds = (cfg or {}).get("thresholds") or {}
        user = ev.get("user") or ""
        if not thresholds or user in ANONYMOUS or ev.get("api_format") == "anomaly":
            return []
        window = cfg["window_minutes"]
        ttl = window * 60 + 60
        slot = int(self.clock() // (window * 60))
        out = []
        for signal, value in _signals(ev).items():
            threshold = thresholds.get(signal)
            if not threshold:
                continue
            key = f"tg:anomali:{signal}:{slot}:{user}"
            try:
                if signal == "subjects":
                    count = await self.backend.add_distinct(key, value, ttl)
                else:
                    count = await self.backend.incr_window(key, ttl)
                if count < threshold or not await self.backend.once(key + ":bildirildi", ttl):
                    continue
            except QuotaBackendError as e:
                metrics.QUOTA_BACKEND_ERRORS.inc()
                log.warning("anomaly_backend_error signal=%s error=%s", signal, e)
                continue
            metrics.ANOMALIES.labels(signal).inc()
            log.info("anomaly user=%s team=%s signal=%s count=%d threshold=%d",
                     user, ev.get("team"), signal, count, threshold)
            out.append(anomaly_event(ev, signal, count, threshold, window))
        return out


# ---------------- risk skoru (ClickHouse) ----------------

# Sinyal ağırlıkları: bir injection denemesi ya da sızan sır, maskesiz giden tek bir kişisel veriden
# daha güçlü bir göstergedir. Skor = 100 * (1 - e^(-toplam / SCALE)): toplam 20 -> ~63, 40 -> ~86.
WEIGHTS = {
    "injection": 5.0,
    "secrets": 4.0,
    "output_leaks": 3.0,
    "overrides": 3.0,
    "blocked": 2.0,
    "unmasked_pii_external": 1.0,
    "subjects": 0.1,
    "after_hours": 0.2,
}
SCALE = 20.0
SPIKE_FACTOR = 3.0      # son 24 saat, kullanıcının günlük ortalamasının bu katı ...
SPIKE_MIN = 5           # ... ve en az bu kadar riskli istek
SPIKE_BONUS = 10.0
RISK_LIMIT = 50

RISK_LABELS = {
    "injection": "Injection denemesi",
    "secrets": "Sır içeren istek",
    "output_leaks": "Cevapta sızıntı",
    "overrides": "Uyarıya rağmen gönderim",
    "blocked": "Engellenen istek",
    "unmasked_pii_external": "Yurt dışına maskesiz kişisel veri",
    "subjects": "Farklı kişi (yurt dışı)",
    "after_hours": "Mesai dışı riskli istek",
}

_RISKY = (f"(action = 'block' OR injection_score >= 0.5 OR notEmpty(output_leaked) OR has(rules, '{OVERRIDE_RULE}') "
          "OR arrayExists(e -> startsWith(e, 'SECRET_'), entities) "
          f"OR (destination = 'external' AND action != 'block' AND {_UNMASKED_PII}))")

RISK_SQL = f"""
SELECT user, any(team) AS team, count() AS requests,
       countIf(injection_score >= 0.5) AS injection,
       countIf(arrayExists(e -> startsWith(e, 'SECRET_'), entities)) AS secrets,
       countIf(notEmpty(output_leaked)) AS output_leaks,
       countIf(has(rules, '{OVERRIDE_RULE}')) AS overrides,
       countIf(action = 'block') AS blocked,
       countIf(destination = 'external' AND action != 'block' AND {_UNMASKED_PII}) AS unmasked_pii_external,
       uniqExactArrayIf(subject_hashes, destination = 'external' AND action != 'block') AS subjects,
       countIf({_RISKY} AND (toHour(event_time) NOT BETWEEN 8 AND 18 OR toDayOfWeek(event_time) >= 6)) AS after_hours,
       countIf({_RISKY} AND event_time >= now() - INTERVAL 1 DAY) AS risky_24h,
       countIf({_RISKY} AND event_time < now() - INTERVAL 1 DAY) AS risky_before,
       max(event_time) AS last_seen
FROM audit
WHERE event_time >= now() - INTERVAL {{days:UInt32}} DAY
  AND ({{team:String}} = '' OR team = {{team:String}})
  AND user NOT IN ({', '.join(repr(u) for u in ANONYMOUS)})
GROUP BY user
HAVING risky_24h + risky_before > 0
ORDER BY {' + '.join(f'{w} * {k}' for k, w in WEIGHTS.items())} DESC
LIMIT {{limit:UInt32}}"""


def score_row(row: Dict[str, Any], days: int) -> Dict[str, Any]:
    """Bir kullanıcının sinyalleri -> skor, katkılar ve ani artış."""
    signals = {k: int(row.get(k) or 0) for k in WEIGHTS}
    contributions = {k: round(signals[k] * w, 1) for k, w in WEIGHTS.items() if signals[k]}
    recent, before = int(row.get("risky_24h") or 0), int(row.get("risky_before") or 0)
    baseline = before / max(days - 1, 1)
    spike = recent >= SPIKE_MIN and recent >= SPIKE_FACTOR * max(baseline, 1.0)
    total = sum(contributions.values()) + (SPIKE_BONUS if spike else 0.0)
    return {
        "user": row.get("user"), "team": row.get("team"), "requests": int(row.get("requests") or 0),
        "score": round(100 * (1 - math.exp(-total / SCALE))),
        "signals": signals,
        "reasons": [{"signal": k, "label": RISK_LABELS[k], "count": signals[k], "points": v}
                    for k, v in sorted(contributions.items(), key=lambda kv: -kv[1])],
        "spike": {"flag": spike, "last_24h": recent, "daily_avg": round(baseline, 1)},
        "last_seen": row.get("last_seen"),
    }


async def report(ch: ClickHouse, days: int, team: str = "", limit: int = RISK_LIMIT) -> Dict[str, Any]:
    rows = await ch.query(RISK_SQL, {"days": days, "team": team, "limit": limit})
    users = sorted((score_row(r, days) for r in rows), key=lambda u: (-u["score"], u["user"] or ""))
    return {"days": days, "team": team, "users": users,
            "weights": WEIGHTS, "labels": RISK_LABELS,
            "spike_rule": {"factor": SPIKE_FACTOR, "min": SPIKE_MIN}}
