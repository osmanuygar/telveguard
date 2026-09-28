"""
AI Kullanım Röntgeni + KVKK yurt dışı aktarım raporu: ClickHouse denetim kayıtları üzerinden.

Tüm sorgular ClickHouse parametreli sorgularıdır ({ad:Tip} + param_ad): kullanıcı girdisi
(ekip adı, tarih) SQL'e string olarak eklenmez.

Önerilen: gateway için yalnızca SELECT yetkili ayrı bir ClickHouse kullanıcısı.
"""
import csv
import io
import json
import os
from datetime import date
from typing import Any, Dict, List, Optional

import httpx


class ClickHouseError(RuntimeError):
    pass


class ClickHouse:
    def __init__(self, http: httpx.AsyncClient, url: str, user: str, password: str, database: str):
        self.http, self.url, self.database = http, url.rstrip("/"), database
        self.auth = {"X-ClickHouse-User": user, "X-ClickHouse-Key": password}

    @classmethod
    def from_env(cls, http: httpx.AsyncClient) -> Optional["ClickHouse"]:
        url = os.getenv("CLICKHOUSE_URL")
        if not url:
            return None
        return cls(http, url, os.getenv("CLICKHOUSE_USER", "default"),
                   os.getenv("CLICKHOUSE_PASSWORD", ""), os.getenv("CLICKHOUSE_DB", "telveguard"))

    async def query(self, sql: str, params: Dict[str, Any]) -> List[Dict[str, Any]]:
        # prefer_column_name_to_alias: "round(sum(est_cost_usd), 6) AS est_cost_usd" gibi sütunla aynı adlı
        # takma adlar, sorgunun başka yerindeki est_cost_usd'yi gölgelemesin (ILLEGAL_AGGREGATION)
        # json_quote_64bit_integers=0: count() (UInt64) JSON'da string değil sayı dönsün
        qs = {"database": self.database, "prefer_column_name_to_alias": "1",
              "output_format_json_quote_64bit_integers": "0",
              **{f"param_{k}": str(v) for k, v in params.items()}}
        try:
            r = await self.http.post(self.url, params=qs, headers=self.auth,
                                     content=f"{sql}\nFORMAT JSONEachRow", timeout=30)
        except httpx.HTTPError as e:
            raise ClickHouseError(f"ClickHouse'a ulaşılamadı: {type(e).__name__}") from e
        if r.status_code != 200:
            raise ClickHouseError(f"ClickHouse hatası ({r.status_code}): {r.text[:300]}")
        return [json.loads(line) for line in r.text.splitlines() if line.strip()]


# ---------------- Röntgen ----------------

_WINDOW = ("event_time >= now() - INTERVAL {days:UInt32} DAY "
           "AND ({team:String} = '' OR team = {team:String})")

# Yurt dışına maskelenmeden giden kişisel veri: dış hedef, engellenmemiş, en az bir PII
# türü maskelenmemiş. Sırlar (SECRET_*) kişisel veri değil, ayrı sayılır.
_UNMASKED_PII = ("arrayExists(e -> NOT startsWith(e, 'SECRET_') AND NOT has(masked_entities, e), entities)")

XRAY_QUERIES = {
    "summary": f"""
        SELECT count() AS requests, uniqExact(user) AS users, uniqExact(team) AS teams,
               countIf(destination = 'external') AS external_requests,
               countIf(action = 'mask') AS masked, countIf(action = 'block') AS blocked,
               countIf(injection_score >= 0.5) AS injection_attempts,
               countIf(arrayExists(e -> startsWith(e, 'SECRET_'), entities)) AS secret_requests,
               countIf(destination = 'external' AND action != 'block' AND {_UNMASKED_PII}) AS external_unmasked_pii,
               countIf(would_action != '' AND would_action != action) AS monitor_diffs,
               countIf(would_action = 'block' AND action != 'block') AS would_block,
               sum(prompt_tokens) AS prompt_tokens, sum(completion_tokens) AS completion_tokens,
               round(sum(est_cost_usd), 6) AS est_cost_usd,
               countIf(est_cost_usd IS NULL) AS cost_unknown_requests,
               round(avg(latency_ms), 1) AS avg_latency_ms
        FROM audit WHERE {_WINDOW}""",
    "daily": f"""
        SELECT toString(toDate(event_time)) AS day, count() AS requests,
               countIf(action = 'allow') AS allow, countIf(action = 'alert') AS alert,
               countIf(action = 'mask') AS mask, countIf(action = 'block') AS block,
               countIf(destination = 'external') AS external, round(sum(est_cost_usd), 6) AS est_cost_usd
        FROM audit WHERE {_WINDOW} GROUP BY day ORDER BY day""",
    "by_team": f"""
        SELECT team, count() AS requests, countIf(destination = 'external') AS external,
               countIf(action = 'mask') AS masked, countIf(action = 'block') AS blocked,
               countIf(injection_score >= 0.5) AS injection_attempts,
               countIf(destination = 'external' AND action != 'block' AND {_UNMASKED_PII}) AS external_unmasked_pii,
               sum(prompt_tokens + completion_tokens) AS tokens, round(sum(est_cost_usd), 6) AS est_cost_usd,
               countIf(est_cost_usd IS NULL) AS cost_unknown_requests
        FROM audit WHERE {_WINDOW} GROUP BY team ORDER BY requests DESC LIMIT 50""",
    "by_model": f"""
        SELECT model, any(destination) AS destination, count() AS requests,
               sum(prompt_tokens + completion_tokens) AS tokens, round(sum(est_cost_usd), 6) AS est_cost_usd,
               countIf(est_cost_usd IS NULL) AS cost_unknown_requests,
               round(avg(latency_ms), 1) AS avg_latency_ms
        FROM audit WHERE {_WINDOW} GROUP BY model ORDER BY requests DESC LIMIT 50""",
    "entities": f"""
        SELECT entity, count() AS requests, countIf(destination = 'external') AS external,
               countIf(action = 'block') AS blocked,
               countIf(action != 'block' AND has(masked_entities, entity)) AS masked,
               countIf(destination = 'external' AND action != 'block'
                       AND NOT has(masked_entities, entity)) AS external_unmasked
        FROM audit ARRAY JOIN entities AS entity WHERE {_WINDOW}
        GROUP BY entity ORDER BY requests DESC""",
    # UNION ALL'daki ORDER BY yalnızca son SELECT'e uygulanır: sıralama dış sorguda
    "rules": f"""
        SELECT rule, mode, hits FROM (
            SELECT rule, 'enforce' AS mode, count() AS hits FROM audit ARRAY JOIN rules AS rule
            WHERE {_WINDOW} GROUP BY rule
            UNION ALL
            SELECT rule, 'monitor' AS mode, count() AS hits FROM audit ARRAY JOIN monitored_rules AS rule
            WHERE {_WINDOW} GROUP BY rule
        ) ORDER BY hits DESC, rule""",
    "top_users": f"""
        SELECT user, any(team) AS team, count() AS requests,
               countIf(action = 'block') AS blocked, countIf(injection_score >= 0.5) AS injection_attempts,
               countIf(destination = 'external' AND notEmpty(entities)) AS external_with_pii
        FROM audit WHERE {_WINDOW}
        GROUP BY user HAVING blocked + injection_attempts + external_with_pii > 0
        ORDER BY blocked + injection_attempts DESC, external_with_pii DESC LIMIT 10""",
}


async def xray(ch: ClickHouse, days: int, team: str) -> Dict[str, Any]:
    params = {"days": days, "team": team}
    out: Dict[str, Any] = {"window": {"days": days, "team": team or None}}
    for name, sql in XRAY_QUERIES.items():
        rows = await ch.query(sql, params)
        out[name] = rows[0] if name == "summary" else rows
    return out


# ---------------- KVKK yurt dışı aktarım raporu ----------------

ENTITY_LABELS = {
    "TCKN": "T.C. kimlik no", "VKN": "Vergi kimlik no", "IBAN_TR": "IBAN",
    "CREDIT_CARD": "Kredi kartı", "PHONE_TR": "Telefon", "EMAIL_ADDRESS": "E-posta",
    "PLATE_TR": "Araç plakası", "PERSON": "Kişi adı", "LOCATION": "Konum", "ORGANIZATION": "Kurum",
}
PROVIDERS = [("gpt-", "OpenAI"), ("o1", "OpenAI"), ("o3", "OpenAI"), ("claude-", "Anthropic"),
             ("gemini-", "Google"), ("mistral", "Mistral"), ("command", "Cohere")]


def provider_of(model: str) -> str:
    return next((name for prefix, name in PROVIDERS if model.startswith(prefix)), "Diğer / bilinmiyor")


KVKK_QUERY = """
    SELECT team, model, entity, count() AS requests, uniqExact(user) AS users,
           countIf(action = 'block') AS blocked,
           countIf(action != 'block' AND has(masked_entities, entity)) AS masked_sent,
           countIf(action != 'block' AND NOT has(masked_entities, entity)) AS unmasked_sent
    FROM audit ARRAY JOIN entities AS entity
    WHERE destination = 'external' AND NOT startsWith(entity, 'SECRET_')
      AND event_time >= toDateTime({start:Date}, 'Europe/Istanbul')
      AND event_time <  toDateTime({end:Date}, 'Europe/Istanbul')
    GROUP BY team, model, entity
    ORDER BY unmasked_sent DESC, requests DESC"""


def month_range(month: str) -> tuple:
    """'2026-09' -> (2026-09-01, 2026-10-01). Geçersizse ValueError."""
    y, m = (int(p) for p in month.split("-"))
    start = date(y, m, 1)
    end = date(y + (m == 12), m % 12 + 1, 1)
    return start, end


async def kvkk_transfer(ch: ClickHouse, month: str) -> List[Dict[str, Any]]:
    start, end = month_range(month)
    rows = await ch.query(KVKK_QUERY, {"start": start.isoformat(), "end": end.isoformat()})
    for r in rows:
        r["provider"] = provider_of(r["model"])
        r["entity_label"] = ENTITY_LABELS.get(r["entity"], r["entity"])
    return rows


KVKK_COLUMNS = [
    ("team", "Ekip"), ("provider", "Sağlayıcı (yurt dışı)"), ("model", "Model"),
    ("entity_label", "Kişisel veri türü"), ("requests", "İstek"), ("users", "Kullanıcı"),
    ("masked_sent", "Maskelenerek giden"), ("unmasked_sent", "Maskelenmeden giden"),
    ("blocked", "Engellenen"),
]


def _csv_safe(value: Any) -> Any:
    """CSV formül enjeksiyonu: ekip/model adı istemci header'ından gelir; "=HYPERLINK(...)"
    gibi bir değer Excel'de formül olarak çalışmasın."""
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value


def kvkk_csv(rows: List[Dict[str, Any]]) -> str:
    """Türkçe Excel uyumlu: UTF-8 BOM + ';' ayırıcı (ondalık virgül kullanan yerel ayar)."""
    buf = io.StringIO()
    buf.write("\ufeff")
    w = csv.writer(buf, delimiter=";", lineterminator="\r\n")
    w.writerow([label for _, label in KVKK_COLUMNS])
    for r in rows:
        w.writerow([_csv_safe(r[key]) for key, _ in KVKK_COLUMNS])
    return buf.getvalue()
