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
# türü maskelenmemiş. Sırlar (SECRET_*) ve kurumsal sözlük terimleri (KURUM_*) kişisel veri
# değil, ayrı sayılır.
_NOT_PII = "(startsWith(e, 'SECRET_') OR startsWith(e, 'KURUM_'))"
_UNMASKED_PII = f"arrayExists(e -> NOT {_NOT_PII} AND NOT has(masked_entities, e), entities)"

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
               countIf(notEmpty(output_leaked)) AS output_leaks,
               countIf(output_action IN ('mask', 'block')) AS output_protected,
               countIf(quota != '' AND quota != 'backend_unavailable') AS quota_blocks,
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
    "by_format": f"""
        SELECT if(api_format = '', 'chat', api_format) AS api_format, count() AS requests,
               round(sum(est_cost_usd), 6) AS est_cost_usd
        FROM audit WHERE {_WINDOW} GROUP BY api_format ORDER BY requests DESC""",
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
PROVIDERS = [("gpt-", "OpenAI"), ("o1", "OpenAI"), ("o3", "OpenAI"), ("text-embedding-", "OpenAI"), ("claude-", "Anthropic"),
             ("gemini-", "Google"), ("mistral", "Mistral"), ("command", "Cohere")]


def provider_of(model: str, registry=None) -> str:
    """Önce politikadaki `providers` adı (ör. "Azure OpenAI"), yoksa model adından tahmin."""
    named = registry.provider_name(model) if registry else None
    return named or next((name for prefix, name in PROVIDERS if model.startswith(prefix)), "Diğer / bilinmiyor")


# ---------------- AI envanteri / VERBİS ----------------

INVENTORY_USAGE_QUERY = """
    SELECT team, model, any(destination) AS destination, count() AS requests, uniqExact(user) AS users,
           toString(min(event_time)) AS first_seen, toString(max(event_time)) AS last_seen,
           groupUniqArrayArray(entities) AS entities,
           countIf(destination = 'external' AND action != 'block' AND notEmpty(entities)) AS external_with_pii
    FROM audit WHERE event_time >= now() - INTERVAL {days:UInt32} DAY
    GROUP BY team, model ORDER BY requests DESC LIMIT 1000"""

# Engellenen istekler aktarılmadığı için VERBİS'e girmez; maskeli gidenler girer (hukuk değerlendirir)
VERBIS_QUERY = """
    SELECT entity, destination, model, team, count() AS requests
    FROM audit ARRAY JOIN entities AS entity
    WHERE event_time >= now() - INTERVAL {days:UInt32} DAY AND action != 'block'
    GROUP BY entity, destination, model, team"""


async def inventory_usage(ch: ClickHouse, days: int) -> List[Dict[str, Any]]:
    return await ch.query(INVENTORY_USAGE_QUERY, {"days": days})


async def verbis_rows(ch: ClickHouse, days: int, registry=None) -> List[Dict[str, Any]]:
    rows = await ch.query(VERBIS_QUERY, {"days": days})
    for r in rows:
        r["provider"] = provider_of(r["model"], registry)
    return rows


KVKK_QUERY = """
    SELECT team, model, entity, count() AS requests, uniqExact(user) AS users,
           countIf(action = 'block') AS blocked,
           countIf(action != 'block' AND has(masked_entities, entity)) AS masked_sent,
           countIf(action != 'block' AND NOT has(masked_entities, entity)) AS unmasked_sent
    FROM audit ARRAY JOIN entities AS entity
    WHERE destination = 'external' AND NOT startsWith(entity, 'SECRET_') AND NOT startsWith(entity, 'KURUM_')
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


async def kvkk_transfer(ch: ClickHouse, month: str, registry=None) -> List[Dict[str, Any]]:
    start, end = month_range(month)
    rows = await ch.query(KVKK_QUERY, {"start": start.isoformat(), "end": end.isoformat()})
    for r in rows:
        r["provider"] = provider_of(r["model"], registry)
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


# ---------------- Olay gezgini ----------------
# Filtreler sabit SQL parçalarından seçilir (beyaz liste); değerler yine parametre olarak bağlanır.

EVENT_COLUMNS = """
    toString(event_id) AS event_id, toString(event_time) AS event_time,
    toUnixTimestamp64Milli(event_time) AS ts, user, team, teams, auth_source, model, destination,
    if(api_format = '', 'chat', api_format) AS api_format, action, rules, reason, monitored_rules,
    would_action, entities, masked_entities, injection_score, injection_engine, output_leaked,
    output_action, output_rules, quota, prompt_tokens, completion_tokens, usage_known, est_cost_usd,
    latency_ms, upstream_status, prompt_chars"""

EVENT_FILTERS = {
    "team": "team = {team:String}",
    "user": "user = {user:String}",
    "model": "model = {model:String}",
    "action": "action = {action:String}",
    "destination": "destination = {destination:String}",
    "api_format": "if(api_format = '', 'chat', api_format) = {api_format:String}",
    "entity": "has(entities, {entity:String})",
    "rule": "(has(rules, {rule:String}) OR has(monitored_rules, {rule:String}) OR has(output_rules, {rule:String}))",
    "day": "toDate(event_time) = toDate({day:String})",
}

# Röntgen kutucuklarından gelinen özel görünümler (Röntgen sorgularıyla aynı tanımlar)
EVENT_FLAGS = {
    "external_unmasked_pii": f"destination = 'external' AND action != 'block' AND {_UNMASKED_PII}",
    "injection": "injection_score >= 0.5",
    "secret": "arrayExists(e -> startsWith(e, 'SECRET_'), entities)",
    "would_block": "would_action = 'block' AND action != 'block'",
    "monitor_diff": "would_action != '' AND would_action != action",
    "output_leak": "notEmpty(output_leaked)",
    "quota": "quota != '' AND quota != 'backend_unavailable'",
}

EVENTS_MAX_LIMIT = 200


def events_query(filters: Dict[str, str], flag: str, before_ts: int, before_id: str,
                 limit: int) -> tuple:
    """(sql, params). `day` verilirse dönem yerine o gün; sayfalama (zaman, id) anahtarıyla."""
    where, params = [], {"limit": limit}
    if filters.get("day"):
        params["day"] = filters["day"]
    else:
        where.append("event_time >= now() - INTERVAL {days:UInt32} DAY")
        params["days"] = int(filters.get("days") or 30)
    for key, clause in EVENT_FILTERS.items():
        if filters.get(key):
            where.append(clause)
            params.setdefault(key, filters[key])
    if flag:
        where.append(EVENT_FLAGS[flag])
    if before_ts:
        where.append("(toUnixTimestamp64Milli(event_time), toString(event_id)) < "
                     "({before_ts:Int64}, {before_id:String})")
        params.update(before_ts=before_ts, before_id=before_id)
    sql = (f"SELECT {EVENT_COLUMNS} FROM audit WHERE {' AND '.join(where)} "
           "ORDER BY event_time DESC, event_id DESC LIMIT {limit:UInt32}")
    return sql, params


async def events(ch: ClickHouse, filters: Dict[str, str], flag: str = "", before_ts: int = 0,
                 before_id: str = "", limit: int = 50) -> Dict[str, Any]:
    sql, params = events_query(filters, flag, before_ts, before_id, limit + 1)
    rows = await ch.query(sql, params)
    more = len(rows) > limit
    rows = rows[:limit]
    return {"events": rows,
            "next": {"before_ts": rows[-1]["ts"], "before_id": rows[-1]["event_id"]} if more and rows else None}


# ---------------- ilgili kişi başvurusu (KVKK md. 11) ----------------

SUBJECT_LIMIT = 1000
SUBJECT_QUERY = """
    SELECT toString(event_id) AS event_id, toString(event_time) AS event_time, team, user, model,
           destination, if(api_format = '', 'chat', api_format) AS api_format, action, rules,
           entities, masked_entities, arrayIntersect(subject_hashes, {hashes:Array(String)}) AS matched
    FROM audit
    WHERE event_time >= now() - INTERVAL {days:UInt32} DAY AND hasAny(subject_hashes, {hashes:Array(String)})
    ORDER BY event_time DESC LIMIT {limit:UInt32}"""

SUBJECT_STATUS = {
    "blocked": "Engellendi; hiçbir yere gönderilmedi",
    "internal": "Kurum içi modele gönderildi; yurt dışına aktarılmadı",
    "masked": "Yurt dışı modele maskelenerek gönderildi; veri aktarılmadı",
    "unmasked": "Yurt dışı modele maskelenmeden gönderildi (yurt dışına aktarım)",
}


def subject_status(ev: Dict[str, Any], entity: str) -> str:
    if ev["action"] == "block":
        return "blocked"
    if ev["destination"] != "external":
        return "internal"
    return "masked" if entity in ev["masked_entities"] else "unmasked"


async def subject_search(ch: ClickHouse, subjects: List[Dict[str, Any]], days: int,
                         registry=None) -> Dict[str, Any]:
    """subjects: SubjectIndex.resolve çıktısı (hatasız olanlar). Olay başına hangi değerin
    eşleştiği ve verinin akıbeti; değer başına özet."""
    by_hash = {h: s for s in subjects for h in s["hashes"]}
    rows = await ch.query(SUBJECT_QUERY, {"hashes": list(by_hash), "days": days, "limit": SUBJECT_LIMIT + 1})
    truncated = len(rows) > SUBJECT_LIMIT
    countries = registry.countries() if registry else {}
    # Anahtar nesne kimliği: iki farklı değerin maskeli etiketi aynı olabilir (son 4 hane)
    events, summary = [], {id(s): {"label": s["label"], "entity": s["entity"],
                                        "entity_label": ENTITY_LABELS.get(s["entity"], s["entity"]),
                                        "events": 0, "first_seen": None, "last_seen": None,
                                        **{k: 0 for k in SUBJECT_STATUS}, "recipients": {}}
                           for s in subjects}
    for r in rows[:SUBJECT_LIMIT]:
        provider = provider_of(r["model"], registry)
        hits = []
        for subj in {id(by_hash[h]): by_hash[h] for h in r["matched"] if h in by_hash}.values():
            status = subject_status(r, subj["entity"])
            hits.append({"label": subj["label"], "entity": subj["entity"], "status": status})
            agg = summary[id(subj)]
            agg["events"] += 1
            agg[status] += 1
            agg["first_seen"] = r["event_time"] if not agg["first_seen"] else min(agg["first_seen"], r["event_time"])
            agg["last_seen"] = r["event_time"] if not agg["last_seen"] else max(agg["last_seen"], r["event_time"])
            if status == "unmasked":
                key = f"{provider} ({countries[provider]})" if provider in countries else provider
                agg["recipients"][key] = agg["recipients"].get(key, 0) + 1
        events.append({k: r[k] for k in ("event_id", "event_time", "team", "user", "model", "destination",
                                         "api_format", "action")} | {"provider": provider, "subjects": hits})
    return {"summary": list(summary.values()), "events": events, "truncated": truncated,
            "statuses": SUBJECT_STATUS}


EVENT_DETAIL_QUERY = f"""
    SELECT {EVENT_COLUMNS}, prompt_sha256, masked_prompt, masked_count, output_scan
    FROM audit WHERE event_id = toUUID({{id:String}}) LIMIT 1"""

# Aynı prompt'un (SHA-256) son 90 günde kaç kez, kaç kullanıcıdan geldiği
SAME_PROMPT_QUERY = """
    SELECT count() AS requests, uniqExact(user) AS users, toString(min(event_time)) AS first_seen
    FROM audit WHERE prompt_sha256 = {sha:String} AND event_time >= now() - INTERVAL 90 DAY"""


async def event_detail(ch: ClickHouse, event_id: str) -> Optional[Dict[str, Any]]:
    rows = await ch.query(EVENT_DETAIL_QUERY, {"id": event_id})
    if not rows:
        return None
    ev = rows[0]
    ev["same_prompt"] = (await ch.query(SAME_PROMPT_QUERY, {"sha": ev["prompt_sha256"]}) or [{}])[0]
    return ev
