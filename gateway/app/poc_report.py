"""
POC değerlendirme raporu: "Telveguard olmasaydı ne olurdu?"

Denetim kayıtlarından yönetici özeti. Her riskli istek (yurt dışına kişisel veri, sır, kurum
bilgisi, prompt injection, model cevabında sızıntı) üç akıbetten birine ayrılır:

  korundu     : uygulanan karar korudu (maskelendi / engellendi)
  gözlemde    : uygulanan karar korumadı ama gözlem modundaki (mode: monitor) bir kural
                maskeleyecek ya da engelleyecekti; kural uygulamaya alınınca korunur
  korumasız   : hiçbir kural korumadı; öneriler bu açığı kapatacak politikayı yazar

Ham metin kullanılmaz: yalnızca veri türleri, kararlar ve kural adları. Örnek olaylarda
kullanıcı adı yoktur (rapor çalışan izleme belgesi değildir). Tarayıcı eklentisi olayları
(api_format=browser) "gölge AI" bölümünde ayrı sayılır.

Gözlemdeki karar istek düzeyindedir: monitör kuralının hangi veri türünü maskeleyeceği
kaydedilmez, bu yüzden "gözlemde" akıbeti bir üst sınırdır.
"""
import asyncio
from datetime import datetime
from typing import Any, Dict, List, Optional

from . import compliance
from .xray import ENTITY_LABELS, XRAY_QUERIES, ClickHouse, inventory_usage, provider_of

_WINDOW = "event_time >= now() - INTERVAL {days:UInt32} DAY"
_GATEWAY = "api_format != 'browser'"
_PROTECTIVE = "('mask', 'block')"


def _kind_exists(prefix: Optional[str]) -> str:
    """İstekte bu türden bir veri var mı (prefix None: kişisel veri = sır ve kurum terimi dışı)."""
    cond = (f"startsWith(e, '{prefix}')" if prefix
            else "NOT (startsWith(e, 'SECRET_') OR startsWith(e, 'KURUM_'))")
    return f"arrayExists(e -> {cond}, entities)"


def _kind_unmasked(prefix: Optional[str]) -> str:
    cond = (f"startsWith(e, '{prefix}')" if prefix
            else "NOT (startsWith(e, 'SECRET_') OR startsWith(e, 'KURUM_'))")
    return f"arrayExists(e -> {cond} AND NOT has(masked_entities, e), entities)"


# ad -> (riskli mi, korundu mu, gözlemde korunur muydu)
RISKS: Dict[str, tuple] = {
    "pii_external": (f"destination = 'external' AND {_kind_exists(None)}",
                     f"action = 'block' OR NOT {_kind_unmasked(None)}",
                     f"would_action IN {_PROTECTIVE}"),
    "secrets": (_kind_exists("SECRET_"),
                f"action = 'block' OR NOT {_kind_unmasked('SECRET_')}",
                f"would_action IN {_PROTECTIVE}"),
    "corporate_external": (f"destination = 'external' AND {_kind_exists('KURUM_')}",
                           f"action = 'block' OR NOT {_kind_unmasked('KURUM_')}",
                           f"would_action IN {_PROTECTIVE}"),
    "injection": ("injection_score >= 0.5", "action = 'block'", "would_action = 'block'"),
    "output_leak": ("notEmpty(output_leaked)", f"output_action IN {_PROTECTIVE}", "0"),
}
RISK_LABELS = {
    "pii_external": "Yurt dışı modele kişisel veri",
    "secrets": "Sır (API anahtarı, parola, private key)",
    "corporate_external": "Yurt dışı modele kurum bilgisi",
    "injection": "Prompt injection girişimi",
    "output_leak": "Model cevabında sızıntı",
}


def _exposed(name: str) -> str:
    when, protected, would = RISKS[name]
    return f"(({when}) AND NOT ({protected}) AND NOT ({would}))"


def _would(name: str) -> str:
    when, protected, would = RISKS[name]
    return f"(({when}) AND NOT ({protected}) AND ({would}))"


ANY_RISK = " OR ".join(f"({r[0]})" for r in RISKS.values())
ANY_EXPOSED = " OR ".join(_exposed(n) for n in RISKS)
ANY_WOULD = f"NOT ({ANY_EXPOSED}) AND ({' OR '.join(_would(n) for n in RISKS)})"

_RISK_COLUMNS = ",\n".join(
    f"countIf({when}) AS {name}_total, countIf(({when}) AND ({protected})) AS {name}_protected, "
    f"countIf({_would(name)}) AS {name}_would"
    for name, (when, protected, _w) in RISKS.items())

QUERIES = {
    "summary": f"""
        SELECT count() AS requests, uniqExact(user) AS users, uniqExact(team) AS teams,
               countIf(destination = 'external') AS external_requests,
               countIf(notEmpty(monitored_rules)) AS monitored_requests,
               toString(min(event_time)) AS first_seen, toString(max(event_time)) AS last_seen,
               round(sum(est_cost_usd), 6) AS est_cost_usd, countIf(est_cost_usd IS NULL) AS cost_unknown_requests,
               countIf({ANY_RISK}) AS risky_total, countIf({ANY_EXPOSED}) AS risky_exposed,
               countIf({ANY_WOULD}) AS risky_would,
               {_RISK_COLUMNS}
        FROM audit WHERE {_WINDOW} AND {_GATEWAY}""",
    "entities": f"""
        SELECT entity, model, destination, count() AS requests,
               countIf(action = 'block' OR has(masked_entities, entity)) AS protected,
               countIf(NOT (action = 'block' OR has(masked_entities, entity))
                       AND would_action IN {_PROTECTIVE}) AS would
        FROM audit ARRAY JOIN entities AS entity WHERE {_WINDOW} AND {_GATEWAY}
        GROUP BY entity, model, destination""",
    "teams": f"""
        SELECT team, count() AS requests, countIf({ANY_RISK}) AS risky,
               countIf({RISKS['pii_external'][0]}) AS pii_external,
               countIf({RISKS['secrets'][0]}) AS secrets,
               countIf({RISKS['injection'][0]}) AS injections,
               countIf({ANY_EXPOSED}) AS exposed, countIf({ANY_WOULD}) AS would
        FROM audit WHERE {_WINDOW} AND {_GATEWAY}
        GROUP BY team ORDER BY exposed + would DESC, risky DESC, requests DESC LIMIT 10""",
    "shadow_sites": f"""
        SELECT model AS site, uniqExact(user) AS users,
               countIf(has(rules, 'golge-ai:visit')) AS visits,
               countIf(notEmpty(entities)) AS with_data,
               countIf(has(rules, 'golge-ai:masked')) AS masked,
               countIf(has(rules, 'golge-ai:cancelled')) AS cancelled,
               countIf(has(rules, 'golge-ai:blocked')) AS blocked,
               countIf(has(rules, 'golge-ai:allowed_override')) AS overridden
        FROM audit WHERE {_WINDOW} AND api_format = 'browser'
        GROUP BY site ORDER BY with_data DESC, visits DESC LIMIT 20""",
    "shadow_entities": f"""
        SELECT entity, count() AS events
        FROM audit ARRAY JOIN entities AS entity WHERE {_WINDOW} AND api_format = 'browser'
        GROUP BY entity ORDER BY events DESC""",
    # Her akıbetten en fazla 3 (korumasız önce), her ekipten akıbet başına 1: liste tek ekip ya da
    # tek akıbetle dolmasın; raporun anlattığı üç durum da örneklensin. Ana bulgu gibi yalnızca
    # gateway istekleri (tarayıcı olayları Gölge AI bölümünde).
    "examples": f"""
        SELECT * FROM (
            SELECT toString(event_id) AS event_id, toString(event_time) AS event_time, team, model, destination,
                   api_format, action, would_action, entities, masked_entities, rules, monitored_rules,
                   injection_score, output_leaked, output_action,
                   multiIf({ANY_EXPOSED}, 'exposed', {ANY_WOULD}, 'would', 'protected') AS outcome
            FROM audit WHERE {_WINDOW} AND {_GATEWAY} AND ({ANY_RISK})
            ORDER BY length(entities) DESC, injection_score DESC, event_time DESC
            LIMIT 1 BY team, outcome
        )
        ORDER BY multiIf(outcome = 'exposed', 0, outcome = 'would', 1, 2), length(entities) DESC,
                 injection_score DESC, event_time DESC
        LIMIT 3 BY outcome LIMIT 8""",
}


def entity_kind(entity: str) -> str:
    return "secret" if entity.startswith("SECRET_") else "corporate" if entity.startswith("KURUM_") else "pii"


def entity_label(entity: str, dictionary_labels: Dict[str, str]) -> str:
    if entity in ENTITY_LABELS:
        return ENTITY_LABELS[entity]
    if entity.startswith("SECRET_"):
        return "Sır: " + entity[7:].lower().replace("_", " ")
    if entity.startswith("KURUM_"):
        return dictionary_labels.get(entity) or "Kurum: " + entity[6:].lower().replace("_", " ")
    return entity


def _outcome(total: int, protected: int, would: int) -> Dict[str, int]:
    total, protected, would = int(total or 0), int(protected or 0), int(would or 0)
    return {"total": total, "protected": protected, "would": would,
            "exposed": max(0, total - protected - would)}


def summarize(s: Dict[str, Any]) -> Dict[str, Any]:
    risks = {name: {"label": RISK_LABELS[name],
                    **_outcome(s.get(f"{name}_total"), s.get(f"{name}_protected"), s.get(f"{name}_would"))}
             for name in RISKS}
    total, exposed, would = (int(s.get(k) or 0) for k in ("risky_total", "risky_exposed", "risky_would"))
    requests = int(s.get("requests") or 0)
    return {
        "requests": requests, "users": int(s.get("users") or 0), "teams": int(s.get("teams") or 0),
        "external_requests": int(s.get("external_requests") or 0),
        "monitored_requests": int(s.get("monitored_requests") or 0),
        "first_seen": s.get("first_seen") if requests else None,
        "last_seen": s.get("last_seen") if requests else None,
        "est_cost_usd": s.get("est_cost_usd"), "cost_unknown_requests": int(s.get("cost_unknown_requests") or 0),
        "risky": {"total": total, "protected": max(0, total - exposed - would), "would": would, "exposed": exposed},
        "risks": risks,
    }


def entity_tables(rows: List[Dict[str, Any]], registry, countries: Dict[str, str],
                  labels: Dict[str, str]) -> tuple:
    """-> (KVKK md. 9 tablosu: yurt dışına kişisel veri, sağlayıcı ve ülkeyle; veri türü özeti)"""
    kvkk: Dict[tuple, Dict[str, Any]] = {}
    by_entity: Dict[str, Dict[str, Any]] = {}
    for r in rows:
        kind = entity_kind(r["entity"])
        external = r["destination"] == "external"
        # Kişisel veri ve kurum bilgisi için risk yurt dışı aktarımdır; sır her yerde risktir
        if kind != "secret" and not external:
            continue
        o = _outcome(r["requests"], r["protected"], r["would"])
        e = by_entity.setdefault(r["entity"], {"entity": r["entity"], "label": entity_label(r["entity"], labels),
                                               "kind": kind, "total": 0, "protected": 0, "would": 0, "exposed": 0})
        for k in ("total", "protected", "would", "exposed"):
            e[k] += o[k]
        if kind == "pii" and external:
            provider = provider_of(r["model"], registry)
            key = (r["entity"], provider)
            k_row = kvkk.setdefault(key, {"entity": r["entity"], "label": entity_label(r["entity"], labels),
                                          "provider": provider,
                                          "country": countries.get(provider, "Bilinmiyor"),
                                          "total": 0, "protected": 0, "would": 0, "exposed": 0})
            for k in ("total", "protected", "would", "exposed"):
                k_row[k] += o[k]
    order = lambda x: (-x["exposed"], -x["would"], -x["total"])  # noqa: E731
    return sorted(kvkk.values(), key=order), sorted(by_entity.values(), key=order)


def _snippet(name: str, when: str, action: str = "mask", extra: str = "") -> str:
    return f"- name: {name}\n  when: {when}\n  action: {action}{extra}"


def recommendations(summary: Dict[str, Any], entities: List[Dict[str, Any]], rules: List[Dict[str, Any]],
                    shadow: Dict[str, Any], inventory: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Bulgulardan politika önerileri: en önemli önce. Her öneri eklenecek YAML'ı da verir."""
    out: List[Dict[str, Any]] = []
    risks = summary["risks"]

    exposed_pii = [e for e in entities if e["kind"] == "pii" and e["exposed"]]
    if exposed_pii:
        types = [e["entity"] for e in exposed_pii]
        n = sum(e["exposed"] for e in exposed_pii)
        out.append({"priority": "high", "title": "Yurt dışı modele giden kişisel veriyi maskeleyin",
                    "detail": f"{n} istekte {', '.join(e['label'] for e in exposed_pii)} hiçbir kurala takılmadan "
                              "yurt dışı modele gitti (KVKK md. 9). Bu türleri maskeleme kuralına ekleyin.",
                    "policy": _snippet("kvkk-yurtdisi-maskele",
                                       f"{{ destination: external, entity_in: [{', '.join(types)}] }}")})
    exposed_secrets = [e for e in entities if e["kind"] == "secret" and e["exposed"]]
    if exposed_secrets:
        out.append({"priority": "high", "title": "Sırları her hedefte maskeleyin",
                    "detail": f"{sum(e['exposed'] for e in exposed_secrets)} istekte "
                              f"{', '.join(e['label'] for e in exposed_secrets)} korumasız gitti (kurum içi modeller "
                              "dahil). Modelin ya da sağlayıcının kayıtlarına düşen sır, sızmış sır sayılmalıdır.",
                    "policy": _snippet("sirlar-her-yerde-maskele", '{ entity_in: ["SECRET_*"] }')})
    if risks["injection"]["exposed"]:
        out.append({"priority": "high", "title": "Prompt injection girişimlerini engelleyin",
                    "detail": f"{risks['injection']['exposed']} şüpheli istek (skor ≥ 0,5) engellenmeden modele ulaştı. "
                              "Engelleme eşiğini düşürmeyi değerlendirin; önce gözlemde deneyin.",
                    "policy": _snippet("prompt-injection-block", "{ injection_score_gte: 0.7 }", "block",
                                       "\n  mode: monitor")})
    if risks["output_leak"]["exposed"]:
        out.append({"priority": "high", "title": "Model cevaplarını da tarayın",
                    "detail": f"{risks['output_leak']['exposed']} cevapta model, girdide olmayan bir kişisel veri ya "
                              "da sır üretti ve kullanıcıya olduğu gibi ulaştı.",
                    "policy": "output_rules:\n" + _snippet("cikti-kimlik-sir-gizle",
                                                          '{ entity_in: [TCKN, IBAN_TR, CREDIT_CARD, "SECRET_*"] }')})
    exposed_corp = [e for e in entities if e["kind"] == "corporate" and e["exposed"]]
    if exposed_corp:
        out.append({"priority": "medium", "title": "Kurum bilgisini yurt dışı modelde maskeleyin",
                    "detail": f"{sum(e['exposed'] for e in exposed_corp)} istekte "
                              f"{', '.join(e['label'] for e in exposed_corp)} yurt dışı modele maskesiz gitti.",
                    "policy": _snippet("kurum-terimleri-yurtdisi-maskele",
                                       '{ destination: external, entity_in: ["KURUM_*"] }')})

    monitor_hits = [r for r in rules if r.get("mode") == "monitor" and int(r.get("hits") or 0) > 0]
    if monitor_hits:
        names = ", ".join(f"{r['rule']} ({int(r['hits'])})" for r in monitor_hits[:5])
        out.append({"priority": "medium", "title": "Gözlemdeki kuralları uygulamaya alın",
                    "detail": f"Gözlem modundaki kurallar {summary['risky']['would']} riskli isteği koruyacaktı. "
                              f"En çok tetiklenenler: {names}. Olaylar ekranında 'Gözlemde farklı karar' görünümüyle "
                              "yanlış alarm olup olmadığına bakıp kuraldaki `mode: monitor` satırını kaldırın.",
                    "policy": None})

    if not shadow["sites"]:
        out.append({"priority": "medium", "title": "Tarayıcı eklentisini dağıtın",
                    "detail": "Bu dönemde gölge AI olayı yok: çalışanların ChatGPT, Gemini gibi sitelere doğrudan "
                              "yapıştırdığı veri görünmüyor. Eklenti MDM ile zorunlu kurulabilir.",
                    "policy": None})
    else:
        t = shadow["totals"]
        risky = t["masked"] + t["cancelled"] + t["blocked"] + t["overridden"]
        if risky and t["overridden"] / risky >= 0.3:
            out.append({"priority": "medium", "title": "Tarayıcı eklentisini engelleme moduna alın",
                        "detail": f"Gölge AI uyarılarının %{round(100 * t['overridden'] / risky)}'ünde kullanıcı "
                                  "'yine de' seçti. Uyarı modu bu kullanıcılarda yetmiyor; MDM'de `mode: block`.",
                        "policy": None})

    undeclared = inventory.get("undeclared") or 0
    if undeclared:
        out.append({"priority": "low", "title": "Beyan edilmemiş AI kullanımını envantere bağlayın",
                    "detail": f"{undeclared} ekip × model kullanımı AI envanterinde (EU AI Act) beyan edilmemiş. "
                              "Beyan edin ya da beyansız kullanımı engelleyin (önce gözlemde).",
                    "policy": _snippet("beyan-edilmemis-model", "{ declared: false, destination: external }",
                                       "block", "\n  mode: monitor")})
    return out


async def build(ch: ClickHouse, days: int, *, registry=None, inventory_cfg: Optional[Dict[str, Any]] = None,
                dictionary_labels: Optional[Dict[str, str]] = None, policy_mode: str = "enforce") -> Dict[str, Any]:
    params = {"days": days}
    names = list(QUERIES)
    results = await asyncio.gather(*(ch.query(QUERIES[n], params) for n in names),
                                   ch.query(XRAY_QUERIES["rules"], {"days": days, "team": ""}),
                                   inventory_usage(ch, days))
    raw = dict(zip(names, results[:len(names)]))
    rules, usage = results[len(names)], results[len(names) + 1]
    labels = dictionary_labels or {}

    summary = summarize(raw["summary"][0] if raw["summary"] else {})
    countries = {**compliance.PROVIDER_COUNTRY, **(registry.countries() if registry else {})}
    kvkk, entities = entity_tables(raw["entities"], registry, countries, labels)

    sites = raw["shadow_sites"]
    totals = {k: sum(int(s.get(k) or 0) for s in sites)
              for k in ("visits", "with_data", "masked", "cancelled", "blocked", "overridden")}
    totals["users"] = max((int(s.get("users") or 0) for s in sites), default=0)
    shadow = {"sites": sites, "totals": totals,
              "entities": [{**e, "label": entity_label(e["entity"], labels)} for e in raw["shadow_entities"]]}

    inv = compliance.build_inventory(inventory_cfg or {"systems": []}, usage)
    inventory = {"systems": len(inv["systems"]), "undeclared": inv["summary"]["unclassified"],
                 "top_undeclared": [{"team": u["team"], "model": u["model"], "requests": u["requests"]}
                                    for u in inv["undeclared"][:5]]}

    examples = [{**e, "labels": [entity_label(x, labels) for x in e["entities"]]} for e in raw["examples"]]
    return {
        "window": {"days": days},
        "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "policy_mode": policy_mode,
        "summary": summary,
        "kvkk": kvkk,
        "entities": entities,
        "teams": raw["teams"],
        "shadow": shadow,
        "examples": examples,
        "rules": rules,
        "inventory": inventory,
        "recommendations": recommendations(summary, entities, rules, shadow, inventory),
    }
