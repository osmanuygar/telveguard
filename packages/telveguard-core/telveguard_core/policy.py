"""
Basit, okunabilir YAML politika motoru. Kurallar sırayla değerlendirilir,
en kısıtlayıcı aksiyon kazanır: block > mask > alert > allow.

Gözlem modu: `mode: monitor` olan kural (ya da en üstte `mode: monitor` ile tüm politika)
isteği etkilemez; yalnızca "uygulansaydı ne olurdu" (would_action) kayda geçer.
Yeni kuralı önce gözlemde açıp yanlış pozitifleri ölçmek için.

`rules` isteğe (girdi), `output_rules` model cevabına uygulanır. Çıktı kurallarında
entity_in, cevapta olup GİRDİDE OLMAYAN değerlere (sızıntı) bakar.

Ekip eşleşmesi: kullanıcı birden fazla ekipteyse (OIDC grupları) kural, ekiplerden
HERHANGİ biri eşleşirse uygulanır; kısıtlayıcı kuraldan grup sırasıyla kaçılamaz.

Model izin listesi: `model_in` / `model_not_in` model adına joker ile bakar ("gpt-*").
`declared: false`, AI envanterinde (inventory.yaml) kullanıcının ekiplerinden biri için bu
modeli içeren bir sistem beyan edilmemişse eşleşir. Envanter gateway'de okunur ve Context'e
`declared` olarak gelir; envanter yoksa (None) `declared` koşulu hiç eşleşmez.

İleride OPA/Rego'ya geçilebilir; YAML formatı güvenlik ekiplerinin
kod yazmadan kural eklemesi için tercih edildi.
"""
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from typing import FrozenSet, List, Optional, Set

import yaml

from .entities import matching_entities

SEVERITY = {"allow": 0, "alert": 1, "mask": 2, "block": 3}
MODES = {"enforce", "monitor"}
# Yazım hatası sessizce geçmesin: bilinmeyen koşul yok sayılsa kural beklenenden geniş eşleşir
WHEN_KEYS = {"teams", "destination", "entity_in", "injection_score_gte", "model_in", "model_not_in", "declared"}


@dataclass
class Context:
    team: str
    model: str
    destination: str            # "internal" (on-prem vLLM vb.) | "external" (yurt dışı API)
    entities: Set[str]
    injection_score: float
    teams: FrozenSet[str] = frozenset()   # boşsa yalnızca `team`
    declared: Optional[bool] = None       # AI envanterinde beyanlı mı; None = envanter yok

    @property
    def all_teams(self) -> Set[str]:
        return set(self.teams) | {self.team}


@dataclass
class Decision:
    action: str = "allow"
    mask_entities: Set[str] = field(default_factory=set)
    rules: List[str] = field(default_factory=list)
    reason: Optional[str] = None
    # Gözlem modundaki eşleşen kurallar ve hepsi uygulansaydı çıkacak aksiyon
    monitored_rules: List[str] = field(default_factory=list)
    would_action: str = "allow"


class PolicyEngine:
    def __init__(self, path: str):
        with open(path, encoding="utf-8") as f:
            cfg = yaml.safe_load(f)
        self.default_action = cfg.get("default_action", "allow")
        self.mode = cfg.get("mode", "enforce")
        self.rules = cfg.get("rules", [])
        self.output_rules = cfg.get("output_rules", [])
        self.destinations = cfg.get("destinations", {})
        self.pricing = cfg.get("pricing", {})
        self.quotas = cfg.get("quotas") or {}   # gateway'de doğrulanır ve uygulanır (quota.py)
        for rule in self.rules + self.output_rules:
            mode = rule.get("mode", self.mode)
            if mode not in MODES:
                raise ValueError(f"Kural '{rule.get('name')}': geçersiz mode '{mode}' ({', '.join(sorted(MODES))})")
            if rule.get("action") not in SEVERITY:
                raise ValueError(f"Kural '{rule.get('name')}': geçersiz action '{rule.get('action')}'")
            self._validate_when(rule)

    @staticmethod
    def _validate_when(rule: dict) -> None:
        name, when = rule.get("name"), rule.get("when") or {}
        if not isinstance(when, dict):
            raise ValueError(f"Kural '{name}': when bir sözlük olmalı")
        unknown = set(when) - WHEN_KEYS
        if unknown:
            raise ValueError(f"Kural '{name}': bilinmeyen koşul(lar) {', '.join(sorted(unknown))} "
                             f"(geçerli: {', '.join(sorted(WHEN_KEYS))})")
        for key in ("model_in", "model_not_in"):
            if key in when and not (isinstance(when[key], list) and when[key]
                                    and all(isinstance(p, str) and p for p in when[key])):
                raise ValueError(f"Kural '{name}': {key} boş olmayan bir model adı listesi olmalı")
        if "declared" in when and not isinstance(when["declared"], bool):
            raise ValueError(f"Kural '{name}': declared true ya da false olmalı")

    def destination_of(self, model: str) -> str:
        for dest, models in self.destinations.items():
            if any(model.startswith(prefix) for prefix in models):
                return dest
        return "external"  # bilinmeyen model = yurt dışı kabul et (güvenli varsayılan)

    def estimate_cost_usd(self, model: str, prompt_tokens: int, completion_tokens: int) -> Optional[float]:
        """`pricing` listesinde ilk eşleşen önekle (USD / 1M token) tahmini maliyet.
        Fiyatı bilinmeyen model için None: "bedava" ile "bilinmiyor" karışmasın."""
        for entry in self.pricing:
            if model.startswith(entry["match"]):
                return round((prompt_tokens * entry["input"] + completion_tokens * entry["output"]) / 1_000_000, 6)
        return None

    def evaluate(self, ctx: Context) -> Decision:
        return self._evaluate(self.rules, ctx, self.default_action)

    def evaluate_output(self, ctx: Context, leaked: Set[str]) -> Decision:
        """Model cevabındaki sızıntılar (girdide olmayan PII / sır) için karar."""
        out_ctx = Context(ctx.team, ctx.model, ctx.destination, set(leaked), 0.0, ctx.teams, ctx.declared)
        return self._evaluate(self.output_rules, out_ctx, "allow")

    def _evaluate(self, rules: List[dict], ctx: Context, default_action: str) -> Decision:
        decision = Decision(action=default_action, would_action=default_action)
        for rule in rules:
            when = rule.get("when", {})
            if not self._matches(when, ctx):
                continue
            action = rule["action"]
            if SEVERITY[action] > SEVERITY[decision.would_action]:
                decision.would_action = action
            if rule.get("mode", self.mode) == "monitor":
                decision.monitored_rules.append(rule["name"])
                continue
            decision.rules.append(rule["name"])
            if action == "mask":
                decision.mask_entities |= matching_entities(ctx.entities, when.get("entity_in", []))
            if SEVERITY[action] > SEVERITY[decision.action]:
                decision.action = action
                decision.reason = rule.get("message", rule["name"])
        return decision

    @staticmethod
    def _matches(when: dict, ctx: Context) -> bool:
        if "teams" in when and not (set(when["teams"]) & ctx.all_teams):
            return False
        if "destination" in when and ctx.destination != when["destination"]:
            return False
        if "entity_in" in when and not matching_entities(ctx.entities, when["entity_in"]):
            return False
        if "injection_score_gte" in when and ctx.injection_score < when["injection_score_gte"]:
            return False
        if "model_in" in when and not any(fnmatchcase(ctx.model, p) for p in when["model_in"]):
            return False
        if "model_not_in" in when and any(fnmatchcase(ctx.model, p) for p in when["model_not_in"]):
            return False
        if "declared" in when and ctx.declared != when["declared"]:   # None hiçbirine eşit değil
            return False
        return True
