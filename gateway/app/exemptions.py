"""
İstisna listesi: kişisel veri gibi görünen ama kamuya açık olan kurum değerleri (kurumun tahsilat
IBAN'ı, destek e-postası, çağrı merkezi numarası). Politika dosyasındaki `exceptions`:

    exceptions:
      - entity: IBAN_TR                       # yerleşik veri türü (TCKN, IBAN_TR, EMAIL_ADDRESS ...)
        label: Kurumun tahsilat hesapları     # konsolda görünen ad (opsiyonel)
        values: ["TR33 0006 1005 1978 6457 8413 26"]
      - entity: EMAIL_ADDRESS
        patterns: ['[\\w.+-]+@sirket\\.com\\.tr']   # değerin TAMAMI eşleşmeli

İstisna değer hiç bulunmamış sayılır: maskelenmez, kurallara, denetim kaydına, KVKK raporlarına ve
çıktı sızıntısı taramasına girmez. Yanlış pozitifleri ve modelin anlamını bozan gereksiz maskelemeyi
azaltır. Değerler biçimden bağımsız karşılaştırılır: IBAN / kart / TCKN boşluksuz, telefon son 10
hanesiyle (+90 / 0 öneki fark etmez), e-posta küçük harfle.

Sırlar (SECRET_*) istisna olamaz: anahtar ne olursa olsun dışarı çıkmamalı. Kurumsal sözlük
(KURUM_*) terimi istemiyorsanız sözlükten çıkarın.
"""
import logging
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Pattern, Set

log = logging.getLogger("telveguard.exemptions")

ENTITY_RX = re.compile(r"^[A-Z][A-Z0-9_]{1,40}$")
FORBIDDEN_PREFIXES = ("SECRET_", "KURUM_")
MAX_VALUES = 10_000
MAX_PATTERN_LEN = 500
_DIGITS = {"TCKN", "VKN", "CREDIT_CARD"}


class ExemptionError(ValueError):
    pass


def normalize(entity: str, value: str) -> str:
    """Karşılaştırma biçimi: aynı değerin farklı yazımları eşit olsun."""
    if entity in _DIGITS:
        return re.sub(r"\D", "", value)
    if entity == "IBAN_TR":
        return re.sub(r"\s", "", value).upper()
    if entity == "PHONE_TR":
        return re.sub(r"\D", "", value)[-10:]
    return re.sub(r"\s+", " ", value.strip()).casefold()


@dataclass(frozen=True)
class Entry:
    entity: str
    label: str
    values: int
    patterns: int


def _str_list(where: str, key: str, value: Any) -> List[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(v, str) and v.strip() for v in value):
        raise ExemptionError(f"{where}: {key} boş olmayan metinlerden oluşan bir liste olmalı")
    return value


class Exemptions:
    def __init__(self, values: Dict[str, Set[str]], patterns: Dict[str, List[Pattern]], entries: List[Entry],
                 raw_values: Optional[Dict[str, List[str]]] = None):
        self.values, self.patterns, self.entries = values, patterns, entries
        self._raw_values = raw_values or {}

    @classmethod
    def from_config(cls, cfg: Optional[Dict[str, Any]]) -> "Exemptions":
        raw = (cfg or {}).get("exceptions") or []
        if not isinstance(raw, list):
            raise ExemptionError("exceptions bir liste olmalı")
        values: Dict[str, Set[str]] = {}
        patterns: Dict[str, List[Pattern]] = {}
        raw_values: Dict[str, List[str]] = {}
        entries: Dict[str, Dict[str, Any]] = {}
        for i, item in enumerate(raw):
            if not isinstance(item, dict):
                raise ExemptionError(f"exceptions[{i}]: bir nesne olmalı")
            entity = item.get("entity")
            where = f"İstisna '{entity or i}'"
            if not isinstance(entity, str) or not ENTITY_RX.match(entity):
                raise ExemptionError(f"{where}: entity büyük harfli bir veri türü adı olmalı (ör. IBAN_TR)")
            if entity.startswith(FORBIDDEN_PREFIXES):
                raise ExemptionError(f"{where}: sırlar (SECRET_*) ve kurumsal sözlük (KURUM_*) istisna olamaz")
            unknown = set(item) - {"entity", "label", "values", "patterns"}
            if unknown:
                raise ExemptionError(f"{where}: bilinmeyen alan: {', '.join(sorted(unknown))}")
            vals = _str_list(where, "values", item.get("values"))
            pats = _str_list(where, "patterns", item.get("patterns"))
            if not vals and not pats:
                raise ExemptionError(f"{where}: values ya da patterns gerekli")
            compiled = []
            for p in pats:
                if len(p) > MAX_PATTERN_LEN:
                    raise ExemptionError(f"{where}: düzenli ifade en fazla {MAX_PATTERN_LEN} karakter")
                try:
                    compiled.append(re.compile(p, re.IGNORECASE | re.UNICODE))
                except re.error as e:
                    raise ExemptionError(f"{where}: geçersiz düzenli ifade {p!r}: {e}") from e
            values.setdefault(entity, set()).update(normalize(entity, v) for v in vals)
            patterns.setdefault(entity, []).extend(compiled)
            raw_values.setdefault(entity, []).extend(vals)
            e = entries.setdefault(entity, {"label": "", "values": 0, "patterns": 0})
            e["label"] = e["label"] or str(item.get("label") or "")
            e["values"] += len(vals)
            e["patterns"] += len(pats)
        if sum(len(v) for v in values.values()) > MAX_VALUES:
            raise ExemptionError(f"exceptions: en fazla {MAX_VALUES} değer")
        return cls(values, patterns, [Entry(k, v["label"], v["values"], v["patterns"]) for k, v in entries.items()],
                   raw_values)

    def is_exempt(self, entity: str, value: str) -> bool:
        if normalize(entity, value) in self.values.get(entity, ()):
            return True
        return any(p.fullmatch(value) for p in self.patterns.get(entity, ()))

    def install(self, pii) -> None:
        """PII motoruna bağlar (önceki kurulumu değiştirir). Motorun o türde bulmadığı değer büyük
        olasılıkla yazım hatasıdır (ör. sağlama toplamı tutmayan IBAN): uyarı loglanır."""
        pii.exempt = None
        for entity, vals in self._raw_values.items():
            for v in vals:
                if not any(f.entity == entity for f in pii.analyze(v)):
                    log.warning("exemption_not_detected entity=%s value_chars=%d "
                                "(motor bu değeri %s olarak tanımıyor; istisna etkisiz)", entity, len(v), entity)
        pii.exempt = self.is_exempt if self.entries else None

    def describe(self) -> List[Dict[str, Any]]:
        """Arayüz için: değerlerin kendisi değil sayıları."""
        return [{"entity": e.entity, "label": e.label, "values": e.values, "patterns": e.patterns}
                for e in self.entries]


def load(policy_path: str) -> Exemptions:
    import yaml

    with open(policy_path, encoding="utf-8") as f:
        return Exemptions.from_config(yaml.safe_load(f))
