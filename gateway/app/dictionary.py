"""
Kurumsal sözlük: kişisel veri olmayan ama kurum dışına çıkmaması gereken terimler (proje kod
adları, müşteri unvanları, iç sunucu adları, ürün kodları). Politika dosyasındaki `dictionary`:

    dictionary:
      - entity: KURUM_PROJE              # "KURUM_" ile başlar; kurallarda entity_in: ["KURUM_*"]
        label: Proje kod adı             # konsolda görünen ad (opsiyonel)
        terms: ["Proje Anka", "Mavi Kartal"]
        terms_file: kurum/projeler.txt   # satır başına bir terim; politika dosyasına göre göreli
        patterns: ['PRJ-\\d{4}']         # düzenli ifade (opsiyonel)
        case_sensitive: false            # varsayılan: büyük / küçük harf (Türkçe İ/ı dahil) fark etmez
        whole_word: true                 # varsayılan: kelimenin parçası eşleşmez ("Ankara" != "Anka")

Bulunan terimler diğer veri türleri gibi davranır: kurallar, maskeleme ([KURUM_PROJE_1], cevapta
geri açılır), denetim kaydı, Röntgen, bildirim. Kişisel veri sayılmazlar: KVKK yurt dışı aktarım
raporuna ve VERBİS'e girmezler, "yurt dışına maskesiz kişisel veri" sayacını etkilemezler.

Binlerce terim tek bir düzenli ifadede ağaç (trie) biçiminde birleştirilir; metin uzunluğuyla
doğrusal taranır, terim sayısıyla yavaşlamaz.
"""
import logging
import os
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from telveguard_core.pii.tr_recognizers import Recognizer

log = logging.getLogger("telveguard.dictionary")

PREFIX = "KURUM_"
ENTITY_RX = re.compile(r"^KURUM_[A-Z0-9_]{1,40}$")
MAX_TERMS = 100_000
MAX_PATTERN_LEN = 500
MIN_TERM_LEN = 2
MAX_TERM_LEN = 200
# Türkçe büyük / küçük harf: re.IGNORECASE İ-i ve I-ı eşlerini tanımaz
_TR_FOLD = {"i": "iİ", "İ": "iİ", "ı": "ıI", "I": "ıI"}
_WORD = r"[^\W_]"


class DictionaryError(ValueError):
    pass


@dataclass(frozen=True)
class Entry:
    entity: str
    label: str
    terms: int
    patterns: int


def _char(c: str, case_sensitive: bool) -> str:
    if not case_sensitive and c in _TR_FOLD:
        return "[" + _TR_FOLD[c] + "]"
    if c.isspace():
        return r"\s+"
    return re.escape(c)


def _fold(term: str, case_sensitive: bool) -> str:
    """Trie anahtarı: aynı terimin farklı yazımları tek dala düşsün."""
    term = re.sub(r"\s+", " ", term.strip())
    if case_sensitive:
        return term
    return "".join("i" if c in "iİ" else "ı" if c in "ıI" else c.lower() for c in term)


def trie_regex(terms: List[str], case_sensitive: bool) -> str:
    """Terim listesini ağaç biçiminde tek düzenli ifadeye çevirir:
    ["anka", "ankara"] -> anka(?:ra)?  (alternatif sayısı değil, harf sayısı kadar adım)."""
    trie: Dict[str, Any] = {}
    for t in {_fold(t, case_sensitive) for t in terms}:
        node = trie
        for c in t:
            node = node.setdefault(c, {})
        node[""] = True

    def build(node: Dict[str, Any]) -> str:
        end = "" in node
        branches = [_char(c, case_sensitive) + build(child) for c, child in sorted(node.items()) if c]
        if not branches:
            return ""
        body = branches[0] if len(branches) == 1 else "(?:" + "|".join(branches) + ")"
        if end:
            return "(?:" + body + ")?"
        return body
    return build(trie)


def _str_list(where: str, key: str, value: Any) -> List[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise DictionaryError(f"{where}: {key} bir metin listesi olmalı")
    return value


def _read_terms(where: str, path: str, base_dir: str) -> List[str]:
    full = path if os.path.isabs(path) else os.path.join(base_dir, path)
    try:
        with open(full, encoding="utf-8") as f:
            return [ln.strip() for ln in f if ln.strip() and not ln.lstrip().startswith("#")]
    except OSError as e:
        raise DictionaryError(f"{where}: terms_file okunamadı ({full}): {e.strerror}") from e


def _parse(i: int, raw: Any, base_dir: str) -> tuple:
    """-> (tanıyıcılar, terim sayısı, düzenli ifade sayısı)"""
    if not isinstance(raw, dict):
        raise DictionaryError(f"dictionary[{i}]: bir nesne olmalı")
    entity = raw.get("entity")
    where = f"Sözlük '{entity or i}'"
    if not isinstance(entity, str) or not ENTITY_RX.match(entity):
        raise DictionaryError(f"{where}: entity 'KURUM_' ile başlayan büyük harfli bir ad olmalı (ör. KURUM_PROJE)")
    unknown = set(raw) - {"entity", "label", "terms", "terms_file", "patterns", "case_sensitive", "whole_word"}
    if unknown:
        raise DictionaryError(f"{where}: bilinmeyen alan: {', '.join(sorted(unknown))}")
    case_sensitive = raw.get("case_sensitive", False)
    whole_word = raw.get("whole_word", True)
    if not isinstance(case_sensitive, bool) or not isinstance(whole_word, bool):
        raise DictionaryError(f"{where}: case_sensitive ve whole_word true ya da false olmalı")
    terms = _str_list(where, "terms", raw.get("terms"))
    if raw.get("terms_file"):
        terms = terms + _read_terms(where, str(raw["terms_file"]), base_dir)
    bad = [t for t in terms if not MIN_TERM_LEN <= len(t.strip()) <= MAX_TERM_LEN]
    if bad:
        raise DictionaryError(f"{where}: terimler {MIN_TERM_LEN}-{MAX_TERM_LEN} karakter olmalı ({bad[0][:40]!r})")
    if len(terms) > MAX_TERMS:
        raise DictionaryError(f"{where}: en fazla {MAX_TERMS} terim")
    patterns = _str_list(where, "patterns", raw.get("patterns"))
    if not terms and not patterns:
        raise DictionaryError(f"{where}: terms, terms_file ya da patterns gerekli")

    flags = re.UNICODE | (0 if case_sensitive else re.IGNORECASE)
    left, right = (rf"(?<!{_WORD})", rf"(?!{_WORD})") if whole_word else ("", "")
    out: List[Recognizer] = []
    if terms:
        out.append(Recognizer(entity, re.compile(left + trie_regex(terms, case_sensitive) + right, flags), 1.0))
    for p in patterns:
        if len(p) > MAX_PATTERN_LEN:
            raise DictionaryError(f"{where}: düzenli ifade en fazla {MAX_PATTERN_LEN} karakter")
        try:
            rx = re.compile(left + "(?:" + p + ")" + right, flags)
        except re.error as e:
            raise DictionaryError(f"{where}: geçersiz düzenli ifade {p!r}: {e}") from e
        if rx.search(""):
            raise DictionaryError(f"{where}: düzenli ifade boş metinle eşleşiyor ({p!r})")
        out.append(Recognizer(entity, rx, 1.0))
    return out, len(terms), len(patterns)


class Dictionary:
    def __init__(self, recognizers: List[Recognizer], entries: List[Entry]):
        self.recognizers, self.entries = recognizers, entries

    @classmethod
    def from_config(cls, cfg: Optional[Dict[str, Any]], base_dir: str = ".") -> "Dictionary":
        raw = (cfg or {}).get("dictionary") or []
        if not isinstance(raw, list):
            raise DictionaryError("dictionary bir liste olmalı")
        recognizers: List[Recognizer] = []
        entries: Dict[str, Dict[str, Any]] = {}
        for i, item in enumerate(raw):
            recs, n_terms, n_patterns = _parse(i, item, base_dir)
            recognizers.extend(recs)
            e = entries.setdefault(item["entity"], {"label": "", "terms": 0, "patterns": 0})
            e["label"] = e["label"] or str(item.get("label") or "")
            e["terms"] += n_terms
            e["patterns"] += n_patterns
        return cls(recognizers, [Entry(k, v["label"], v["terms"], v["patterns"]) for k, v in entries.items()])

    def install(self, pii) -> None:
        """PII motoruna ekler (önceki kurulumu değiştirir; yeniden yüklemede çift kayıt olmaz)."""
        pii.recognizers = [r for r in pii.recognizers if not r.entity.startswith(PREFIX)] + self.recognizers

    def describe(self) -> List[Dict[str, Any]]:
        """Arayüz için: terimlerin kendisi değil sayıları (terimler de gizli bilgidir)."""
        return [{"entity": e.entity, "label": e.label, "terms": e.terms, "patterns": e.patterns}
                for e in self.entries]


def load(policy_path: str) -> Dictionary:
    import yaml

    with open(policy_path, encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
    return Dictionary.from_config(cfg, os.path.dirname(os.path.abspath(policy_path)))
