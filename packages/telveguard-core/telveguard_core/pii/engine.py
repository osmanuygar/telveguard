"""
Hafif PII motoru: regex + checksum + opsiyonel BERT NER. Ağır bağımlılık yok.

Geri çevrilebilir maskeleme: prompt dış LLM'e [TCKN_1] gibi yer tutucularla gider,
cevap dönünce gateway orijinal değerleri geri koyar. Kişisel veri kurum dışına çıkmaz.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from ..entities import entity_matches
from .secret_recognizers import SECRET_RECOGNIZERS
from .tr_recognizers import TR_RECOGNIZERS


@dataclass
class Finding:
    entity: str
    start: int
    end: int
    score: float


@dataclass
class MaskResult:
    text: str
    findings: List[Finding]
    vault: Dict[str, str] = field(default_factory=dict)  # placeholder -> orijinal


class TrPiiEngine:
    def __init__(self, enable_ner: bool = False, min_score: float = 0.5):
        self.recognizers = TR_RECOGNIZERS + SECRET_RECOGNIZERS
        self.min_score = min_score
        self._ner = None
        if enable_ner:
            from .tr_ner import TurkishNer
            self._ner = TurkishNer()

    def analyze(self, text: str) -> List[Finding]:
        results: List[Finding] = []
        for rec in self.recognizers:
            for m in rec.pattern.finditer(text):
                value = m.group(rec.group)
                if rec.validator and not rec.validator(value):
                    continue
                results.append(Finding(rec.entity, m.start(rec.group), m.end(rec.group), rec.score))
        if self._ner is not None:
            results.extend(Finding(*r) for r in self._ner.analyze(text))
        results = [r for r in results if r.score >= self.min_score]
        return self._drop_overlaps(results)

    @staticmethod
    def _drop_overlaps(results: List[Finding]) -> List[Finding]:
        # Çakışmada yüksek skor, eşitse uzun olan kazanır
        # (ör. IBAN içindeki rakamlar ayrıca TCKN/telefon sanılmasın)
        results = sorted(results, key=lambda r: (-r.score, -(r.end - r.start)))
        kept: List[Finding] = []
        for r in results:
            if all(r.end <= k.start or r.start >= k.end for k in kept):
                kept.append(r)
        return sorted(kept, key=lambda r: r.start)

    def mask(self, text: str, entities_to_mask: Optional[List[str]] = None,
             vault: Optional[Dict[str, str]] = None) -> MaskResult:
        """Aynı vault birden fazla mesajda paylaşılır: aynı TCKN hep [TCKN_1] olur."""
        findings = self.analyze(text)
        vault = vault if vault is not None else {}
        reverse = {v: k for k, v in vault.items()}
        counters: Dict[str, int] = {}
        for k in vault:
            ent = k.strip("[]").rsplit("_", 1)[0]
            counters[ent] = counters.get(ent, 0) + 1

        out, cursor = [], 0
        for f in findings:
            if entities_to_mask is not None and not entity_matches(f.entity, entities_to_mask):
                continue
            original = text[f.start:f.end]
            placeholder = reverse.get(original)
            if placeholder is None:
                counters[f.entity] = counters.get(f.entity, 0) + 1
                placeholder = f"[{f.entity}_{counters[f.entity]}]"
                vault[placeholder] = original
                reverse[original] = placeholder
            out.append(text[cursor:f.start])
            out.append(placeholder)
            cursor = f.end
        out.append(text[cursor:])
        return MaskResult("".join(out), findings, vault)

    @staticmethod
    def unmask(text: str, vault: Dict[str, str]) -> str:
        # Uzun anahtar önce: [TCKN_10] işlenmeden [TCKN_1] değiştirilmesin
        for placeholder in sorted(vault, key=len, reverse=True):
            text = text.replace(placeholder, vault[placeholder])
        return text
