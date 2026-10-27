"""
Hafif PII motoru: regex + checksum + opsiyonel BERT NER. Ağır bağımlılık yok.

Geri çevrilebilir maskeleme: prompt dış LLM'e [TCKN_1] gibi yer tutucularla gider,
cevap dönünce gateway orijinal değerleri geri koyar. Kişisel veri kurum dışına çıkmaz.

Tarama normalleştirilmiş metinde yapılır: görünmez biçim karakterleri (Unicode Cf: sıfır
genişlikli boşluk, yumuşak tire, yön işaretleri, etiket karakterleri) atılır, NFKC uygulanır
(tam genişlikli / daire içi rakamlar). Araya U+200B sıkıştırılmış bir TCKN insana ve modele
TCKN'dir; regex'e değildi. Bulguların ofsetleri ORİJİNAL metne geri eşlenir: maskeleme araya
sıkıştırılmış karakterler dahil tüm değeri kapatır.
"""
import unicodedata
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from ..entities import entity_matches
from .secret_recognizers import SECRET_RECOGNIZERS
from .tr_recognizers import TR_RECOGNIZERS

# Unicode Cf (biçim) kategorisi; tarayıcı eklentisinde (extension/src/detectors.js) aynı liste
INVISIBLE_RANGES = [
    (0x00AD, 0x00AD), (0x0600, 0x0605), (0x061C, 0x061C), (0x06DD, 0x06DD), (0x070F, 0x070F),
    (0x0890, 0x0891), (0x08E2, 0x08E2), (0x180E, 0x180E), (0x200B, 0x200F), (0x202A, 0x202E),
    (0x2060, 0x2064), (0x2066, 0x206F), (0xFEFF, 0xFEFF), (0xFFF9, 0xFFFB), (0x110BD, 0x110BD),
    (0x110CD, 0x110CD), (0x13430, 0x1343F), (0x1BCA0, 0x1BCA3), (0x1D173, 0x1D17A),
    (0xE0001, 0xE0001), (0xE0020, 0xE007F),
]
_INVISIBLE = frozenset(chr(c) for lo, hi in INVISIBLE_RANGES for c in range(lo, hi + 1))


def normalize_for_scan(text: str) -> Tuple[str, Optional[List[int]]]:
    """(taranacak metin, normalleştirilmiş her karakterin orijinal konumu). Değişiklik
    gerekmiyorsa (çoğu metin) eşleme None: ofsetler zaten orijinal metnindir."""
    if text.isascii() or (unicodedata.is_normalized("NFKC", text) and _INVISIBLE.isdisjoint(text)):
        return text, None
    out: List[str] = []
    index: List[int] = []
    for i, ch in enumerate(text):
        if ch in _INVISIBLE:
            continue
        n = unicodedata.normalize("NFKC", ch) if ord(ch) > 127 else ch
        out.append(n)
        index.extend([i] * len(n))
    return "".join(out), index


def normalize_text(text: str) -> str:
    """Değer karşılaştırması için (ilgili kişi araması, istisnalar): taramayla aynı normalleştirme."""
    return normalize_for_scan(text)[0]


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
        # (tür, değer) -> True ise bulgu yok sayılır: kurumun kendi IBAN'ı, destek e-postası gibi
        # kamuya açık değerler (gateway'de politikadaki `exceptions`)
        self.exempt: Optional[Callable[[str, str], bool]] = None
        self._ner = None
        if enable_ner:
            from .tr_ner import TurkishNer
            self._ner = TurkishNer()

    def analyze(self, text: str) -> List[Finding]:
        scan, index = normalize_for_scan(text)
        results: List[Finding] = []
        for rec in self.recognizers:
            for m in rec.pattern.finditer(scan):
                value = m.group(rec.group)
                if rec.validator and not rec.validator(value):
                    continue
                results.append(Finding(rec.entity, m.start(rec.group), m.end(rec.group), rec.score))
        if self._ner is not None:
            results.extend(Finding(*r) for r in self._ner.analyze(scan))
        results = self._drop_overlaps([r for r in results if r.score >= self.min_score and r.end > r.start])
        if self.exempt is not None:
            # Çakışma çözüldükten SONRA: istisna IBAN'ın içindeki rakamlar TCKN / telefon sayılmasın
            results = [r for r in results if not self.exempt(r.entity, scan[r.start:r.end])]
        if index is not None:
            for r in results:
                r.start, r.end = index[r.start], index[r.end - 1] + 1
        return results

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
