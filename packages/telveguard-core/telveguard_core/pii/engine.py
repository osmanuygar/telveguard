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
import functools
import hashlib
import os
import re
import threading
import unicodedata
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Callable, Dict, FrozenSet, List, Optional, Tuple

from ..entities import entity_matches
from .secret_recognizers import SECRET_RECOGNIZERS
from .synthetic import SYNTHETIC_ENTITIES, make_surrogate, synthetic_key
from .tr_recognizers import TR_RECOGNIZERS

MASK_STYLES = ("placeholder", "synthetic")

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


def canonical_value(entity: str, value: str) -> str:
    """Yer tutucu eşlemesi için: aynı numaranın farklı yazımları ("391 417 776 94", "39141777694")
    aynı yer tutucuyu alsın. Yalnızca biçimi anlamı değiştirmeyen numaralar; sır, e-posta, sözlük
    terimi olduğu gibi (büyük / küçük harf farkı farklı bir sır olabilir)."""
    if entity in ("TCKN", "VKN", "CREDIT_CARD"):
        return re.sub(r"\D", "", value)
    if entity == "PHONE_TR":
        return re.sub(r"\D", "", value)[-10:]
    if entity == "IBAN_TR":
        return re.sub(r"\s", "", value).upper()
    return value


def placeholder_entity(placeholder: str) -> str:
    """[TCKN_3] -> TCKN"""
    return placeholder.strip("[]").rsplit("_", 1)[0]


def is_placeholder(key: str) -> bool:
    """Vault anahtarı yer tutucu mu ([TCKN_1]), sahte değer mi (synthetic.py)."""
    return key.startswith("[") and key.endswith("]")


def _alnum(value: str) -> str:
    return re.sub(r"[^0-9A-Za-z]", "", value).upper()


@functools.lru_cache(maxsize=256)
def _surrogate_pattern(keys: FrozenSet[str]) -> "re.Pattern[str]":
    """Sahte numaralar (TCKN, IBAN, telefon, plaka) model yeniden biçimlendirse de bulunsun:
    "10000000146" -> "100 000 001 46", "34 ABC 123" -> "34ABC123". Rakam / harf sırası aynı,
    aralarında tek ayraç olabilir."""
    alts = ["[ .\\-]?".join(map(re.escape, _alnum(k))) for k in sorted(keys, key=len, reverse=True)]
    return re.compile(r"(?<![0-9A-Za-z])(?:" + "|".join(alts) + r")(?![0-9A-Za-z])", re.IGNORECASE)


class KnownValues:
    """Sızıntı karşılaştırması için vault'taki değerler: gerçek değerler, sahte değerler ve sahte
    numaraların başka yazımı. Model sahte değeri cevapta tekrarlarsa bu yeni bir değer değildir."""

    def __init__(self, vault: Dict[str, str]):
        self._values = set(vault.values())
        synthetic = [k for k in vault if not is_placeholder(k)]
        self._values.update(synthetic)
        self._canon = {_alnum(k) for k in synthetic if "@" not in k}

    def __contains__(self, value: str) -> bool:
        return value in self._values or (bool(self._canon) and _alnum(value) in self._canon)


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


# Tarama önbelleği: aynı metin (Claude Code her turda tüm konuşmayı yeniden gönderir) yeniden
# taranmaz. Anahtar metnin SHA-256 özeti + tanıyıcı kuşağı; değer bulgular (ham metin saklanmaz).
# Tanıyıcılar ya da istisnalar değişince kuşak artar, önbellek boşalır.
SCAN_CACHE_SIZE = int(os.getenv("TELVEGUARD_SCAN_CACHE_SIZE", "4096"))
SCAN_CACHE_MIN_CHARS = 256      # kısa metni taramak özetlemekten ucuz
# Parça sınırı penceresi: "\n" ile birleştirilmiş metinde sınırı aşan bulgu (ör. iki mesaja bölünmüş
# telefon, çok kelimeli sözlük terimi) için sınırın iki yanından bu kadar karakter taranır
BOUNDARY_CHARS = 128
_EDGE = 8   # kesilmiş pencere kenarında lookbehind / lookahead bağlamı eksik: bu kadar içeriden başlamalı


class TrPiiEngine:
    def __init__(self, enable_ner: bool = False, min_score: float = 0.5):
        self._recognizers = TR_RECOGNIZERS + SECRET_RECOGNIZERS
        self._synthetic_key: Optional[bytes] = None
        self._exempt: Optional[Callable[[str, str], bool]] = None
        self._gen = 0
        self._cache: "OrderedDict[Tuple[int, bytes], Tuple]" = OrderedDict()
        self._cache_lock = threading.Lock()
        self.min_score = min_score
        # (tür, değer) -> True ise bulgu yok sayılır: kurumun kendi IBAN'ı, destek e-postası gibi
        # kamuya açık değerler (gateway'de politikadaki `exceptions`)
        self._ner = None
        if enable_ner:
            from .tr_ner import TurkishNer
            self._ner = TurkishNer()

    # Tanıyıcı / istisna değişince önbellek geçersiz (Dictionary.install, Exemptions.install atar)
    @property
    def recognizers(self):
        return self._recognizers

    @recognizers.setter
    def recognizers(self, value) -> None:
        self._recognizers = value
        self._invalidate()

    @property
    def exempt(self) -> Optional[Callable[[str, str], bool]]:
        return self._exempt

    @exempt.setter
    def exempt(self, value: Optional[Callable[[str, str], bool]]) -> None:
        self._exempt = value
        self._invalidate()

    def _invalidate(self) -> None:
        with self._cache_lock:
            self._gen += 1
            self._cache.clear()

    def analyze(self, text: str, cache: bool = False) -> List[Finding]:
        """cache=True: tekrar eden metinler için (istek parçaları). Her çağrıda yeni Finding
        nesneleri döner; çağıranın ofsetleri değiştirmesi önbelleği bozmaz."""
        if not cache or SCAN_CACHE_SIZE <= 0 or len(text) < SCAN_CACHE_MIN_CHARS:
            return self._analyze(text)
        gen = self._gen
        key = (gen, hashlib.sha256(text.encode("utf-8", "surrogatepass")).digest())
        with self._cache_lock:
            hit = self._cache.get(key)
            if hit is not None:
                self._cache.move_to_end(key)
        if hit is not None:
            return [Finding(*t) for t in hit]
        found = self._analyze(text)
        with self._cache_lock:
            if gen == self._gen:     # tarama sırasında tanıyıcılar değiştiyse eski sonucu saklama
                self._cache[key] = tuple((f.entity, f.start, f.end, f.score) for f in found)
                while len(self._cache) > SCAN_CACHE_SIZE:
                    self._cache.popitem(last=False)
        return found

    def analyze_parts(self, texts: List[str], cache: bool = True) -> Tuple[List[List[Finding]], List[Finding]]:
        """Parça parça tarama: (parça başına bulgular, "\n".join(texts) içindeki tüm bulgular).
        Tek parça değişince yalnızca o yeniden taranır (önbellek). Sınır pencereleri iki tür bulgu
        ekler: sınırı aşan (iki mesaja bölünmüş telefon) ve bağlamı öteki parçada kalan ("vergi no:"
        bir parçanın sonunda, numara sonrakinin başında). Parça içi bir bulguyla çakışan eklenmez;
        pencerenin kesilmiş kenarına yakın olan da (uzun sayının ortasından başlayan sahte eşleşme)."""
        per = [self.analyze(t, cache=cache) for t in texts]
        combined: List[Finding] = []
        offset = 0
        starts = []
        for t, found in zip(texts, per):
            starts.append(offset)
            combined.extend(Finding(f.entity, f.start + offset, f.end + offset, f.score) for f in found)
            offset += len(t) + 1
        occupied: Optional[bytearray] = None   # sınır bulgusu çıkınca bir kez kurulur (çoğu istekte hiç)
        for i in range(1, len(texts)):
            prev, nxt = texts[i - 1], texts[i]
            if not prev or not nxt:
                continue
            left, right = prev[-BOUNDARY_CHARS:], nxt[:BOUNDARY_CHARS]
            window = left + "\n" + right
            base = starts[i] - 1 - len(left)          # pencerenin birleşik metindeki başlangıcı
            cut = len(left)                            # pencerede "\n"in konumu
            lo = _EDGE if len(left) < len(prev) else 0          # kesilmiş kenar payı
            hi = len(window) - (_EDGE if len(right) < len(nxt) else 0)
            for f in self.analyze(window, cache=cache):
                if not (f.start <= cut < f.end) and (f.start < lo or f.end > hi):
                    continue
                g = Finding(f.entity, f.start + base, f.end + base, f.score)
                if occupied is None:
                    occupied = bytearray(offset)
                    for k in combined:
                        occupied[k.start:k.end] = b"\x01" * (k.end - k.start)
                if occupied.find(1, g.start, g.end) == -1:
                    occupied[g.start:g.end] = b"\x01" * (g.end - g.start)
                    combined.append(g)
        combined.sort(key=lambda f: f.start)
        return per, combined

    def _analyze(self, text: str) -> List[Finding]:
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
        # Dolu karakterler bayt dizisinde: bulgu yoğun metinde (5 MB'ta 260 bin bulgu) karesel olmasın
        occupied = bytearray(max((r.end for r in results), default=0))
        kept: List[Finding] = []
        for r in results:
            if occupied.find(1, r.start, r.end) == -1:
                occupied[r.start:r.end] = b"\x01" * (r.end - r.start)
                kept.append(r)
        return sorted(kept, key=lambda r: r.start)

    def mask(self, text: str, entities_to_mask: Optional[List[str]] = None,
             vault: Optional[Dict[str, str]] = None, findings: Optional[List[Finding]] = None,
             style: str = "placeholder") -> MaskResult:
        """Aynı vault birden fazla mesajda paylaşılır: aynı TCKN hep [TCKN_1] olur (farklı yazımı da:
        "391 417 776 94" ve "39141777694"; geri açılınca ilk görülen yazım döner).
        style="synthetic": biçimi belli türler yer tutucu yerine geçerli görünen sahte değer alır
        (synthetic.py); vault'ta anahtar sahte değerdir."""
        if style not in MASK_STYLES:
            raise ValueError(f"Geçersiz maskeleme biçimi '{style}' ({', '.join(MASK_STYLES)})")
        findings = self.analyze(text) if findings is None else findings   # hazır bulgu: yeniden taranmaz
        vault = vault if vault is not None else {}
        reverse: Dict[Tuple[str, str], str] = {}
        counters: Dict[str, int] = {}
        for k, v in vault.items():
            if not is_placeholder(k):
                continue        # sahte değer: aynı değer yeniden aynı sahteyi alır (belirlenimci)
            ent = placeholder_entity(k)
            reverse.setdefault((ent, canonical_value(ent, v)), k)
            counters[ent] = counters.get(ent, 0) + 1

        out, cursor = [], 0
        for f in findings:
            if entities_to_mask is not None and not entity_matches(f.entity, entities_to_mask):
                continue
            original = text[f.start:f.end]
            canon = canonical_value(f.entity, original)
            key = (f.entity, canon)
            placeholder = reverse.get(key)
            if placeholder is None and style == "synthetic" and f.entity in SYNTHETIC_ENTITIES:
                placeholder = self._surrogate(f.entity, original, canon, vault)
                if placeholder is not None:
                    vault[placeholder] = original
                    reverse[key] = placeholder
            if placeholder is None:
                counters[f.entity] = counters.get(f.entity, 0) + 1
                placeholder = f"[{f.entity}_{counters[f.entity]}]"
                vault[placeholder] = original
                reverse[key] = placeholder
            out.append(text[cursor:f.start])
            out.append(placeholder)
            cursor = f.end
        out.append(text[cursor:])
        return MaskResult("".join(out), findings, vault)

    def _surrogate(self, entity: str, original: str, canon: str, vault: Dict[str, str]) -> Optional[str]:
        if self._synthetic_key is None:
            self._synthetic_key = synthetic_key()
        for attempt in range(8):
            s = make_surrogate(entity, original, canon, self._synthetic_key, attempt)
            if s is None:
                return None
            # Orijinalin kendisi, başka bir değerin sahtesi ya da vault'taki gerçek bir değer olamaz
            if _alnum(s) != _alnum(original) and vault.get(s, original) == original and s not in vault.values():
                return s
        return None

    @staticmethod
    def unmask(text: str, vault: Dict[str, str]) -> str:
        # Uzun anahtar önce: [TCKN_10] işlenmeden [TCKN_1] değiştirilmesin
        synthetic = []
        for placeholder in sorted(vault, key=len, reverse=True):
            if not is_placeholder(placeholder):
                synthetic.append(placeholder)
            elif placeholder in text:
                text = text.replace(placeholder, vault[placeholder])
        if not synthetic:
            return text
        for email in (k for k in synthetic if "@" in k):
            text = text.replace(email, vault[email])
        numbers = {_alnum(k): vault[k] for k in synthetic if "@" not in k}
        if numbers:
            text = _surrogate_pattern(frozenset(k for k in synthetic if "@" not in k)).sub(
                lambda m: numbers.get(_alnum(m.group(0)), m.group(0)), text)
        return text
