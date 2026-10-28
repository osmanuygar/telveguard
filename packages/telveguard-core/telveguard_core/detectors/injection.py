"""
Prompt injection tespiti - iki katman:

1) Hızlı yol: Türkçe + İngilizce sezgisel kurallar (<1 ms). Global araçların
   çoğu İngilizce eğitildiği için Türkçe saldırıları kaçırır; bu katman o boşluğu kapatır.
2) Opsiyonel: LLM Guard PromptInjection (DeBERTa sınıflandırıcı, MIT lisans).
   ENABLE_LLM_GUARD=1 ile açılır, modeli LLM_GUARD_MODEL_PATH dizininden okur (internet yok).
   LLM_GUARD_THRESHOLD (0,92), LLM_GUARD_USE_ONNX=1 (CPU'da daha hızlı, onnx/ alt dizini).
"""
import hashlib
import os
import re
import threading
import unicodedata
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import FrozenSet, List

# (desen, ağırlık) - Türkçe ekler için kök + \w* kullanılıyor
_RULES = [
    # TR: talimatları yok sayma
    (r"(önceki|yukarıdaki|tüm|bütün)\s+(talimat|kural|yönerge|komut)\w*\s+(yok\s*say|unut|görmezden\s*gel|iptal\s*et)", 0.9),
    (r"(talimat|kural|yönerge)\w*\s+(yok\s*say|unut|görmezden\s*gel)", 0.7),
    # TR: sistem promptunu sızdırma
    (r"(sistem|gizli)\s+(prompt|mesaj|talimat)\w*\s*(u|ı|i|ü)?\s*(göster|yaz|ver|paylaş|söyle|açıkla)", 0.85),
    # TR: rol / mod değiştirme
    # "dan" ayrı kelime olmalı ("Ankara'dan modern" eşleşmesin) ve "mod" sadece
    # mod/mode ve Türkçe ekleriyle ("model", "modern" değil)
    (r"(?<![\w'’])(geliştirici|developer|jailbreak|dan)\s+mod(?:e|u|a|da|una|unu|unda|dasın|undasın)?\b", 0.8),
    (r"artık\s+(sen\s+)?(kısıtlama|sınır|filtre)\w*\s+(yok|olmayan)", 0.8),
    # EN
    (r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|rules|prompts?)", 0.9),
    (r"(reveal|print|show)\s+(your\s+)?(system\s+prompt|hidden\s+instructions)", 0.85),
    (r"you\s+are\s+now\s+(dan|in\s+developer\s+mode|unrestricted)", 0.85),
    # Gizli/görünmez karakterlerle kaçırma (zero-width, tag chars)
    (r"[\u200b-\u200f\u2060\ufeff\U000e0000-\U000e007f]", 0.6),
]


def _fold(text: str) -> str:
    """Türkçe duyarlı katlama. str.casefold() "İ"yi "i̇" (i + U+0307) yapar ve
    "TALİMAT" -> "tali̇mat" eşleşmez; ayrıca "I" -> "i" olur ama Türkçede "ı"dır.
    Bu yüzden İ/I/ı/i hepsi "i"ye indirilir; küçük harfli kurallarda da ı -> i yapılır
    (kurallara casefold uygulanmaz: "\\U000e0000" kaçışı bozulur).
    NFKC, tam genişlikli / uyumluluk karakterleriyle kaçırmayı da kapatır."""
    text = unicodedata.normalize("NFKC", text).replace("İ", "i").replace("\u0307", "")
    return text.casefold().replace("ı", "i")


_COMPILED = [(re.compile(p.replace("ı", "i"), re.IGNORECASE), w) for p, w in _RULES]


@dataclass
class InjectionResult:
    score: float
    matched: List[str] = field(default_factory=list)
    engine: str = "heuristic"


# LLM Guard injection dediğinde verilen skor: varsayılan engelleme eşiğinin (0,85) üstünde
LLM_GUARD_DETECTED_SCORE = 0.9


def _build_llm_guard():
    """LLM Guard PromptInjection'ı LOKAL modelle kurar (air-gapped: HuggingFace'e hiç çıkmaz).
    Model scripts/mirror_models.sh ile indirilir; varsayılan dizin /models/prompt-injection.
    LLM Guard >= 0.3.16 API'si: PromptInjection(model=Model(path=...)) (kaynaktan doğrulandı)."""
    from llm_guard.input_scanners import PromptInjection  # type: ignore
    from llm_guard.input_scanners.prompt_injection import V2_MODEL  # type: ignore
    from llm_guard.model import Model  # type: ignore

    path = os.getenv("LLM_GUARD_MODEL_PATH", "/models/prompt-injection")
    if not os.path.isdir(path):
        raise RuntimeError(f"LLM Guard modeli bulunamadı: {path} (scripts/mirror_models.sh ile indirin, "
                           "LLM_GUARD_MODEL_PATH ile gösterin)")
    use_onnx = os.getenv("LLM_GUARD_USE_ONNX") == "1"
    offline = {"local_files_only": True}
    model = Model(path=path, revision=None,
                  onnx_path=path if use_onnx else None, onnx_revision=None,
                  onnx_subfolder="onnx", onnx_filename="model.onnx",
                  pipeline_kwargs=dict(V2_MODEL.pipeline_kwargs), kwargs=dict(offline),
                  tokenizer_kwargs=dict(offline))
    threshold = float(os.getenv("LLM_GUARD_THRESHOLD", "0.92"))
    return PromptInjection(model=model, threshold=threshold, use_onnx=use_onnx)


# Parça sınırı penceresi: iki mesaja bölünmüş saldırı cümlesi ("Önceki tüm" + "talimatları yok say")
BOUNDARY_CHARS = 200
_CACHE_SIZE = int(os.getenv("TELVEGUARD_SCAN_CACHE_SIZE", "4096"))
_CACHE_MIN_CHARS = 256


class InjectionDetector:
    def __init__(self):
        self._llm_guard = _build_llm_guard() if os.getenv("ENABLE_LLM_GUARD") == "1" else None
        self._cache: "OrderedDict[bytes, FrozenSet[int]]" = OrderedDict()
        self._lock = threading.Lock()

    @staticmethod
    def _rules(text: str) -> FrozenSet[int]:
        """Eşleşen kural sıra numaraları."""
        lowered = _fold(text)
        return frozenset(i for i, (rx, _) in enumerate(_COMPILED) if rx.search(lowered))

    def _rules_cached(self, text: str) -> FrozenSet[int]:
        if _CACHE_SIZE <= 0 or len(text) < _CACHE_MIN_CHARS:
            return self._rules(text)
        key = hashlib.sha256(text.encode("utf-8", "surrogatepass")).digest()
        with self._lock:
            hit = self._cache.get(key)
            if hit is not None:
                self._cache.move_to_end(key)
                return hit
        found = self._rules(text)
        with self._lock:
            self._cache[key] = found
            while len(self._cache) > _CACHE_SIZE:
                self._cache.popitem(last=False)
        return found

    def scan(self, text: str) -> InjectionResult:
        return self._result(self._rules(text), text)

    def scan_parts(self, texts: List[str]) -> InjectionResult:
        """scan("\n".join(texts)) ile aynı sonuç; değişmeyen parçalar yeniden taranmaz (önbellek).
        Kural eşleşmesi parçaların ve parça sınırı pencerelerinin birleşimidir (_fold karakter
        bazlıdır, "\n" ayırıcıdır). LLM Guard açıksa sınıflandırıcı yine birleşik metne bakar."""
        hits = set()
        for t in texts:
            hits |= self._rules_cached(t)
        for prev, nxt in zip(texts, texts[1:]):
            if prev and nxt:
                hits |= self._rules_cached(prev[-BOUNDARY_CHARS:] + "\n" + nxt[:BOUNDARY_CHARS])
        return self._result(frozenset(hits), None, texts)

    def _result(self, hits: FrozenSet[int], text, texts=None) -> InjectionResult:
        matched = [_COMPILED[i][0].pattern[:60] for i in sorted(hits)]
        score = max((_COMPILED[i][1] for i in hits), default=0.0)
        result = InjectionResult(score=score, matched=matched)

        if self._llm_guard is not None and score < LLM_GUARD_DETECTED_SCORE:
            text = text if text is not None else "\n".join(texts)
            # scan() -> (metin, is_valid, risk_score). risk_score OLASILIK DEĞİL: eşiğe göre
            # ölçeklenmiş [-1, 1] (0,95 olasılık / 0,92 eşik -> 0,4). Olasılık gibi okunursa
            # tespit edilen injection engelleme eşiğinin altında kalır. Karar is_valid'dedir.
            _, is_valid, _risk = self._llm_guard.scan(text)
            if not is_valid:
                result = InjectionResult(score=LLM_GUARD_DETECTED_SCORE, matched=matched + ["llm_guard"],
                                         engine="llm_guard")
        return result
