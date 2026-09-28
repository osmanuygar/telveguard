"""
Prompt injection tespiti - iki katman:

1) Hızlı yol: Türkçe + İngilizce sezgisel kurallar (<1 ms). Global araçların
   çoğu İngilizce eğitildiği için Türkçe saldırıları kaçırır; bu katman o boşluğu kapatır.
2) Opsiyonel: LLM Guard PromptInjection (DeBERTa sınıflandırıcı, MIT lisans).
   ENABLE_LLM_GUARD=1 ile açılır, modeli lokal dizinden okur.
"""
import os
import re
import unicodedata
from dataclasses import dataclass, field
from typing import List

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


class InjectionDetector:
    def __init__(self):
        self._llm_guard = None
        if os.getenv("ENABLE_LLM_GUARD") == "1":
            from llm_guard.input_scanners import PromptInjection  # type: ignore

            self._llm_guard = PromptInjection(threshold=0.9)

    def scan(self, text: str) -> InjectionResult:
        lowered = _fold(text)
        matched, score = [], 0.0
        for rx, weight in _COMPILED:
            if rx.search(lowered):
                matched.append(rx.pattern[:60])
                score = max(score, weight)
        result = InjectionResult(score=score, matched=matched)

        if self._llm_guard is not None and score < 0.9:
            _, is_valid, risk = self._llm_guard.scan(text)
            if risk > result.score:
                result = InjectionResult(score=float(risk), matched=matched + ["llm_guard"],
                                         engine="llm_guard")
        return result
