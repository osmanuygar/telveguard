"""
Türkiye'ye özel PII tanıyıcıları - SIFIR ağır bağımlılık (sadece stdlib `re`).

Neden Presidio değil? `presidio_analyzer` import edilince spaCy ve ~376 MB bağımlılık
geliyor. Bir güvenlik gateway'inin sıcak yolunda bu hem gecikme hem tedarik zinciri
riski. Presidio kullanan ekipler için `presidio_adapter.py` aynı kuralları sarar.

Tüm kimlik tanıyıcıları checksum doğrular; rastgele 11 haneli sayı != TCKN.
"""
import re
from dataclasses import dataclass
from typing import Callable, List, Optional


# ---------- Doğrulama fonksiyonları ----------

def _digits(value: str) -> List[int]:
    return [int(c) for c in re.sub(r"\D", "", value)]


def is_valid_tckn(value: str) -> bool:
    d = _digits(value)
    if len(d) != 11 or d[0] == 0:
        return False
    d10 = ((sum(d[0:9:2]) * 7) - sum(d[1:8:2])) % 10
    return d[9] == d10 and d[10] == sum(d[:10]) % 10


def is_valid_vkn(value: str) -> bool:
    d = _digits(value)
    if len(d) != 10:
        return False
    total = 0
    for i in range(9):
        tmp = (d[i] + 9 - i) % 10
        v = (tmp * 2 ** (9 - i)) % 9
        if tmp != 0 and v == 0:
            v = 9
        total += v
    return (10 - total % 10) % 10 == d[9]


def is_valid_tr_iban(value: str) -> bool:
    s = re.sub(r"\s", "", value).upper()
    if not re.fullmatch(r"TR\d{24}", s):
        return False
    numeric = "".join(str(int(ch, 36)) for ch in s[4:] + s[:4])
    return int(numeric) % 97 == 1


def is_valid_luhn(value: str) -> bool:
    d = _digits(value)
    if not 13 <= len(d) <= 19:
        return False
    total = 0
    for i, n in enumerate(reversed(d)):
        if i % 2 == 1:
            n = n * 2 - 9 if n * 2 > 9 else n * 2
        total += n
    return total % 10 == 0


# ---------- Tanıyıcı tanımı ----------

@dataclass(frozen=True)
class Recognizer:
    entity: str
    pattern: "re.Pattern[str]"
    score: float
    validator: Optional[Callable[[str], bool]] = None
    group: int = 0  # eşleşmenin hangi grubu PII (bağlam kelimesini dışarıda bırakmak için)


def _rx(p: str, flags: int = 0) -> "re.Pattern[str]":
    return re.compile(p, flags)


TR_RECOGNIZERS: List[Recognizer] = [
    Recognizer("TCKN", _rx(r"(?<!\d)[1-9]\d{10}(?!\d)"), 1.0, is_valid_tckn),
    # 10 haneli sayıların ~%10'u tesadüfen checksum'ı geçer: sadece "vergi/vkn" bağlamıyla
    Recognizer("VKN", _rx(r"(?:vkn|vergi\s*(?:kimlik\s*)?(?:no|numarası)?)\W{0,3}(\d{10})(?!\d)", re.I),
               1.0, is_valid_vkn, group=1),
    Recognizer("IBAN_TR", _rx(r"\bTR\d{2}(?:\s?\d{4}){5}\s?\d{2}\b", re.I), 1.0, is_valid_tr_iban),
    Recognizer("CREDIT_CARD", _rx(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)"), 1.0, is_valid_luhn),
    Recognizer("EMAIL_ADDRESS", _rx(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b"), 1.0),
    Recognizer("PHONE_TR", _rx(r"(?<![\d\w])(?:\+?90[\s-]?|0)?\(?5\d{2}\)?[\s-]?\d{3}[\s-]?\d{2}[\s-]?\d{2}(?!\d)"), 0.7),
    # Plakada büyük harf şart (IGNORECASE yok); Q, W, X plakada kullanılmaz
    Recognizer("PLATE_TR", _rx(r"\b(?:0[1-9]|[1-7]\d|8[01])\s?[A-PR-VYZ]{1,3}\s?\d{2,4}\b"), 0.6),
]
