"""
Sahte değerle maskeleme (politikada `masking: {style: synthetic}`): `[TCKN_1]` yerine geçerli
görünen sahte bir değer.

Model yer tutucuyu anlamayınca cevap bozulur ("[TCKN_1] numaralı kişinin TC'si eksik görünüyor").
Sahte değer sağlama toplamından geçer (TCKN, VKN, IBAN, kart) ve orijinalin yazımını korur
(boşluk, tire): model onu gerçek bir değer gibi işler, cevap dönünce gerçeğine çevrilir.

Sahte değer anahtarlı HMAC'ten türetilir: aynı değer aynı sahteyi alır (konuşma her turda yeniden
maskelenir; sağlayıcının prompt önbelleği bozulmaz) ama anahtar bilinmeden sahteden gerçeğe
gidilemez (TCKN uzayı ~10^9, anahtarsız özet kaba kuvvetle çözülürdü). Anahtar
`TELVEGUARD_SYNTHETIC_KEY`; yoksa süreç başına rastgele (yeniden başlayınca sahteler değişir).

Yalnızca biçimi belli türler: sır, sözlük terimi ve NER bulguları yer tutucuyla maskelenir.
"""
import hashlib
import hmac
import os
import re
from typing import Iterator, Optional

SYNTHETIC_ENTITIES = frozenset({"TCKN", "VKN", "IBAN_TR", "CREDIT_CARD", "PHONE_TR", "EMAIL_ADDRESS", "PLATE_TR"})
SYNTHETIC_EMAIL_DOMAIN = "example.com"   # RFC 2606: gerçek bir posta kutusuna gidemez
_PLATE_LETTERS = "ABCDEFGHIJKLMNOPRSTUVYZ"   # plakada Q, W, X yok


def synthetic_key() -> bytes:
    raw = os.getenv("TELVEGUARD_SYNTHETIC_KEY", "")
    if raw and len(raw.encode()) < 32:
        raise ValueError("TELVEGUARD_SYNTHETIC_KEY en az 32 bayt olmalı")
    return raw.encode() if raw else os.urandom(32)


def _stream(key: bytes, entity: str, canonical: str, attempt: int) -> Iterator[int]:
    """Anahtarlı, belirlenimci bayt akışı."""
    block = 0
    while True:
        msg = f"{entity}\0{canonical}\0{attempt}\0{block}".encode("utf-8", "surrogatepass")
        yield from hmac.new(key, msg, hashlib.sha256).digest()
        block += 1


def _digits(rnd: Iterator[int], n: int) -> str:
    return "".join(str(next(rnd) % 10) for _ in range(n))


def _layout(original: str, digits: str) -> str:
    """Orijinalin rakamlarını sırayla `digits` ile değiştirir; ayraçlar ve harfler yerinde kalır."""
    it = iter(digits)
    return "".join(next(it) if ch.isdigit() else ch for ch in original)


def _tckn(rnd) -> str:
    d = [1 + next(rnd) % 9] + [next(rnd) % 10 for _ in range(8)]
    d.append(((sum(d[0:9:2]) * 7) - sum(d[1:8:2])) % 10)
    d.append(sum(d) % 10)
    return "".join(map(str, d))


def _vkn(rnd) -> str:
    d = [next(rnd) % 10 for _ in range(9)]
    total = 0
    for i in range(9):
        tmp = (d[i] + 9 - i) % 10
        v = (tmp * 2 ** (9 - i)) % 9
        if tmp != 0 and v == 0:
            v = 9
        total += v
    return "".join(map(str, d)) + str((10 - total % 10) % 10)


def _luhn_complete(payload: str) -> str:
    total = 0
    for i, ch in enumerate(reversed(payload + "0")):
        n = int(ch)
        if i % 2 == 1:
            n = n * 2 - 9 if n * 2 > 9 else n * 2
        total += n
    return payload + str((10 - total % 10) % 10)


def _iban_digits(rnd) -> str:
    """TR IBAN'ın 24 rakamı: kontrol (2) + banka (5) + rezerv "0" + hesap (16)."""
    bban = _digits(rnd, 5) + "0" + _digits(rnd, 16)
    check = 98 - int(bban + "292700") % 97     # T=29, R=27, kontrol "00"
    return f"{check:02d}{bban}"


def _plate(original: str, rnd) -> str:
    city = f"{1 + next(rnd) % 81:02d}"
    out, n = [], 0
    for ch in original:
        if ch.isdigit():
            out.append(city[n] if n < 2 else str(next(rnd) % 10))
            n += 1
        elif ch.isalpha():
            out.append(_PLATE_LETTERS[next(rnd) % len(_PLATE_LETTERS)])
        else:
            out.append(ch)
    return "".join(out)


def make_surrogate(entity: str, original: str, canonical: str, key: bytes, attempt: int = 0) -> Optional[str]:
    """Orijinalin yazımında, aynı türden geçerli sahte değer; desteklenmeyen tür ya da beklenmeyen
    biçimde None (çağıran yer tutucuya döner)."""
    rnd = _stream(key, entity, canonical, attempt)
    n = sum(ch.isdigit() for ch in original)
    if entity == "TCKN" and n == 11:
        return _layout(original, _tckn(rnd))
    if entity == "VKN" and n == 10:
        return _layout(original, _vkn(rnd))
    if entity == "IBAN_TR" and n == 24:
        return _layout(original, _iban_digits(rnd))
    if entity == "CREDIT_CARD" and 13 <= n <= 19:
        first = next(ch for ch in original if ch.isdigit())   # kart ağı (Visa / Mastercard) kalsın
        return _layout(original, _luhn_complete(first + _digits(rnd, n - 2)))
    if entity == "PHONE_TR" and n >= 10:
        kept = re.sub(r"\D", "", original)[:n - 9]            # ülke / alan öneki ve operatörün "5"i
        return _layout(original, kept + _digits(rnd, 9))
    if entity == "EMAIL_ADDRESS" and "@" in original:
        return f"kisi.{bytes(next(rnd) for _ in range(3)).hex()}@{SYNTHETIC_EMAIL_DOMAIN}"
    if entity == "PLATE_TR":
        return _plate(original, rnd)
    return None
