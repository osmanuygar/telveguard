"""
KVKK md. 11 ilgili kişi başvurusu: "Kişisel verilerim yapay zekâ hizmetlerine gönderildi mi?"

Ham değer hiçbir zaman saklanmaz. Her istekte bulunan TANIMLAYICILARIN (TCKN, VKN, IBAN, kart,
telefon, e-posta, plaka) anahtarlı özeti (HMAC-SHA256, TELVEGUARD_SUBJECT_HASH_KEY) denetim
kaydına `subject_hashes` olarak yazılır. Başvuruda verilen değer aynı anahtarla özetlenip
kayıtlarda aranır.

Neden anahtarlı: geçerli TCKN sayısı ~10^9'dur; anahtarsız SHA-256 özeti birkaç dakikada
kaba kuvvetle geri çevrilir. Anahtar olmadan özetler işe yaramaz; anahtar Secret'ta durmalı ve
ClickHouse'a erişen kişilerle paylaşılmamalıdır.

Anahtar değişirse eski kayıtlar artık bulunamaz (eski anahtar TELVEGUARD_SUBJECT_HASH_KEY_OLD
ile bir süre aramaya eklenebilir). Anahtar yoksa özellik kapalıdır: özet yazılmaz.

Değerler biçimden bağımsız eşleşsin diye normalize edilir: "0532 123 45 67" ile
"+90 532 1234567" aynı telefondur; IBAN boşluksuz, e-posta küçük harf.
"""
import hashlib
import hmac
import logging
import os
import re
from typing import Dict, Iterable, List, Optional

log = logging.getLogger("telveguard.subjects")

# Kişiyi tanımlayan türler. Kişi adı (NER) yazım farklarıyla güvenilir eşleşmez; sırlar kişisel
# veri değildir.
SUBJECT_ENTITIES = ("TCKN", "VKN", "IBAN_TR", "CREDIT_CARD", "PHONE_TR", "EMAIL_ADDRESS", "PLATE_TR")
MIN_KEY_LEN = 32
HASH_HEX = 32          # 128 bit: çakışma pratikte imkânsız, sütun küçük kalır
MAX_SEARCH_VALUES = 20


def normalize(entity: str, value: str) -> str:
    if entity in ("TCKN", "VKN", "CREDIT_CARD"):
        return re.sub(r"\D", "", value)
    if entity == "PHONE_TR":
        return re.sub(r"\D", "", value)[-10:]          # 90 / 0 öneki olmadan 5XXXXXXXXX
    if entity in ("IBAN_TR", "PLATE_TR"):
        return re.sub(r"[\s-]", "", value).upper().replace("İ", "I")
    if entity == "EMAIL_ADDRESS":
        return value.strip().lower()
    return value.strip()


class SubjectIndex:
    def __init__(self, key: Optional[str], old_key: Optional[str] = None):
        for name, k in (("TELVEGUARD_SUBJECT_HASH_KEY", key), ("TELVEGUARD_SUBJECT_HASH_KEY_OLD", old_key)):
            if k and len(k) < MIN_KEY_LEN:
                raise ValueError(f"{name} en az {MIN_KEY_LEN} karakter olmalı (ör. openssl rand -hex 32)")
        self._key = key.encode() if key else None
        self._old = old_key.encode() if old_key else None

    @classmethod
    def from_env(cls) -> "SubjectIndex":
        index = cls(os.getenv("TELVEGUARD_SUBJECT_HASH_KEY") or None,
                    os.getenv("TELVEGUARD_SUBJECT_HASH_KEY_OLD") or None)
        if not index.enabled:
            log.info("subject_index_disabled: TELVEGUARD_SUBJECT_HASH_KEY yok; ilgili kişi araması kapalı")
        return index

    @property
    def enabled(self) -> bool:
        return self._key is not None

    @staticmethod
    def _digest(key: bytes, entity: str, value: str) -> str:
        return hmac.new(key, f"{entity}:{normalize(entity, value)}".encode(), hashlib.sha256).hexdigest()[:HASH_HEX]

    def hash(self, entity: str, value: str) -> str:
        return self._digest(self._key, entity, value)

    def event_hashes(self, text: str, findings: Iterable) -> List[str]:
        """Denetim olayına yazılacak özetler (yalnızca tanımlayıcı türler, tekrarsız)."""
        if not self.enabled:
            return []
        return sorted({self.hash(f.entity, text[f.start:f.end]) for f in findings if f.entity in SUBJECT_ENTITIES})

    def resolve(self, pii, items: List) -> List[Dict]:
        """Başvurudaki değerler -> [{label, entity, hashes}] ya da {label, error}. Değer metin
        (tür otomatik bulunur) ya da {"entity": "VKN", "value": "..."} olabilir: VKN gibi
        bağlamsız tanınmayan türler için. label, değerin maskeli hâlidir (cevapta ve logda ham
        değer dolaşmasın)."""
        keys = [k for k in (self._key, self._old) if k]
        out = []
        for item in items:
            entity = ""
            if isinstance(item, dict):
                entity, value = str(item.get("entity") or ""), str(item.get("value") or "").strip()
                if entity not in SUBJECT_ENTITIES:
                    out.append({"label": mask_label(value), "error": f"Tür şunlardan biri olmalı: "
                                f"{', '.join(SUBJECT_ENTITIES)}"})
                    continue
            else:
                value = str(item).strip()
                findings = [f for f in pii.analyze(value) if f.entity in SUBJECT_ENTITIES]
                if not findings:
                    out.append({"label": mask_label(value), "error": "Tanınan bir kimlik / iletişim bilgisi "
                                "değil (TCKN, IBAN, kart, telefon, e-posta, plaka; VKN için türü seçin)."})
                    continue
                # "TC 123..." gibi açıklamalı yazımda yalnızca tanımlayıcının kendisi
                f = max(findings, key=lambda f: f.end - f.start)
                entity, value = f.entity, value[f.start:f.end]
            if not normalize(entity, value):
                out.append({"label": mask_label(value), "error": "Boş değer."})
                continue
            out.append({"label": mask_label(value, entity), "entity": entity,
                        "hashes": [self._digest(k, entity, value) for k in keys]})
        return out


def mask_label(value: str, entity: str = "") -> str:
    """Raporda / logda görünen hâl: son 4 karakter dışında gizli (e-postada alan adı açık)."""
    if entity == "EMAIL_ADDRESS" and "@" in value:
        local, _, domain = value.partition("@")
        return f"{local[:1]}***@{domain}"
    v = re.sub(r"\s", "", value)
    return "*" * max(0, len(v) - 4) + v[-4:] if len(v) > 4 else "****"
