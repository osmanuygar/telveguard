"""
Tarayıcı eklentisinin JavaScript motoru (extension/src/detectors.js) Python motoruyla aynı
sonucu vermeli. Bu test Python'un beklenen çıktısını extension/tests/fixtures.json ile
karşılaştırır; JS tarafı aynı dosyayı `node extension/tests/detectors.test.js` ile doğrular.

Python motoru değişince:  REGENERATE_FIXTURES=1 pytest tests/test_extension_parity.py

Metinler base64 saklanır: sahte anahtarlar (ghp_..., sk_live_...) dosyada düz durursa GitHub
push protection / secret scanning onları gerçek sır sanıp push'u engelleyebilir.
"""
import base64
import json
import os
from pathlib import Path

from telveguard_core.pii.engine import TrPiiEngine
from tests.test_tr_pii import make_iban, make_tckn, make_vkn

FIXTURES = Path(__file__).resolve().parent.parent / "extension" / "tests" / "fixtures.json"


def _k(*parts):  # sahte anahtarlar kaynakta parça parça (secret scanning)
    return "".join(parts)


TEXTS = [
    # Türkçe kişisel veri
    f"Müşteri TC {make_tckn(1)} ve {make_tckn(2)}, tekrar {make_tckn(1)}",
    f"IBAN {make_iban()} ile ödeme; boşluklu: TR{make_iban()[2:4]} 0006 2000 0000 0012 3456 7890",
    f"Vergi no: {make_vkn()} olan firma, vkn {make_vkn('987654321')}",
    "Kart 4111 1111 1111 1111 ve 5500-0000-0000-0004 ile ödendi",
    "Cep 0532 123 45 67, +90 555 987 65 43, e-posta ali.veli@ornek.com.tr",
    "Araç 34 ABC 123 ve 06 A 1234 plakalı",
    # sırlar
    _k("AWS anahtar AKIA", "Q3EXAMPLE7ABCDEF ve aws_secret_access_key = ",
       "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
    _k("token ghp_", "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8 ve sk-ant-", "api03-Ab12Cd34Ef56Gh78Ij90Kl"),
    _k("sk-proj-", "Ab12Cd34Ef56Gh78Ij90Kl12Mn34 xoxb-", "1234567890-abcdefghij AIza",
       "SyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6q"),
    _k("sk_", "live_4eC39HqLyjWDarjtT1zdp7dc ve eyJ", "hbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmN"),
    _k("-----BEGIN ", "RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA7x\n-----END RSA PRIVATE KEY----- sonrası"),
    _k("bağlantı postgres://", "app:S3cr3t!pw@db.sirket.local:5432/crm ve şifre: Yaz2026!guclu"),
    '"password": "hunter2hunter", password=changeme123',
    # negatifler (yanlış pozitif olmamalı)
    "Sipariş no 12345678901, stok kodu 1234567890, ilan no 987654321",
    "password=password or None; password: ${DB_PASSWORD}; pwd = self.settings.password",
    "Risk-free task-force; postgres://db.sirket.local:5432/crm; şifre: [SECRET_PASSWORD_1]",
    "Kart 4111 1111 1111 1112 (Luhn tutmaz), IBAN TR000006200000000123456789",
]


def _b64(s: str) -> str:
    return base64.b64encode(s.encode("utf-8")).decode("ascii")


def expected():
    engine = TrPiiEngine()
    out = []
    for text in TEXTS:
        findings = engine.analyze(text)
        out.append({"text_b64": _b64(text),
                     "findings": [[f.entity, f.start, f.end] for f in findings],
                     "masked_b64": _b64(engine.mask(text).text)})
    return out


def test_fixtures_match_python_engine():
    exp = expected()
    if os.getenv("REGENERATE_FIXTURES") == "1":
        FIXTURES.write_text(json.dumps(exp, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    assert FIXTURES.exists(), "REGENERATE_FIXTURES=1 ile oluşturun"
    assert json.loads(FIXTURES.read_text(encoding="utf-8")) == exp, \
        "Python motoru değişti: REGENERATE_FIXTURES=1 pytest tests/test_extension_parity.py"


def test_fixtures_cover_every_recognizer():
    from telveguard_core.pii.secret_recognizers import SECRET_RECOGNIZERS
    from telveguard_core.pii.tr_recognizers import TR_RECOGNIZERS
    seen = {f[0] for case in expected() for f in case["findings"]}
    assert seen == {r.entity for r in TR_RECOGNIZERS + SECRET_RECOGNIZERS}


# ---------------- kurumsal sözlük (özetle eşleşme) ----------------

DICT_FIXTURES = FIXTURES.parent / "dictionary_fixtures.json"
DICT_CONFIG = {"dictionary": [
    {"entity": "KURUM_PROJE", "label": "Proje kod adı",
     "terms": ["Proje Anka", "Kızılay Projesi", "Mavi", "Anka Turna"]},
    {"entity": "KURUM_MUSTERI", "label": "Müşteri unvanı", "terms": ["Akdeniz Holding A.Ş.", "Işık Lojistik"]},
    {"entity": "KURUM_KOD", "terms": ["ACME"], "case_sensitive": True},
    {"entity": "KURUM_SUNUCU", "patterns": [r"[a-z0-9][a-z0-9.-]*\.sirket\.local"]},
]}
DICT_TEXTS = [
    "PROJE ANKA bütçesi ve Kızılay Projesi toplantısı",
    "proje   anka\nraporu; KIZILAY PROJESİ onaylandı",
    "Mavi'nin teslim tarihi; Mavişehir şubesi ve Ankara ofisi, Proje Ankara değil",
    "Akdeniz Holding A.Ş. ile ışık lojistik ve IŞIK LOJİSTİK sözleşmesi",
    "ACME bayisi, acme ve Acme değil",
    "Sunucular db01.sirket.local ve api.sirket.local:8443, sirket.local.com değil",
    "Proje Anka Turna birlikte geçerse soldaki kazanır",
    f"Proje Anka müşterisi TC {make_tckn(1)}, e-posta ali@sirket.local",
    "Önceden maskeli [KURUM_PROJE_1] ve yeni Mavi",
]


def dictionary_expected():
    from app.dictionary import Dictionary
    d = Dictionary.from_config(DICT_CONFIG)
    engine = TrPiiEngine()
    d.install(engine)
    cases = [{"text_b64": _b64(t), "findings": [[f.entity, f.start, f.end] for f in engine.analyze(t)],
              "masked_b64": _b64(engine.mask(t).text)} for t in DICT_TEXTS]
    return {"payload": d.browser(), "cases": cases}


def test_dictionary_fixtures_match_python_engine():
    exp = dictionary_expected()
    if os.getenv("REGENERATE_FIXTURES") == "1":
        DICT_FIXTURES.write_text(json.dumps(exp, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    assert DICT_FIXTURES.exists(), "REGENERATE_FIXTURES=1 ile oluşturun"
    assert json.loads(DICT_FIXTURES.read_text(encoding="utf-8")) == exp, \
        "Sözlük motoru değişti: REGENERATE_FIXTURES=1 pytest tests/test_extension_parity.py"
    payload = json.dumps(exp["payload"], ensure_ascii=False).lower()
    assert not any(t.lower() in payload for item in DICT_CONFIG["dictionary"] for t in item.get("terms", []))
