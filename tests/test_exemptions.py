"""İstisna listesi: kurumun kamuya açık IBAN'ı, destek e-postası gibi değerler kişisel veri sayılmaz."""
import logging

import pytest

from app.exemptions import Exemptions, ExemptionError, normalize
from telveguard_core.pii.engine import TrPiiEngine
from tests.test_gateway import _capture_events, captured, client  # noqa: F401  (fixture)
from tests.test_tr_pii import make_iban, make_tckn

KURUM_IBAN = make_iban(account="0000000999999999")
CFG = {"exceptions": [
    {"entity": "IBAN_TR", "label": "Tahsilat hesabı", "values": [KURUM_IBAN]},
    {"entity": "EMAIL_ADDRESS", "patterns": [r"[\w.+-]+@sirket\.com\.tr"]},
    {"entity": "PHONE_TR", "values": ["0532 000 00 00"]},
]}


def engine(cfg=CFG) -> TrPiiEngine:
    pii = TrPiiEngine()
    Exemptions.from_config(cfg).install(pii)
    return pii


def found(pii, text):
    return [(f.entity, text[f.start:f.end]) for f in pii.analyze(text)]


def spaced(iban: str) -> str:
    return " ".join(iban[i:i + 4] for i in range(0, len(iban), 4))


# ---------------- eşleşme ----------------

def test_exempt_values_are_not_findings_in_any_spelling():
    pii = engine()
    other = make_iban(account="0000000123456789")
    text = (f"Ödemeyi {spaced(KURUM_IBAN).lower()} hesabına yapın, müşteri IBAN'ı {other}. "
            "Destek: Destek@Sirket.com.tr, müşteri: ali@ornek.com. Arayın: +90 532 000 0000, müşteri 0533 111 22 33")
    assert found(pii, text) == [("IBAN_TR", other), ("EMAIL_ADDRESS", "ali@ornek.com"), ("PHONE_TR", "0533 111 22 33")]


def test_digits_inside_exempt_iban_not_detected_as_other_types():
    pii = engine()
    assert found(pii, f"IBAN {KURUM_IBAN}") == []


def test_pattern_must_match_whole_value():
    pii = engine()
    assert found(pii, "x@sirket.com.tr.saldirgan.com") == [("EMAIL_ADDRESS", "x@sirket.com.tr.saldirgan.com")]


def test_exemption_is_per_entity():
    tckn = make_tckn()
    pii = engine({"exceptions": [{"entity": "VKN", "values": [tckn[:10]]}]})
    assert found(pii, f"TC {tckn}") == [("TCKN", tckn)]


def test_mask_leaves_exempt_values():
    pii = engine()
    tckn = make_tckn()
    out = pii.mask(f"{tckn} numaralı müşteri {KURUM_IBAN} hesabına ödesin")
    assert out.text == f"[TCKN_1] numaralı müşteri {KURUM_IBAN} hesabına ödesin"


@pytest.mark.parametrize("entity, a, b", [
    ("PHONE_TR", "+90 (532) 000-00-00", "05320000000"),
    ("CREDIT_CARD", "4111-1111-1111-1111", "4111111111111111"),
    ("PERSON", "  Ayşe   Yılmaz ", "ayşe yılmaz"),
])
def test_normalize(entity, a, b):
    assert normalize(entity, a) == normalize(entity, b)


@pytest.mark.parametrize("cfg, msg", [
    ([{"entity": "SECRET_AWS_KEY", "values": ["AKIA..."]}], "istisna olamaz"),
    ([{"entity": "KURUM_PROJE", "values": ["Anka"]}], "istisna olamaz"),
    ([{"entity": "IBAN_TR"}], "values ya da patterns gerekli"),
    ([{"entity": "IBAN_TR", "values": [""]}], "boş olmayan"),
    ([{"entity": "iban", "values": ["x"]}], "büyük harfli"),
    ([{"entity": "IBAN_TR", "value": ["x"]}], "bilinmeyen alan"),
    ([{"entity": "EMAIL_ADDRESS", "patterns": ["(bozuk"]}], "geçersiz düzenli ifade"),
    ({"entity": "IBAN_TR"}, "liste olmalı"),
])
def test_invalid_config_rejected(cfg, msg):
    with pytest.raises(ExemptionError, match=msg):
        Exemptions.from_config({"exceptions": cfg})


def test_undetectable_value_warns(caplog):
    with caplog.at_level(logging.WARNING, "telveguard.exemptions"):
        engine({"exceptions": [{"entity": "IBAN_TR", "values": ["TR00 1234"]}]})
    assert "exemption_not_detected entity=IBAN_TR" in caplog.text and "TR00" not in caplog.text


def test_empty_config_installs_nothing():
    pii = engine({})
    assert pii.exempt is None


# ---------------- gateway ----------------

def test_gateway_does_not_mask_or_record_exempt_value(client):  # noqa: F811
    Exemptions.from_config(CFG).install(client.app.state.pii)
    events = _capture_events(client)
    tckn = make_tckn()
    r = client.post("/v1/chat/completions", json={"model": "gpt-4o", "messages": [
        {"role": "user", "content": f"{tckn} müşterisine {KURUM_IBAN} hesabımızı ilet"}]})
    assert r.status_code == 200
    sent = captured["body"]["messages"][-1]["content"]
    assert "[TCKN_1]" in sent and KURUM_IBAN in sent
    assert events[-1]["entities"] == ["TCKN"]
