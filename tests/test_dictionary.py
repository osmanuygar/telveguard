"""Kurumsal sözlük: proje adları, müşteri unvanları, iç sunucu adları (KURUM_*)."""
import time

import pytest

from app import xray as xray_mod
from app.dictionary import Dictionary, DictionaryError, load, trie_regex
from telveguard_core.pii.engine import TrPiiEngine
from tests.test_gateway import captured, client  # noqa: F401  (fixture)
from tests.test_xray import AUTH, admin  # noqa: F401  (fixture)


def engine(*entries) -> TrPiiEngine:
    pii = TrPiiEngine()
    Dictionary.from_config({"dictionary": list(entries)}).install(pii)
    return pii


def found(pii, text):
    return [(f.entity, text[f.start:f.end]) for f in pii.analyze(text)]


PROJE = {"entity": "KURUM_PROJE", "label": "Proje kod adı", "terms": ["Proje Anka", "Kızılay Projesi", "Mavi"]}


# ---------------- eşleşme ----------------

@pytest.mark.parametrize("text, hit", [
    ("PROJE ANKA bütçesi", "PROJE ANKA"),
    ("proje   anka", "proje   anka"),               # boşluk farkı
    ("KIZILAY PROJESİ toplantısı", "KIZILAY PROJESİ"),   # Türkçe büyük harf
    ("kızılay projesi", "kızılay projesi"),
    ("Mavi'nin teslim tarihi", "Mavi"),             # kesme işaretli ek
    ("Ankara ofisi", None),                          # kelimenin parçası değil
    ("Mavişehir şubesi", None),
    ("Proje Ankara", None),
])
def test_terms_match_whole_words_case_insensitive(text, hit):
    hits = [v for e, v in found(engine(PROJE), text) if e == "KURUM_PROJE"]
    assert hits == ([hit] if hit else [])


def test_case_sensitive_and_partial_word_options():
    pii = engine({"entity": "KURUM_URUN", "terms": ["TGX"], "case_sensitive": True, "whole_word": False})
    assert found(pii, "modeltgx ve modelTGX") == [("KURUM_URUN", "TGX")]


def test_patterns():
    pii = engine({"entity": "KURUM_SUNUCU", "patterns": [r"[a-z0-9][a-z0-9.-]*\.sirket\.local"]},
                 {"entity": "KURUM_PROJE", "patterns": [r"PRJ-\d{4}"]})
    assert found(pii, "db01.prod.sirket.local ve PRJ-2041, prj-2041") == [
        ("KURUM_SUNUCU", "db01.prod.sirket.local"), ("KURUM_PROJE", "PRJ-2041"), ("KURUM_PROJE", "prj-2041")]


def test_longer_builtin_wins_overlap():
    pii = engine({"entity": "KURUM_PROJE", "terms": ["anka"]})
    assert found(pii, "anka@ornek.com") == [("EMAIL_ADDRESS", "anka@ornek.com")]


def test_trie_shares_prefixes():
    assert trie_regex(["anka", "ankara", "proje anka"], False) == r"(?:anka(?:ra)?|proje\s+anka)"


def test_many_terms_fast():
    terms = [f"Musteri Unvani {i} A.Ş." for i in range(20_000)]
    t0 = time.perf_counter()
    pii = engine({"entity": "KURUM_MUSTERI", "terms": terms})
    text = ("Görüşme notları: " + "lorem ipsum dolor sit amet " * 4000) + "MUSTERI UNVANI 19999 A.Ş. ile"
    hits = found(pii, text)
    assert ("KURUM_MUSTERI", "MUSTERI UNVANI 19999 A.Ş.") in hits
    assert time.perf_counter() - t0 < 3


def test_terms_file_relative_with_comments(tmp_path):
    (tmp_path / "kurum").mkdir()
    (tmp_path / "kurum" / "musteriler.txt").write_text("# müşteri listesi\nAcme Lojistik\n\nBeta Enerji\n", "utf-8")
    (tmp_path / "policy.yaml").write_text(
        "dictionary:\n  - entity: KURUM_MUSTERI\n    terms_file: kurum/musteriler.txt\n", "utf-8")
    d = load(str(tmp_path / "policy.yaml"))
    assert d.describe() == [{"entity": "KURUM_MUSTERI", "label": "", "terms": 2, "patterns": 0}]
    pii = TrPiiEngine()
    d.install(pii)
    assert found(pii, "acme lojistik ile görüştük") == [("KURUM_MUSTERI", "acme lojistik")]


def test_install_is_idempotent():
    pii = TrPiiEngine()
    base = len(pii.recognizers)
    d = Dictionary.from_config({"dictionary": [PROJE]})
    d.install(pii)
    d.install(pii)
    assert len(pii.recognizers) == base + 1


@pytest.mark.parametrize("entry, message", [
    ({"entity": "PROJE", "terms": ["x1"]}, "KURUM_"),
    ({"entity": "KURUM_proje", "terms": ["x1"]}, "KURUM_"),
    ({"entity": "KURUM_PROJE"}, "gerekli"),
    ({"entity": "KURUM_PROJE", "terms": ["a"]}, "karakter"),
    ({"entity": "KURUM_PROJE", "terms": "Anka"}, "liste"),
    ({"entity": "KURUM_PROJE", "patterns": ["(abc"]}, "geçersiz düzenli ifade"),
    ({"entity": "KURUM_PROJE", "patterns": ["x*"]}, "boş metinle"),
    ({"entity": "KURUM_PROJE", "terms": ["ab"], "regex": "x"}, "bilinmeyen alan"),
    ({"entity": "KURUM_PROJE", "terms_file": "yok.txt"}, "okunamadı"),
    ({"entity": "KURUM_PROJE", "terms": ["ab"], "whole_word": "evet"}, "true ya da false"),
])
def test_invalid_entries(entry, message):
    with pytest.raises(DictionaryError, match=message):
        Dictionary.from_config({"dictionary": [entry]})


def test_default_policy_dictionary_valid():
    assert {e["entity"] for e in load("policies/default.yaml").describe()} >= {"KURUM_PROJE", "KURUM_SUNUCU"}


# ---------------- gateway ----------------

def chat(c, content, model="gpt-4o"):
    return c.post("/v1/chat/completions", json={"model": model, "messages": [{"role": "user", "content": content}]})


def test_external_model_gets_masked_term_and_user_gets_original(client):  # noqa: F811
    r = chat(client, "Proje Anka için db01.sirket.local sunucusundaki raporu özetle")
    assert r.status_code == 200
    sent = captured["body"]["messages"][-1]["content"]
    assert sent == "[KURUM_PROJE_1] için [KURUM_SUNUCU_1] sunucusundaki raporu özetle"
    assert "Proje Anka" in r.json()["choices"][0]["message"]["content"]


def test_internal_model_keeps_terms(client):  # noqa: F811
    chat(client, "Proje Anka durumu", model="vllm/qwen3")
    assert captured["body"]["messages"][-1]["content"] == "Proje Anka durumu"


def test_policy_info_lists_counts_not_terms(client, admin):  # noqa: F811
    info = client.get("/v1/policy/info", headers=AUTH).json()
    proje = next(d for d in info["dictionary"] if d["entity"] == "KURUM_PROJE")
    assert proje["terms"] == 2 and proje["label"] == "Proje kod adı"
    assert "Proje Anka" not in str(info["dictionary"])


def test_kvkk_reports_exclude_dictionary_terms():
    assert "startsWith(entity, 'KURUM_')" in xray_mod.KVKK_QUERY
    assert "KURUM_" in xray_mod._UNMASKED_PII and "KURUM_" in xray_mod.EVENT_FLAGS["external_unmasked_pii"]
