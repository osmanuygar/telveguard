"""
Sır tespiti testleri. Sahte anahtarlar çalışma anında parçalardan birleştirilir:
kaynakta gerçek sır biçiminde dize olmasın (GitHub push protection / secret scanning).
"""
import pytest

from telveguard_core.entities import matching_entities
from telveguard_core.pii.engine import TrPiiEngine
from telveguard_core.policy import Context, PolicyEngine
from tests.test_tr_pii import make_tckn


def fake(prefix: str, body: str) -> str:
    return prefix + body


SAMPLES = {
    "SECRET_AWS_KEY": fake("AKIA", "Q3EXAMPLE7ABCDEF"),
    "SECRET_GITHUB_TOKEN": fake("ghp_", "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"),
    "SECRET_OPENAI_KEY": fake("sk-proj-", "Ab12Cd34Ef56Gh78Ij90Kl12Mn34"),
    "SECRET_ANTHROPIC_KEY": fake("sk-ant-", "api03-Ab12Cd34Ef56Gh78Ij90Kl"),
    "SECRET_SLACK_TOKEN": fake("xoxb-", "1234567890-abcdefghij"),
    "SECRET_GOOGLE_API_KEY": fake("AIza", "SyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6q"),
    "SECRET_STRIPE_KEY": fake("sk_" + "live_", "4eC39HqLyjWDarjtT1zdp7dc"),
    "SECRET_JWT": fake("eyJ", "hbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"),
    "SECRET_DB_URL": fake("postgres://", "app:S3cr3t!pw@db.sirket.local:5432/crm"),
}


@pytest.fixture(scope="module")
def engine():
    return TrPiiEngine()


@pytest.mark.parametrize("entity,value", SAMPLES.items())
def test_secret_detected_and_masked(engine, entity, value):
    text = f"Şu kodu düzelt: token = {value} teşekkürler"
    assert entity in {f.entity for f in engine.analyze(text)}
    masked = engine.mask(text, ["SECRET_*"])
    assert value not in masked.text and f"[{entity}_1]" in masked.text
    assert engine.unmask(masked.text, masked.vault) == text


def test_private_key_block_masked_even_if_truncated(engine):
    header = "-----BEGIN " + "RSA PRIVATE KEY-----"
    full = f"{header}\nMIIEowIBAAKCAQEA7x\n-----END RSA PRIVATE KEY-----"
    for text in (f"Anahtar:\n{full}\nbitti", f"Anahtar:\n{header}\nMIIEowIBAAKCAQEA7x"):
        masked = engine.mask(text, ["SECRET_*"]).text
        assert "MIIEowIBAAKCAQEA7x" not in masked and "[SECRET_PRIVATE_KEY_1]" in masked


def test_password_in_turkish_context(engine):
    text = "Sunucu şifre: Yaz2026!guclu olarak ayarlandı"
    masked = engine.mask(text, ["SECRET_*"]).text
    assert "Yaz2026!guclu" not in masked and "şifre: [SECRET_PASSWORD_1]" in masked


def test_db_url_wins_over_email_overlap(engine):
    # "pw@db.sirket.local" e-posta gibi görünür; daha uzun olan bağlantı dizesi kazanmalı
    ents = [f.entity for f in engine.analyze(SAMPLES["SECRET_DB_URL"])]
    assert ents == ["SECRET_DB_URL"]


@pytest.mark.parametrize("text", [
    "Risk-free task-force toplantısı",            # "sk-" kelime içinde
    "Parola politikası: en az 12 karakter",       # "parola" var ama atama yok
    "postgres://db.sirket.local:5432/crm",        # parolasız bağlantı dizesi
    "Sipariş AKIA123 kodlu",                      # kısa, AWS biçimi değil
])
def test_no_false_positive(engine, text):
    assert not any(f.entity.startswith("SECRET_") for f in engine.analyze(text))


def test_tr_pii_still_detected_next_to_secret(engine):
    tckn = make_tckn()
    ents = {f.entity for f in engine.analyze(f"TC {tckn} ve anahtar {SAMPLES['SECRET_AWS_KEY']}")}
    assert {"TCKN", "SECRET_AWS_KEY"} <= ents


def test_glob_matching():
    assert matching_entities({"TCKN", "SECRET_JWT", "SECRET_AWS_KEY"}, ["SECRET_*"]) == {"SECRET_JWT", "SECRET_AWS_KEY"}


def test_default_policy_masks_secret_even_for_internal_model():
    policy = PolicyEngine("policies/default.yaml")
    d = policy.evaluate(Context("analitik", "vllm/qwen3", "internal", {"SECRET_AWS_KEY"}, 0.0))
    assert d.action == "mask" and d.mask_entities == {"SECRET_AWS_KEY"}


# Parola tanıyıcısı: kod / yorum / şablon kalıpları parola sayılmamalı (repo taramasında görüldü)
@pytest.mark.parametrize("text", [
    "aioredis.from_url(url, password=password or None, socket_timeout=0.5)",
    "redisUrl: ''   # (parola: secret'taki redis-password)",
    "password: ${DB_PASSWORD}",
    'password = os.getenv("DB_PASSWORD")',
    'PASSWORD: "{{ .Values.secrets.pw }}"',
    "password: ********",
    "şifre: <şifreniz>",
    "pwd = self.settings.password",
    "password=None",
])
def test_password_false_positives_ignored(engine, text):
    assert "SECRET_PASSWORD" not in {f.entity for f in engine.analyze(text)}


@pytest.mark.parametrize("text,value", [
    ("şifre: Yaz2026!guclu", "Yaz2026!guclu"),
    ("password=changeme123", "changeme123"),
    ("DB_PASSWORD=Sup3rS3cret", "Sup3rS3cret"),
    ("parola: Summer2026", "Summer2026"),
    ('"password": "hunter2hunter"', "hunter2hunter"),
])
def test_real_passwords_still_detected(engine, text, value):
    found = [f for f in engine.analyze(text) if f.entity == "SECRET_PASSWORD"]
    assert found and text[found[0].start:found[0].end] == value


@pytest.mark.parametrize("text", [
    "def __init__(self, url: str, password: Optional[str] = None):",
    "şifre: [SECRET_PASSWORD_1]",          # maskelenmiş metin tekrar taranırsa kendi yer tutucusu
])
def test_type_annotations_and_own_placeholders_ignored(engine, text):
    assert "SECRET_PASSWORD" not in {f.entity for f in engine.analyze(text)}


def test_masking_is_idempotent(engine):
    """Maskeli metni tekrar maskelemek değiştirmemeli (ör. ContextForge + gateway art arda)."""
    once = engine.mask("şifre: Yaz2026!guclu ve TC 10000000146").text
    assert engine.mask(once).text == once
