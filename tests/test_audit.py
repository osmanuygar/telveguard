"""Denetim hattı: Kafka bağlantı güvenliği (TLS / SASL)."""
import ssl

import pytest

from app import audit


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for k in ("KAFKA_SECURITY_PROTOCOL", "KAFKA_SASL_MECHANISM", "KAFKA_SASL_USERNAME", "KAFKA_SASL_PASSWORD",
              "KAFKA_SSL_CA_FILE", "KAFKA_SSL_CERT_FILE", "KAFKA_SSL_KEY_FILE"):
        monkeypatch.delenv(k, raising=False)


def test_plaintext_by_default():
    assert audit.kafka_security() == {"security_protocol": "PLAINTEXT"}


def test_sasl_ssl(monkeypatch):
    monkeypatch.setenv("KAFKA_SECURITY_PROTOCOL", "sasl_ssl")
    monkeypatch.setenv("KAFKA_SASL_USERNAME", "telveguard")
    monkeypatch.setenv("KAFKA_SASL_PASSWORD", "gizli")
    cfg = audit.kafka_security()
    assert cfg["security_protocol"] == "SASL_SSL" and cfg["sasl_mechanism"] == "SCRAM-SHA-512"
    assert (cfg["sasl_plain_username"], cfg["sasl_plain_password"]) == ("telveguard", "gizli")
    assert isinstance(cfg["ssl_context"], ssl.SSLContext) and cfg["ssl_context"].verify_mode == ssl.CERT_REQUIRED


@pytest.mark.parametrize("env, message", [
    ({"KAFKA_SECURITY_PROTOCOL": "TLS"}, "KAFKA_SECURITY_PROTOCOL"),
    ({"KAFKA_SECURITY_PROTOCOL": "SASL_SSL"}, "KAFKA_SASL_USERNAME"),
    ({"KAFKA_SECURITY_PROTOCOL": "SASL_SSL", "KAFKA_SASL_MECHANISM": "GSSAPI",
      "KAFKA_SASL_USERNAME": "u", "KAFKA_SASL_PASSWORD": "p"}, "KAFKA_SASL_MECHANISM"),
])
def test_invalid_settings_fail_at_startup(monkeypatch, env, message):
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    with pytest.raises(ValueError, match=message):
        audit.kafka_security()


async def test_producer_gets_security_settings(monkeypatch):
    aiokafka = pytest.importorskip("aiokafka")
    got = {}

    class FakeProducer:
        def __init__(self, **kwargs):
            got.update(kwargs)

        async def start(self):
            pass
    monkeypatch.setattr(aiokafka, "AIOKafkaProducer", FakeProducer)
    monkeypatch.setenv("KAFKA_BOOTSTRAP", "kafka:9093")
    monkeypatch.setenv("KAFKA_SECURITY_PROTOCOL", "SSL")
    await audit.AuditSink().start()
    assert got["bootstrap_servers"] == "kafka:9093" and got["security_protocol"] == "SSL" and got["ssl_context"]
