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


# ---------------- Kafka açılışta erişilemez ----------------

class FakeProducer:
    """İlk `fail` start() denemesi bağlantı hatası verir."""
    fail = 0
    starts = 0
    sent = []

    def __init__(self, **kwargs):
        pass

    async def start(self):
        FakeProducer.starts += 1
        if FakeProducer.starts <= FakeProducer.fail:
            raise ConnectionError("kafka yok")

    async def stop(self):
        pass

    async def send_and_wait(self, topic, value, key=None):
        FakeProducer.sent.append(value)


@pytest.fixture()
def fake_kafka(monkeypatch):
    import aiokafka
    FakeProducer.fail, FakeProducer.starts, FakeProducer.sent = 0, 0, []
    monkeypatch.setattr(aiokafka, "AIOKafkaProducer", FakeProducer)
    monkeypatch.setattr(audit, "RECONNECT_MIN_SECONDS", 0.01)
    monkeypatch.setenv("KAFKA_BOOTSTRAP", "kafka:9092")
    return FakeProducer


async def test_gateway_starts_without_kafka_and_reconnects(fake_kafka, caplog):
    import asyncio
    import logging

    from app.metrics import AUDIT_FAILURES
    fake_kafka.fail = 2
    sink = audit.AuditSink()
    before = AUDIT_FAILURES._value.get()
    with caplog.at_level(logging.INFO, logger="telveguard.audit"):
        await sink.start()                                  # hata fırlatmaz: gateway açılır
        await sink.emit({"event_id": "1", "team": "t"})     # henüz bağlı değil: stdout + sayaç
        assert fake_kafka.sent == [] and AUDIT_FAILURES._value.get() == before + 1
        for _ in range(100):
            if sink._producer:
                break
            await asyncio.sleep(0.01)
        await sink.emit({"event_id": "2", "team": "t"})
    assert fake_kafka.starts == 3 and fake_kafka.sent == [{"event_id": "2", "team": "t"}]
    assert any("audit_kafka_unavailable" in m for m in caplog.messages)
    assert any("audit_kafka_connected" in m for m in caplog.messages)
    await sink.stop()


async def test_kafka_config_error_still_fails_startup(fake_kafka, monkeypatch):
    monkeypatch.setenv("KAFKA_SECURITY_PROTOCOL", "SASL_SSL")      # şifre yok
    with pytest.raises(ValueError, match="KAFKA_SASL_USERNAME"):
        await audit.AuditSink().start()


async def test_stop_cancels_reconnect(fake_kafka):
    fake_kafka.fail = 10**6
    sink = audit.AuditSink()
    await sink.start()
    task = sink._reconnect_task
    await sink.stop()
    import asyncio
    await asyncio.sleep(0)
    assert task.cancelled() or task.done()
