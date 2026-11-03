"""
Denetim (audit) olayları -> Kafka -> ClickHouse.

KVKK veri minimizasyonu: ham prompt ASLA loglanmaz. Varsayılan olarak sadece
SHA-256 özeti ve bulunan varlık türleri yazılır. AUDIT_STORE_MASKED=1 ise
maskelenmiş metin de saklanır (PII'lar yer tutucu halinde).

Kafka yoksa (lokal geliştirme) olaylar stdout'a JSON satır olarak yazılır.

Kurumsal Kafka: KAFKA_SECURITY_PROTOCOL (SSL | SASL_SSL | SASL_PLAINTEXT), KAFKA_SASL_MECHANISM
(PLAIN | SCRAM-SHA-256 | SCRAM-SHA-512), KAFKA_SASL_USERNAME / KAFKA_SASL_PASSWORD, kurum içi CA
için KAFKA_SSL_CA_FILE, karşılıklı TLS için KAFKA_SSL_CERT_FILE / KAFKA_SSL_KEY_FILE. Olaylarda
kullanıcı, ekip ve ilgili kişi özetleri vardır: düz metin bağlantı ve yetkisiz topic yazımı
(sahte denetim kaydı) üretimde kabul edilemez.
Kafka çalışırken erişilemez olursa istek BOZULMAZ (politika zaten uygulanmıştır):
olay stdout'a düşer (log toplayıcı alır) ve "audit_kafka_failed" hatası loglanır.
Açılışta erişilemezse de gateway açılır (Kafka bakımı yapay zekâ trafiğini kesmesin): olaylar
stdout'a yazılır, arka planda artan aralıklarla yeniden bağlanılır ("audit_kafka_unavailable").
Yapılandırma hatası (ör. eksik SASL şifresi) ise açılışı durdurur: yanlış kurulum sessiz kalmasın.
"""
import asyncio
import hashlib
import json
import logging
import os
import time
import uuid
from typing import Optional

from .metrics import AUDIT_FAILURES

RECONNECT_MIN_SECONDS, RECONNECT_MAX_SECONDS = 2.0, 60.0

log = logging.getLogger("telveguard.audit")


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


KAFKA_PROTOCOLS = ("PLAINTEXT", "SSL", "SASL_SSL", "SASL_PLAINTEXT")
KAFKA_SASL_MECHANISMS = ("PLAIN", "SCRAM-SHA-256", "SCRAM-SHA-512")


def kafka_security() -> dict:
    """KAFKA_* ortam değişkenlerinden aiokafka güvenlik ayarları; hatalı değer açılışta hata verir."""
    e = os.getenv
    protocol = e("KAFKA_SECURITY_PROTOCOL", "PLAINTEXT").upper()
    if protocol not in KAFKA_PROTOCOLS:
        raise ValueError(f"KAFKA_SECURITY_PROTOCOL şunlardan biri olmalı: {', '.join(KAFKA_PROTOCOLS)}")
    out: dict = {"security_protocol": protocol}
    if protocol in ("SSL", "SASL_SSL"):
        from aiokafka.helpers import create_ssl_context
        out["ssl_context"] = create_ssl_context(cafile=e("KAFKA_SSL_CA_FILE") or None,
                                                certfile=e("KAFKA_SSL_CERT_FILE") or None,
                                                keyfile=e("KAFKA_SSL_KEY_FILE") or None)
    if protocol.startswith("SASL_"):
        mechanism = e("KAFKA_SASL_MECHANISM", "SCRAM-SHA-512").upper()
        if mechanism not in KAFKA_SASL_MECHANISMS:
            raise ValueError(f"KAFKA_SASL_MECHANISM şunlardan biri olmalı: {', '.join(KAFKA_SASL_MECHANISMS)}")
        if not (e("KAFKA_SASL_USERNAME") and e("KAFKA_SASL_PASSWORD")):
            raise ValueError("SASL için KAFKA_SASL_USERNAME ve KAFKA_SASL_PASSWORD gerekli")
        out.update(sasl_mechanism=mechanism, sasl_plain_username=e("KAFKA_SASL_USERNAME"),
                   sasl_plain_password=e("KAFKA_SASL_PASSWORD"))
    return out


class AuditSink:
    def __init__(self):
        self.bootstrap = os.getenv("KAFKA_BOOTSTRAP")
        self.topic = os.getenv("KAFKA_AUDIT_TOPIC", "telveguard.audit.v1")
        self.store_masked = os.getenv("AUDIT_STORE_MASKED") == "1"
        self._producer = None
        self._security = None
        self._reconnect_task = None

    async def start(self):
        if not self.bootstrap:
            return
        self._security = kafka_security()   # yapılandırma hatası açılışı durdurur
        if not await self._connect():
            self._reconnect_task = asyncio.create_task(self._reconnect())

    async def _connect(self) -> bool:
        from aiokafka import AIOKafkaProducer

        producer = AIOKafkaProducer(
            bootstrap_servers=self.bootstrap,
            value_serializer=lambda v: json.dumps(v, ensure_ascii=False).encode(),
            acks="all", enable_idempotence=True, linger_ms=20, **self._security,
        )
        try:
            await producer.start()
        except Exception as e:
            log.error("audit_kafka_unavailable bootstrap=%s error=%s: olaylar bağlanana kadar stdout'a yazılıyor",
                      self.bootstrap, type(e).__name__)
            try:
                await producer.stop()
            except Exception:
                pass
            return False
        self._producer = producer
        log.info("audit_kafka_connected bootstrap=%s", self.bootstrap)
        return True

    async def _reconnect(self):
        delay = RECONNECT_MIN_SECONDS
        while True:
            await asyncio.sleep(delay)
            if await self._connect():
                return
            delay = min(delay * 2, RECONNECT_MAX_SECONDS)

    async def stop(self):
        if self._reconnect_task:
            self._reconnect_task.cancel()
        if self._producer:
            await self._producer.stop()

    def build_event(self, *, user: str, team: str, model: str, destination: str,
                    decision, entities, injection, prompt: str,
                    masked_prompt: Optional[str], latency_ms: float,
                    upstream_status: Optional[int]) -> dict:
        return {
            "event_id": str(uuid.uuid4()),
            "ts": int(time.time() * 1000),
            "user": user,
            "team": team,
            "model": model,
            "destination": destination,
            "action": decision.action,
            "rules": decision.rules,
            "reason": decision.reason or "",
            "monitored_rules": decision.monitored_rules,
            "would_action": decision.would_action,
            # KVKK raporu: hangi türler maskelenerek gitti (entities - masked = açık giden)
            "masked_entities": sorted(decision.mask_entities),
            "entities": sorted(entities),
            "injection_score": injection.score,
            "injection_engine": injection.engine,
            "prompt_sha256": sha256(prompt),
            "prompt_chars": len(prompt),
            "masked_prompt": masked_prompt if self.store_masked and masked_prompt else "",
            "latency_ms": round(latency_ms, 2),
            "upstream_status": upstream_status or 0,
        }

    async def emit(self, event: dict):
        if self._producer:
            try:
                await self._producer.send_and_wait(self.topic, event, key=event["team"].encode())
                return
            except Exception as e:  # Kafka hatası kullanıcı isteğini 500'e çevirmesin
                AUDIT_FAILURES.inc()
                log.error("audit_kafka_failed event_id=%s error=%s", event["event_id"], type(e).__name__)
        elif self.bootstrap:   # Kafka tanımlı ama henüz bağlanılamadı: alarm için sayılır
            AUDIT_FAILURES.inc()
        # Yedek yol: olay kaybolmasın (ham prompt zaten olayda yok). Log değil veri: log seviyesinden
        # bağımsız, düz JSON satırı (log toplayıcı ayrıştırır)
        print(json.dumps(event, ensure_ascii=False), flush=True)
