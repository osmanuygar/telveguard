"""
Denetim (audit) olayları -> Kafka -> ClickHouse.

KVKK veri minimizasyonu: ham prompt ASLA loglanmaz. Varsayılan olarak sadece
SHA-256 özeti ve bulunan varlık türleri yazılır. AUDIT_STORE_MASKED=1 ise
maskelenmiş metin de saklanır (PII'lar yer tutucu halinde).

Kafka yoksa (lokal geliştirme) olaylar stdout'a JSON satır olarak yazılır.
Kafka çalışırken erişilemez olursa istek BOZULMAZ (politika zaten uygulanmıştır):
olay stdout'a düşer (log toplayıcı alır) ve "audit_kafka_failed" hatası loglanır.
"""
import hashlib
import json
import logging
import os
import time
import uuid
from typing import Optional

from .metrics import AUDIT_FAILURES

log = logging.getLogger("telveguard.audit")


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class AuditSink:
    def __init__(self):
        self.bootstrap = os.getenv("KAFKA_BOOTSTRAP")
        self.topic = os.getenv("KAFKA_AUDIT_TOPIC", "telveguard.audit.v1")
        self.store_masked = os.getenv("AUDIT_STORE_MASKED") == "1"
        self._producer = None

    async def start(self):
        if self.bootstrap:
            from aiokafka import AIOKafkaProducer

            self._producer = AIOKafkaProducer(
                bootstrap_servers=self.bootstrap,
                value_serializer=lambda v: json.dumps(v, ensure_ascii=False).encode(),
                acks="all", enable_idempotence=True, linger_ms=20,
            )
            await self._producer.start()

    async def stop(self):
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
        # Yedek yol: olay kaybolmasın (ham prompt zaten olayda yok)
        log.info(json.dumps(event, ensure_ascii=False))
