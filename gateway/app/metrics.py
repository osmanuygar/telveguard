"""
Prometheus metrikleri (/metrics).

Etiketler yalnızca SINIRLI kümelerden gelir (karar, hedef, veri türü, hata nedeni).
Model adı ve ekip istemci kontrolündedir; etiket yapılsaydı sonsuz sayıda seri üretilip
Prometheus şişirilebilirdi (kardinalite saldırısı). Ekip / model kırılımı Röntgen'dedir.

Pod'da birden fazla uvicorn worker'ı çalışır: PROMETHEUS_MULTIPROC_DIR tanımlıysa
(entrypoint.sh ayarlar) tüm worker'ların metrikleri birleştirilerek sunulur.
"""
import os

from prometheus_client import CONTENT_TYPE_LATEST, REGISTRY, CollectorRegistry, Counter, Histogram, generate_latest
from prometheus_client import multiprocess

REQUESTS = Counter("telveguard_requests", "Politika kararına göre istekler",
                   ["action", "destination", "api_format"])  # api_format: chat | responses | messages
ENTITIES = Counter("telveguard_entities_detected", "Tespit edilen PII / sır türleri",
                   ["entity", "stage"])  # stage: input | output_leak
INJECTIONS = Counter("telveguard_injection_detected", "Injection skoru >= 0,5 olan istekler")
OUTPUT_ACTIONS = Counter("telveguard_output_actions", "Model cevabındaki sızıntıya uygulanan karar", ["action"])
UPSTREAM_ERRORS = Counter("telveguard_upstream_errors", "Upstream LLM hataları", ["destination", "kind"])
AUDIT_FAILURES = Counter("telveguard_audit_failures", "Kafka'ya yazılamayan denetim olayları (stdout'a düştü)")
AUTH_FAILURES = Counter("telveguard_auth_failures", "Reddedilen kimlik doğrulamaları", ["reason"])

_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120)
REQUEST_SECONDS = Histogram("telveguard_request_duration_seconds", "Uçtan uca istek süresi",
                            ["destination"], buckets=_BUCKETS)
SCAN_SECONDS = Histogram("telveguard_scan_duration_seconds",
                         "Tarama + politika süresi (gateway'in eklediği gecikme)",
                         buckets=(0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25))
UPSTREAM_SECONDS = Histogram("telveguard_upstream_duration_seconds", "Upstream LLM cevap süresi",
                             ["destination"], buckets=_BUCKETS)


def upstream_error_kind(status: int) -> str:
    return "http_5xx" if status >= 500 else "http_4xx"


def render() -> tuple:
    if os.getenv("PROMETHEUS_MULTIPROC_DIR"):
        registry = CollectorRegistry()
        multiprocess.MultiProcessCollector(registry)
    else:
        registry = REGISTRY
    return generate_latest(registry), CONTENT_TYPE_LATEST
