#!/bin/sh
# Prometheus çoklu süreç modu: her uvicorn worker'ı metriklerini bu dizine yazar,
# /metrics hepsini birleştirir. Açılışta temizlenir (önceki çalıştırmanın sayaçları karışmasın).
set -eu
export PROMETHEUS_MULTIPROC_DIR="${PROMETHEUS_MULTIPROC_DIR:-/tmp/prometheus}"
rm -rf "$PROMETHEUS_MULTIPROC_DIR"
mkdir -p "$PROMETHEUS_MULTIPROC_DIR"
exec uvicorn app.main:app --host 0.0.0.0 --port "${PORT:-8080}" \
    --workers "${WORKERS:-2}" --no-server-header
