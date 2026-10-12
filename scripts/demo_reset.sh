#!/usr/bin/env bash
# Demo ortamını tek komutla sıfırdan kurar: test ortamı + sektör profili (politika, sözlük, envanter)
# + son 14 güne yayılmış demo trafiği + geliştirme eklentisi. Demo sabahı çalıştırın: tarihler güncel olur.
# Demo trafiği profilin GÖZLEM politikasıyla (poc.yaml) üretilir: POC raporu "gözlemde korunurdu" der.
# Ardından gateway UYGULAMA politikasıyla (policy.yaml) yeniden başlar: canlı demoda koruma gerçekten çalışır.
#
#   scripts/demo_reset.sh [profil]      profil: demo/<ad>/ (varsayılan eticaret)
#
# Yalnızca yerel demo içindir: kimlik doğrulanmaz (AUTH_MODE=header), token'lar sabittir.
set -euo pipefail
PROFILE="${1:-eticaret}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
for f in policy.yaml poc.yaml inventory.yaml; do
  [ -f "demo/$PROFILE/$f" ] || { echo "Profil eksik: demo/$PROFILE/$f" >&2; exit 1; }
done
COMPOSE=(docker compose -f docker-compose.yml -f docker-compose.test.yml -f docker-compose.demo.yml)
export DEMO_PROFILE="$PROFILE"
mkdir -p dist
LOG="dist/demo-reset.log"
: > "$LOG"

wait_gateway() {
  for _ in $(seq 1 90); do
    if curl -sf localhost:8080/xray >/dev/null && curl -sf -u telveguard:telveguard "localhost:8123/?query=SELECT%201" >/dev/null; then
      return 0
    fi
    sleep 2
  done
  echo "Gateway açılmadı: ${COMPOSE[*]} logs gateway" >&2; exit 1
}

echo "1/4 Ortam sıfırlanıyor (ClickHouse dahil)…"
"${COMPOSE[@]}" down --remove-orphans >>"$LOG" 2>&1 || true
DEMO_POLICY=poc.yaml "${COMPOSE[@]}" up -d --build >>"$LOG" 2>&1 || { echo "Docker başlatılamadı, ayrıntı: $LOG" >&2; exit 1; }
wait_gateway

echo "2/4 Demo trafiği üretiliyor ($PROFILE, gözlem modu)…"
python3 scripts/demo_traffic.py --profile "$PROFILE" --days 14 --requests 3000 --seed 2026 | grep "kayıt yazıldı"

echo "3/4 Gateway uygulama politikasıyla yeniden başlıyor…"
DEMO_POLICY=policy.yaml "${COMPOSE[@]}" up -d gateway >>"$LOG" 2>&1
sleep 2
wait_gateway

echo "4/4 Geliştirme eklentisi hazırlanıyor…"
scripts/dev_extension.sh >/dev/null

cat <<MSG

Demo hazır.
  Konsol        : http://localhost:8080/xray        (token: e2e-admin-token)
  POC raporu    : http://localhost:8080/xray#rapor
  Kurum Asistanı: http://localhost:8080/asistan
  Eklenti       : chrome://extensions > Geliştirici modu > Paketlenmemiş öğe yükle > dist/extension-dev
                  (zaten yüklüyse ↻ ile yenileyin)
  Kılavuz       : docs/demo.md
Kapatmak için   : ${COMPOSE[*]} down
MSG
