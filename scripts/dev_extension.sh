#!/usr/bin/env bash
# Elle test için eklenti kopyası: yerel test ortamına (docker-compose.test.yml) bağlı, MDM gerektirmez.
#
#   scripts/dev_extension.sh [gateway adresi] [eklenti token'ı] [mod] [onaylı AI aracı adresi]
#   varsayılan:  http://localhost:8080  e2e-extension-token  warn  <gateway>/asistan (demo "Kurum Asistanı")
#   Onaylı aracı kapatmak için 4. argümana "-" verin.
#
# Çıktı: dist/extension-dev/  ->  chrome://extensions > Geliştirici modu > "Paketlenmemiş öğe yükle"
# Yalnızca geliştirme içindir: token pakete gömülür, dağıtmayın (dağıtım: package_extension.sh).
set -euo pipefail

GATEWAY="${1:-http://localhost:8080}"
TOKEN="${2:-e2e-extension-token}"
MODE="${3:-warn}"
SANCTIONED="${4:-${GATEWAY%/}/asistan}"
[ "$SANCTIONED" = "-" ] && SANCTIONED=""
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/dist/extension-dev"

rm -rf "$OUT"
mkdir -p "$OUT"
cp -R "$ROOT/extension/manifest.json" "$ROOT/extension/managed_schema.json" "$ROOT/extension/popup.html" \
      "$ROOT/extension/src" "$OUT/"

python3 - "$OUT" "${GATEWAY%/}" "$TOKEN" "$MODE" "$SANCTIONED" <<'EOF'
import json, re, sys
out, gateway, token, mode, sanctioned = sys.argv[1:]
m = json.load(open(f"{out}/manifest.json", encoding="utf-8"))
m["name"] += " (geliştirme)"
m["host_permissions"] = [gateway + "/*"]
json.dump(m, open(f"{out}/manifest.json", "w", encoding="utf-8"), ensure_ascii=False, indent=2)

p = f"{out}/src/background.js"
s = open(p, encoding="utf-8").read()
new = (f'const DEFAULTS = {{ telveguardUrl: {json.dumps(gateway)}, reportToken: {json.dumps(token)}, '
       f'mode: {json.dumps(mode)}, user: "demo.kullanici", team: "musteri-hizmetleri",')
s, n = re.subn(r'const DEFAULTS = \{ telveguardUrl: "", reportToken: "", mode: "warn", user: "unknown", team: "default",', new, s)
assert n == 1, "background.js DEFAULTS bulunamadı"
old = 'sanctionedAiUrl: "", sanctionedAiName: ""'
assert s.count(old) == 1, "background.js sanctionedAiUrl bulunamadı"
name = "Kurum Asistanı" if sanctioned else ""
s = s.replace(old, f"sanctionedAiUrl: {json.dumps(sanctioned)}, sanctionedAiName: {json.dumps(name, ensure_ascii=False)}")
open(p, "w", encoding="utf-8").write(s)
EOF
echo "Hazır: $OUT"
echo "chrome://extensions > Geliştirici modu > Paketlenmemiş öğe yükle > bu klasör"
