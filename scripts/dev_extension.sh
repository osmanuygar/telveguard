#!/usr/bin/env bash
# Elle test için eklenti kopyası: yerel test ortamına (docker-compose.test.yml) bağlı, MDM gerektirmez.
#
#   scripts/dev_extension.sh [gateway adresi] [eklenti token'ı] [mod]
#   varsayılan:  http://localhost:8080  e2e-extension-token  warn
#
# Çıktı: dist/extension-dev/  ->  chrome://extensions > Geliştirici modu > "Paketlenmemiş öğe yükle"
# Yalnızca geliştirme içindir: token pakete gömülür, dağıtmayın (dağıtım: package_extension.sh).
set -euo pipefail

GATEWAY="${1:-http://localhost:8080}"
TOKEN="${2:-e2e-extension-token}"
MODE="${3:-warn}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/dist/extension-dev"

rm -rf "$OUT"
mkdir -p "$OUT"
cp -R "$ROOT/extension/manifest.json" "$ROOT/extension/managed_schema.json" "$ROOT/extension/popup.html" \
      "$ROOT/extension/src" "$OUT/"

python3 - "$OUT" "${GATEWAY%/}" "$TOKEN" "$MODE" <<'EOF'
import json, re, sys
out, gateway, token, mode = sys.argv[1:]
m = json.load(open(f"{out}/manifest.json", encoding="utf-8"))
m["name"] += " (geliştirme)"
m["host_permissions"] = [gateway + "/*"]
json.dump(m, open(f"{out}/manifest.json", "w", encoding="utf-8"), ensure_ascii=False, indent=2)

p = f"{out}/src/background.js"
s = open(p, encoding="utf-8").read()
new = (f'const DEFAULTS = {{ telveguardUrl: {json.dumps(gateway)}, reportToken: {json.dumps(token)}, '
       f'mode: {json.dumps(mode)}, user: "gelistirici", team: "test",')
s, n = re.subn(r'const DEFAULTS = \{ telveguardUrl: "", reportToken: "", mode: "warn", user: "unknown", team: "default",', new, s)
assert n == 1, "background.js DEFAULTS bulunamadı"
open(p, "w", encoding="utf-8").write(s)
EOF
echo "Hazır: $OUT"
echo "chrome://extensions > Geliştirici modu > Paketlenmemiş öğe yükle > bu klasör"
