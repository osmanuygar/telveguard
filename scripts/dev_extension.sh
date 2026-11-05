#!/usr/bin/env bash
# Elle test için eklenti kopyası: yerel test ortamına (docker-compose.test.yml) bağlı, MDM gerektirmez.
#
#   scripts/dev_extension.sh [gateway adresi] [eklenti token'ı] [mod] [onaylı AI aracı adresi] [kullanıcı]
#   varsayılan:  http://localhost:8080  e2e-extension-token  warn  <gateway>/asistan (demo "Kurum Asistanı")
#                kullanıcı boş: Chrome'da oturum açmış profilin e-postası (yoksa "unknown")
#   Onaylı aracı kapatmak için 4. argümana "-" verin.
#
# Çıktı: dist/extension-dev/  ->  chrome://extensions > Geliştirici modu > "Paketlenmemiş öğe yükle"
# Firefox (128+): BROWSER=firefox scripts/dev_extension.sh ...  ->  dist/extension-dev-firefox/
#   about:debugging#/runtime/this-firefox > "Geçici Eklenti Yükle" > manifest.json (Firefox kapanınca kalkar).
#   Firefox profil e-postası vermez: kullanıcıyı 5. argümanla verin (yoksa "unknown").
# Yalnızca geliştirme içindir: token pakete gömülür, dağıtmayın (dağıtım: package_extension.sh).
set -euo pipefail

GATEWAY="${1:-http://localhost:8080}"
TOKEN="${2:-e2e-extension-token}"
MODE="${3:-warn}"
SANCTIONED="${4:-${GATEWAY%/}/asistan}"
[ "$SANCTIONED" = "-" ] && SANCTIONED=""
USER_NAME="${5:-}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BROWSER="${BROWSER:-chrome}"
OUT="$ROOT/dist/extension-dev"
[ "$BROWSER" = "firefox" ] && OUT="$ROOT/dist/extension-dev-firefox"

rm -rf "$OUT"
mkdir -p "$OUT"
cp -R "$ROOT/extension/manifest.json" "$ROOT/extension/managed_schema.json" "$ROOT/extension/popup.html" "$ROOT/extension/preview.html" \
      "$ROOT/extension/src" "$OUT/"

python3 - "$OUT" "${GATEWAY%/}" "$TOKEN" "$MODE" "$SANCTIONED" "$USER_NAME" "$BROWSER" <<'EOF'
import json, re, sys
out, gateway, token, mode, sanctioned, user, browser = sys.argv[1:]
m = json.load(open(f"{out}/manifest.json", encoding="utf-8"))
m["name"] += " (geliştirme)"
m["host_permissions"] = [gateway + "/*"]
if browser == "firefox":   # package_extension_firefox.sh ile aynı uyarlama
    m["background"] = {"scripts": [m["background"]["service_worker"]]}
    m["permissions"] = [p for p in m["permissions"] if not p.startswith("identity")]
    m.pop("minimum_chrome_version", None)
    m.pop("storage", None)
    m["browser_specific_settings"] = {"gecko": {"id": "telveguard-dev@sirket.local", "strict_min_version": "128.0"}}
json.dump(m, open(f"{out}/manifest.json", "w", encoding="utf-8"), ensure_ascii=False, indent=2)

p = f"{out}/src/background.js"
s = open(p, encoding="utf-8").read()
new = (f'const DEFAULTS = {{ telveguardUrl: {json.dumps(gateway)}, reportToken: {json.dumps(token)}, '
       f'mode: {json.dumps(mode)}, user: {json.dumps(user)}, team: "musteri-hizmetleri",')
s, n = re.subn(r'const DEFAULTS = \{ telveguardUrl: "", reportToken: "", mode: "warn", user: "", team: "default",', new, s)
assert n == 1, "background.js DEFAULTS bulunamadı"
old = 'sanctionedAiUrl: "", sanctionedAiName: ""'
assert s.count(old) == 1, "background.js sanctionedAiUrl bulunamadı"
name = "Kurum Asistanı" if sanctioned else ""
s = s.replace(old, f"sanctionedAiUrl: {json.dumps(sanctioned)}, sanctionedAiName: {json.dumps(name, ensure_ascii=False)}")
open(p, "w", encoding="utf-8").write(s)
EOF
echo "Hazır: $OUT"
if [ "$BROWSER" = "firefox" ]; then
  echo "about:debugging#/runtime/this-firefox > Geçici Eklenti Yükle > $OUT/manifest.json"
else
  echo "chrome://extensions > Geliştirici modu > Paketlenmemiş öğe yükle > bu klasör"
fi
