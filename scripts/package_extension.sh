#!/usr/bin/env bash
# Tarayıcı eklentisini kurumun Telveguard adresi için paketler.
#
#   scripts/package_extension.sh https://telveguard.sirket.local [https://indirme.sirket.local/telveguard]
#
# 1. argüman: gateway adresi (manifest host_permissions; eklenti olayları ve sözlüğü buradan alır)
# 2. argüman (opsiyonel): .crx ve update.xml'in yayınlanacağı adres (kendi sunucunuzdan dağıtım).
#    Verilirse manifest'e update_url yazılır, .crx ve update.xml üretilir. Verilmezse yalnızca
#    Chrome Web Store / Edge Add-ons'a yüklenecek .zip üretilir (mağaza güncellemeyi kendi yapar).
#
# Çıktı: dist/extension/ (telveguard-<sürüm>.zip, telveguard.crx, update.xml, eklenti kimliği)
# Anahtar: dist/extension-key.pem. Eklenti kimliği bu anahtardan türer; kaybederseniz yeni sürüm
# kurulu eklentiyi güncelleyemez (yeni eklenti sayılır). Depoya koymayın, kasada saklayın.
set -euo pipefail

GATEWAY="${1:?Kullanım: $0 <gateway adresi> [dağıtım adresi]}"
UPDATE_BASE="${2:-}"
GATEWAY="${GATEWAY%/}"
UPDATE_BASE="${UPDATE_BASE%/}"
case "$GATEWAY" in https://*) ;; *) echo "Gateway adresi https:// ile başlamalı" >&2; exit 1 ;; esac

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/dist/extension"
KEY="${EXTENSION_KEY:-$ROOT/dist/extension-key.pem}"
BUILD="$(mktemp -d)"
trap 'rm -rf "$BUILD"' EXIT

mkdir -p "$OUT"
cp -R "$ROOT/extension/manifest.json" "$ROOT/extension/managed_schema.json" "$ROOT/extension/popup.html" \
      "$ROOT/extension/src" "$BUILD/"

python3 - "$BUILD/manifest.json" "$GATEWAY" "$UPDATE_BASE" <<'EOF'
import json, sys
path, gateway, update_base = sys.argv[1:]
m = json.load(open(path, encoding="utf-8"))
m["host_permissions"] = [gateway + "/*"]
if update_base:
    m["update_url"] = update_base + "/update.xml"
json.dump(m, open(path, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
EOF
VERSION="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["version"])' "$BUILD/manifest.json")"

# Mağaza paketi (Chrome Web Store / Edge Add-ons)
(cd "$BUILD" && zip -qr "$OUT/telveguard-$VERSION.zip" .)
echo "Mağaza paketi: dist/extension/telveguard-$VERSION.zip"

[ -n "$UPDATE_BASE" ] || exit 0

# Kendi sunucunuzdan dağıtım: imza anahtarı, .crx ve update.xml
if [ ! -f "$KEY" ]; then
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$KEY" 2>/dev/null
  chmod 600 "$KEY"
  echo "Yeni imza anahtarı: $KEY  (kasada saklayın; kimlik buna bağlı)"
fi
# Eklenti kimliği: açık anahtarın (DER) SHA-256'sının ilk 32 onaltılık hanesi, 0-f -> a-p
EXT_ID="$(openssl pkey -in "$KEY" -pubout -outform DER 2>/dev/null | openssl dgst -sha256 -binary | xxd -p -c 64 \
          | cut -c1-32 | tr '0-9a-f' 'a-p')"

CHROME="${CHROME:-}"
for c in "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" google-chrome chromium chromium-browser; do
  [ -n "$CHROME" ] && break
  if [ -x "$c" ] || command -v "$c" >/dev/null 2>&1; then CHROME="$c"; fi
done
if [ -z "$CHROME" ]; then
  echo "Chrome bulunamadı: .crx için CHROME=/yol/chrome ile tekrar çalıştırın" >&2
  exit 1
fi
cp -R "$BUILD" "$OUT/telveguard-src"
"$CHROME" --headless=new --no-sandbox --pack-extension="$OUT/telveguard-src" --pack-extension-key="$KEY" >/dev/null 2>&1 || true
rm -rf "$OUT/telveguard-src"
if [ ! -f "$OUT/telveguard-src.crx" ]; then
  echo ".crx üretilemedi. Chrome açıksa kapatıp tekrar deneyin." >&2
  exit 1
fi
mv "$OUT/telveguard-src.crx" "$OUT/telveguard.crx"

cat > "$OUT/update.xml" <<EOF
<?xml version='1.0' encoding='UTF-8'?>
<gupdate xmlns='http://www.google.com/update2/response' protocol='2.0'>
  <app appid='$EXT_ID'>
    <updatecheck codebase='$UPDATE_BASE/telveguard.crx' version='$VERSION' />
  </app>
</gupdate>
EOF
echo "$EXT_ID" > "$OUT/extension-id.txt"
cat <<EOF
Kendi sunucunuzdan dağıtım:
  dist/extension/telveguard.crx ve dist/extension/update.xml -> $UPDATE_BASE/
  Eklenti kimliği: $EXT_ID
  MDM / GPO (ExtensionInstallForcelist): $EXT_ID;$UPDATE_BASE/update.xml
EOF
