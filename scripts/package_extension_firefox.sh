#!/usr/bin/env bash
# Tarayıcı eklentisinin Firefox paketi.
#
#   scripts/package_extension_firefox.sh https://telveguard.sirket.local [eklenti kimliği]
#
# 1. argüman: gateway adresi (manifest host_permissions)
# 2. argüman (opsiyonel): Firefox eklenti kimliği, varsayılan telveguard@sirket.local. Kimlik
#    değişirse yeni eklenti sayılır ve yönetici politikası (policies.json) da güncellenmelidir.
#
# Çıktı: dist/extension-firefox/telveguard-<sürüm>-firefox.zip
# Firefox imzasız eklentiyi kurmaz: paket AMO'da "unlisted" olarak imzalanır (web-ext sign).
set -euo pipefail

GATEWAY="${1:?Kullanım: $0 <gateway adresi> [eklenti kimliği]}"
EXT_ID="${2:-telveguard@sirket.local}"
GATEWAY="${GATEWAY%/}"
case "$GATEWAY" in https://*) ;; *) echo "Gateway adresi https:// ile başlamalı" >&2; exit 1 ;; esac

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/dist/extension-firefox"
BUILD="$(mktemp -d)"
trap 'rm -rf "$BUILD"' EXIT

mkdir -p "$OUT"
cp -R "$ROOT/extension/manifest.json" "$ROOT/extension/popup.html" "$ROOT/extension/preview.html" "$ROOT/extension/src" "$BUILD/"

python3 - "$BUILD/manifest.json" "$GATEWAY" "$EXT_ID" <<'EOF'
import json, sys
path, gateway, ext_id = sys.argv[1:]
m = json.load(open(path, encoding="utf-8"))
m["host_permissions"] = [gateway + "/*"]
# Firefox MV3 service worker çalıştırmaz: aynı dosya olay sayfası olarak yüklenir
m["background"] = {"scripts": [m["background"]["service_worker"]]}
# identity Firefox'ta profil e-postası vermez (kişi MDM'deki user'dan gelir); şema ve Chrome sürüm alt sınırı yok sayılır
m["permissions"] = [p for p in m["permissions"] if not p.startswith("identity")]
m.pop("minimum_chrome_version", None)
m.pop("storage", None)
m["browser_specific_settings"] = {"gecko": {"id": ext_id, "strict_min_version": "128.0"}}
json.dump(m, open(path, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
EOF
VERSION="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["version"])' "$BUILD/manifest.json")"

(cd "$BUILD" && zip -qr "$OUT/telveguard-$VERSION-firefox.zip" .)
echo "Firefox paketi: dist/extension-firefox/telveguard-$VERSION-firefox.zip"
