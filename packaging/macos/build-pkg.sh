#!/usr/bin/env bash
# Genera dist/sentinel-<versión>-macos.pkg. Solo en macOS (usa pkgbuild).
# Para firmarlo:  SENTINEL_PKG_IDENTIDAD="Developer ID Installer: …" ./packaging/macos/build-pkg.sh
set -euo pipefail
AQUI="$(cd "$(dirname "$0")/../.." && pwd)"
[ "$(uname -s)" = Darwin ] || { echo "El .pkg solo se puede generar en macOS."; exit 1; }
VER="$(sed -n 's/^VERSION = "\(.*\)"/\1/p' "$AQUI/sentinel/core.py")"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
# el paquete no deja archivos propios: lleva el programa junto a su script y este llama al instalador de siempre
mkdir -p "$TMP/scripts/sentinel-src" "$AQUI/dist"
cp -R "$AQUI/sentinel" "$AQUI/bin" "$AQUI/yara" "$AQUI/packaging" "$AQUI/README.md" "$AQUI/LICENSE" "$AQUI/install-mac.sh" "$AQUI/uninstall-mac.sh" "$TMP/scripts/sentinel-src/"
find "$TMP/scripts" -name __pycache__ -prune -exec rm -rf {} +
cp "$AQUI/packaging/macos/postinstall" "$TMP/scripts/postinstall"; chmod 755 "$TMP/scripts/postinstall"
SALIDA="$AQUI/dist/sentinel-$VER-macos.pkg"
FIRMA=(); [ -n "${SENTINEL_PKG_IDENTIDAD:-}" ] && FIRMA=(--sign "$SENTINEL_PKG_IDENTIDAD")
pkgbuild --nopayload --scripts "$TMP/scripts" --identifier io.github.saraivaruas.sentinel --version "$VER" ${FIRMA[@]+"${FIRMA[@]}"} "$SALIDA"
echo "$SALIDA"
