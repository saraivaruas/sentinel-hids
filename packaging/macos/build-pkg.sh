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
# el icono de la barra de menú, compilado para Apple Silicon e Intel: quien instala no necesita compilador
mkdir -p "$TMP/scripts/sentinel-src/prebuilt"
for arq in arm64 x86_64; do
  xcrun swiftc -O -target "$arq-apple-macos13" -o "$TMP/barra-$arq" "$AQUI/packaging/macos/barra.swift"
done
lipo -create -o "$TMP/scripts/sentinel-src/prebuilt/sentinel-barra" "$TMP/barra-arm64" "$TMP/barra-x86_64"
# Python propio, uno por tipo de procesador. Se usa solo si su huella coincide con la anotada.
CACHE="$AQUI/dist/descargas"; mkdir -p "$CACHE" "$TMP/scripts/sentinel-src/runtime"
while read -r arq huella url; do
  case "$arq" in ""|\#*) continue;; esac
  archivo="$CACHE/$huella.tar.gz"
  [ -f "$archivo" ] || curl -fsSL --retry 3 -o "$archivo" "$url"
  if ! echo "$huella  $archivo" | shasum -a 256 -c - >/dev/null; then
    rm -f "$archivo"; echo "La huella de Python para $arq no coincide: no se genera el paquete." >&2; exit 1
  fi
  cp "$archivo" "$TMP/scripts/sentinel-src/runtime/$arq.tar.gz"
done < "$AQUI/packaging/macos/python-runtime.txt"
for arq in arm64 x86_64; do [ -f "$TMP/scripts/sentinel-src/runtime/$arq.tar.gz" ] || { echo "Falta Python para $arq en python-runtime.txt" >&2; exit 1; }; done
cp "$AQUI/packaging/macos/postinstall" "$TMP/scripts/postinstall"; chmod 755 "$TMP/scripts/postinstall"
SALIDA="$AQUI/dist/sentinel-$VER-macos.pkg"
FIRMA=(); [ -n "${SENTINEL_PKG_IDENTIDAD:-}" ] && FIRMA=(--sign "$SENTINEL_PKG_IDENTIDAD")
pkgbuild --nopayload --scripts "$TMP/scripts" --identifier io.github.saraivaruas.sentinel --version "$VER" ${FIRMA[@]+"${FIRMA[@]}"} "$SALIDA"
echo "$SALIDA"
