#!/usr/bin/env bash
# Descarga, verifica e instala Sentinel (con todas sus dependencias) en un solo paso.
#   sudo SENTINEL_URL=https://tu-servidor/sentinel-2.0.0.tar.gz SENTINEL_SHA256=<huella> bash get-sentinel.sh
# La huella es obligatoria: no se instala nada que no coincida con ella.
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "Ejecútalo con sudo"; exit 1; }
: "${SENTINEL_URL:?Falta SENTINEL_URL}"; : "${SENTINEL_SHA256:?Falta SENTINEL_SHA256}"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
if command -v curl >/dev/null; then curl -fsSL "$SENTINEL_URL" -o "$T/s.tgz"; elif command -v wget >/dev/null; then wget -q "$SENTINEL_URL" -O "$T/s.tgz"; else echo "Falta curl o wget"; exit 1; fi
echo "$SENTINEL_SHA256  $T/s.tgz" | sha256sum -c - >/dev/null || { echo "La huella no coincide: se cancela la instalación."; exit 1; }
tar -xzf "$T/s.tgz" -C "$T"; cd "$T"/sentinel-*/
./install.sh "$@"
