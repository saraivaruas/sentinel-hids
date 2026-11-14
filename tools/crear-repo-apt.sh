#!/usr/bin/env bash
# Genera un repositorio APT firmado de Sentinel, listo para publicar (por ejemplo con GitHub Pages o cualquier servidor web estático).
# Uso:  ./tools/crear-repo-apt.sh <huella-GPG> [carpeta-de-salida]     (por defecto: dist/apt)
#   La clave privada la pones tú (tools/crear-clave-de-publicacion.sh); aquí solo se usa para firmar y nunca se copia.
# Resultado:  <salida>/{dists/stable/{Release,InRelease,Release.gpg,main/binary-all/Packages*},pool/main/*.deb,sentinel-archive-keyring.gpg,sentinel-archive-keyring.asc,LEEME.txt}
set -euo pipefail
HUELLA="${1:?Uso: $0 <huella-GPG> [carpeta-de-salida]}"
AQUI="$(cd "$(dirname "$0")/.." && pwd)"; OUT="${2:-$AQUI/dist/apt}"
URL="${SENTINEL_APT_URL:-https://saraivaruas.github.io/sentinel-hids/apt}"
command -v apt-ftparchive >/dev/null || { echo "Falta apt-ftparchive (paquete apt-utils)"; exit 1; }
DEBS=("$AQUI"/dist/sentinel_*_all.deb); [ -e "${DEBS[0]}" ] || { echo "No hay .deb en dist/: ejecuta primero packaging/build-deb.sh"; exit 1; }
rm -rf "$OUT"; mkdir -p "$OUT/pool/main" "$OUT/dists/stable/main/binary-all"
cp "${DEBS[@]}" "$OUT/pool/main/"
( cd "$OUT" && apt-ftparchive packages pool/main > dists/stable/main/binary-all/Packages && gzip -9kf dists/stable/main/binary-all/Packages )
( cd "$OUT" && apt-ftparchive -o APT::FTPArchive::Release::Origin=Sentinel -o APT::FTPArchive::Release::Label=Sentinel -o APT::FTPArchive::Release::Suite=stable \
    -o APT::FTPArchive::Release::Codename=stable -o APT::FTPArchive::Release::Architectures=all -o APT::FTPArchive::Release::Components=main \
    -o "APT::FTPArchive::Release::Description=Sentinel, detector de intrusiones para Linux" release dists/stable > dists/stable/Release )
gpg --batch --yes --local-user "$HUELLA" --armor --detach-sign -o "$OUT/dists/stable/Release.gpg" "$OUT/dists/stable/Release"
gpg --batch --yes --local-user "$HUELLA" --clearsign -o "$OUT/dists/stable/InRelease" "$OUT/dists/stable/Release"
gpg --armor --export "$HUELLA" > "$OUT/sentinel-archive-keyring.asc"
gpg --export "$HUELLA" > "$OUT/sentinel-archive-keyring.gpg"
cat > "$OUT/LEEME.txt" <<EOT
Repositorio APT de Sentinel (firmado). Para instalar en Debian/Ubuntu:

  sudo install -d -m 0755 /etc/apt/keyrings
  curl -fsSL $URL/sentinel-archive-keyring.gpg | sudo tee /etc/apt/keyrings/sentinel-archive-keyring.gpg >/dev/null
  echo "deb [signed-by=/etc/apt/keyrings/sentinel-archive-keyring.gpg] $URL stable main" | sudo tee /etc/apt/sources.list.d/sentinel.list
  sudo apt update && sudo apt install sentinel

Huella de la clave: $(gpg --with-colons --fingerprint "$HUELLA" | awk -F: '/^fpr:/ {print $10; exit}')
EOT
echo "Repositorio listo en $OUT"; echo "Publícalo en: $URL"
