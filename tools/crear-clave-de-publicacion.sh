#!/usr/bin/env bash
# Crea (una sola vez) la clave GPG con la que firmas las publicaciones de Sentinel y deja su parte PÚBLICA en packaging/release-key.asc.
# La clave privada se queda en tu llavero (~/.gnupg), protegida con la frase que elijas: no sale de tu equipo ni va al repositorio.
# Uso: ./tools/crear-clave-de-publicacion.sh "Tu Nombre" tu@correo
set -euo pipefail
NOMBRE="${1:?Uso: $0 \"Tu Nombre\" tu@correo}"; CORREO="${2:?Uso: $0 \"Tu Nombre\" tu@correo}"
AQUI="$(cd "$(dirname "$0")/.." && pwd)"
echo "GPG te pedirá una frase secreta: elígela tú y guárdala bien (sin ella no se puede firmar)."
gpg --quick-generate-key "$NOMBRE (publicaciones de Sentinel) <$CORREO>" ed25519 sign 3y
HUELLA="$(gpg --list-keys --with-colons "$CORREO" | awk -F: '/^fpr:/ {print $10; exit}')"
gpg --armor --export "$HUELLA" > "$AQUI/packaging/release-key.asc"
echo
echo "Clave creada. Huella: $HUELLA"
echo "Clave pública guardada en packaging/release-key.asc (NO va a git: está en .gitignore; el .deb construido en este equipo la incluye y la CI la exporta de tu secreto)."
echo "Para firmar una publicación:  SENTINEL_SIGN_KEY=$HUELLA ./packaging/make-release.sh   y sube también dist/SHA256SUMS.asc a la release."
