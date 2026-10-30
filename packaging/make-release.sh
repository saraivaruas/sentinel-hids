#!/usr/bin/env bash
# Genera dist/: el paquete .deb, el tarball con instalador y SHA256SUMS.
set -euo pipefail
AQUI="$(cd "$(dirname "$0")/.." && pwd)"; cd "$AQUI"
VER="$(python3 -c "import sys;sys.path.insert(0,'.');from sentinel import core;print(core.VERSION)")"
(cd tests && python3 -W ignore -m unittest discover -s . >/dev/null 2>&1) || { echo "Las pruebas fallan: no se publica"; exit 1; }
"$AQUI/packaging/build-deb.sh" >/dev/null
rm -f "dist/sentinel-$VER.tar.gz"
tar --exclude=dist --exclude=.git --exclude=__pycache__ --exclude=docs -czf "dist/sentinel-$VER.tar.gz" --transform "s,^\.,sentinel-$VER," .
(cd dist && sha256sum "sentinel_${VER}_all.deb" "sentinel-$VER.tar.gz" > SHA256SUMS && cat SHA256SUMS)
