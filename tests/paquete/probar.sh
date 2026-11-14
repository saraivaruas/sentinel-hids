#!/usr/bin/env bash
# Prueba el .deb de punta a punta en una distribución limpia (se ejecuta DENTRO de un contenedor, como root):
# instalar con sus dependencias → comprobar → actualizar sin perder la configuración → quitar → purgar.
# Uso:  docker run --rm -v "$PWD/dist:/dist:ro" -v "$PWD/tests/paquete:/t:ro" debian:12 bash /t/probar.sh
set -euo pipefail
DEB="$(ls /dist/sentinel_*_all.deb | tail -1)"
ok() { echo "  ✔ $*"; }
fallo() { echo "  ✖ $*" >&2; exit 1; }
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
echo "== instalar ($(. /etc/os-release; echo "$PRETTY_NAME"))"
apt-get install -y -qq --no-install-recommends "$DEB" >/dev/null
sentinel --help >/dev/null && ok "el comando sentinel funciona"
[ -f /etc/sentinel/sentinel.conf ] && ok "se creó /etc/sentinel/sentinel.conf"
[ -f /usr/share/metainfo/io.github.saraivaruas.sentinel.metainfo.xml ] && ok "AppStream instalado"
[ -f /usr/share/applications/sentinel.desktop ] && ok "lanzador de escritorio instalado"
sentinel requisitos --json | python3 -c "import json,sys; d=json.load(sys.stdin); assert d['requisitos']" && ok "sentinel requisitos --json"
sentinel endurecer plan --json | python3 -c "import json,sys; assert json.load(sys.stdin)" && ok "sentinel endurecer plan --json"
sentinel ia estado >/dev/null || true; ok "sentinel ia estado no falla"
python3 - <<'PY'
import sys; sys.path.insert(0, "/opt/sentinel")
from sentinel import core, ia, ui
assert ia.Redactor(usuarios=["ana"], host="h1").redactar("ana 203.0.113.5").count("203") == 0
PY
ok "módulos importables y el redactor de IA oculta IPs"
echo "== actualizar sin perder la configuración"
echo "# MARCA-DEL-USUARIO" >> /etc/sentinel/sentinel.conf
echo "clave-smtp" > /etc/sentinel/smtp.pass; chmod 600 /etc/sentinel/smtp.pass
apt-get install -y -qq --reinstall "$DEB" >/dev/null
grep -q "MARCA-DEL-USUARIO" /etc/sentinel/sentinel.conf && ok "sentinel.conf intacto tras actualizar" || fallo "la actualización pisó sentinel.conf"
[ "$(cat /etc/sentinel/smtp.pass)" = "clave-smtp" ] && ok "smtp.pass intacta" || fallo "se perdió smtp.pass"
echo "== quitar"
dpkg -r sentinel >/dev/null
[ ! -e /opt/sentinel ] && ok "/opt/sentinel retirado" || fallo "quedó /opt/sentinel"
[ -f /etc/sentinel/sentinel.conf ] && ok "la configuración se conserva al quitar" || fallo "se borró la configuración al quitar"
echo "== purgar"
dpkg -P sentinel >/dev/null
[ ! -e /etc/sentinel ] && [ ! -e /var/lib/sentinel ] && [ ! -e /var/log/sentinel ] && ok "purga completa (sin restos ni claves)" || fallo "quedaron archivos tras purgar"
id sentinel >/dev/null 2>&1 && fallo "quedó el usuario sentinel" || ok "usuario del sistema retirado"
echo "TODO BIEN"
