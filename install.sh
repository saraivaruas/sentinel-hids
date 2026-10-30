#!/usr/bin/env bash
# Instala Sentinel v2. Uso: sudo ./install.sh [--dry-run] [--sin-limpiar] [--exponer-senuelos]
#   --dry-run            muestra lo que haría sin cambiar nada
#   --sin-limpiar        no retira los restos de la versión 1 (scripts antiguos y la línea de rc.local)
#   --exponer-senuelos   abre en el cortafuegos los puertos señuelo para que los vea Internet (por defecto quedan cerrados)
set -euo pipefail

DRY=0; LIMPIAR=1; EXPONER=0
for a in "$@"; do case "$a" in --dry-run) DRY=1;; --sin-limpiar) LIMPIAR=0;; --exponer-senuelos) EXPONER=1;; -h|--help) sed -n 2,6p "$0"; exit 0;; *) echo "Opción desconocida: $a"; exit 1;; esac; done

AQUI="$(cd "$(dirname "$0")" && pwd)"
DEST=/opt/sentinel
USUARIO="${SUDO_USER:-root}"
do_() { if [ "$DRY" = 1 ]; then echo "  [simulación] $*"; else "$@"; fi; }
paso() { echo; echo "== $*"; }

if [ "$DRY" = 0 ] && [ "$(id -u)" -ne 0 ]; then echo "Ejecútalo con sudo (o usa --dry-run para ver qué haría)."; exit 1; fi
command -v python3 >/dev/null || { echo "Falta python3"; exit 1; }
command -v systemctl >/dev/null || { echo "Falta systemd"; exit 1; }
PYV=$(python3 -c 'import sys;print("%d%d"%sys.version_info[:2])'); [ "$PYV" -ge 38 ] || { echo "Se necesita Python 3.8 o superior"; exit 1; }

paso "1/8 Usuario sin privilegios para los señuelos"
id sentinel >/dev/null 2>&1 && echo "  ya existe" || do_ useradd --system --no-create-home --shell /usr/sbin/nologin sentinel

paso "2/8 Programa en $DEST (solo root puede modificarlo)"
do_ rm -rf "$DEST"; do_ mkdir -p "$DEST"
do_ cp -a "$AQUI/sentinel" "$AQUI/bin" "$AQUI/README.md" "$DEST/"
do_ find "$DEST" -name __pycache__ -prune -exec rm -rf {} +
do_ chown -R root:root "$DEST"; do_ chmod -R go-w "$DEST"
do_ ln -sf "$DEST/bin/sentinel" /usr/local/bin/sentinel

paso "3/8 Configuración, estado y registros"
do_ mkdir -p /etc/sentinel
if [ -e /etc/sentinel/sentinel.conf ]; then echo "  /etc/sentinel/sentinel.conf ya existe: no se toca"; else
  do_ cp "$AQUI/etc/sentinel.conf.example" /etc/sentinel/sentinel.conf
  do_ sed -i "s/^desktop_user = .*/desktop_user = $USUARIO/" /etc/sentinel/sentinel.conf; fi
do_ chown root:adm /etc/sentinel/sentinel.conf; do_ chmod 640 /etc/sentinel/sentinel.conf
do_ install -d -m 750 -o root -g adm /var/lib/sentinel /var/log/sentinel
do_ install -d -m 770 -o root -g sentinel /var/log/sentinel/decoy
do_ install -m 644 /dev/stdin /etc/logrotate.d/sentinel <<'EOF'
/var/log/sentinel/events.jsonl /var/log/sentinel/decoy/honeypot.jsonl {
    weekly
    rotate 8
    compress
    missingok
    notifempty
    copytruncate
}
EOF

paso "4/8 Retirar la versión 1 (se guarda copia en /root/sentinel-v1-respaldo)"
if [ "$LIMPIAR" = 1 ]; then
  do_ mkdir -p /root/sentinel-v1-respaldo
  [ -f /etc/rc.local ] && { do_ cp -a /etc/rc.local /root/sentinel-v1-respaldo/rc.local; do_ sed -i '/sentinel-core.sh/d' /etc/rc.local; }
  for f in /usr/local/bin/sentinel-app /usr/local/bin/sentinel-fim /usr/local/bin/sentinel-honeypot /usr/share/applications/sentinel-jsr.desktop /opt/sentinel-jsr; do
    [ -e "$f" ] && do_ mv "$f" /root/sentinel-v1-respaldo/ || true; done
else echo "  omitido (--sin-limpiar)"; fi

paso "5/8 Servicios de systemd"
do_ cp "$AQUI"/systemd/*.service "$AQUI"/systemd/*.timer /etc/systemd/system/
do_ systemctl daemon-reload

paso "6/8 Referencia inicial de integridad y del equipo"
do_ /usr/local/bin/sentinel baseline init

paso "7/8 Arrancar"
do_ systemctl enable --now sentinel-honeypot.service sentinel-monitor.service sentinel-scan.timer sentinel-report.timer

paso "8/8 Cortafuegos de los señuelos"
if [ "$EXPONER" = 1 ]; then
  for p in $(python3 -c "import sys;sys.path.insert(0,'$AQUI');from sentinel import core;print(' '.join(core.csv(core.load_config().get('honeypot','ports'))))"); do
    do_ ufw allow "$p/tcp" comment sentinel-senuelo; done
else echo "  Los puertos señuelo quedan cerrados hacia afuera (detectan escaneos locales). El escaneo de puertos externo se detecta igual con los registros del cortafuegos."; echo "  Para exponerlos: sudo ./install.sh --exponer-senuelos"; fi

echo; echo "Listo. Comprueba con:  sentinel status   y   sentinel test"
