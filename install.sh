#!/usr/bin/env bash
# Instala Sentinel v2 y las dependencias que falten (Ubuntu/Debian, Fedora/RHEL, Arch, openSUSE).
# Uso: sudo ./install.sh [--dry-run] [--sin-dependencias] [--sin-limpiar] [--exponer-senuelos]
#   --dry-run            muestra lo que haría sin cambiar nada
#   --sin-dependencias   no instala paquetes (solo copia Sentinel)
#   --sin-limpiar        no retira los restos de la versión 1 (scripts antiguos y la línea de rc.local)
#   --exponer-senuelos   abre en el cortafuegos los puertos señuelo para que los vea Internet (por defecto quedan cerrados)
set -euo pipefail

DRY=0; LIMPIAR=1; EXPONER=0; DEPS=1
for a in "$@"; do case "$a" in --dry-run) DRY=1;; --sin-dependencias) DEPS=0;; --sin-limpiar) LIMPIAR=0;; --exponer-senuelos) EXPONER=1;; -h|--help) sed -n 2,8p "$0"; exit 0;; *) echo "Opción desconocida: $a"; exit 1;; esac; done

AQUI="$(cd "$(dirname "$0")" && pwd)"
DEST=/opt/sentinel
USUARIO="${SUDO_USER:-}"
[ -z "$USUARIO" ] && [ -n "${PKEXEC_UID:-}" ] && USUARIO="$(id -nu "$PKEXEC_UID" 2>/dev/null || true)"
[ -z "$USUARIO" ] && USUARIO=root
do_() { if [ "$DRY" = 1 ]; then echo "  [simulación] $*"; else "$@"; fi; }
paso() { echo; echo "== $*"; }

if [ "$DRY" = 0 ] && [ "$(id -u)" -ne 0 ]; then echo "Ejecútalo con sudo (o usa --dry-run para ver qué haría)."; exit 1; fi
HAY_SYSTEMD=0; [ -d /run/systemd/system ] && HAY_SYSTEMD=1

# ---------- dependencias: detecta la distribución y qué falta
detectar_gestor() {
  local id like
  id="${SENTINEL_FAKE_OS:-}"; like="${SENTINEL_FAKE_LIKE:-}"
  if [ -z "$id" ] && [ -r /etc/os-release ]; then . /etc/os-release; id="${ID:-}"; like="${ID_LIKE:-}"; fi
  case " $id $like " in
    *" debian "*|*" ubuntu "*) PM=apt;;
    *" fedora "*|*" rhel "*|*" centos "*) PM=dnf;;
    *" arch "*) PM=pacman;;
    *" suse "*|*" opensuse"*) PM=zypper;;
    *) PM="";;
  esac
}
# comando -> paquete en cada familia
paquete() {
  case "$PM:$1" in
    apt:python3) echo python3;; dnf:python3|zypper:python3) echo python3;; pacman:python3) echo python;;
    *:inotifywait) echo inotify-tools;;
    apt:notify-send) echo libnotify-bin;; dnf:notify-send|pacman:notify-send) echo libnotify;; zypper:notify-send) echo libnotify-tools;;
    apt:pkexec) echo policykit-1;; *:pkexec) echo polkit;;
    apt:ss|zypper:ss|pacman:ss) echo iproute2;; dnf:ss) echo iproute;;
    apt:ps|zypper:ps) echo procps;; dnf:ps|pacman:ps) echo procps-ng;;
    *:runuser) echo util-linux;;
    *:logrotate) echo logrotate;;
    apt:firewall) echo ufw;; dnf:firewall|zypper:firewall) echo firewalld;; pacman:firewall) echo iptables-nft;;
    apt:lynis|pacman:lynis|zypper:lynis) echo lynis;;
  esac
}
faltan() {   # comandos que no están instalados (SENTINEL_FAKE_MISSING fuerza la lista, para pruebas)
  local c out=""
  if [ -n "${SENTINEL_FAKE_MISSING:-}" ]; then echo "$SENTINEL_FAKE_MISSING"; return; fi
  for c in python3 inotifywait notify-send pkexec ss ps runuser logrotate lynis; do command -v "$c" >/dev/null 2>&1 || out="$out $c"; done
  # motor de bloqueo: basta con tener alguno (CrowdSec, ufw, firewalld o iptables)
  if ! command -v cscli >/dev/null && ! command -v ufw >/dev/null && ! command -v firewall-cmd >/dev/null && ! command -v iptables >/dev/null; then out="$out firewall"; fi
  echo "$out"
}
paso "0/8 Dependencias"
if [ "$DEPS" = 0 ]; then echo "  omitido (--sin-dependencias)"; else
  detectar_gestor
  FALTA="$(faltan)"
  if [ -z "${FALTA// /}" ]; then echo "  todo está instalado"; else
    PAQS=""; for c in $FALTA; do p="$(paquete "$c")"; [ -n "$p" ] && PAQS="$PAQS $p"; done
    PAQS="$(echo $PAQS | tr ' ' '\n' | sort -u | tr '\n' ' ')"
    echo "  faltan:$FALTA"
    if [ -z "$PM" ]; then echo "  No reconozco el gestor de paquetes de esta distribución: instala a mano el equivalente de:$FALTA"
    elif [ -z "${PAQS// /}" ]; then echo "  (sin paquete conocido para esta distribución)"
    else
      echo "  se instalará con $PM: $PAQS"
      case "$PM" in
        apt) do_ apt-get update -qq; do_ env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends $PAQS;;
        dnf) do_ dnf install -y $PAQS;;
        pacman) do_ pacman -S --noconfirm --needed $PAQS;;
        zypper) do_ zypper --non-interactive install $PAQS;;
      esac
    fi
  fi
fi
command -v python3 >/dev/null || [ "$DRY" = 1 ] || { echo "Falta python3 y no se pudo instalar"; exit 1; }
[ "$HAY_SYSTEMD" = 1 ] || echo "  Aviso: no hay systemd en este entorno (contenedor): se instala el programa y se omiten los servicios."
PYV=$(python3 -c 'import sys;print("%d%d"%sys.version_info[:2])' 2>/dev/null || echo 38); [ "$PYV" -ge 38 ] || { echo "Se necesita Python 3.8 o superior"; exit 1; }

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

paso "5/8 Servicios de systemd y acceso directo al panel"
do_ install -D -m 644 "$AQUI/sentinel/ui/icon.svg" /usr/share/icons/hicolor/scalable/apps/sentinel.svg
do_ install -D -m 644 "$AQUI/desktop/sentinel.desktop" /usr/share/applications/sentinel.desktop
command -v update-desktop-database >/dev/null && do_ update-desktop-database /usr/share/applications || true
command -v gtk-update-icon-cache >/dev/null && do_ gtk-update-icon-cache -q /usr/share/icons/hicolor || true
do_ cp "$AQUI"/systemd/*.service "$AQUI"/systemd/*.timer /etc/systemd/system/
[ "$HAY_SYSTEMD" = 1 ] && do_ systemctl daemon-reload || true

paso "6/8 Referencia inicial de integridad y del equipo"
do_ /usr/local/bin/sentinel baseline init

paso "7/8 Arrancar"
[ "$HAY_SYSTEMD" = 1 ] && do_ systemctl enable --now sentinel-honeypot.service sentinel-monitor.service sentinel-scan.timer sentinel-report.timer || echo "  (sin systemd: inicia a mano con «sentinel monitor»)"

paso "8/8 Cortafuegos de los señuelos"
if [ "$EXPONER" = 1 ]; then
  for p in $(python3 -c "import sys;sys.path.insert(0,'$AQUI');from sentinel import core;print(' '.join(core.csv(core.load_config().get('honeypot','ports'))))"); do
    do_ ufw allow "$p/tcp" comment sentinel-senuelo; done
else echo "  Los puertos señuelo quedan cerrados hacia afuera (detectan escaneos locales). El escaneo de puertos externo se detecta igual con los registros del cortafuegos."; echo "  Para exponerlos: sudo ./install.sh --exponer-senuelos"; fi

[ "$DRY" = 0 ] && [ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ] || true
echo; echo "Listo. Comprueba con:  sentinel status   y   sentinel test"
echo "Panel gráfico: busca «Sentinel» en el menú de aplicaciones, o ejecuta:  sentinel ui"
