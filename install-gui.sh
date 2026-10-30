#!/usr/bin/env bash
# Instalador gráfico de Sentinel: ventanas para confirmar, elegir opciones, pedir la AUTORIZACIÓN de administrador (ventana del sistema) y mostrar el avance.
# Se abre con doble clic en «Instalar Sentinel» o con:  ./install-gui.sh
set -u
AQUI="$(cd "$(dirname "$0")" && pwd)"
LOG="$(mktemp /tmp/sentinel-instalacion.XXXXXX.log)"
TIT="Instalar Sentinel"
TO=""; [ -n "${SENTINEL_GUI_TIMEOUT:-}" ] && TO="--timeout=$SENTINEL_GUI_TIMEOUT"   # solo para pruebas

# zenity dibuja las ventanas; si falta, se instala pidiendo la autorización con la ventana del sistema
if ! command -v zenity >/dev/null 2>&1; then
  if command -v pkexec >/dev/null 2>&1 && command -v apt-get >/dev/null 2>&1; then
    pkexec env DEBIAN_FRONTEND=noninteractive apt-get install -y zenity >/dev/null 2>&1 || true
  fi
  command -v zenity >/dev/null 2>&1 || { echo "No hay entorno gráfico disponible. Usa:  sudo $AQUI/install.sh"; exec sudo "$AQUI/install.sh" "$@"; }
fi

zenity --question $TO --title "$TIT" --width=560 --ok-label="Continuar" --cancel-label="Cancelar" --icon-name=security-high --no-markup --text="Sentinel vigila este equipo: detecta intrusiones, cambios en archivos importantes, ataques en vivo y procesos sospechosos, y te avisa con ventanas.

Para instalarlo el sistema te pedirá la autorización de administrador (una ventana con tu clave).

Qué hará:
  • Instalar lo que falte (inotify, notificaciones, polkit…)
  • Copiar Sentinel a /opt/sentinel y crear sus servicios
  • Crear la referencia de integridad de los archivos importantes
  • Dejar un acceso «Sentinel» en tu menú de aplicaciones" || exit 0

SEL="$(zenity --list --checklist $TO --title "$TIT" --width=560 --height=330 --text="Elige las opciones y pulsa Aceptar:" --separator="|" --hide-header \
  --column="" --column="Opción" \
  TRUE "Instalar las dependencias que falten" \
  TRUE "Retirar la versión 1 de Sentinel (con copia de respaldo)" \
  FALSE "Abrir los puertos señuelo hacia Internet (avanzado)")" || exit 0

flags=()
case "$SEL" in *"dependencias"*) ;; *) flags+=(--sin-dependencias);; esac
case "$SEL" in *"versión 1"*) ;; *) flags+=(--sin-limpiar);; esac
case "$SEL" in *"señuelo"*) flags+=(--exponer-senuelos);; esac

# pkexec muestra la ventana de autorización del sistema; el avance se ve en la barra de progreso
pkexec "$AQUI/install.sh" "${flags[@]}" 2>&1 | tee "$LOG" \
  | awk '/^== [0-9]\/8/ { split($2, a, "/"); print "#" $0; print int(a[1] * 100 / 8); fflush() } END { print 100 }' \
  | zenity --progress --no-cancel --auto-close --title "$TIT" --width=520 --text="Esperando la autorización de administrador…"
rc=${PIPESTATUS[0]}

if [ "$rc" -eq 126 ] || [ "$rc" -eq 127 ]; then
  zenity --warning --no-markup --title "$TIT" --width=460 --text="Instalación cancelada: no se autorizó el acceso de administrador. No se cambió nada."
  exit 1
fi
if [ "$rc" -ne 0 ]; then
  zenity --error --no-markup --title "$TIT" --width=520 --text="La instalación falló (código $rc). Se abrirá el detalle." >/dev/null 2>&1
  tail -n 60 "$LOG" | zenity --text-info --title "Detalle de la instalación" --width=760 --height=480 --font="monospace 10" >/dev/null 2>&1
  exit "$rc"
fi

zenity --info --no-markup --title "$TIT" --width=500 --ok-label="Seguir" --text="Sentinel quedó instalado y protegiendo este equipo.

A continuación verás una ventana de alerta de PRUEBA: así es como Sentinel te avisará cuando detecte algo." >/dev/null 2>&1
sentinel test >/dev/null 2>&1 &
sleep 3
if zenity --question $TO --title "$TIT" --width=460 --ok-label="Abrir panel" --cancel-label="Más tarde" --no-markup --text="¿Quieres abrir el panel de Sentinel ahora?"; then
  nohup sentinel ui >/dev/null 2>&1 &
fi
exit 0
