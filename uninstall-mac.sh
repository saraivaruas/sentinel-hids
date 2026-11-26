#!/usr/bin/env bash
# Desinstala Sentinel de macOS. Uso: sudo ./uninstall-mac.sh [--todo]   (--todo borra también registros, referencias y configuración)
set -euo pipefail
[ "$(uname -s)" = Darwin ] || { echo "Este desinstalador es para macOS. En Linux usa ./uninstall.sh"; exit 1; }
[ "$(id -u)" -eq 0 ] || { echo "Ejecútalo con sudo"; exit 1; }
DEST=/opt/sentinel
# con PIN configurado, desinstalar Sentinel exige el PIN (si acabas de escribirlo con «sentinel pin verificar», no se repite)
if [ -x "$DEST/bin/sentinel" ]; then
  PY="$(cat "$DEST/python" 2>/dev/null || echo /usr/bin/python3)"
  instalado() { "$PY" -I -c "import sys; sys.path.insert(0, '$DEST'); $1"; }
  if ! instalado "from sentinel import pin; sys.exit(0 if not pin.required() or pin.stop_authorized() else 1)"; then
    "$DEST/bin/sentinel" pin verificar || { echo "Sentinel está protegido con PIN: no se desinstala sin el PIN correcto." >&2; exit 1; }
  fi
  instalado "from sentinel import servicio; sys.exit(1 if servicio.detener() else 0)" || { echo "No pude detener Sentinel." >&2; exit 1; }
fi
rm -f /Library/LaunchDaemons/io.github.saraivaruas.sentinel.*.plist /usr/local/bin/sentinel /etc/newsyslog.d/sentinel.conf
rm -rf "$DEST" /Applications/Sentinel.app
dscl . -delete /Users/_sentinel >/dev/null 2>&1 || true
dscl . -delete /Groups/_sentinel >/dev/null 2>&1 || true
pfctl -a com.apple/sentinel -F all >/dev/null 2>&1 || true      # quita los bloqueos
if [ "${1:-}" = "--todo" ]; then rm -rf /var/lib/sentinel /var/log/sentinel /etc/sentinel; echo "Todo eliminado."; else echo "Programa eliminado. Se conservan /var/lib/sentinel, /var/log/sentinel y /etc/sentinel (usa --todo para borrarlos)."; fi
