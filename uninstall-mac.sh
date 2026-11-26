#!/usr/bin/env bash
# Desinstala Sentinel de macOS. Uso: sudo ./uninstall-mac.sh [--todo]   (--todo borra también registros, referencias y configuración)
set -euo pipefail
[ "$(uname -s)" = Darwin ] || { echo "Este desinstalador es para macOS. En Linux usa ./uninstall.sh"; exit 1; }
[ "$(id -u)" -eq 0 ] || { echo "Ejecútalo con sudo"; exit 1; }
DEST=/opt/sentinel
# con PIN configurado, desinstalar Sentinel exige el PIN
if [ -x "$DEST/bin/sentinel" ]; then
  "$DEST/bin/sentinel" pin verificar || { echo "Sentinel está protegido con PIN: no se desinstala sin el PIN correcto." >&2; exit 1; }
  "$DEST/bin/sentinel" detener >/dev/null || true
fi
rm -f /Library/LaunchDaemons/io.github.saraivaruas.sentinel.*.plist /usr/local/bin/sentinel /etc/newsyslog.d/sentinel.conf
rm -rf "$DEST"
pfctl -a com.apple/sentinel -F all >/dev/null 2>&1 || true      # quita los bloqueos
if [ "${1:-}" = "--todo" ]; then rm -rf /var/lib/sentinel /var/log/sentinel /etc/sentinel; echo "Todo eliminado."; else echo "Programa eliminado. Se conservan /var/lib/sentinel, /var/log/sentinel y /etc/sentinel (usa --todo para borrarlos)."; fi
