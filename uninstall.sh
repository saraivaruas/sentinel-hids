#!/usr/bin/env bash
# Desinstala Sentinel v2. Uso: sudo ./uninstall.sh [--todo]   (--todo borra también registros, referencias y el usuario sentinel)
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "Ejecútalo con sudo"; exit 1; }
systemctl disable --now sentinel-monitor.service sentinel-honeypot.service sentinel-scan.timer sentinel-report.timer 2>/dev/null || true
rm -f /etc/systemd/system/sentinel-*.service /etc/systemd/system/sentinel-*.timer /usr/local/bin/sentinel /etc/logrotate.d/sentinel
rm -rf /opt/sentinel
rm -f /usr/share/applications/sentinel.desktop /usr/share/icons/hicolor/scalable/apps/sentinel.svg
systemctl daemon-reload
ufw status 2>/dev/null | grep -q sentinel-senuelo && for p in $(ufw status numbered | grep sentinel-senuelo | awk -F'[][]' '{print $2}' | sort -rn); do yes | ufw delete "$p" >/dev/null; done || true
if [ "${1:-}" = "--todo" ]; then rm -rf /var/lib/sentinel /var/log/sentinel /etc/sentinel; userdel sentinel 2>/dev/null || true; echo "Todo eliminado."; else echo "Programa eliminado. Se conservan /var/lib/sentinel, /var/log/sentinel y /etc/sentinel (usa --todo para borrarlos)."; fi
