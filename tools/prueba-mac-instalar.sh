#!/usr/bin/env bash
# Prueba real en macOS: instalar, comprobar que queda vigilando, detener, iniciar, reinstalar y desinstalar.
# SOLO para equipos desechables (la CI `mac-instalar`). Se ejecuta con sudo.
set -u
[ "${GITHUB_ACTIONS:-}" = true ] || { echo "Solo en la CI (GITHUB_ACTIONS=true)."; exit 1; }
AQUI="$(cd "$(dirname "$0")/.." && pwd)"
FALLOS=0
comprobar() { local nombre="$1"; shift; if "$@" >/dev/null 2>&1; then echo "OK    $nombre"; else echo "FALLO $nombre"; FALLOS=$((FALLOS+1)); fi; }
esperar() { local s="$1"; shift; for _ in $(seq 1 "$s"); do "$@" >/dev/null 2>&1 && return 0; sleep 1; done; return 1; }
SVC=system/io.github.saraivaruas.sentinel
corriendo() { launchctl print "$SVC.monitor" 2>/dev/null | grep -q 'state = running'; }
no_corriendo() { ! corriendo; }
evento() { grep -q -- "$1" /var/log/sentinel/events.jsonl; }
pid() { pgrep -f '/opt/sentinel monitor' | head -1; }

echo "== instalar"; "$AQUI/install-mac.sh"; comprobar "el instalador termina bien" test $? = 0
comprobar "el monitor queda corriendo" esperar 60 corriendo
for t in scan report equipo; do comprobar "tarea programada $t cargada" launchctl print "$SVC.$t"; done
comprobar "vigila en vivo" esperar 120 evento "en vivo de archivos: sí"
/usr/local/bin/sentinel status | tee /tmp/status.txt
comprobar "status lo da por activo" grep -Eq 'sentinel-monitor +.*active' /tmp/status.txt
comprobar "status no menciona systemctl" sh -c '! grep -q systemctl /tmp/status.txt'
sleep 20
comprobar "la propia instalación no genera avisos de archivos" sh -c '! grep -q "\"source\": \"fim\"" /var/log/sentinel/events.jsonl'
touch /Library/LaunchDaemons/com.ejemplo.intruso.plist
comprobar "avisa de un programa de arranque nuevo" esperar 60 evento com.ejemplo.intruso
for i in 1 2 3 4 5 6; do ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "noexiste$i@127.0.0.1" true >/dev/null 2>&1; sleep 1; done
comprobar "avisa de la fuerza bruta (el servicio lee el registro)" esperar 60 evento fuerza_bruta
comprobar "el panel de otro equipo puede leer los registros (grupo admin)" test "$(stat -f %Sg /var/log/sentinel/events.jsonl)" = admin

ANTES="$(pid)"; kill -9 "$ANTES"
comprobar "si matan el monitor, launchd lo vuelve a levantar" esperar 60 sh -c "p=\$(pgrep -f '/opt/sentinel monitor' | head -1); [ -n \"\$p\" ] && [ \"\$p\" != '$ANTES' ]"
comprobar "detener funciona" /usr/local/bin/sentinel detener
comprobar "queda detenido" esperar 30 no_corriendo
comprobar "iniciar funciona" /usr/local/bin/sentinel iniciar
comprobar "vuelve a correr" esperar 60 corriendo
launchctl kickstart "$SVC.scan"; sleep 40
comprobar "la revisión programada no se cae" sh -c '! grep -q Traceback /var/log/sentinel/scan.salida.log'
launchctl kickstart "$SVC.equipo"; sleep 60
comprobar "el informe programado se genera" sh -c 'ls /var/lib/sentinel/informes/equipo-*.html'
echo "== reinstalar encima"; "$AQUI/install-mac.sh" >/dev/null; comprobar "reinstalar funciona" test $? = 0
comprobar "sigue corriendo tras reinstalar" esperar 60 corriendo

echo "== registros"; tail -n 40 /var/log/sentinel/*.salida.log
echo "== eventos"; /usr/bin/python3 -I -c 'import json
for l in open("/var/log/sentinel/events.jsonl"):
    e = json.loads(l); print(e["sev"], e["source"], e["kind"], "|", e["msg"][:160])'
comprobar "ningún módulo informó un error" sh -c '! grep -q "\"source\": \"monitor\", \"kind\": \"error\"" /var/log/sentinel/events.jsonl'
comprobar "ningún programa se cayó" sh -c '! grep -q Traceback /var/log/sentinel/*.salida.log'

echo "== desinstalar"; "$AQUI/uninstall-mac.sh" --todo; comprobar "el desinstalador termina bien" test $? = 0
comprobar "no queda el servicio" sh -c "! launchctl print $SVC.monitor"
comprobar "no quedan procesos" sh -c "! pgrep -f '/opt/sentinel monitor'"
for r in /opt/sentinel /etc/sentinel /var/lib/sentinel /var/log/sentinel /usr/local/bin/sentinel; do comprobar "no queda $r" test ! -e "$r"; done
rm -f /Library/LaunchDaemons/com.ejemplo.intruso.plist
if [ "$FALLOS" = 0 ]; then echo "Todas las comprobaciones pasaron."; else echo "$FALLOS comprobaciones fallidas"; exit 1; fi
