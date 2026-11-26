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

echo "== panel (como $SUDO_USER)"
sudo -u "$SUDO_USER" -H /usr/bin/python3 -I "$AQUI/tools/prueba-mac-panel.py"; comprobar "el panel funciona" test $? = 0
/usr/local/bin/sentinel requisitos > /tmp/req.txt; comprobar "no falta ningún requisito" grep -q "Todo lo necesario ya está instalado" /tmp/req.txt
/usr/local/bin/sentinel test; comprobar "la prueba de alertas funciona" test $? = 0
/usr/local/bin/sentinel audit | tee /tmp/audit.txt
comprobar "la auditoría reconoce las protecciones de macOS" sh -c 'grep -q "SIP" /tmp/audit.txt && ! grep -Eq "no se pudo revisar|ufw|auditd" /tmp/audit.txt'
/usr/local/bin/sentinel endurecer plan

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

echo "== icono de la barra de menú"
comprobar "el icono se compiló" test -x /opt/sentinel/bin/sentinel-barra
sudo -u "$SUDO_USER" /opt/sentinel/bin/sentinel-barra --una-vez | tee /tmp/barra.txt
comprobar "el icono lee el estado real" grep -Eq '^(protegido|revision|atencion|peligro)\|' /tmp/barra.txt
comprobar "el icono queda en la barra de quien usa el equipo" esperar 30 pgrep -u "$SUDO_USER" -f /opt/sentinel/bin/sentinel-barra

echo "== señuelos"
comprobar "los señuelos se activan" /usr/local/bin/sentinel senuelos activar
comprobar "quedan escuchando" esperar 30 nc -z 127.0.0.1 2222
comprobar "corren con el usuario sin privilegios" test "$(ps -o user= -p "$(pgrep -f '/opt/sentinel honeypot' | head -1)" | tr -d ' ')" = _sentinel
echo hola | nc -w 3 127.0.0.1 2222 >/dev/null
comprobar "avisa de quien toca un señuelo" esperar 60 evento toque
comprobar "activarlos no se reporta como ataque" sh -c '! grep -q "sentinel.honeypot.plist" /var/log/sentinel/events.jsonl'
comprobar "ese usuario no puede leer los registros" sh -c '! sudo -u _sentinel cat /var/log/sentinel/events.jsonl'
comprobar "los señuelos se apagan" /usr/local/bin/sentinel senuelos desactivar
comprobar "el puerto queda cerrado" sh -c '! nc -z 127.0.0.1 2222'

echo "== USB y extensiones"
/usr/bin/python3 -I -c 'import sys; sys.path.insert(0, "/opt/sentinel"); from sentinel import hostcheck; print("usb:", hostcheck.usb_devices()); print("extensiones:", hostcheck.kernel_modules())'
ioreg -p IOUSB -l -w0 | grep -E '\+-o |idVendor|idProduct|USB Product Name' | head -30; kmutil showloaded --list-only 2>/dev/null | grep -v com.apple | head; systemextensionsctl list

echo "== con PIN"
printf '\nsecreto-123\n' | /usr/local/bin/sentinel --pin-stdin pin establecer; comprobar "se puede poner un PIN" test $? = 0
comprobar "sin escribir el PIN no se reinstala" sh -c "! '$AQUI/install-mac.sh' </dev/null"
comprobar "sin escribir el PIN no se desinstala" sh -c "! '$AQUI/uninstall-mac.sh' </dev/null"
comprobar "y sigue corriendo" corriendo
echo secreto-123 | /usr/local/bin/sentinel --pin-stdin pin verificar; comprobar "con el PIN se autoriza" test $? = 0
"$AQUI/install-mac.sh" </dev/null >/dev/null; comprobar "una actualización autorizada no vuelve a pedir el PIN" test $? = 0
comprobar "sigue corriendo tras actualizar" esperar 60 corriendo
printf 'secreto-123\n' | /usr/local/bin/sentinel --pin-stdin pin verificar >/dev/null

echo "== registros"; tail -n 40 /var/log/sentinel/*.salida.log
echo "== eventos"; /usr/bin/python3 -I -c 'import json
for l in open("/var/log/sentinel/events.jsonl"):
    e = json.loads(l); print(e["sev"], e["source"], e["kind"], "|", e["msg"][:160])'
comprobar "ningún módulo informó un error" sh -c '! grep -q "\"source\": \"monitor\", \"kind\": \"error\"" /var/log/sentinel/events.jsonl'
comprobar "ningún programa se cayó" sh -c '! grep -q Traceback /var/log/sentinel/*.salida.log'

echo "== desinstalar"; "$AQUI/uninstall-mac.sh" --todo; comprobar "el desinstalador termina bien" test $? = 0
comprobar "no queda el servicio" sh -c "! launchctl print $SVC.monitor"
comprobar "no quedan procesos" sh -c "! pgrep -f '/opt/sentinel monitor'"
comprobar "no queda el icono" sh -c '! pgrep -f /opt/sentinel/bin/sentinel-barra'
comprobar "no queda el usuario de los señuelos" sh -c '! dscl . -read /Users/_sentinel'
for r in /opt/sentinel /etc/sentinel /var/lib/sentinel /var/log/sentinel /usr/local/bin/sentinel; do comprobar "no queda $r" test ! -e "$r"; done
rm -f /Library/LaunchDaemons/com.ejemplo.intruso.plist

echo "== instalador .pkg"
comprobar "el .pkg se genera" "$AQUI/packaging/macos/build-pkg.sh"
PKG="$(ls "$AQUI"/dist/sentinel-*-macos.pkg)"
installer -pkg "$PKG" -target /; comprobar "macOS instala el .pkg" test $? = 0
comprobar "instalado con el .pkg, el monitor corre" esperar 90 corriendo
comprobar "sentinel responde" /usr/local/bin/sentinel status
"$AQUI/uninstall-mac.sh" --todo; comprobar "se desinstala después del .pkg" test $? = 0
comprobar "no queda /opt/sentinel tras el .pkg" test ! -e /opt/sentinel
if [ "$FALLOS" = 0 ]; then echo "Todas las comprobaciones pasaron."; else echo "$FALLOS comprobaciones fallidas"; exit 1; fi
