#!/usr/bin/env bash
# Instala Sentinel en macOS (para Linux usa ./install.sh).
# Uso: sudo ./install-mac.sh [--dry-run]
#   --dry-run   muestra lo que haría sin cambiar nada
set -euo pipefail

DRY=0
for a in "$@"; do case "$a" in --dry-run) DRY=1;; -h|--help) sed -n 2,4p "$0"; exit 0;; *) echo "Opción desconocida: $a"; exit 1;; esac; done

AQUI="$(cd "$(dirname "$0")" && pwd)"
DEST=/opt/sentinel
USUARIO="${SUDO_USER:-}"
do_() { if [ "$DRY" = 1 ]; then echo "  [simulación] $*"; else "$@"; fi; }
paso() { echo; echo "== $*"; }

[ "${SENTINEL_FAKE_UNAME:-$(uname -s)}" = Darwin ] || { echo "Este instalador es para macOS. En Linux usa ./install.sh"; exit 1; }
[ "$DRY" = 1 ] || [ "$(id -u)" -eq 0 ] || { echo "Ejecútalo con sudo:  sudo ./install-mac.sh"; exit 1; }

# Sentinel corre como administrador: solo se usa un Python que un usuario corriente no pueda cambiar (no el de Homebrew).
buscar_python() {
  local p
  for p in /usr/bin/python3 /Library/Frameworks/Python.framework/Versions/Current/bin/python3; do
    [ -x "$p" ] || continue
    [ "$p" = /usr/bin/python3 ] && ! xcode-select -p >/dev/null 2>&1 && continue   # sin las herramientas de Apple es solo un aviso
    "$p" -I -c 'import sys; sys.exit(sys.version_info < (3, 8))' 2>/dev/null && { echo "$p"; return 0; }
  done
  return 1
}
# El instalador .pkg trae su propio Python (uno por tipo de procesador): así no hacen falta las herramientas de Apple.
INCLUIDO="$AQUI/runtime/$(uname -m).tar.gz"; TMPPY=""
if [ -f "$INCLUIDO" ]; then
  if [ "$DRY" = 1 ]; then PY="$DEST/runtime/bin/python3"; echo "  [simulación] usar el Python incluido en el paquete"
  else
    TMPPY="$(mktemp -d)"; trap 'rm -rf "$TMPPY"' EXIT
    tar -xzf "$INCLUIDO" -C "$TMPPY"
    PY="$TMPPY/python/bin/python3"
    "$PY" -I -c 'import ssl, sqlite3, plistlib' || { echo "El Python incluido no funciona en este equipo."; exit 1; }
  fi
else
  PY="$(buscar_python || true)"
  if [ -z "$PY" ]; then
    [ "$DRY" = 1 ] && PY=/usr/bin/python3 || { echo "Falta Python 3. Instala las herramientas de Apple con:  xcode-select --install   y vuelve a ejecutar este instalador."; exit 1; }
  fi
fi
modulo() { do_ "$PY" -I -c "import sys; sys.path.insert(0, '$DEST'); from sentinel import servicio; $1" "${@:2}"; }

# Una instalación anterior con PIN solo se reemplaza con el PIN. Una actualización ya lo comprobó y no lo vuelve a pedir.
anterior() { "$PY" -I -c "import sys; sys.path.insert(0, '$DEST'); $1"; }
if [ "$DRY" = 0 ] && [ -x "$DEST/bin/sentinel" ]; then
  if ! anterior "from sentinel import pin; sys.exit(0 if not pin.required() or pin.stop_authorized() else 1)"; then
    "$DEST/bin/sentinel" pin verificar || { echo "Sentinel está protegido con PIN: no se reinstala sin el PIN correcto." >&2; exit 1; }
  fi
  anterior "from sentinel import servicio; sys.exit(1 if servicio.detener() else 0)" || { echo "No pude detener la versión anterior." >&2; exit 1; }
fi

paso "1/5 Programa en $DEST (solo el administrador puede modificarlo)"
echo "  Python: $PY"
do_ rm -rf "$DEST"; do_ mkdir -p "$DEST" /usr/local/bin
do_ cp -R "$AQUI/sentinel" "$AQUI/bin" "$AQUI/yara" "$AQUI/README.md" "$DEST/"
do_ find "$DEST" -name __pycache__ -prune -exec rm -rf {} +
if [ -f "$INCLUIDO" ]; then
  if [ "$DRY" = 1 ]; then echo "  [simulación] instalar el Python incluido en $DEST/runtime"
  else mv "$TMPPY/python" "$DEST/runtime"; PY="$DEST/runtime/bin/python3"; fi
fi
# se compila todo ahora: si Python lo hiciera después, Sentinel vería aparecer archivos nuevos en su propia carpeta
if [ "$DRY" = 1 ]; then echo "  [simulación] precompilar $DEST"
else "$PY" -I -m compileall -q "$DEST" >/dev/null 2>&1 || true; fi
if [ "$DRY" = 0 ]; then echo "$PY" > "$DEST/python"; fi
do_ chown -R root:wheel "$DEST"; do_ chmod -R go-w "$DEST"; do_ chmod -R a+rX "$DEST"
do_ ln -sf "$DEST/bin/sentinel" /usr/local/bin/sentinel

paso "2/5 Configuración, estado y registros"
do_ mkdir -p /etc/sentinel
if [ -e /etc/sentinel/sentinel.conf ]; then echo "  /etc/sentinel/sentinel.conf ya existe: no se toca"; else
  do_ cp "$AQUI/packaging/macos/sentinel.conf" /etc/sentinel/sentinel.conf
  do_ sed -i '' "s/^desktop_user =.*/desktop_user = $USUARIO/" /etc/sentinel/sentinel.conf; fi
do_ chown root:admin /etc/sentinel/sentinel.conf; do_ chmod 640 /etc/sentinel/sentinel.conf
do_ install -d -m 750 -o root -g admin /var/lib/sentinel /var/log/sentinel
do_ mkdir -p /etc/newsyslog.d
do_ cp "$AQUI/packaging/macos/newsyslog.conf" /etc/newsyslog.d/sentinel.conf

# Usuario sin privilegios para los puertos señuelo (apagados hasta que los actives)
crear_usuario() {
  dscl . -read /Users/_sentinel >/dev/null 2>&1 && return 0
  local id=300
  while { dscl . -list /Users UniqueID; dscl . -list /Groups PrimaryGroupID; } | awk '{print $2}' | grep -qx "$id"; do id=$((id+1)); done
  dscl . -create /Groups/_sentinel
  dscl . -create /Groups/_sentinel PrimaryGroupID "$id"
  dscl . -create /Users/_sentinel
  dscl . -create /Users/_sentinel UniqueID "$id"
  dscl . -create /Users/_sentinel PrimaryGroupID "$id"
  dscl . -create /Users/_sentinel UserShell /usr/bin/false
  dscl . -create /Users/_sentinel NFSHomeDirectory /var/empty
  dscl . -create /Users/_sentinel RealName "Sentinel (puertos señuelo)"
  dscl . -create /Users/_sentinel IsHidden 1
}
if [ "$DRY" = 1 ]; then echo "  [simulación] crear el usuario _sentinel"; else crear_usuario; fi
do_ chmod 755 /etc/sentinel
do_ chmod 751 /var/log/sentinel          # el usuario de los señuelos solo puede pasar hasta su carpeta, no listar ni leer
do_ install -d -m 770 -o root -g _sentinel /var/log/sentinel/decoy

# El panel como aplicación, para abrirlo desde el Launchpad o Aplicaciones
APP="/Applications/Sentinel.app/Contents"
do_ mkdir -p "$APP/MacOS"
do_ cp "$AQUI/packaging/macos/Info.plist" "$APP/Info.plist"
do_ cp "$AQUI/packaging/macos/abrir-panel" "$APP/MacOS/Sentinel"
do_ chmod 755 "$APP/MacOS/Sentinel"

# Icono en la barra de menú (viene compilado en el .pkg; desde el código se compila aquí. Si no se puede, Sentinel funciona igual)
BARRA=/Library/LaunchAgents/io.github.saraivaruas.sentinel.barra.plist
HECHO="$AQUI/prebuilt/sentinel-barra"
preparar_barra() {
  if [ -f "$HECHO" ]; then cp "$HECHO" "$DEST/bin/sentinel-barra"
  else xcrun -f swiftc >/dev/null 2>&1 && xcrun swiftc -O -o "$DEST/bin/sentinel-barra" "$AQUI/packaging/macos/barra.swift"; fi
}
if [ "$DRY" = 1 ]; then
  if [ -f "$HECHO" ]; then echo "  [simulación] copiar el icono ya compilado (sentinel-barra) e instalar $BARRA"; else echo "  [simulación] compilar sentinel-barra e instalar $BARRA"; fi
elif preparar_barra; then
  chmod 755 "$DEST/bin/sentinel-barra"
  cp "$AQUI/packaging/macos/barra.plist" "$BARRA"; chown root:wheel "$BARRA"; chmod 644 "$BARRA"
else echo "  Aviso: no pude preparar el icono de la barra de menú (desde el código hacen falta las herramientas de Apple: xcode-select --install)."; fi

paso "3/5 Tareas de launchd"
modulo "servicio.instalar(sys.argv[1])" "$PY"

paso "4/5 Referencia inicial de integridad"
# al reinstalar se acepta la referencia anterior (con PIN, «accept» no vuelve a preguntarlo)
if [ -e /var/lib/sentinel/fim_baseline.json ]; then do_ "$DEST/bin/sentinel" baseline accept; else do_ "$DEST/bin/sentinel" baseline init; fi

paso "5/5 Arrancar"
# el icono aparece ya para quien está usando el equipo (y solo, al iniciar sesión, para los demás)
if [ "$DRY" = 0 ] && [ -e "$BARRA" ] && [ -n "$USUARIO" ]; then
  uid="$(id -u "$USUARIO")"
  launchctl bootout "gui/$uid/io.github.saraivaruas.sentinel.barra" >/dev/null 2>&1 || true
  launchctl bootstrap "gui/$uid" "$BARRA" >/dev/null 2>&1 || echo "  El icono de la barra aparecerá cuando vuelvas a iniciar sesión."
fi
modulo "e = servicio.iniciar(); print(chr(10).join(e)); sys.exit(1 if e else 0)"

echo; echo "Listo. Comprueba con:  sentinel status"
echo "Para ver todos los archivos del sistema, da «Acceso total al disco» a $PY en Ajustes > Privacidad y seguridad."
