#!/usr/bin/env bash
# Construye dist/sentinel_<versión>_all.deb. El paquete declara sus dependencias: «apt install ./sentinel_*.deb» las baja e instala solas.
set -euo pipefail
AQUI="$(cd "$(dirname "$0")/.." && pwd)"
VER="$(python3 -c "import sys;sys.path.insert(0,'$AQUI');from sentinel import core;print(core.VERSION)")"
OUT="${SENTINEL_DIST:-$AQUI/dist}"; T="$(mktemp -d)"; P="$T/pkg"
trap 'rm -rf "$T"' EXIT
mkdir -p "$OUT" "$P/DEBIAN" "$P/opt/sentinel" "$P/usr/bin" "$P/lib/systemd/system" "$P/usr/share/applications" "$P/usr/share/icons/hicolor/scalable/apps" "$P/etc/sentinel" "$P/etc/logrotate.d" "$P/usr/share/doc/sentinel"

cp -a "$AQUI/sentinel" "$AQUI/bin" "$AQUI/README.md" "$P/opt/sentinel/"
find "$P/opt/sentinel" -name __pycache__ -prune -exec rm -rf {} +
ln -s /opt/sentinel/bin/sentinel "$P/usr/bin/sentinel"
cp "$AQUI"/systemd/*.service "$AQUI"/systemd/*.timer "$P/lib/systemd/system/"
install -m 644 "$AQUI/desktop/sentinel.desktop" "$P/usr/share/applications/sentinel.desktop"
install -m 644 "$AQUI/sentinel/ui/icon.svg" "$P/usr/share/icons/hicolor/scalable/apps/sentinel.svg"
sed 's/^desktop_user = .*/desktop_user =/' "$AQUI/etc/sentinel.conf.example" > "$P/etc/sentinel/sentinel.conf"
cat > "$P/etc/logrotate.d/sentinel" <<'EOF'
/var/log/sentinel/events.jsonl /var/log/sentinel/decoy/honeypot.jsonl {
    weekly
    rotate 8
    compress
    missingok
    notifempty
    copytruncate
}
EOF
cp "$AQUI/README.md" "$P/usr/share/doc/sentinel/README.md"
cp "$AQUI/LICENSE" "$P/usr/share/doc/sentinel/copyright"
install -m 755 "$AQUI/packaging/debian/postinst" "$AQUI/packaging/debian/prerm" "$AQUI/packaging/debian/postrm" "$P/DEBIAN/"
echo /etc/sentinel/sentinel.conf > "$P/DEBIAN/conffiles"
find "$P" -type d -exec chmod 755 {} +; find "$P" -type f ! -path "*/DEBIAN/*" ! -perm -u+x -exec chmod 644 {} +; find "$P/opt/sentinel" -type f -exec chmod go-w,a+r {} +; chmod 755 "$P/opt/sentinel/bin/sentinel"
SIZE=$(du -sk "$P" | cut -f1)
cat > "$P/DEBIAN/control" <<EOF
Package: sentinel
Version: $VER
Section: admin
Priority: optional
Architecture: all
Installed-Size: $SIZE
Maintainer: Jorge Luis Saraiva Ruas <28052181+saraivaruas@users.noreply.github.com>
Depends: python3 (>= 3.8), systemd, procps, iproute2, util-linux, coreutils
Recommends: inotify-tools, libnotify-bin, policykit-1 | polkitd, logrotate, ufw | firewalld | iptables
Suggests: crowdsec, crowdsec-firewall-bouncer-iptables, lynis, mailutils
Description: Sentinel: detector de intrusiones y cambios para Linux
 Vigila la integridad de archivos críticos, detecta puertas traseras web,
 fuerza bruta, escaneos de puertos y procesos sospechosos, tiene puertos
 señuelo y un panel gráfico local. Bloquea atacantes de forma temporal con
 CrowdSec, firewalld, ufw o iptables. Sin dependencias de Python externas.
EOF
fakeroot dpkg-deb --build --root-owner-group "$P" "$OUT/sentinel_${VER}_all.deb" >/dev/null
echo "$OUT/sentinel_${VER}_all.deb"
