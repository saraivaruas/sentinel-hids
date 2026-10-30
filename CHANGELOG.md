# Historial de cambios

El formato sigue [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/) y el versionado [SemVer](https://semver.org/lang/es/).

## [2.0.0] - 2026-10-30

Reescritura completa de Sentinel-JSR (v1).

### Agregado
- Vigilante de integridad de archivos con referencia SHA-256, permisos y dueño; vigilancia en vivo (inotify) y detección de SUID/SGID nuevos.
- Detección de puertas traseras web y shells inversas en carpetas de aplicaciones.
- Detección en vivo desde el journal: fuerza bruta (SSH, sudo, su), acceso exitoso tras ataque y escaneo de puertos.
- Puertos señuelo en un proceso aislado y sin privilegios.
- Detectores del equipo: puertos nuevos, procesos desde carpetas temporales, binarios borrados, mineros, lectores de teclado, USB, módulos del kernel, cuentas y procesos ocultos.
- Auditoría de postura con 16 revisiones y su comando de arreglo.
- Panel gráfico local (tema oscuro y claro) y ventanas emergentes de alerta.
- Bloqueo temporal con CrowdSec, firewalld, ufw o iptables.
- Instalación automática de dependencias (apt, dnf, pacman, zypper), instalador con ventanas, paquete `.deb` y descarga verificada por SHA-256.

### Corregido respecto a la v1
- El reemplazo de archivos críticos por renombre (como hacen `useradd` y `vipw`) ya se detecta.
- La IP del atacante se extraía mal y el bloqueo nunca se aplicaba.
- El arranque dependía de un `/etc/rc.local` inexistente; ahora usa systemd.
