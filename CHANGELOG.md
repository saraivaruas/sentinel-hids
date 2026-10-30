# Historial de cambios

El formato sigue [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/) y el versionado [SemVer](https://semver.org/lang/es/).

## [2.1.0] - 2026-10-30

### Agregado
- **Expedientes de atacantes** (SQLite): por cada IP, de dónde viene (país, ciudad, red, empresa), cuántos intentos hizo y de qué tipo, usuarios y puertos probados, paquetes enviados y su historial de bloqueos y liberaciones.
- **Ubicación geográfica** con lector MMDB en Python puro (DB-IP / GeoLite2, offline) y consulta opcional a RIPEstat/RDAP, con caché de 30 días.
- **Captura y análisis de paquetes** propia (AF_PACKET, sin dependencias): escaneos de puertos SYN y UDP, escaneos sigilosos (NULL/FIN/XMAS), inundación SYN y ping masivo, con bloqueo automático.
- **Explicaciones en lenguaje sencillo** («como para un niño») de cada tipo de ataque y de cada tipo de paquete, con semáforo de peligro y recomendaciones.
- Panel: páginas **Atacantes** (con liberar y bloquear) y **Paquetes** (qué es un paquete, glosario, últimos sospechosos). Comandos `sentinel attackers`, `attacker`, `packets` y `bans ban`.

- **Actualizaciones:** el panel detecta cuando hay una versión nueva publicada en GitHub y ofrece instalarla con un botón. Se descarga solo de las publicaciones del repositorio, se exige que la huella SHA-256 coincida y que el paquete sea Sentinel con la versión anunciada; el panel se reinicia solo. `sentinel update [--instalar]`. Desactivable con `[update] check = no`.

### Seguridad
- El lanzador `sentinel` ya no carga código de la carpeta actual ni de `PYTHONPATH` (usa `python -I`). Antes, ejecutar `sudo sentinel` dentro de una carpeta con un paquete falso llamado `sentinel` lo ejecutaba como administrador.

### Corregido
- Los paquetes de la interfaz local (tipo de enlace 772) no se interpretaban.

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
