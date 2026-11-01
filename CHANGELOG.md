# Historial de cambios

El formato sigue [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/) y el versionado [SemVer](https://semver.org/lang/es/).

## [2.5.1] - 2026-11-01

### Corregido
- Si se instala una versión nueva con `apt` o el instalador mientras el panel está abierto, el panel **se reinicia solo** con el código nuevo (antes seguía con el viejo y rechazaba las acciones nuevas, como guardar el PIN).

## [2.5.0] - 2026-11-01

### Agregado
- **PIN de protección** (se configura en *Ajustes*): sin él no se puede detener Sentinel (`sentinel detener`, `systemctl stop`), desinstalarlo (`apt remove`, `uninstall.sh`), cambiar ajustes, ampliar la lista blanca, aceptar cambios de integridad, liberar IPs ni aplicar cambios al firewall. Se guarda como hash PBKDF2-SHA256 con sal; 5 errores seguidos bloquean 10 minutos; cada intento deja una alerta. Si alguien ordena detener el servicio sin PIN, el monitor **sigue vigilando** y lanza una alerta crítica. Límite: quien ya es root puede apagar cualquier programa a la fuerza (`kill -9`); el PIN cierra las vías normales y deja rastro.
- **Detección de puertas traseras con desofuscación**: reconstruye texto partido (`'ev'.'al'`), `chr()`, `\x65`, comentarios dentro de palabras y base64/gzip anidados antes de buscar firmas, detecta funciones elegidas por la petición, `preg_replace /e`, decodificadores anidados y puntúa señales de ofuscación. Probado sin falsos positivos sobre 4000 archivos PHP reales.
- Política de polkit (`org.sentinel.policy`) para que el sistema recuerde la clave unos minutos.

### Cambiado
- Menos contraseñas: guardar los ajustes del firewall pide la clave una sola vez (antes una por ajuste), el plan se actualiza solo y se quitó el botón «Actualizar (pide clave)».

## [2.4.0] - 2026-11-01

### Agregado
- **Aviso en la esquina inferior derecha** (propio, con GTK): aparece unos segundos y se cierra solo, y un aviso nuevo reemplaza al anterior. Si no hay GTK, se usa la notificación normal del escritorio. Se elige con `notify_style`.
- Panel: página **Ajustes** para activar o apagar los señuelos y configurar los avisos (gravedad mínima, dónde aparecen, segundos visibles, ventana grande).
- Eventos: los filtros de gravedad muestran cuántos eventos hay en cada nivel, se filtran al instante y hay un selector de **módulo**.

### Corregido
- Los cambios en los servicios de Sentinel (`/etc/systemd/system/sentinel-*`, enlaces `*.wants`) durante su propia actualización salían como eventos de gravedad alta; ahora quedan informativos.

## [2.3.0] - 2026-11-01

### Agregado
- **Exposición real** en el módulo Firewall: cruza lo que escucha el equipo con lo que permite el firewall y dice, puerto por puerto, si se alcanza desde afuera, con el programa y un consejo (por ejemplo, hacer que un servicio escuche solo en 127.0.0.1).
- **Detección de Docker**: los puertos que publica Docker en todas las interfaces saltan el firewall; ahora se detectan, se marcan como lo más grave y se avisa cuando aparece uno nuevo.
- **Aplicar a prueba con reversión automática**: el panel aplica el plan con 90 s para confirmar; si no confirmas, el firewall vuelve solo a como estaba (`sentinel firewall aplicar --probar 90`, `confirmar`, `restaurar`).
- **Puertos limitados por origen** (`restrict = 22=100.64.0.0/10|203.0.113.7`), **perfiles listos** (estación, web, servidor) y **límite de intentos al SSH** (`ssh_limit`, ufw limit).
- **Aviso de cambios externos**: si alguien agrega o quita reglas del firewall sin pasar por Sentinel, se registra un evento (alto si abre un puerto a cualquiera).

## [2.2.0] - 2026-11-01

### Cambiado
- **Avisos menos molestos**: las alertas salen como notificación en la esquina de la pantalla y se cierran solas (8 s; las graves 15 s, configurable con `notify_seconds`). La ventana grande ya no aparece por defecto (`popup_min = never`; se puede activar).

### Agregado
- **Módulo Firewall**, separado de la detección: deja abiertos desde afuera solo los puertos que configures (por defecto 80 y 443) y cierra el resto, con **ufw** o **iptables** (`sentinel firewall estado|plan|aplicar|config`). Mantiene el puerto de SSH si el equipo sirve SSH (tus conexiones ssh de despliegue hacia otros servidores son salientes y no se tocan), nunca cierra nada si el tráfico saliente no está permitido y guarda una copia de las reglas antes de cambiar.
- El panel del firewall se recarga solo cada 5 s, muestra la antigüedad de la información (en rojo si pasa de 3 min), tiene botón **↻ Recargar** y el monitor lee el firewall cada 60 s (`refresh_seconds`).
- Panel: menú lateral en dos grupos, **Sentinel · detección** y **Firewall · puertos** (páginas *Puertos* y *Reglas y ajustes*, con plan, aplicar y configuración).

### Seguridad
- **Sentinel ya no abre puertos**: se eliminó la opción `--exponer-senuelos` y la regla de cortafuegos que permitía los puertos señuelo. La instalación y la actualización apagan los señuelos y borran las reglas `sentinel-senuelo` que dejaron versiones anteriores.

## [2.1.1] - 2026-10-30

### Seguridad
- **Los señuelos (honeypot) ya no se activan solos**: la instalación no abre ningún puerto nuevo. Se activan a propósito con `sudo systemctl enable --now sentinel-honeypot` o `./install.sh --exponer-senuelos`. Si ya estaban activos, la actualización no los toca.

### Corregido
- Los cambios en los archivos de Sentinel durante su propia actualización ya no se muestran como alertas (quedan como informativos) y la nueva versión se acepta como referencia de integridad.
- El panel no podía leer `events.jsonl` creado por versiones anteriores (dueño `root:root`) y mostraba la lista de eventos vacía; ahora se corrige el grupo `adm` al escribir y al actualizar el paquete.

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
