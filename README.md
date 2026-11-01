# Sentinel — detector de intrusiones para Linux (HIDS)

[![tests](https://github.com/saraivaruas/sentinel-hids/actions/workflows/tests.yml/badge.svg)](https://github.com/saraivaruas/sentinel-hids/actions/workflows/tests.yml)
[![Licencia: MIT](https://img.shields.io/badge/licencia-MIT-green.svg)](LICENSE)
![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue)
![Linux](https://img.shields.io/badge/plataforma-Linux-lightgrey)
![Sin dependencias](https://img.shields.io/badge/dependencias%20de%20Python-0-brightgreen)

**Sentinel** es un **sistema de detección de intrusiones para el equipo (HIDS)** de código abierto para Linux: vigila la **integridad de archivos**, detecta **puertas traseras web (webshells)**, **fuerza bruta**, **escaneo de puertos** y **procesos sospechosos**, tiene **señuelos (honeypots)**, bloquea atacantes de forma temporal y te avisa con **ventanas de alerta** y un **panel gráfico**. Escrito en Python, sin librerías externas. 🇬🇧 [English version](README.en.md).

![Panel de Sentinel](docs/panel-resumen-oscuro.png)

> Reemplaza a «Sentinel-JSR» (v1, scripts de shell). Se instala solo, con sus dependencias, en Ubuntu/Debian, Fedora/RHEL, Arch y openSUSE.

## Firewall (módulo aparte)

Sentinel detecta y avisa; el **módulo Firewall** decide qué puertos quedan abiertos. Se configura en `[firewall]` de `sentinel.conf` (o en el panel, grupo «Firewall») y funciona con **ufw** o **iptables**:

```bash
sentinel firewall plan                      # muestra qué se cerraría y qué se abriría (no cambia nada)
sudo sentinel firewall aplicar              # lo aplica, guardando antes una copia de las reglas
sudo sentinel firewall config allow_tcp 80,443,8443
```

El panel muestra la **exposición real** (incluidos los puertos de Docker, que saltan el firewall), aplica los cambios **a prueba** (si no confirmas en 90 s vuelve atrás solo), permite limitar puertos a ciertos orígenes (`restrict`), elegir un perfil (`profile`) y avisa si alguien cambia las reglas por fuera de Sentinel.

Por defecto solo quedan abiertos el **80 y el 443**, más el puerto de SSH si este equipo sirve SSH. Las conexiones ssh que haces *desde* este equipo hacia otros servidores (despliegues) no se ven afectadas, y no se aplica nada si el tráfico saliente está bloqueado.

## Qué bloquea y qué solo avisa

Sentinel **bloquea direcciones IP, nada más**. Todo lo demás lo detecta y te avisa, pero **no toca tus archivos ni detiene procesos**.

**Bloquea una IP por 24 horas** (con CrowdSec, firewalld, ufw o iptables) cuando:

| Qué hace la IP | Umbral por defecto (configurable) |
|---|---|
| Adivina contraseñas (SSH, sudo, su) | 5 intentos fallidos en 10 minutos (`[auth] fail_threshold`) |
| Escanea puertos | 12 puertos distintos en 60 segundos, visto en el registro del cortafuegos (`[auth] scan_ports`) |
| Escaneo con paquetes (SYN, UDP, sigiloso NULL/FIN/XMAS) | según `[packets]`; necesita la captura de paquetes (root) |
| Inundación de conexiones (SYN flood) o ping masivo | más de 300 intentos o 100 pings en 10 segundos |
| Toca un señuelo | cualquier conexión (solo si activaste los señuelos) |

**Nunca bloquea** tu red local, el equipo mismo (loopback), Tailscale ni lo que pongas en la lista blanca (`[allow] ips`). También puedes bloquear o liberar una IP a mano.

**Solo avisa** (sin bloquear nada):

| Qué detecta | Gravedad típica |
|---|---|
| Archivos del sistema cambiados, nuevos o borrados (`/etc/passwd`, `sudoers`, SSH, cron, servicios, llaves…), permisos abiertos y SUID nuevos | alta / crítica |
| Puertas traseras web (webshells) en `/var/www/html` | crítica |
| Ingreso exitoso después de muchos intentos fallidos, o ingreso remoto como root | crítica / alta |
| Procesos desde `/tmp`, con el ejecutable borrado, mineros de criptomonedas, conexiones a puertos de troyanos | media / crítica |
| Puertos nuevos en escucha, lectores de teclado no esperados, USB nuevos, módulos del kernel, cuentas nuevas o sin contraseña, procesos ocultos | media / crítica |
| Cambios en el firewall hechos por fuera de Sentinel, y puertos que Docker publica saltándose el firewall | media / alta |

**Qué cierra puertos.** Eso no lo hace el detector sino el **módulo Firewall** (ver arriba): deja abiertos solo lo que configures y cierra el resto.

**PIN de protección.** En *Ajustes* puedes registrar un PIN. Con PIN, para detener Sentinel, desinstalarlo, cambiar sus ajustes, ampliar la lista blanca, aceptar cambios de integridad o aplicar cambios al firewall hay que escribirlo (el panel y los comandos lo piden; `apt remove` y `uninstall.sh` también). Se guarda como hash, 5 errores seguidos bloquean 10 minutos y cada intento sin PIN deja una alerta crítica; si alguien ordena detener el servicio sin PIN, **Sentinel sigue vigilando**.

**Límites.** El escaneo de puertos solo se ve si el cortafuegos registra los bloqueos o si la captura de paquetes está activa. Quien ya es root puede apagar cualquier programa a la fuerza (por ejemplo `kill -9`): el PIN cierra las vías normales, avisa y deja rastro, pero no es una barrera absoluta. Si el monitor deja de latir, un temporizador aparte te avisa.

## Novedades de la 2.7

- **«Esto es normal» y modo aprendizaje**: aceptas un aviso con un botón (pide tu PIN) y, al instalar programas nuevos, `sentinel aprender 3` acepta los puertos, USB y módulos nuevos sin avisar durante 3 días. Los ataques nunca se «aceptan».
- **Registros web**: si tienes nginx o apache, Sentinel lee sus registros de acceso (`[weblog]`) y bloquea 24 h a quien ejecuta comandos, inyecta SQL, busca `.env`/`.git`, usa escáneres o prueba contraseñas en tu login.
- **Latido externo** (`[alerts] heartbeat_url`): un servicio como healthchecks.io te avisa si Sentinel deja de latir, aunque lo apaguen a la fuerza.
- **Actualizaciones firmadas**: crea tu clave con `tools/crear-clave-de-publicacion.sh`; los equipos que traen su clave pública solo aceptan publicaciones firmadas.
- **Antivirus y YARA** opcionales, verificación contra el paquete oficial, **horas de silencio**, eventos **resueltos**, **ícono en la barra del sistema** y página **Servidores** para ver otros Sentinel por SSH (solo lectura).

## Qué detecta

| Detector | Qué hace | Gravedad típica |
|---|---|---|
| **Integridad de archivos** | Referencia SHA-256 + permisos + dueño de `/etc/passwd`, `shadow`, `sudoers`, SSH, PAM, cron, servicios, `/usr/local/bin`, llaves `authorized_keys`, etc. Detecta archivos nuevos, modificados, eliminados, enlaces redirigidos, permisos abiertos y **SUID/SGID nuevos**. Vigila en vivo (inotify) carpetas completas, así que detecta el reemplazo de archivos que hacen `useradd` o `vipw`. | alta / crítica |
| **Puertas traseras web** | En carpetas web (`/var/www/html`) revisa los archivos nuevos o modificados contra firmas de webshells y shells inversas, **incluso ofuscadas**: reconstruye texto partido (`'ev'.'al'`), `chr()`, `\x65`, comentarios dentro de palabras y base64/gzip anidados, y puntúa señales de ofuscación. No es infalible ante código hecho a medida. | crítica |
| **Ataques en vivo** | Lee el journal: fuerza bruta SSH/sudo/su, acceso exitoso tras intentos fallidos, root remoto y **escaneo de puertos** (bloqueos del cortafuegos). | alta / crítica |
| **Señuelos** (opcionales) | Puertos falsos (2222, 2323, 3390, 5900, 60009) sin servicio real, en un proceso sin privilegios y aislado. **Vienen apagados** porque abren puertos; se activan desde *Ajustes* o con `sudo sentinel senuelos activar`. Quien se conecta queda registrado y bloqueado. | alta |
| **Sitios web** | Lee los registros de nginx/apache: inyección SQL, ejecución de comandos, `../`, archivos secretos, escáneres, paneles de administración, ráfagas de 404 y fuerza bruta del login. Bloquea la IP. | alta |
| **Equipo** | Puertos nuevos en escucha o que pasan de local a públicos, procesos que corren desde `/tmp`, con el ejecutable borrado o con nombre de minero, conexiones a puertos de troyanos, lectores de teclado no esperados, USB, módulos del kernel, cuentas nuevas, UID 0 duplicado, cuentas sin contraseña, procesos ocultos y SUID nuevos. | media / crítica |
| **Postura** | `sentinel audit`: 16 revisiones de configuración con su arreglo (cortafuegos, SSH, permisos web, parámetros del kernel, actualizaciones, credenciales con permisos abiertos…). | — |

**Respuesta.** Los atacantes se bloquean de forma **temporal** (24 h) con CrowdSec o ufw; nunca la red local, Tailscale ni la lista blanca. A diferencia de la v1, **no detiene procesos ni modifica tus archivos**.
**Avisos.** Registro JSONL privado, journal, aviso en la esquina de la pantalla (y, si lo activas, una ventana grande de alerta) y, opcionalmente, correo o celular (ntfy). No repite el mismo aviso en una hora.

**Avisos de alerta.** Los avisos salen en la **esquina inferior derecha** de tu pantalla y se cierran solos a los pocos segundos (`notify_seconds`, 8 por defecto; las graves 15), así no molestan. Quedan en el historial de notificaciones de tu escritorio. Si prefieres una ventana grande con el botón **Abrir panel**, actívala con `popup_min = high`. Funciona desde el servicio (root) hacia tu sesión gráfica, X11 o Wayland. Prueba con `sentinel test`.

## Expedientes de atacantes y paquetes

Cuando alguien ataca, Sentinel no solo lo bloquea: **abre un expediente** de esa IP y lo explica como si se lo contaras a un niño.

- **De dónde viene:** país, ciudad, empresa y red (archivo local DB-IP o servicios públicos RIPEstat/RDAP; `geo_mode` en `[intel]`; offline = no sale nada de tu equipo).
- **Cuántos intentos hizo y de qué tipo:** adivinar contraseñas, probar usuarios o llaves, escaneo de puertos, escaneo sigiloso, inundación de timbres (SYN flood), ping masivo, caer en un señuelo. Con los usuarios y los puertos que probó.
- **Paquetes:** captura de red propia (sin `tcpdump`, necesita root) que mira solo lo no solicitado —intentos de conexión, paquetes raros, pings— y los clasifica («toc-toc», «portazo», «árbol de Navidad»…). No guarda el contenido, solo quién, a qué puerta y de qué clase.
- **Qué hizo Sentinel:** bloqueo de 24 horas, historial de bloqueos y liberaciones (quién y cuándo). Puedes **liberar** o **bloquear** una IP desde el panel o con `sentinel bans unban|ban IP`.
- **Explicado fácil:** para cada cosa, «qué es», «para qué sirve» y «¿es peligroso?» con semáforo (🟢 🟡 🔴), más una página «Paquetes» con un glosario.

```bash
sentinel attackers                 # lista con riesgo, lugar e intentos
sentinel attacker 203.0.113.9      # expediente completo, explicado fácil (--tecnico: sin explicaciones)
sentinel packets                   # qué es un paquete y los últimos sospechosos
sentinel bans ban 203.0.113.9 --horas 24
```

![Expediente de un atacante](docs/panel-atacantes.png)
![Qué es un paquete](docs/panel-paquetes.png)

La captura de paquetes se verificó con tráfico real en un contenedor (`tools/prueba_captura_real.py`). Se desactiva con `[packets] enabled = no`. Privacidad: en modo en línea la IP del atacante se consulta a RIPEstat/RDAP; los expedientes se guardan 90 días.

## Panel gráfico

Se abre desde el menú de aplicaciones («Sentinel») o con `sentinel ui`, como una ventana de aplicación. Funciona sin internet: es una página local que solo escucha en `127.0.0.1` y exige una llave que se guarda en `~/.config/sentinel/ui_token`.

- **Resumen:** estado de la protección (Protegido, Para revisar, Requiere atención, Posible intrusión), eventos por gravedad, actividad de 24 horas, servicios, IPs más activas y eventos recientes en vivo.
- **Eventos:** historial con filtros por gravedad (con conteo), módulo, período y búsqueda; cada fila se abre para ver sus datos.
- **Bloqueos:** IPs bloqueadas con su tiempo restante y botón para desbloquear; lista blanca.
- **Postura:** puntaje de seguridad del equipo y cada hallazgo con su comando de arreglo (con botón «Copiar»).
- **Ajustes:** activar o apagar los señuelos y configurar los avisos (gravedad mínima, esquina o notificación del sistema, segundos visibles).
- **Firewall (grupo aparte en el menú):** *Puertos* (exposición real, plan, aplicar a prueba con confirmación) y *Reglas y ajustes* (reglas actuales, puertos abiertos, perfiles, orígenes permitidos).
- **Acciones:** escanear ahora, revisión profunda, desbloquear y lista blanca. Las que necesitan administrador piden tu clave con la ventana normal del sistema (`pkexec`); el panel nunca corre como root.
- Tema oscuro y claro, y adaptado a celular/ventanas angostas.

Seguridad del panel: valida `Host` y `Origin` (contra DNS-rebinding y CSRF), CSP estricta, y todo texto de los eventos —que puede venir de un atacante— se muestra como texto, nunca como HTML. Las acciones son una lista cerrada con valores validados. Para verlo con datos de ejemplo sin instalar nada: `python3 tools/demo_datos.py /tmp/demo` y luego `SENTINEL_STATE=/tmp/demo/state SENTINEL_LOG=/tmp/demo/log python3 -m sentinel ui`.

## Instalar (baja e instala todo lo necesario)

Sentinel no usa librerías de Python externas. Lo que sí necesita del sistema (inotify, notificaciones, polkit, un motor de bloqueo…) **se instala solo**. Hay cuatro formas:

**0. Instalador con ventanas (la más cómoda en un escritorio).** Doble clic en `install-gui.sh` (o en «Instalar Sentinel») o `./install-gui.sh`. Salta una ventana de bienvenida, otra para elegir opciones, la **ventana de autorización del sistema** (donde escribes tu clave de administrador), una barra de avance y, al terminar, una ventana de alerta de prueba y la pregunta de si abrir el panel. Si algo falla muestra el detalle; si cancelas la autorización no cambia nada.

**1. Paquete .deb (Ubuntu, Debian, Mint…) — la más simple.** `apt` resuelve y baja las dependencias:

```bash
sudo apt install ./sentinel_2.4.0_all.deb
```

**2. Instalador (Ubuntu/Debian, Fedora/RHEL, Arch, openSUSE).** Detecta la distribución, calcula qué falta, lo instala con `apt`, `dnf`, `pacman` o `zypper`, y después instala Sentinel:

```bash
sudo ./install.sh --dry-run      # primero mira qué haría, sin cambiar nada
sudo ./install.sh                # instala dependencias + Sentinel, retira la v1 (copia en /root/sentinel-v1-respaldo) y arranca
```

**3. Descarga e instalación en un paso**, desde cualquier servidor donde publiques el `.tar.gz` (verifica la huella antes de instalar; sin huella no instala):

```bash
sudo SENTINEL_URL=https://tu-servidor/sentinel-2.0.0.tar.gz SENTINEL_SHA256=<huella> bash get-sentinel.sh
```

Después de instalar: `sentinel status`, `sentinel test` (debería salir una notificación) y `sentinel audit`.

| Paquete | Se instala si falta | Para qué |
|---|---|---|
| python3 (≥ 3.8), systemd, procps, iproute2, util-linux | siempre | base |
| inotify-tools | sí | vigilancia de archivos en vivo |
| libnotify, polkit | sí | avisos de escritorio y acciones del panel con clave |
| logrotate | sí | rotación de registros |
| ufw / firewalld / iptables | solo si no hay ningún motor de bloqueo | bloquear atacantes (se instala, **no** se activa) |
| lynis | sí (donde existe) | informe semanal |
| CrowdSec | no (opcional, [instrucciones oficiales](https://docs.crowdsec.net/)) | bloqueo colaborativo; si está activo, Sentinel lo prefiere |

Motor de bloqueo (`[ban] backend = auto`): CrowdSec → firewalld → ufw (activo) → iptables. Todos con caducidad (24 h).

Opciones del instalador: `--sin-dependencias`, `--sin-limpiar` (no toca la v1).
Desinstalar: `sudo apt purge sentinel` o `sudo ./uninstall.sh` (`--todo` borra también registros y referencias).
Generar la versión (paquete + tarball + huellas): `packaging/make-release.sh` → `dist/`.

## Uso diario

| Comando | Para qué |
|---|---|
| `sentinel status` | servicios, latido, referencia, bloqueos y últimos eventos |
| `sentinel events --min medium --horas 48` | ver eventos |
| `sentinel scan [--deep]` | revisar ahora (código de salida 0 limpio, 1 media, 2 alta o crítica) |
| `sentinel baseline accept [rutas]` | aceptar un cambio legítimo como nueva referencia |
| `sentinel bans` / `sentinel bans unban IP` | ver o quitar bloqueos |
| `sentinel allow ip 203.0.113.7` | lista blanca (`ip`, `proc`, `port`, `path`) |
| `sentinel audit` | postura de seguridad |
| `sentinel ui` | abre el panel gráfico |
| `sentinel report --lynis` | informe HTML (semanal, automático) con el índice de Lynis |

Configuración: `/etc/sentinel/sentinel.conf` (parte de `etc/sentinel.conf.example`). Registros: `/var/log/sentinel/`.

## Cómo está armado

```
sentinel-monitor (root)  ── vigilancia en vivo de archivos (inotify) · journal · señuelos · revisión del equipo cada 5 min · latido
sentinel-honeypot (usuario «sentinel», aislado)  ── puertos señuelo; solo escribe su registro
sentinel-scan.timer      ── revisión cada 30 min y aviso si el monitor deja de latir
sentinel-report.timer    ── informe y Lynis cada lunes
```

## Pruebas

```bash
cd tests && python3 -m unittest discover -s .     # 100 pruebas, ~12 s, sin permisos de administrador
```

Incluyen los dos fallos de la v1: el reemplazo de archivos por renombre y la extracción de la IP del atacante.

## Límites (lo que Sentinel no es)

- No es un antivirus: detecta cambios y comportamientos sospechosos, no analiza malware por firmas completas.
- Un atacante que ya tiene **root** puede detenerlo o alterar sus referencias. Sentinel lo hace más difícil (programa y referencias son de root, latido vigilado, vigila su propio directorio) y lo avisa si queda mudo, pero para ese caso hace falta además un registro remoto (correo/ntfy) o un monitoreo externo.
- La referencia de integridad se crea al instalar: instálalo en un equipo que consideres limpio.
- Las firmas de puertas traseras cubren patrones comunes, no ofuscación avanzada.

## Contribuir

Es código abierto (MIT) y las mejoras son bienvenidas, pero **todo cambio entra mediante un Pull Request** revisado por el mantenedor: nadie escribe directamente en `main`. Lee [CONTRIBUTING.md](CONTRIBUTING.md). Las vulnerabilidades se reportan en privado: [SECURITY.md](SECURITY.md).

## Licencia

[MIT](LICENSE) © 2026 Jorge Luis Saraiva Ruas.

<sub>Palabras clave: HIDS, detección de intrusiones, intrusion detection, monitoreo de integridad de archivos, file integrity monitoring, FIM, detector de webshells, honeypot, fuerza bruta SSH, escaneo de puertos, seguridad Linux, blue team, CrowdSec, ufw, firewalld, systemd, panel de seguridad.</sub>
