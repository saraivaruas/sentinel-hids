# Sentinel v2

Detector de intrusiones y de cambios para Linux (estaciones de trabajo y servidores). Reemplaza a Sentinel-JSR v1.
Escrito en Python con la biblioteca estándar: no instala dependencias nuevas. Se apoya en lo que ya hay (systemd, CrowdSec o ufw, inotify, journal).

## Qué detecta

| Detector | Qué hace | Gravedad típica |
|---|---|---|
| **Integridad de archivos** | Referencia SHA-256 + permisos + dueño de `/etc/passwd`, `shadow`, `sudoers`, SSH, PAM, cron, servicios, `/usr/local/bin`, llaves `authorized_keys`, etc. Detecta archivos nuevos, modificados, eliminados, enlaces redirigidos, permisos abiertos y **SUID/SGID nuevos**. Vigila en vivo (inotify) carpetas completas, así que detecta el reemplazo de archivos que hacen `useradd` o `vipw`. | alta / crítica |
| **Puertas traseras web** | En carpetas web (`/var/www/html`) revisa los archivos nuevos o modificados contra firmas de webshells y shells inversas (`eval(base64_decode(...))`, `system($_POST...)`, `/dev/tcp/...`, `curl \| sh`). | crítica |
| **Ataques en vivo** | Lee el journal: fuerza bruta SSH/sudo/su, acceso exitoso tras intentos fallidos, root remoto y **escaneo de puertos** (bloqueos del cortafuegos). | alta / crítica |
| **Señuelos** | Puertos falsos (2222, 2323, 3390, 5900, 60009) sin servicio real, en un proceso sin privilegios y aislado. Quien se conecta queda registrado y bloqueado. | alta |
| **Equipo** | Puertos nuevos en escucha o que pasan de local a públicos, procesos que corren desde `/tmp`, con el ejecutable borrado o con nombre de minero, conexiones a puertos de troyanos, lectores de teclado no esperados, USB, módulos del kernel, cuentas nuevas, UID 0 duplicado, cuentas sin contraseña, procesos ocultos y SUID nuevos. | media / crítica |
| **Postura** | `sentinel audit`: 16 revisiones de configuración con su arreglo (cortafuegos, SSH, permisos web, parámetros del kernel, actualizaciones, credenciales con permisos abiertos…). | — |

**Respuesta.** Los atacantes se bloquean de forma **temporal** (24 h) con CrowdSec o ufw; nunca la red local, Tailscale ni la lista blanca. A diferencia de la v1, **no detiene procesos ni modifica tus archivos**.
**Avisos.** Registro JSONL privado, journal, notificación de escritorio y, opcionalmente, correo o celular (ntfy). No repite el mismo aviso en una hora.

## Panel gráfico

![Panel de Sentinel](docs/panel-resumen-oscuro.png)

Se abre desde el menú de aplicaciones («Sentinel») o con `sentinel ui`, como una ventana de aplicación. Funciona sin internet: es una página local que solo escucha en `127.0.0.1` y exige una llave que se guarda en `~/.config/sentinel/ui_token`.

- **Resumen:** estado de la protección (Protegido, Para revisar, Requiere atención, Posible intrusión), eventos por gravedad, actividad de 24 horas, servicios, IPs más activas y eventos recientes en vivo.
- **Eventos:** historial con filtros por gravedad, período y búsqueda; cada fila se abre para ver sus datos.
- **Bloqueos:** IPs bloqueadas con su tiempo restante y botón para desbloquear; lista blanca.
- **Postura:** puntaje de seguridad del equipo y cada hallazgo con su comando de arreglo (con botón «Copiar»).
- **Acciones:** escanear ahora, revisión profunda, desbloquear y lista blanca. Las que necesitan administrador piden tu clave con la ventana normal del sistema (`pkexec`); el panel nunca corre como root.
- Tema oscuro y claro, y adaptado a celular/ventanas angostas.

Seguridad del panel: valida `Host` y `Origin` (contra DNS-rebinding y CSRF), CSP estricta, y todo texto de los eventos —que puede venir de un atacante— se muestra como texto, nunca como HTML. Las acciones son una lista cerrada con valores validados. Para verlo con datos de ejemplo sin instalar nada: `python3 tools/demo_datos.py /tmp/demo` y luego `SENTINEL_STATE=/tmp/demo/state SENTINEL_LOG=/tmp/demo/log python3 -m sentinel ui`.

## Instalar

```bash
sudo ./install.sh --dry-run      # primero mira qué haría, sin cambiar nada
sudo ./install.sh                # instala, retira la v1 (con copia en /root/sentinel-v1-respaldo) y arranca
sentinel status
sentinel test                    # comprueba que las alertas llegan (debería salir una notificación)
sentinel audit                   # revisión de postura con el arreglo de cada hallazgo
```

Opciones: `--sin-limpiar` (no toca la v1), `--exponer-senuelos` (abre los puertos señuelo hacia Internet; por defecto quedan cerrados y el escaneo externo se detecta igual con el cortafuegos).
Desinstalar: `sudo ./uninstall.sh` (`--todo` borra también registros y referencias).

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
cd tests && python3 -m unittest discover -s .     # 49 pruebas, ~6 s, sin permisos de administrador
```

Incluyen los dos fallos de la v1: el reemplazo de archivos por renombre y la extracción de la IP del atacante.

## Límites (lo que Sentinel no es)

- No es un antivirus: detecta cambios y comportamientos sospechosos, no analiza malware por firmas completas.
- Un atacante que ya tiene **root** puede detenerlo o alterar sus referencias. Sentinel lo hace más difícil (programa y referencias son de root, latido vigilado, vigila su propio directorio) y lo avisa si queda mudo, pero para ese caso hace falta además un registro remoto (correo/ntfy) o un monitoreo externo.
- La referencia de integridad se crea al instalar: instálalo en un equipo que consideres limpio.
- Las firmas de puertas traseras cubren patrones comunes, no ofuscación avanzada.
