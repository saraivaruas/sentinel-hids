# Historial de cambios

El formato sigue [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/) y el versionado [SemVer](https://semver.org/lang/es/).

## [Sin publicar]

### Agregado
- **Auditoría en macOS:** revisa cortafuegos, SIP, FileVault, Gatekeeper, actualizaciones automáticas, SSH, credenciales y Sentinel; antes puntuaba el Mac con comprobaciones de Linux. Lo que no se puede determinar no se da por bueno. 3 pruebas nuevas.
- Las pruebas del panel de endurecimiento simulan Linux, que es lo que comprueban, también en la CI de Mac.
- **Endurecimiento en macOS:** las medidas son de Linux, así que ya no se evalúan ni se aplican en un Mac; la línea de comandos y el panel lo dicen y remiten a la auditoría. 1 prueba nueva.
- **Actualizar en macOS** descarga y verifica el paquete y ejecuta `install-mac.sh` (antes habría ejecutado el instalador de Linux). Las publicaciones anteriores no lo traen: en ese caso lo dice y no instala nada. 2 pruebas nuevas.
- La prueba en simulación del instalador de macOS ya no depende de si el equipo que la corre tiene Sentinel instalado.
- La prueba del instalador en macOS comprueba que con PIN no se reinstala ni desinstala sin escribirlo, y que una actualización autorizada sí termina.
- **Reinstalar o actualizar en macOS con PIN** ya no pide el PIN varias veces ni se queda a medias sin terminal: se comprueba una vez, se detiene el servicio y la referencia anterior se conserva con `baseline accept`.
- La prueba del instalador en macOS abre además cada página del panel, pulsa «Revisar ahora», envía una notificación y comprueba requisitos y alertas de prueba.
- En macOS el instalador deja **Sentinel** en Aplicaciones (abre el panel) y el desinstalador lo quita. 1 prueba nueva.
- **Los botones del panel funcionan en macOS:** en vez de `pkexec` (que no existe allí) usan `sudo` con una ventana de contraseña del sistema; el PIN sigue viajando por la entrada estándar. 4 pruebas nuevas.
- **Avisos en pantalla en macOS:** las alertas salen como notificaciones del sistema en la sesión de quien usa el equipo (antes no aparecía nada). El texto de la alerta viaja como dato, nunca dentro del guion, para que un atacante no pueda ejecutar nada. 2 pruebas nuevas.
- Las pruebas del horario del informe y de `status` simulan `systemd`; en la CI de Mac fallaban desde que existe el manejo con `launchd`.
- La prueba de «no reponer lo liberado» dependía de que el equipo tuviera `pfctl` y fallaba en Debian 12; ahora lo simula.
- **Panel, Ajustes → «Privacidad de red»:** muestra la MAC, la IP y si se envía el nombre; permite activar o apagar el cambio programado, elegir el intervalo, cambiar ahora y volver a la MAC de fábrica, con confirmación, PIN y clave de administrador. Si otro programa ya cambia la MAC, no deja activarlo y dice cuál. 4 pruebas nuevas.
- **Cambio programado de MAC e IP (Linux), apagado por defecto:** `sudo sentinel identidad activar --cada 2` y `desactivar`, con un temporizador de systemd. El primer cambio llega al cumplirse el intervalo y no se activa si otro programa ya cambia la MAC o la IP. Piden el PIN. 7 pruebas nuevas.
- **`sentinel requisitos` en macOS** comprueba `launchd`, el registro del sistema, `lsof`, `pf` y `ssh-keygen`; antes pedía instalar `systemd`, `iproute2` y otras piezas de Linux. 1 prueba nueva.
- **Informe del equipo en macOS:** usa `lsof`, `ps` y el registro del sistema para puertos, conexiones, accesos fallidos, shells reversas, túneles, cuentas, dueños y persistencia. Antes inventaba una conexión a partir de un error y daba por revisados paquetes, accesos y actualizaciones que no había mirado: lo que no se revisa en Mac ahora lo dice. 4 pruebas nuevas.
- **Detener e iniciar en macOS:** `launchd` responde antes de terminar, así que `sentinel iniciar` justo después de `detener` no hacía nada y el desinstalador fallaba al borrar carpetas en uso. Ahora se espera a que el servicio termine. Encontrado con la prueba real. 2 pruebas nuevas.
- **`sudo sentinel identidad rotar` y `restaurar` (Linux):** MAC aleatoria a través de NetworkManager e IP nueva por DHCP, sin enviar el nombre del equipo. Si no llega una IP o la puerta de salida deja de responder, vuelve sola a lo anterior; `restaurar` regresa a la MAC de fábrica y a los ajustes originales. Piden el PIN. 7 pruebas nuevas (con una red simulada).
- **`sentinel identidad estado` (Linux):** muestra la MAC en uso y la de fábrica, la IP, si se envía el nombre del equipo a la red y si otros programas ya cambian la MAC o la IP. Solo lee. 5 pruebas nuevas.
- **Hoja de ruta de privacidad de red:** rotación de MAC e IP dentro de Sentinel (fase 1) y modo discreto para anunciarse lo menos posible (fase 2), con sus límites.
- **Prueba real del instalador (`mac-instalar`):** en los cuatro equipos instala, comprueba que el servicio vigila y alerta, que revive si lo matan, que `detener`/`iniciar` y las tareas programadas funcionan, reinstala encima y desinstala sin dejar restos.
- **Instalador para macOS (`sudo ./install-mac.sh`) y desinstalador (`uninstall-mac.sh`):** instala en `/opt/sentinel`, escribe una configuración propia de Mac, programa las tareas, crea la referencia de integridad y arranca; respeta el PIN y rota los registros. 2 pruebas nuevas.
- El comando `sentinel` usa el Python que el instalador de macOS anota (uno que un usuario corriente no pueda cambiar), en vez del primero del PATH. En Linux no cambia nada. 1 prueba nueva.
- **Parada con PIN en macOS:** `launchd` no deja distinguir un apagado de una orden de detener ni negarse a ella, así que Sentinel avisa (gravedad alta) y sale, en vez de insistir y registrar un «intento de detener» crítico en cada reinicio. Es una protección más débil que en Linux. 1 prueba nueva.
- **`status`, `detener`, `iniciar`, el panel y el horario del informe funcionan en macOS** con `launchd`; antes mostraban errores de `systemctl`. Los señuelos figuran como no disponibles. En Linux no cambia nada. 2 pruebas nuevas.
- **Servicios en macOS (`launchd`):** definición de las cuatro tareas (monitor siempre encendido, revisión cada 30 minutos, informe semanal e informe del equipo) y cómo cargarlas, consultarlas y detenerlas. Python corre aislado y sin carpetas modificables por usuarios en el PATH. 5 pruebas nuevas.
- **Falsa alerta del agente SSH:** las versiones recientes de OpenSSH (la de macOS 26, y las nuevas de Linux) crean sockets en `~/.ssh/agent` en cada sesión y salían como alerta ALTA. Se ignoran la carpeta y los sockets; cualquier archivo que aparezca dentro se sigue avisando. 1 prueba nueva.
- **Prueba del monitor completo en macOS (`mac-monitor`):** lo arranca como administrador con las rutas reales, crea un programa de arranque, provoca accesos fallidos, ejecuta los comandos principales y exige que no haya errores.
- En macOS los registros y el estado quedan legibles para el grupo `admin` (allí no existe `adm`), para que el panel pueda leerlos. 1 prueba nueva.
- **Valores por defecto de macOS:** se vigilan sus rutas críticas (`/private/etc`, `LaunchDaemons`, `LaunchAgents`, tareas programadas, `/Users/*/.ssh`…), sus carpetas y registros web (Apache y Homebrew), y el señuelo ya no usa el 5900 («Compartir pantalla»). Lo que escribas en `sentinel.conf` sigue mandando. 1 prueba nueva.
- En macOS la página del cortafuegos explica que todavía no se administra (y que el bloqueo con `pf` sí funciona) en vez de pedir `ufw` o `iptables`. 1 prueba nueva.
- **Prueba real del bloqueo en macOS (`mac-bloqueo`):** conexiones IPv4 e IPv6 de verdad que deben cortarse al bloquear, seguir para las demás direcciones y volver al liberar o caducar.
- **Los bloqueos sobreviven a un reinicio en macOS:** el sistema olvida las reglas de `pf` al apagarse, así que el monitor repone los bloqueos vigentes (respetando los que liberaste desde la terminal). 2 pruebas nuevas.
- **Bloqueo de IP en macOS con `pf`:** Sentinel bloquea y libera atacantes en un ancla propia (`com.apple/sentinel`) sin tocar `/etc/pf.conf`, y corta las conexiones que la IP ya tenía abiertas. Si las reglas del equipo no incluyen esa ancla, avisa en lugar de fingir que bloqueó. 4 pruebas nuevas.
- La hoja de ruta marca como hecha la detección de fuerza bruta en macOS, probada en equipos reales de GitHub.
- **Prueba real de la fuerza bruta en macOS:** `mac-registro` deja de solo capturar muestras: en macOS 26 y 15 (Apple Silicon e Intel) provoca accesos fallidos de SSH, `sudo` y `su` mientras el detector de Sentinel escucha, y falla si no salen las alertas.
- **Fuerza bruta en macOS:** el detector de accesos lee el registro unificado (`log stream`) en lugar del journal: SSH (fuerza bruta, acceso tras intentos fallidos, root remoto), `sudo` y `su`. Solo acepta mensajes escritos por los programas del sistema (por su ruta completa), para que otro programa no pueda inventar ataques y provocar bloqueos. En Linux no cambia nada. 2 pruebas nuevas.
- **`su` fallido en macOS:** se reconoce el aviso «BAD SU» y se alerta igual que en Linux. 1 prueba nueva.
- La tarea `mac-registro` falla la clave de `sudo` con un usuario administrador y la de `su` con terminal, para ver lo que anota cada uno.
- La tarea `mac-registro` ya no se corta en el primer acceso fallido (era justo lo que debía provocar) y comprueba la clave del usuario de prueba.
- **Muestras reales del registro de macOS:** una tarea aparte de la CI (`mac-registro`) provoca accesos fallidos de SSH, sudo y su en macOS 26 y 15 y muestra lo que anota el sistema, para escribir el detector de fuerza bruta sobre datos reales.
- **Hoja de ruta (`ROADMAP.md`):** estado del porte a macOS, lo que falta por orden de importancia y cómo se prueba.
- **Inicio del porte a macOS:** la CI corre ahora las pruebas también en macOS (macOS 26 Tahoe y macOS 15 Sequoia, cada uno en Apple Silicon e Intel; Python 3.12, y 3.10 en Tahoe). macOS 14 y 13 ya no existen en GitHub Actions. Es informativo (`continue-on-error`) y no bloquea el resto: sirve para ver qué módulos dependen de Linux antes de reescribirlos.

- **Módulo `plataforma`:** un solo lugar donde se decide si el equipo es Linux o macOS y si existe `/proc`; los detectores preguntan ahí en vez de mirar el sistema por su cuenta. 3 pruebas nuevas.
- **Procesos sospechosos en macOS:** sin `/proc`, `hostcheck` lee los procesos con `ps` y sigue detectando mineros y programas que corren desde carpetas temporales (comparando `/tmp` con `/private/tmp`). El «ejecutable borrado» se queda solo en Linux, porque macOS no lo informa.
- **Archivos SUID en macOS:** el `find` de macOS no entiende `-perm /6000`, así que allí la búsqueda se hace en Python (mismas exclusiones: `node_modules`, `.git`, cachés, contenedores; no cruza de disco). Carpetas por defecto de Mac: `/usr`, `/bin`, `/sbin`, `/opt`, `/etc`, `/private/tmp`, `/Users`. 1 prueba nueva.
- **Puertos y conexiones en macOS:** `ss` no existe allí; se usa `lsof` y su salida se convierte al formato de `ss`, de modo que las alertas de puerto nuevo, puerto expuesto y conexión a puertos de troyanos funcionan igual. En macOS el monitor necesita correr como administrador para ver todos los procesos. 3 pruebas nuevas (con muestras escritas a mano; falta contrastarlas con un Mac real).
- **Cuentas en macOS:** se leen con `pwd` (el servicio de directorio) y siguen avisando de cuentas nuevas con acceso y de un segundo usuario con UID 0. «Cuenta sin contraseña» no se revisa en Mac (no hay `/etc/shadow`). 2 pruebas nuevas.
- **La revisión del equipo ya no se cae en macOS:** las revisiones que dependen de `/proc` (lectores de teclado y procesos ocultos, solo Linux) quedan desactivadas en Mac en lugar de fallar. USB y módulos del kernel todavía no se vigilan en Mac. 1 prueba nueva.
- Las pruebas del estado de la captura de paquetes simulan `AF_PACKET` y corren también en macOS. La captura real en Mac (con BPF) queda pendiente: hoy el panel la mostrará como no disponible.
- Las pruebas del instalador gráfico (`install-gui.sh`, con zenity y pkexec) se omiten en macOS: es el instalador de Linux. El de Mac (`.pkg` y `launchd`) queda pendiente.
- Las pruebas de falsos positivos de procesos simulan `/proc`, así que prueban la clasificación (binario borrado, reinicio pendiente, Sentinel no se reporta a sí mismo) igual en Linux y en macOS. En la CI de Mac, de las 8 pruebas que fallaban solo quedaban estas 3.
- **Sondeo de cambios para la vigilancia en vivo de macOS (`fim.cambios_rapidos`):** compara solo metadatos (tipo, permisos, dueño, tamaño, fecha, inodo) entre dos pasadas, sin leer ni calcular hashes, y respeta las exclusiones. En las carpetas ignora fecha y tamaño (cambian con cada archivo que entra o sale, aunque esté excluido, y provocarían revisiones de más). Es la base de la vigilancia en vivo sin `inotifywait`. 2 pruebas nuevas.
- **Vigilancia de archivos en vivo en macOS:** sin `inotifywait`, el monitor revisa cada 10 segundos (`[fim] poll_seconds`) qué archivos vigilados cambiaron y manda a comprobar solo esos, en vez de esperar la revisión periódica de 15 minutos. En Linux no cambia nada. 3 pruebas nuevas.

## [2.11.2] - 2026-11-16

### Corregido
- **Falso positivo de «shell reversa»:** un script que solo usa `/dev/tcp/127.0.0.1/...` (o `localhost`/`::1`) para esperar a un servicio local, como el que usa el bouncer de CrowdSec, ya no se marca como ALTO. Si el mismo comando trae un destino externo o un patrón clásico (`bash -i >`, `nc -e`, `socat exec`…), sigue alertando.
- Cuando sí alerta, el informe local ahora incluye el comando (recortado a 140 caracteres) para poder investigar sin abrir `/proc`. El correo no cambia. 2 pruebas nuevas.

## [2.11.1] - 2026-11-14

### Agregado
- **El informe del equipo revisa los dueños de lo crítico:** carpetas y archivos del sistema (`/var/lib/dpkg`, `/var/lib/apt`, `/etc/sudoers.d`, `/usr/bin`…) que no sean de root, o que cualquiera pueda escribir sin «sticky», salen como **ALTO**. Caso real que lo motivó: un `chown -R` equivocado dejó `/var` y dpkg/apt en manos de un usuario, que así podía llegar a root en la siguiente actualización. 4 pruebas nuevas.

## [2.11.0] - 2026-11-14

### Agregado
- **Página «Endurecimiento» en el panel:** cada medida con ✔/○/✖, qué hace, para qué sirve, riesgo y estado actual; eliges cuáles aplicar (perfil básico / recomendado / estricto), se confirma, pide administrador y PIN, y hay botón «Deshacer la última tanda».
- **Página «Primeros pasos»:** lista de lo que está listo y lo que falta (requisitos, PIN, correo, endurecimiento, IA) con un botón «Ir» a cada lugar; se abre sola la primera vez si falta algo y deja un aviso numérico en el menú.

- **Paquetes para las tiendas, probados en la CI:** AppStream (Centro de Software), repositorio APT firmado (`tools/crear-repo-apt.sh`, verificado con `apt` real, rechaza una firma alterada), Snap *classic* (`snap/`), Flatpak solo-panel en modo lectura (`packaging/flatpak/`) y la guía `packaging/PUBLICAR.md`. La CI instala, actualiza, quita y purga el `.deb` en Debian 12, Ubuntu 22.04 y 24.04 y corre las pruebas también en Debian 12.

### Seguridad
- El cliente HTTP del asistente de IA **nunca sigue redirecciones**: antes habría reenviado la clave de la API (cabecera) a otro servidor si el destino redirigía. Prueba incluida.

### Corregido
- Tailscale: su puerto UDP (41641) ya no se informa como «bloqueado por el firewall»: Tailscale lo abre por su cuenta y solo responde a pares autenticados (queda como «privada» con la explicación).
- Las pruebas del firewall ya no leen el `sentinel.conf` real del equipo que las ejecuta.
- `pyproject.toml` toma la versión del código (decía 2.1.0).

## [2.10.0] - 2026-11-14

### Agregado
- **Asistente de IA que explica cada detección** (opcional, apagado de fábrica). Botón «Explicar con IA» en cada evento y página «Asistente de IA» para configurarlo (`sentinel ia estado|configurar|probar|quitar`). Dos modos: **local** (Ollama en tu equipo, nada sale de aquí; es el predeterminado) o **api** (Anthropic u OpenAI/compatible, con tu propia clave).
- **Solo explica, nunca actúa:** el módulo no puede ejecutar programas; la respuesta es texto y el panel la pinta como texto. Siempre rotulada «generado por IA, puede equivocarse». Sin IA, sin red o con error se muestra una explicación fija.
- **Privacidad:** antes de enviar se ocultan IPs (v4/v6), correos, usuarios, nombre del equipo, rutas `/home/…` y cadenas que parecen claves; la respuesta se restaura solo en tu pantalla. El evento viaja como dato no confiable (puede traer texto de un atacante) y no puede cerrar la marca del prompt.
- La clave de la API se guarda en `/etc/sentinel/ia.key` (0640 root:adm, como los registros; el panel corre con tu usuario) y nunca en `sentinel.conf` ni en la lista de procesos; el modo local solo acepta direcciones de este equipo y la API solo https. Cambiar la configuración pide administrador y PIN.
- 13 pruebas nuevas.

## [2.9.1] - 2026-11-14

### Cambiado
- **El instalador (`install.sh`) ya no pide empezar con `sudo` ni instala en silencio.** Corre con tu usuario, detecta qué tiene tu equipo, lo muestra con ✔ / ✖, pregunta («¿Instalar lo que falta y después Sentinel?») y **solo si aceptas** pide tu contraseña de administrador y sigue. Si dices que no, no se instala nada (y sin Python 3 avisa que Sentinel no podría funcionar). `--si` instala sin preguntar (para automatizar) y sin terminal también continúa. 6 pruebas nuevas, con un `sudo` falso para que nunca instalen nada real.

## [2.9.0] - 2026-11-14

### Agregado
- **Endurecimiento guiado** (`sentinel endurecer plan|aplicar|revertir`). Catálogo de medidas explicadas en lenguaje claro (red, kernel, módulos poco usados, SSH, actualizaciones automáticas, volcados de memoria, auditoría) en tres perfiles acumulativos: básico, recomendado y estricto. Fuentes: CIS Benchmarks, Lynis y el Kernel Self Protection Project (no es una certificación). Pensado para equipos ajenos: **nada se aplica solo** (el plan es solo lectura), cada medida escribe archivos propios (drop-ins) y guarda una copia con manifiesto, una medida con comprobación que falla (`sshd -t`) se **deshace sola**, SSH solo con llave **no se aplica si nadie tiene una llave** (no te deja fuera) y `revertir` lo deja todo como estaba. Aplicar y revertir piden el PIN. El vigilante de archivos no reporta como ataque lo que Sentinel mismo cambia.
- **Requisitos** (`sentinel requisitos` y página «Requisitos» del panel): detecta solo qué tiene el equipo, lo marca con ✔ / ✖ / ○ (obligatorio, recomendado, opcional), pregunta y, si aceptas, instala lo que falta con apt, dnf, pacman o zypper pidiendo tu contraseña de administrador (sudo en la terminal, la ventana de clave del sistema en el panel). Nada se instala sin que lo aceptes.
- **Página «Correo e informes» en el panel**: configurar o cambiar el SMTP (con atajos para Gmail y Outlook y la explicación de la contraseña de aplicación), probarlo, quitarlo, elegir las horas del informe del equipo (`sentinel equipo --horario 08:00,16:00,23:00`, con un drop-in del temporizador que una actualización no pisa), activar o apagar el envío y mandar un informe ahora. La contraseña viaja por la entrada estándar, nunca en la lista de procesos ni en el panel.

## [2.8.4] - 2026-11-14

### Corregido
- **`sentinel status` dice lo mismo que el panel.** Empieza con el veredicto («PROTEGIDO» o «REQUIERE ATENCIÓN» y por qué), ya no cuenta ni lista los avisos que marcaste como revisados, y muestra la referencia de integridad sin necesitar sudo (antes decía «0 elementos · falta: baseline init» aunque existiera).

## [2.8.3] - 2026-11-14

### Corregido
- **Se podía saber qué es un paquete pero no si Sentinel los estaba detectando.** El estado de la captura (`packets_stats.json`) solo se escribía cuando había algo sospechoso que guardar; en una red tranquila quedaba horas sin actualizarse y el panel decía «captura apagada» con la captura funcionando. Ahora se escribe cada 5 s siempre.
- **El panel y `sentinel packets` muestran el estado real**: «Capturando ahora · N paquetes vistos · M escaneo(s) detectado(s) (sin novedades: es lo normal)», «Sin señal de la captura hace X» si el monitor se detuvo, o «Captura apagada» con el motivo (por ejemplo, sin permisos).

## [2.8.2] - 2026-11-14

### Corregido
- **Detener Sentinel con tu PIN ya no pone el panel en «Requiere atención».** El aviso «Sentinel fue detenido de forma autorizada» salía con gravedad *alta* y cada actualización o limpieza (que detienen el monitor) dejaba el resumen en naranja. Ahora es *baja*: queda en el historial pero no cuenta como alerta. Una parada **sin** PIN sigue siendo CRÍTICA.

## [2.8.1] - 2026-11-14

### Corregido
- **Actualizar el paquete ya no pisa `sentinel.conf`.** El archivo iba como «conffile» de dpkg y el propio Sentinel lo edita (`allow`, `config`, `smtp`): al actualizar a la 2.8.0 se reemplazó por el de fábrica y se perdieron la lista blanca y `notify_min` (quedó la copia en `sentinel.conf.dpkg-old`). Ahora el paquete instala solo un ejemplo en `/usr/share/sentinel/` y el `postinst` crea la configuración únicamente si no existe.
- **`sentinel smtp estado` sin sudo** decía «contraseña: falta» aunque `/etc/sentinel/smtp.pass` existe (solo root puede leerla). Ahora dice «guardada (solo root puede leerla)».

## [2.8.0] - 2026-11-14

### Agregado
- **Informe completo del equipo** (`sentinel equipo`): autenticación (journal), firewall con los **puertos abiertos a cualquier origen** y cómo cerrarlos, conexiones salientes por proceso, indicadores de shell reversa, procesos desde carpetas temporales, integridad de paquetes (`dpkg -V`), cuentas/sudoers/llaves SSH, persistencia, salud de CrowdSec y del resto de herramientas, túneles públicos, actualizaciones pendientes y los eventos de Sentinel de las últimas 24 h. Reúne y reemplaza los scripts sueltos `auditoria_red.sh` y `auditoria_extra.sh`. El resultado es ALTO / MEDIO / BAJO; solo ALTO y MEDIO suben el riesgo. No incluye el historial de comandos ni los argumentos de los procesos (el informe viaja por correo).
- **Correo por SMTP desde Sentinel** (`[smtp]`, `sentinel smtp estado|configurar|importar|probar|quitar`): sin depender del comando `mail`, con STARTTLS o SSL. La contraseña **no** va en `sentinel.conf` (lo lee el grupo `adm`): se guarda en `/etc/sentinel/smtp.pass` (0600, solo root). `sentinel smtp importar --desde ~/.msmtprc` reutiliza una configuración de msmtp sin volver a escribirla. Las alertas por correo usan SMTP si está configurado, con tope por hora (`email_max_per_hour`; las críticas siempre salen).
- **Temporizador `sentinel-equipo.timer`**: genera el informe a las 08:00, 16:00 y 23:00 y lo manda por correo. Con `Persistent=true`: si el equipo estaba apagado a esa hora, se ejecuta al encender (con el cron anterior esos informes se perdían).

### Corregido (falsos positivos)
- **Parar Sentinel durante `apt upgrade`** ya no es una alerta CRÍTICA de «intento de detener sin PIN»: apt/needrestart reinician servicios al actualizar. Sin una actualización en curso la alerta sigue igual. (El servicio `unattended-upgrade-shutdown`, siempre encendido en Ubuntu, no cuenta como actualización.)
- **Programas de desarrollo reemplazados mientras corrían** (`claude` o `node` actualizados con npm, proyectos .NET recompilados) ya no son «binario borrado» de gravedad alta: pasan a «reinicio pendiente». En `/tmp`, `/dev/shm`, `/var/tmp` y `/run/user` sigue siendo alta.
- **Respuestas UDP** a puertos donde el equipo tiene un programa (Meet/WebRTC/STUN de Google) ya no cuentan como «escaneo de puertos UDP»: antes bloqueaban 24 h una IP de Google. Un escaneo real a puertos sin nada escuchando se detecta igual.
- **Regla de firewall del loopback** (`Anywhere on lo`): ya no se informa como «abierta a cualquiera» (la etiqueta lleva «[N]» delante y no coincidía) ni al agregarla ni al quitarla.
- **Sentinel no se reporta a sí mismo**: sus archivos en `/opt/sentinel` que coinciden con el paquete oficial bajan a informativos (si no coinciden, el aviso se mantiene: alguien los tocó) y sus propios procesos no se analizan como sospechosos.

## [2.7.0] - 2026-11-01

### Agregado
- **«Esto es normal»**: botón en cada evento que lo acepta (lista blanca o referencia nueva) en vez de editar archivos; nunca se ofrece para ataques ni posibles puertas traseras. Con **modo aprendizaje** (`sentinel aprender 3`, o desde Ajustes) los puertos, USB y módulos nuevos se aceptan sin avisar durante unos días.
- **Vigilancia de los registros web** (nginx y apache): inyección SQL, ejecución de comandos (log4shell, `eval`, `<?php`), salida de carpeta (`../`), archivos secretos (`.env`, `.git`), escáneres, paneles de administración, ráfagas de 404 y fuerza bruta de inicio de sesión; con bloqueo temporal y explicación para niños de cada tipo.
- **Latido externo**: Sentinel avisa cada 5 min a un servicio de tu elección (healthchecks.io u otro, solo `https`) que sigue vivo; si se apaga a la fuerza, ese servicio te avisa al correo o al celular. También se configuran el correo y ntfy desde Ajustes.
- **Publicaciones firmadas con GPG**: el actualizador exige la firma de `SHA256SUMS` cuando el equipo trae la clave pública del autor (que viene en el paquete ya instalado, no en la descarga). `tools/crear-clave-de-publicacion.sh` crea la clave y `SENTINEL_SIGN_KEY=… packaging/make-release.sh` firma.
- **ClamAV y reglas YARA** opcionales para las carpetas web (si ya están instalados), con tope de archivos por revisión; se incluyen reglas YARA básicas.
- **Verificación contra el paquete oficial** (como `debsums`): un archivo del sistema que coincide con el de su paquete baja a informativo.
- **Horas de silencio** (sin avisos en pantalla de noche, salvo críticos) y eventos **«resueltos»** que dejan de contar en el resumen y los informes.
- **Ícono en la barra del sistema** (AppIndicator) con el color del estado; se inicia solo.
- **Varios servidores en un panel**: página *Servidores* que consulta por SSH, con tus llaves y solo en lectura, el resumen de otros Sentinel (`sentinel resumen --json`).

## [2.6.3] - 2026-11-01

### Corregido
- Al actualizar con `apt` teniendo un PIN, el PIN se pregunta **una sola vez** (antes salía «PIN de Sentinel:» dos veces y la primera, sin explicación, parecía un cuelgue). Si se omite con Enter, no se vuelve a preguntar.

## [2.6.2] - 2026-11-01

### Corregido
- Al actualizar con `apt` teniendo un PIN, la pregunta del PIN ahora se ve claramente en la terminal, se puede omitir con Enter y no espera más de 2 minutos (antes quedaba esperando sin explicar y la instalación parecía colgada).

## [2.6.1] - 2026-11-01

### Corregido
- **Informes sin ruido**: con los eventos reales de un equipo de pruebas, los avisos de gravedad media o más bajaron de 79 a 0 (todo era ruido propio). Cambios: los puertos UDP altos que cambian solos al reiniciar (syncthing, chrome, timesyncd) ya no son «puerto nuevo»; un puerto nuevo que solo escucha en local es gravedad baja; `acpid` no se marca como lector de teclado; un cambio en `/etc/ufw/user*.rules` es gravedad baja (el módulo Firewall avisa con detalle qué regla cambió y deja en alta lo que abre un puerto a cualquiera); y el informe cuenta solo hallazgos reales (sin pruebas, arranques ni paradas del monitor).
- **Informe y eventos más claros**: «eliminado» ahora dice qué significa (el archivo ya no existe: se borró o se reemplazó) y el informe junta los eventos repetidos de una misma carpeta en una sola fila (antes salían 21 líneas por 7 archivos).
- Las copias antiguas de los servicios de Sentinel que el paquete reemplaza se aceptan en la referencia al actualizar, así no se vuelven a avisar cada hora como «eliminadas» (y bajan a gravedad baja con su explicación).

## [2.6.0] - 2026-11-01

### Cambiado (solo diseño; no se quitó ninguna función)
- **Menú lateral con hamburguesa**: se recoge a solo íconos (con la sección y el nombre al pasar el cursor), recuerda tu elección y en pantallas angostas es un cajón que se abre y se cierra.
- **Tablero de gráficos** en Resumen: tarjetas con mini-gráfica de 7 días, actividad por hora, **dona por gravedad**, **barras por módulo**, IPs más activas, servicios y eventos recientes, en una cuadrícula ordenada de 12 columnas.
- Barra superior fija, tablas con encabezado fijo y columnas ordenadas, contenedores con el mismo espacio y tamaño, insignias más sobrias y tema claro/oscuro más calmo.
- Corregido: los botones y campos con `hidden` (por ejemplo «Quitar PIN» sin PIN) se veían igual.

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
