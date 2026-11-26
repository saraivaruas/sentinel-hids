# Hoja de ruta

Estado de la privacidad de red, del porte de Sentinel a macOS y de lo que viene después. Lo ya publicado está en el [historial de cambios](CHANGELOG.md).

**Leyenda:** ✅ hecho y probado en la CI · 🟡 en parte · ⬜ pendiente

## Privacidad de red (Linux)

Dos objetivos: cambiar cada cierto tiempo la MAC y la IP del equipo, y anunciarse lo menos posible en la red.

**Límite que no se puede saltar:** ningún equipo conectado es invisible. El router o el switch ven su MAC y su tráfico, y quien esté en la misma red puede encontrarlo con un barrido ARP. Lo que sí se puede es no anunciar el nombre, no contestar a sondeos, no ofrecer puertos y cambiar de identidad.

### Fase 1: rotación de MAC e IP

Reemplaza a los scripts sueltos (`change-mac.sh` y `change-ip.sh`).

| N.º | Estado | Pieza | Detalle |
|---|---|---|---|
| 1.1 | ⬜ | `sentinel identidad estado` | Solo lee: interfaz, MAC actual y de fábrica, IP, si se envía el nombre del equipo y si hay otros programas rotando. |
| 1.2 | ⬜ | `sentinel identidad rotar` y `restaurar` | MAC aleatoria a través de NetworkManager y dirección IP nueva por DHCP, sin enviar el nombre. Si la red deja de responder, vuelve sola a lo anterior. |
| 1.3 | ⬜ | Rotación programada | `activar` y `desactivar`, cada cuántas horas, con un temporizador de systemd. |
| 1.4 | ⬜ | Retirar los scripts antiguos | Quitar la tarea de `cron` y `macchanger.service`, con confirmación y copia de respaldo. |
| 1.5 | ⬜ | Página en el panel | Estado, botón «Cambiar ahora» e intervalo. |

La IP se obtiene por DHCP: no se inventa una al azar, porque puede chocar con la de otro equipo o quedar fuera del rango de la red.

### Fase 2: discreción en la red

| N.º | Estado | Pieza | Detalle |
|---|---|---|---|
| 2.1 | ⬜ | Revisión de lo que delata al equipo | Solo lee: nombre por DHCP, LLMNR, mDNS, NetBIOS, SSDP, puertos abiertos, respuesta a ping y anuncios de programas (Syncthing, por ejemplo). |
| 2.2 | ⬜ | No anunciarse | Apagar LLMNR y mDNS y no enviar el nombre. |
| 2.3 | ⬜ | No contestar a ping | Solo la petición de eco en IPv4 e IPv6; lo que la red necesita para funcionar (ARP, descubrimiento de vecinos) se mantiene. |
| 2.4 | ⬜ | Entrada cerrada | Con el módulo cortafuegos: nada abierto desde fuera, sin respuesta a lo no pedido. |
| 2.5 | ⬜ | Modo discreto | Un interruptor que aplica 2.2 a 2.4, comprueba que la red siga funcionando y se puede deshacer. |
| 2.6 | ⬜ | Página en el panel | |

### Fase 3: más adelante

| N.º | Estado | Pieza |
|---|---|---|
| 3.1 | ⬜ | Wi-Fi: MAC distinta por red y búsqueda de redes con MAC aleatoria |
| 3.2 | ⬜ | Lo mismo en macOS |

## Porte a macOS

«Probado en la CI» significa que pasan las pruebas automáticas en los equipos macOS de GitHub Actions (macOS 26 Tahoe y 15 Sequoia, Apple Silicon e Intel). Ninguna pieza se da por buena como producto hasta probarla en un Mac real.

## Base del porte a macOS

| Estado | Pieza |
|---|---|
| ✅ | La CI corre las pruebas en macOS |
| ✅ | Módulo `plataforma` (decide si es Linux o macOS) |
| ✅ | Procesos sospechosos con `ps` |
| ✅ | Archivos SUID |
| ✅ | Puertos y conexiones con `lsof` (probado con muestras escritas a mano) |
| ✅ | Cuentas del sistema |
| ⬜ | USB y módulos del kernel |

## Lo que falta para un Sentinel completo en Mac

En orden de importancia.

| N.º | Estado | Pieza | Detalle |
|---|---|---|---|
| 1 | 🟡 | Vigilancia de archivos | Funciona en vivo por sondeo cada 10 s. Faltan las rutas críticas de macOS (ver punto 6). |
| 2 | ✅ | Fuerza bruta (`authwatch`) | Lee el registro unificado de macOS. La prueba real (`mac-registro`) detecta ataques por SSH, `sudo` y `su`. El bloqueo de la IP depende del punto 3. |
| 3 | ⬜ | Bloqueo de IP y firewall | Con `pf` en lugar de `ufw`/`iptables`. |
| 4 | ⬜ | Servicio e instalación | `launchd`, instalador `.pkg` e icono en la barra de menú. |
| 5 | ⬜ | Captura de paquetes | Con BPF. |
| 6 | ⬜ | Configuración por defecto para Mac | Rutas vigiladas propias (`/etc/sudoers`, `/Library/LaunchDaemons`, `~/.ssh`, `/etc/pf.conf`…). |
| 7 | ⬜ | API y app de iOS | La app solo acompaña: alertas, estado de los equipos y bloquear o liberar IPs. iOS no permite que una app vigile el sistema. |

## Cómo se prueba

- **GitHub Actions con macOS:** pruebas automáticas en cada subida. No tiene pantalla interactiva.
- **Mac en la nube, por horas:** para lo que exige un equipo real (permisos como «Acceso total al disco», barra de menú, instalador, simulador de iPhone y TestFlight).
- Publicar la app de iOS requiere una cuenta de Apple Developer.
