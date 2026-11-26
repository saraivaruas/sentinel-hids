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
| 1.1 | 🟡 | `sentinel identidad estado` | Solo lee: interfaz, MAC actual y de fábrica, IP, si se envía el nombre del equipo y si hay otros programas rotando. Probado en un equipo real; falta confirmar la CI. |
| 1.2 | 🟡 | `sentinel identidad rotar` y `restaurar` | MAC aleatoria a través de NetworkManager y dirección IP nueva por DHCP, sin enviar el nombre. Si la red deja de responder, vuelve sola a lo anterior. **Probado en un equipo real** (adaptador USB `r8152`) una vez apagado el gancho de `macchanger`; falta confirmar la CI. |
| 1.3 | 🟡 | Rotación programada | `activar` y `desactivar`, cada cuántas horas, con un temporizador de systemd. Apagado por defecto. Hecho y probado con una red simulada; falta probarlo en un equipo real y en la CI. |
| 1.4 | 🟡 | Retirar los scripts antiguos | `sudo sentinel identidad retirar` (con confirmación y copia) y `devolver`. `retirar` **probado en un equipo real**; `devolver` solo con archivos de ejemplo. Falta confirmar la CI. |
| 1.5 | 🟡 | Apartado en Ajustes del panel | «Privacidad de red»: estado, activar o apagar, intervalo, «Cambiar ahora» y volver a la MAC de fábrica. Hecho y visto en el navegador; falta usar sus botones en un equipo real y que pase por la CI. |

La IP se obtiene por DHCP: no se inventa una al azar, porque puede chocar con la de otro equipo o quedar fuera del rango de la red.

### Fase 2: discreción en la red

| N.º | Estado | Pieza | Detalle |
|---|---|---|---|
| 2.1 | 🟡 | Revisión de lo que delata al equipo | Solo lee: nombre por DHCP, LLMNR, mDNS, NetBIOS, SSDP, puertos abiertos, respuesta a ping y anuncios de programas (Syncthing, por ejemplo). Comando `sentinel discrecion`, probado en un equipo real sin permisos de administrador; falta con ellos y que pase por la CI. |
| 2.2 | 🟡 | No anunciarse | Apagar LLMNR, mDNS y Avahi y no enviar el nombre. Hecho y probado con un sistema simulado; falta un equipo real y la CI. Chrome y Syncthing siguen anunciándose: son ajustes de cada programa. |
| 2.3 | 🟡 | No contestar a ping | Solo la petición de eco en IPv4 e IPv6; ARP y el descubrimiento de vecinos se mantienen. Afecta también al ping desde la VPN y el propio equipo. Hecho y probado con un sistema simulado; falta un equipo real y la CI. |
| 2.4 | ⬜ | Entrada cerrada | Con el módulo cortafuegos: nada abierto desde fuera, sin respuesta a lo no pedido. |
| 2.5 | 🟡 | Modo discreto | `sentinel discrecion aplicar` y `revertir`: aplica 2.2 y 2.3 y se puede deshacer. Falta sumar 2.4 y comprobarlo en un equipo real. |
| 2.6 | 🟡 | Apartado en Ajustes del panel | «Modo discreto en la red»: hallazgos, elegir medidas y deshacer. Hecho y visto en el navegador; falta usar sus botones en un equipo real y que pase por la CI. |

### Fase 3: más adelante

| N.º | Estado | Pieza |
|---|---|---|
| 3.1 | ⬜ | Wi-Fi: MAC distinta por red y búsqueda de redes con MAC aleatoria |
| 3.2 | ⬜ | Lo mismo en macOS |

## Porte a macOS

«Probado en la CI» significa que pasan las pruebas automáticas en los equipos macOS de GitHub Actions (macOS 26 Tahoe y 15 Sequoia, Apple Silicon e Intel). Ninguna pieza se da por buena como producto hasta probarla en un Mac real.

«Probado en la CI» se marca solo cuando la prueba real de esa pieza pasó en GitHub. 🟡 incluye lo escrito y probado solo con simulaciones, o cuya prueba real aún no termina.

## Base del porte a macOS

| Estado | Pieza |
|---|---|
| ✅ | La CI corre las pruebas en macOS |
| ✅ | Módulo `plataforma` (decide si es Linux o macOS) |
| ✅ | Procesos sospechosos con `ps` |
| ✅ | Archivos SUID |
| ✅ | Puertos y conexiones con `lsof` |
| ✅ | Cuentas del sistema |
| ✅ | USB y extensiones del núcleo y del sistema |

## Paridad con Linux

| N.º | Estado | Pieza | Detalle |
|---|---|---|---|
| 1 | ✅ | Vigilancia de archivos | En vivo por sondeo cada 10 s, con las rutas críticas de macOS. |
| 2 | ✅ | Fuerza bruta | Lee el registro unificado: SSH, `sudo` y `su` (`mac-registro`). |
| 3 | ✅ | Bloqueo de IP | Con `pf`, repuesto tras reiniciar (`mac-bloqueo`). |
| 3b | ✅ | Administrar puertos del cortafuegos | Con `pf`: plan, aplicar a prueba, confirmar y restaurar; probado con conexiones reales (`mac-bloqueo`). |
| 4a | ✅ | Servicio e instalador | `install-mac.sh` y `launchd`: instalar, detener, iniciar, desinstalar y protección con PIN (`mac-instalar`). |
| 4b | 🟡 | Instalador `.pkg` | Se genera, instala y desinstala en equipos reales (`mac-instalar`). Sin firmar: firmarlo y notarizarlo requiere la cuenta de Apple Developer. |
| 4c | ✅ | Icono en la barra de menú | Se compila, lee el estado y queda corriendo (`mac-instalar`). Falta verlo en un Mac con pantalla. |
| 5 | ✅ | Captura de paquetes | Con BPF; detecta un escaneo real (`mac-captura`). |
| 6 | ✅ | Configuración, `status` y requisitos propios de macOS | Probados con el servicio instalado. |
| 7 | ✅ | Panel | Páginas, acciones, avisos y aplicación en Aplicaciones probados (`mac-instalar`). Falta ver la ventana de contraseña en un Mac con pantalla. |
| 8 | ✅ | Informe del equipo y auditoría | Todas las secciones propias de macOS, probadas (`mac-instalar`). |
| 9 | ✅ | Señuelos | Con usuario propio sin privilegios; probados (`mac-instalar`). |
| 10 | 🟡 | Actualizaciones | Usan el instalador de Mac; hace falta publicar una versión que lo incluya. |
| 11 | ✅ | Endurecimiento guiado | Aplicar y revertir probado en los cuatro tipos de Mac (`mac-instalar`). FileVault solo se revisa. |
| 12 | 🟡 | Ventana grande de alerta y PIN sin terminal | Con ventanas del sistema; falta verlas en un Mac con pantalla. |
| 13 | ⬜ | API y app de iOS | La app solo acompaña: alertas, estado de los equipos y bloquear o liberar IPs. iOS no permite que una app vigile el sistema. |

## Cómo se prueba

- **GitHub Actions con macOS:** pruebas automáticas en cada subida. No tiene pantalla interactiva.
- **Mac en la nube, por horas:** para lo que exige un equipo real (permisos como «Acceso total al disco», barra de menú, instalador, simulador de iPhone y TestFlight).
- Publicar la app de iOS requiere una cuenta de Apple Developer.
