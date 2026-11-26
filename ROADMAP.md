# Hoja de ruta

Estado del porte de Sentinel a macOS y de lo que viene después. Lo ya publicado está en el [historial de cambios](CHANGELOG.md).

**Leyenda:** ✅ hecho y probado en la CI · 🟡 en parte · ⬜ pendiente

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
