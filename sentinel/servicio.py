"""Servicios de Sentinel en los dos sistemas: systemd en Linux y launchd en macOS.

El resto del programa pregunta aquí con los nombres de systemd («sentinel-monitor», «sentinel-scan.timer»…) y este
módulo los traduce. Las funciones aceptan `run` (el ejecutor de comandos) para probarse sin tocar el equipo.
"""
from __future__ import annotations

import os
import plistlib

from . import core, plataforma

PREFIJO = "io.github.saraivaruas.sentinel."
DESTINO = "/opt/sentinel"
HORAS_EQUIPO = ("08:00", "16:00", "23:00")
TAREAS = ("monitor", "scan", "report", "equipo")


def carpeta_launchd() -> str:
    return os.environ.get("SENTINEL_LAUNCHD_DIR", "/Library/LaunchDaemons")


def tarea(unidad: str) -> str:
    """«sentinel-scan.timer» -> «scan»."""
    return unidad.replace("sentinel-", "", 1).split(".")[0]


def ruta(nombre: str) -> str:
    return os.path.join(carpeta_launchd(), PREFIJO + nombre + ".plist")


def definicion(nombre: str, python: str, destino: str = DESTINO, horas=HORAS_EQUIPO) -> dict:
    """Contenido del .plist de una tarea. Python va aislado (-I): no lee la carpeta actual ni paquetes del usuario."""
    args = {"monitor": ["monitor"], "scan": ["scan", "--watchdog"], "report": ["report"], "equipo": ["equipo", "--programado"]}[nombre]
    codigo = "import sys; sys.path.insert(0, sys.argv[1]); sys.argv[0] = 'sentinel'; from sentinel.cli import main; sys.exit(main(sys.argv[2:]))"
    d = {"Label": PREFIJO + nombre, "ProgramArguments": [python, "-I", "-u", "-c", codigo, destino, *args],
         "EnvironmentVariables": {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "es_ES.UTF-8"},
         "StandardOutPath": f"/var/log/sentinel/{nombre}.salida.log", "StandardErrorPath": f"/var/log/sentinel/{nombre}.salida.log"}
    if nombre == "monitor":
        d.update(RunAtLoad=True, KeepAlive=True, ThrottleInterval=5, ExitTimeOut=20)
    elif nombre == "scan":
        d.update(StartInterval=1800, Nice=10)                                         # red de seguridad del monitor en vivo
    elif nombre == "report":
        d.update(StartCalendarInterval={"Weekday": 1, "Hour": 8, "Minute": 0}, Nice=15)  # lunes
    else:
        d.update(StartCalendarInterval=[{"Hour": int(h[:2]), "Minute": int(h[3:])} for h in horas], Nice=15)
    return d


def escribir(nombre: str, python: str, destino: str = DESTINO, horas=HORAS_EQUIPO) -> str:
    p = ruta(nombre)
    with open(p, "wb") as f:
        plistlib.dump(definicion(nombre, python, destino, horas), f)
    os.chmod(p, 0o644)  # launchd rechaza los que otros puedan modificar
    return p


def estado(unidad: str, run=None) -> str:
    """Como «systemctl is-active»: «active», «inactive» o «not-found». Una tarea programada está activa si está cargada."""
    run = run or core.run
    if not plataforma.ES_MAC:
        return run(["systemctl", "is-active", unidad], 5)[1].strip().split("\n")[-1]
    nombre = tarea(unidad)
    if nombre not in TAREAS:
        return "not-found"
    rc, out = run(["launchctl", "print", f"system/{PREFIJO}{nombre}"], 5)
    if rc != 0:
        return "inactive" if os.path.exists(ruta(nombre)) else "not-found"
    return "active" if nombre != "monitor" or "state = running" in out else "inactive"


def iniciar(run=None, nombres=TAREAS) -> list[str]:
    """macOS: carga las tareas instaladas. Devuelve los errores (lista vacía = todo bien)."""
    run = run or core.run
    errores = []
    for n in nombres:
        if not os.path.exists(ruta(n)):
            errores.append(f"{n}: no está instalada ({ruta(n)})")
            continue
        if run(["launchctl", "print", f"system/{PREFIJO}{n}"], 5)[0] == 0:
            continue  # ya cargada
        run(["launchctl", "enable", f"system/{PREFIJO}{n}"], 20)
        rc, out = run(["launchctl", "bootstrap", "system", ruta(n)], 30)
        if rc != 0:
            errores.append(f"{n}: {out.strip()[:160]}")
    return errores


def detener(run=None, nombres=TAREAS) -> list[str]:
    """macOS: descarga las tareas (siguen instaladas y vuelven al reiniciar el equipo o con iniciar())."""
    run = run or core.run
    errores = []
    for n in nombres:
        if run(["launchctl", "print", f"system/{PREFIJO}{n}"], 5)[0] != 0:
            continue
        rc, out = run(["launchctl", "bootout", f"system/{PREFIJO}{n}"], 60)
        if rc != 0:
            errores.append(f"{n}: {out.strip()[:160]}")
    return errores


def reiniciar_monitor(run=None) -> None:
    """Para que el monitor lea la configuración nueva (solo si ya estaba en marcha)."""
    run = run or core.run
    if plataforma.ES_MAC:
        run(["launchctl", "kickstart", "-k", f"system/{PREFIJO}monitor"], 30) if estado("sentinel-monitor", run) == "active" else None
    else:
        run(["systemctl", "try-restart", "sentinel-monitor.service"], 20)
