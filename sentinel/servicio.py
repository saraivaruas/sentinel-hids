"""Servicios de Sentinel en los dos sistemas: systemd en Linux y launchd en macOS.

El resto del programa pregunta aquí con los nombres de systemd («sentinel-monitor», «sentinel-scan.timer»…) y este
módulo los traduce. Las funciones aceptan `run` (el ejecutor de comandos) para probarse sin tocar el equipo.
"""
from __future__ import annotations

import os
import plistlib
import time

from . import core, plataforma

PREFIJO = "io.github.saraivaruas.sentinel."
DESTINO = "/opt/sentinel"
HORAS_EQUIPO = ("08:00", "16:00", "23:00")
TAREAS = ("monitor", "scan", "report", "equipo")
OPCIONALES = ("honeypot",)                 # solo si se activan («sentinel senuelos activar»)
USUARIO_SENUELOS = "_sentinel"             # usuario sin privilegios que crea el instalador


def carpeta_launchd() -> str:
    return os.environ.get("SENTINEL_LAUNCHD_DIR", "/Library/LaunchDaemons")


def tarea(unidad: str) -> str:
    """«sentinel-scan.timer» -> «scan»."""
    return unidad.replace("sentinel-", "", 1).split(".")[0]


def ruta(nombre: str) -> str:
    return os.path.join(carpeta_launchd(), PREFIJO + nombre + ".plist")


def definicion(nombre: str, python: str, destino: str = DESTINO, horas=HORAS_EQUIPO) -> dict:
    """Contenido del .plist de una tarea. Python va aislado (-I): no lee la carpeta actual ni paquetes del usuario."""
    args = {"monitor": ["monitor"], "scan": ["scan", "--watchdog"], "report": ["report"], "equipo": ["equipo", "--programado"], "honeypot": ["honeypot"]}[nombre]
    codigo = "import sys; sys.path.insert(0, sys.argv[1]); sys.argv[0] = 'sentinel'; from sentinel.cli import main; sys.exit(main(sys.argv[2:]))"
    d = {"Label": PREFIJO + nombre, "ProgramArguments": [python, "-I", "-u", "-c", codigo, destino, *args],
         "EnvironmentVariables": {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "es_ES.UTF-8"},
         "StandardOutPath": f"/var/log/sentinel/{nombre}.salida.log", "StandardErrorPath": f"/var/log/sentinel/{nombre}.salida.log"}
    if nombre == "monitor":
        d.update(RunAtLoad=True, KeepAlive=True, ThrottleInterval=5, ExitTimeOut=20)
    elif nombre == "scan":
        d.update(StartInterval=1800, Nice=10)                                         # red de seguridad del monitor en vivo
    elif nombre == "honeypot":
        salida = "/var/log/sentinel/decoy/honeypot.salida.log"                        # la única carpeta donde ese usuario puede escribir
        d.update(RunAtLoad=True, KeepAlive=True, ThrottleInterval=5, UserName=USUARIO_SENUELOS, GroupName=USUARIO_SENUELOS, StandardOutPath=salida, StandardErrorPath=salida)
        d["EnvironmentVariables"]["SENTINEL_CONF"] = conf_senuelos()
    elif nombre == "report":
        d.update(StartCalendarInterval={"Weekday": 1, "Hour": 8, "Minute": 0}, Nice=15)  # lunes
    else:
        d.update(StartCalendarInterval=[{"Hour": int(h[:2]), "Minute": int(h[3:])} for h in horas], Nice=15)
    return d


def conf_senuelos() -> str:
    return os.path.join(os.path.dirname(core.conf_path()), "senuelos.conf")


def activar_senuelos(python: str, destino: str = DESTINO, run=None) -> list[str]:
    """macOS: pone en marcha los puertos señuelo. Su usuario no puede leer sentinel.conf, así que recibe una copia solo con su sección."""
    cfg = core.load_config()
    with open(conf_senuelos(), "w", encoding="utf-8") as f:
        f.write("# Copia de [honeypot] para el usuario de los señuelos. Se rehace al activarlos: edita sentinel.conf, no este archivo.\n[honeypot]\n"
                + "".join(f"{k} = {v}\n" for k, v in cfg.items("honeypot")))
    os.chmod(conf_senuelos(), 0o644)
    escribir("honeypot", python, destino)
    detener(run, ["honeypot"])             # si ya estaba, se vuelve a cargar con los puertos de ahora
    return iniciar(run, ["honeypot"])


def desactivar_senuelos(run=None) -> list[str]:
    errores = detener(run, ["honeypot"])
    if not errores:
        for p in (ruta("honeypot"), conf_senuelos()):
            if os.path.exists(p):
                os.remove(p)
    return errores


def escribir(nombre: str, python: str, destino: str = DESTINO, horas=HORAS_EQUIPO) -> str:
    p = ruta(nombre)
    with open(p, "wb") as f:
        plistlib.dump(definicion(nombre, python, destino, horas), f)
    os.chmod(p, 0o644)  # launchd rechaza los que otros puedan modificar
    return p


def instalar(python: str, destino: str = DESTINO) -> None:
    """Escribe las tareas con las horas que diga la configuración (no las arranca)."""
    from . import equipo
    horas = equipo.horas_validas(core.load_config().get("equipo", "horas", fallback="")) or list(HORAS_EQUIPO)
    for n in TAREAS:
        escribir(n, python, destino, horas)


def estado(unidad: str, run=None) -> str:
    """Como «systemctl is-active»: «active», «inactive» o «not-found». Una tarea programada está activa si está cargada."""
    run = run or core.run
    if not plataforma.ES_MAC:
        return run(["systemctl", "is-active", unidad], 5)[1].strip().split("\n")[-1]
    nombre = tarea(unidad)
    if nombre not in TAREAS + OPCIONALES:
        return "not-found"
    rc, out = run(["launchctl", "print", f"system/{PREFIJO}{nombre}"], 5)
    if rc != 0:
        return "inactive" if os.path.exists(ruta(nombre)) else "not-found"
    return "active" if nombre not in ("monitor", "honeypot") or "state = running" in out else "inactive"


def iniciar(run=None, nombres=None) -> list[str]:
    """macOS: carga las tareas instaladas. Devuelve los errores (lista vacía = todo bien)."""
    run = run or core.run
    errores = []
    for n in nombres or TAREAS + tuple(o for o in OPCIONALES if os.path.exists(ruta(o))):
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


def detener(run=None, nombres=None, espera: float = 45.0, dormir=time.sleep) -> list[str]:
    """macOS: descarga las tareas (siguen instaladas y vuelven al reiniciar el equipo o con iniciar()).

    launchd responde antes de que el programa termine: se espera a que cada tarea desaparezca. Sin eso, un
    iniciar() inmediato no haría nada y el desinstalador borraría carpetas todavía en uso."""
    run = run or core.run
    pendientes = {}
    for n in nombres or TAREAS + OPCIONALES:
        if run(["launchctl", "print", f"system/{PREFIJO}{n}"], 5)[0] != 0:
            continue
        pendientes[n] = run(["launchctl", "bootout", f"system/{PREFIJO}{n}"], 60)[1].strip()[:160]
    limite = time.monotonic() + espera
    while pendientes:
        for n in list(pendientes):
            if run(["launchctl", "print", f"system/{PREFIJO}{n}"], 5)[0] != 0:
                del pendientes[n]
        if not pendientes or time.monotonic() >= limite:
            break
        dormir(0.5)
    return [f"{n}: no se pudo detener {motivo}".rstrip() for n, motivo in pendientes.items()]


def reiniciar_monitor(run=None) -> None:
    """Para que el monitor lea la configuración nueva (solo si ya estaba en marcha)."""
    run = run or core.run
    if plataforma.ES_MAC:
        run(["launchctl", "kickstart", "-k", f"system/{PREFIJO}monitor"], 30) if estado("sentinel-monitor", run) == "active" else None
    else:
        run(["systemctl", "try-restart", "sentinel-monitor.service"], 20)
