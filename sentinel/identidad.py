"""Identidad del equipo en la red: dirección MAC e IP (por ahora solo Linux con NetworkManager).

Las funciones aceptan `run` (el ejecutor de comandos) para probarse sin tocar la red.
"""
from __future__ import annotations

import glob
import os
import re

from . import core, plataforma

TIPOS = ("802-3-ethernet", "802-11-wireless")
ROTADORES = re.compile(r"change[-_]?(mac|ip)|macchanger", re.I)
CRON = ("/etc/crontab", "/etc/cron.d/*", "/var/spool/cron/crontabs/*")


def interfaz(cfg, run=core.run) -> str:
    """La que diga la configuración o, si no, la de la salida a internet."""
    fija = cfg.get("identidad", "interfaz", fallback="").strip()
    if fija:
        return fija
    m = re.search(r"^default\b.*?\bdev (\S+)", run(["ip", "route", "show", "default"], 5)[1], re.M)
    return m.group(1) if m else ""


def macs(dev: str, run=core.run) -> tuple[str, str]:
    """(MAC en uso, MAC de fábrica). `ip` solo muestra «permaddr» cuando son distintas."""
    out = run(["ip", "-o", "link", "show", "dev", dev], 5)[1]
    actual = re.search(r"link/ether ([0-9a-f:]{17})", out)
    fabrica = re.search(r"permaddr ([0-9a-f:]{17})", out)
    a = actual.group(1) if actual else ""
    return a, fabrica.group(1) if fabrica else a


def direccion(dev: str, run=core.run) -> str:
    m = re.search(r"\binet ([0-9.]+/\d+)", run(["ip", "-4", "-o", "addr", "show", "dev", dev, "scope", "global"], 5)[1])
    return m.group(1) if m else ""


def puerta(dev: str, run=core.run) -> str:
    m = re.search(r"^default via (\S+)", run(["ip", "route", "show", "default", "dev", dev], 5)[1], re.M)
    return m.group(1) if m else ""


def leer(uuid: str, campos: list[str], run=core.run) -> dict | None:
    """Valores de una conexión de NetworkManager (uno por línea, vacío = sin definir)."""
    rc, out = run(["nmcli", "--escape", "no", "-g", ",".join(campos), "connection", "show", uuid], 10)
    if rc != 0:
        return None
    lineas = out.split("\n")
    return {c: (lineas[i].strip() if i < len(lineas) else "") for i, c in enumerate(campos)}


def otros_rotadores(run=core.run, patrones=CRON) -> tuple[list[str], bool]:
    """Programas ajenos a Sentinel que ya cambian la MAC o la IP. El segundo valor dice si se pudo revisar todo el cron."""
    hallados, completo = [], True
    if run(["systemctl", "is-enabled", "macchanger.service"], 5)[1].strip() == "enabled":
        hallados.append("macchanger.service (cambia la MAC al arrancar)")
    for patron in patrones:
        carpeta = os.path.dirname(patron)
        if os.path.isdir(carpeta) and not os.access(carpeta, os.R_OK):
            completo = False                                   # el cron de cada usuario solo lo lee root
            continue
        for ruta in sorted(glob.glob(patron)):
            try:
                with open(ruta, encoding="utf-8", errors="replace") as f:
                    for linea in f:
                        if not linea.lstrip().startswith("#") and ROTADORES.search(linea):
                            hallados.append(f"{ruta}: {linea.strip()}")
            except IsADirectoryError:
                continue
            except OSError:
                completo = False
    return hallados, completo


def estado(cfg, run=core.run) -> dict:
    """Foto de solo lectura. Con «error» no vacío, no se puede rotar."""
    if plataforma.ES_MAC:
        return {"error": "La rotación de MAC e IP todavía no está disponible en macOS."}
    dev = interfaz(cfg, run)
    if not dev:
        return {"error": "No encuentro la interfaz de red con salida a internet. Indícala en [identidad] interfaz."}
    rc, out = run(["nmcli", "-g", "GENERAL.CON-UUID", "device", "show", dev], 10)
    uuid = out.strip()
    if rc != 0 or not uuid:
        return {"error": f"NetworkManager no administra {dev} (hace falta «nmcli» y una conexión activa)."}
    base = leer(uuid, ["connection.type"], run) or {}
    tipo = base.get("connection.type", "")
    if tipo not in TIPOS:
        return {"error": f"{dev} no es una conexión por cable ni Wi-Fi ({tipo or 'tipo desconocido'})."}
    v = leer(uuid, ["ipv4.method", "ipv4.dhcp-send-hostname"], run) or {}
    actual, fabrica = macs(dev, run)
    otros, completo = otros_rotadores(run)
    return {"error": "", "interfaz": dev, "conexion": uuid, "tipo": tipo, "mac": actual, "mac_fabrica": fabrica,
            "aleatoria": actual != fabrica, "ip": direccion(dev, run), "puerta": puerta(dev, run),
            "metodo": v.get("ipv4.method", ""), "envia_nombre": v.get("ipv4.dhcp-send-hostname", "") != "no",
            "otros": otros, "cron_revisado": completo}
