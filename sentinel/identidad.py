"""Identidad del equipo en la red: dirección MAC e IP (por ahora solo Linux con NetworkManager).

Las funciones aceptan `run` (el ejecutor de comandos) para probarse sin tocar la red.
"""
from __future__ import annotations

import glob
import os
import re
import secrets
import time

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


def mac_aleatoria() -> str:
    """Dirección al azar marcada como «administrada localmente» y de un solo equipo: no pertenece a ningún fabricante."""
    b = bytearray(secrets.token_bytes(6))
    b[0] = (b[0] & 0xFC) | 0x02
    return ":".join(f"{x:02x}" for x in b)


def _archivo() -> str:
    return os.path.join(core.state_dir(), "identidad.json")


def _guardado() -> dict:
    d = core.read_json(_archivo(), {}) or {}
    d.setdefault("originales", {})
    return d


def _aplicar(uuid: str, dev: str, valores: dict, run) -> tuple[bool, str]:
    """Escribe los valores en la conexión y la vuelve a activar (la red se corta unos segundos)."""
    rc, out = run(["nmcli", "connection", "modify", uuid, *[x for par in valores.items() for x in par]], 20)
    if rc == 0:
        rc, out = run(["nmcli", "--wait", "45", "connection", "up", "uuid", uuid, "ifname", dev], 60)
    return rc == 0, out.strip()


def _responde(ip: str, run, intentos: int = 4, espera: float = 2.0) -> bool:
    for i in range(intentos):
        if ip and run(["ping", "-c", "1", "-W", "2", ip], 5)[0] == 0:
            return True
        if i + 1 < intentos:
            time.sleep(espera)
    return False


def _fallo(e: dict, mac: str, ping_antes: bool, run) -> str:
    """¿Qué quedó mal tras el cambio? Vacío = todo bien."""
    if macs(e["interfaz"], run)[0] != mac:
        return "la interfaz no tomó la MAC nueva"
    if not direccion(e["interfaz"], run):
        return "la red no entregó una dirección IP"
    if ping_antes and not _responde(puerta(e["interfaz"], run), run):
        return "la puerta de salida dejó de responder"
    return ""


def rotar(cfg, alerter, run=core.run) -> dict:
    """Cambia la MAC (y con ella la IP que da el DHCP) sin enviar el nombre del equipo. Si algo falla, vuelve atrás."""
    e = estado(cfg, run)
    if e["error"]:
        return {"ok": False, "mensaje": e["error"]}
    uuid, dev, prop = e["conexion"], e["interfaz"], e["tipo"] + ".cloned-mac-address"
    previo = leer(uuid, [prop, "ipv4.dhcp-client-id", "ipv4.dhcp-send-hostname", "ipv6.dhcp-send-hostname"], run)
    if previo is None:
        return {"ok": False, "mensaje": "No pude leer la conexión actual; no se cambió nada."}
    d = _guardado()
    d["originales"].setdefault(uuid, previo)              # solo la primera vez: es a lo que vuelve «restaurar»
    d["ultimo_intento"] = core.now()
    core.atomic_write_json(_archivo(), d)
    ping_antes = _responde(e["puerta"], run, 2)           # hay redes cuya puerta nunca contesta: eso no es un fallo
    mac = mac_aleatoria()
    nuevo = {prop: mac, "ipv4.dhcp-client-id": "mac", "ipv4.dhcp-send-hostname": "no", "ipv6.dhcp-send-hostname": "no"}
    ok, salida = _aplicar(uuid, dev, nuevo, run)
    motivo = _fallo(e, mac, ping_antes, run) if ok else (salida or "NetworkManager no pudo activar la conexión")
    if motivo:
        # sin MAC definida NetworkManager conservaría la nueva: se activa con la anterior y luego se deja como estaba
        vuelta, _ = _aplicar(uuid, dev, {**previo, prop: previo[prop] or e["mac"]}, run)
        if not previo[prop]:
            run(["nmcli", "connection", "modify", uuid, prop, ""], 20)
        msg = f"No se cambió la identidad de {dev}: {motivo}. " + ("Se volvió a la anterior." if vuelta else "TAMPOCO pude volver atrás: revisa la red (sudo sentinel identidad restaurar).")
        alerter.emit("medium" if vuelta else "high", "identidad", "rotacion_fallida", msg, key=f"identidad:fallo:{int(core.now())}")
        return {"ok": False, "mensaje": msg}
    ip = direccion(dev, run)
    msg = f"Identidad cambiada en {dev}: MAC {e['mac']} → {mac} · IP {e['ip'] or 'ninguna'} → {ip}"
    alerter.emit("info", "identidad", "rotada", msg, key=f"identidad:ok:{int(core.now())}")
    return {"ok": True, "mensaje": msg, "mac": mac, "ip": ip}


def restaurar(cfg, alerter, run=core.run) -> dict:
    """Vuelve a la MAC de fábrica y a los ajustes que tenía la conexión antes de la primera rotación."""
    e = estado(cfg, run)
    if e["error"]:
        return {"ok": False, "mensaje": e["error"]}
    uuid, dev, prop = e["conexion"], e["interfaz"], e["tipo"] + ".cloned-mac-address"
    d = _guardado()
    original = d["originales"].get(uuid)
    if original is None:
        return {"ok": False, "mensaje": "Sentinel no ha cambiado esta conexión: no hay nada que restaurar."}
    ok, salida = _aplicar(uuid, dev, {**original, prop: original[prop] or "permanent"}, run)
    if not ok:
        return {"ok": False, "mensaje": f"No pude restaurar {dev}: {salida}"}
    if not original[prop]:
        run(["nmcli", "connection", "modify", uuid, prop, ""], 20)
    del d["originales"][uuid]
    core.atomic_write_json(_archivo(), d)
    msg = f"Identidad restaurada en {dev}: MAC {macs(dev, run)[0]} · IP {direccion(dev, run) or 'ninguna'}"
    alerter.emit("info", "identidad", "restaurada", msg, key=f"identidad:rest:{int(core.now())}")
    return {"ok": True, "mensaje": msg}
