"""Qué delata a este equipo en la red local. Solo lee: no cambia nada (por ahora solo Linux).

Estados: «expuesto» (se nota), «discreto» (no se nota) y «por comprobar» (no se puede asegurar desde aquí).
"""
from __future__ import annotations

import os
import re

from . import core, identidad, plataforma
from .firewall import exposure

EXPUESTO, DISCRETO, DUDA = "expuesto", "discreto", "por comprobar"
PROC = "/proc/sys/net"
UFW = "/etc/ufw"
# puertos UDP con los que un programa se anuncia o responde a quien busca equipos
ANUNCIOS = {137: "NetBIOS", 138: "NetBIOS", 1716: "KDE Connect", 1900: "SSDP/UPnP", 3702: "WS-Discovery", 5353: "mDNS", 5355: "LLMNR",
            17500: "descubrimiento de Dropbox", 21027: "descubrimiento de Syncthing"}


def _item(ident: str, titulo: str, estado: str, detalle: str) -> dict:
    return {"id": ident, "titulo": titulo, "estado": estado, "detalle": detalle}


def _hacia_la_red(i: dict) -> bool:
    """¿Escucha donde puede llegar otro equipo de la red local? (ni en este mismo equipo ni solo por Tailscale)."""
    a = i["addr"]
    return not (a.startswith(exposure.LOOP) or a.endswith("%lo") or "%tailscale" in a or a.startswith(("100.", "fd7a:", "[fd7a:")))


def _quien(i: dict) -> str:
    return i["proc"] or "programa sin identificar"


def nombre(cfg, run) -> dict:
    titulo = "Nombre del equipo al pedir la dirección IP"
    e = identidad.estado(cfg, run)
    if e["error"]:
        return _item("nombre", titulo, DUDA, e["error"])
    if e["metodo"] != "auto":
        return _item("nombre", titulo, DISCRETO, "La dirección es fija: no se pide por DHCP.")
    if e["envia_nombre"]:
        return _item("nombre", titulo, EXPUESTO, "El router recibe el nombre de este equipo.")
    return _item("nombre", titulo, DISCRETO, "No se envía.")


def anuncios(escuchas: list[dict]) -> dict:
    titulo = "Programas que anuncian o buscan equipos"
    hallados = sorted({(i["port"], _quien(i)) for i in escuchas if i["proto"] == "udp" and i["port"] in ANUNCIOS and _hacia_la_red(i)})
    if not hallados:
        return _item("anuncios", titulo, DISCRETO, "Ninguno escucha (mDNS, LLMNR, NetBIOS, SSDP y similares).")
    return _item("anuncios", titulo, EXPUESTO, "; ".join(f"{p}: {ANUNCIOS[n]} (udp {n})" for n, p in hallados))


def cortafuegos_encendido() -> bool:
    try:
        with open(os.path.join(UFW, "ufw.conf"), encoding="utf-8") as f:
            return bool(re.search(r"^ENABLED=yes", f.read(), re.M | re.I))
    except OSError:
        return False


def puertos(escuchas: list[dict]) -> dict:
    titulo = "Puertos que escuchan hacia la red"
    por: dict[str, set[str]] = {}
    for i in escuchas:
        if _hacia_la_red(i) and not (i["proto"] == "udp" and i["port"] in ANUNCIOS):
            por.setdefault(_quien(i), set()).add(f"{i['proto']} {i['port']}")
    if not por:
        return _item("puertos", titulo, DISCRETO, "Ninguno.")
    lista = "; ".join(f"{p}: {', '.join(sorted(v))}" for p, v in sorted(por.items()))
    if cortafuegos_encendido():
        return _item("puertos", titulo, DUDA, lista + ". El cortafuegos (ufw) está encendido; mira cuáles deja pasar con: sudo sentinel firewall plan")
    return _item("puertos", titulo, EXPUESTO, lista + ". No veo ufw encendido.")


def ping(version: int) -> dict:
    ident, titulo = f"ping{version}", f"Respuesta a ping (IPv{version})"
    sysctl = os.path.join(PROC, "ipv4", "icmp_echo_ignore_all") if version == 4 else os.path.join(PROC, "ipv6", "icmp", "echo_ignore_all")
    try:
        with open(sysctl, encoding="ascii") as f:
            if f.read().strip() == "1":
                return _item(ident, titulo, DISCRETO, "El sistema no contesta.")
    except OSError:
        pass
    if not cortafuegos_encendido():
        return _item(ident, titulo, DUDA, "El sistema contestaría, salvo que otro cortafuegos lo descarte.")
    try:
        with open(os.path.join(UFW, "before.rules" if version == 4 else "before6.rules"), encoding="utf-8") as f:
            reglas = f.read()
    except PermissionError:
        return _item(ident, titulo, DUDA, "Hay que leer las reglas del cortafuegos: sudo sentinel discrecion")
    except OSError:
        return _item(ident, titulo, DUDA, "No encuentro las reglas del cortafuegos.")
    proto = "icmp --icmp-type" if version == 4 else "icmpv6 --icmpv6-type"
    if re.search(rf"^-A ufw6?-before-input -p {proto} echo-request -j ACCEPT", reglas, re.M):
        return _item(ident, titulo, EXPUESTO, "El cortafuegos deja pasar el ping y el sistema contesta.")
    return _item(ident, titulo, DISCRETO, "El cortafuegos no lo deja pasar.")


def revisar(cfg, run=core.run) -> dict:
    if plataforma.ES_MAC:
        return {"error": "La revisión de discreción en la red todavía no está disponible en macOS.", "hallazgos": []}
    rc, out = run(["ss", "-H", "-tulnp"], 10)
    if rc != 0:
        return {"error": "No pude ver qué escucha el equipo (hace falta «ss»).", "hallazgos": []}
    escuchas = exposure.parse_ss(out)
    return {"error": "", "hallazgos": [nombre(cfg, run), anuncios(escuchas), puertos(escuchas), ping(4), ping(6)]}
