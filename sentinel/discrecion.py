"""Qué delata a este equipo en la red local y el «modo discreto» para delatarse menos (por ahora solo Linux).

`revisar` solo lee. `aplicar` cambia únicamente lo suyo, guarda lo que había y `revertir` lo repone.

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
ARCHIVO_PING = "/etc/sysctl.d/99-sentinel-discrecion.conf"
ARCHIVO_ANUNCIOS = "/etc/systemd/resolved.conf.d/sentinel-discrecion.conf"
AVAHI = ["avahi-daemon.service", "avahi-daemon.socket"]
ECO = {"net.ipv4.icmp_echo_ignore_all": "ipv4/icmp_echo_ignore_all", "net.ipv6.icmp.echo_ignore_all": "ipv6/icmp/echo_ignore_all"}
NOMBRE = ["ipv4.dhcp-send-hostname", "ipv6.dhcp-send-hostname"]
MEDIDAS = {"nombre": "No enviar el nombre del equipo al router", "anuncios": "Apagar los anuncios del sistema (mDNS, LLMNR y Avahi)", "ping": "No contestar a ping"}
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


def aplicadas() -> list[str]:
    return [m for m in MEDIDAS if m in _guardado()]


def revisar(cfg, run=core.run) -> dict:
    if plataforma.ES_MAC:
        return {"error": "La revisión de discreción en la red todavía no está disponible en macOS.", "hallazgos": []}
    rc, out = run(["ss", "-H", "-tulnp"], 10)
    if rc != 0:
        return {"error": "No pude ver qué escucha el equipo (hace falta «ss»).", "hallazgos": []}
    escuchas = exposure.parse_ss(out)
    return {"error": "", "aplicadas": aplicadas(), "hallazgos": [nombre(cfg, run), anuncios(escuchas), puertos(escuchas), ping(4), ping(6)]}


# ---------- modo discreto: cada medida devuelve (bien, «lo que había» o el motivo del fallo)
def _archivo() -> str:
    return os.path.join(core.state_dir(), "discrecion.json")


def _guardado() -> dict:
    return (core.read_json(_archivo(), {}) or {}).get("aplicado", {})


def _guardar(aplicado: dict) -> None:
    core.atomic_write_json(_archivo(), {"aplicado": aplicado}, share=True)     # el panel (usuario normal) lo lee


def _escribir(ruta: str, texto: str) -> None:
    os.makedirs(os.path.dirname(ruta), mode=0o755, exist_ok=True)
    with open(ruta, "w", encoding="utf-8") as f:
        f.write("# Sentinel · modo discreto. Para quitarlo: sudo sentinel discrecion revertir\n" + texto)
    os.chmod(ruta, 0o644)


def _borrar(ruta: str) -> None:
    if os.path.exists(ruta):
        os.remove(ruta)


def _poner_nombre(cfg, run):
    e = identidad.estado(cfg, run)
    if e["error"]:
        return False, e["error"]
    previo = identidad.leer(e["conexion"], NOMBRE, run)
    if previo is None:
        return False, "no pude leer la conexión"
    rc, out = run(["nmcli", "connection", "modify", e["conexion"], *[x for c in NOMBRE for x in (c, "no")]], 20)
    return (True, {"conexion": e["conexion"], "valores": previo}) if rc == 0 else (False, out.strip())


def _quitar_nombre(previo: dict, run):
    rc, out = run(["nmcli", "connection", "modify", previo["conexion"], *[x for c in NOMBRE for x in (c, previo["valores"].get(c) or "yes")]], 20)
    return rc == 0, out.strip()


def _poner_ping(cfg, run):
    previo = {}
    for clave, rel in ECO.items():
        try:
            with open(os.path.join(PROC, rel), encoding="ascii") as f:
                previo[clave] = f.read().strip()
        except OSError:
            continue                                          # el kernel no tiene ese ajuste
    if not previo:
        return False, "este kernel no permite ignorar el ping"
    _escribir(ARCHIVO_PING, "".join(f"{k} = 1\n" for k in previo))
    rc, out = run(["sysctl", "-p", ARCHIVO_PING], 20)
    if rc != 0:
        _quitar_ping(previo, run)
        return False, out.strip()
    return True, previo


def _quitar_ping(previo: dict, run):
    _borrar(ARCHIVO_PING)
    errores = [out.strip() for rc, out in (run(["sysctl", "-w", f"{k}={v}"], 20) for k, v in previo.items()) if rc != 0]
    return not errores, "; ".join(errores)


def _resolved_bien(run) -> tuple[bool, str]:
    rc, out = run(["systemctl", "restart", "systemd-resolved.service"], 30)
    activo = run(["systemctl", "is-active", "systemd-resolved.service"], 5)[1].strip() == "active"
    return rc == 0 and activo, out.strip() or "systemd-resolved no quedó activo"


def _poner_anuncios(cfg, run):
    avahi = run(["systemctl", "is-active", "avahi-daemon.service"], 5)[1].strip() == "active"
    _escribir(ARCHIVO_ANUNCIOS, "[Resolve]\nLLMNR=no\nMulticastDNS=no\n")
    ok, motivo = _resolved_bien(run)
    if ok and avahi:
        rc, motivo = run(["systemctl", "disable", "--now", *AVAHI], 30)
        ok = rc == 0
    if not ok:
        _quitar_anuncios({"avahi": avahi}, run)
        return False, motivo.strip()
    return True, {"avahi": avahi}


def _quitar_anuncios(previo: dict, run):
    _borrar(ARCHIVO_ANUNCIOS)
    ok, motivo = _resolved_bien(run)
    if previo.get("avahi"):
        rc, out = run(["systemctl", "enable", "--now", *AVAHI], 30)
        ok, motivo = ok and rc == 0, motivo if rc == 0 else out.strip()
    return ok, motivo


_ACCIONES = {"nombre": (_poner_nombre, _quitar_nombre), "anuncios": (_poner_anuncios, _quitar_anuncios), "ping": (_poner_ping, _quitar_ping)}


def _elegidas(solo) -> list[str]:
    malas = [m for m in solo or [] if m not in MEDIDAS]
    if malas:
        raise ValueError(f"medida desconocida: {', '.join(malas)} (hay: {', '.join(MEDIDAS)})")
    return [m for m in MEDIDAS if not solo or m in solo]


def _aceptar_cambios(cfg, alerter) -> None:
    """Apagar Avahi cambia enlaces de systemd que Sentinel vigila: es un cambio pedido por el usuario."""
    identidad._aceptar_cambios(cfg, alerter, ["/etc/systemd/system/multi-user.target.wants/avahi-daemon.service",
                                              "/etc/systemd/system/sockets.target.wants/avahi-daemon.socket", "/etc/systemd/system/dbus-org.freedesktop.Avahi.service"])


def aplicar(cfg, alerter, solo: list[str] | None = None, run=core.run) -> dict:
    if plataforma.ES_MAC:
        return {"ok": False, "mensaje": "El modo discreto todavía no está disponible en macOS."}
    aplicado, hechas, fallos = _guardado(), [], []
    for m in _elegidas(solo):
        if m in aplicado:
            continue                                          # no se pisa lo que había antes de la primera vez
        ok, dato = _ACCIONES[m][0](cfg, run)
        if ok:
            aplicado[m] = dato
            _guardar(aplicado)
            hechas.append(m)
        else:
            fallos.append(f"{MEDIDAS[m]}: {dato or 'sin detalle'}")
    if "anuncios" in hechas:
        _aceptar_cambios(cfg, alerter)
    partes = []
    if hechas:
        partes.append("Modo discreto aplicado: " + "; ".join(MEDIDAS[m].lower() for m in hechas) + ".")
        if "nombre" in hechas:
            partes.append("El nombre dejará de enviarse desde la próxima vez que se conecte la red.")
    if fallos:
        partes.append("No se pudo (quedó como estaba): " + "; ".join(fallos))
    msg = " ".join(partes) or "Ya estaba aplicado."
    if hechas:
        alerter.emit("info", "discrecion", "aplicada", msg, key=f"discrecion:on:{int(core.now())}")
    return {"ok": not fallos, "mensaje": msg}


def revertir(cfg, alerter, solo: list[str] | None = None, run=core.run) -> dict:
    aplicado, hechas, fallos = _guardado(), [], []
    for m in _elegidas(solo):
        if m not in aplicado:
            continue
        ok, motivo = _ACCIONES[m][1](aplicado[m], run)
        if ok:
            del aplicado[m]
            _guardar(aplicado)
            hechas.append(m)
        else:
            fallos.append(f"{MEDIDAS[m]}: {motivo or 'sin detalle'}")
    if "anuncios" in hechas:
        _aceptar_cambios(cfg, alerter)
    if not hechas and not fallos:
        return {"ok": True, "mensaje": "No hay nada que deshacer."}
    msg = " ".join(([("Modo discreto deshecho: " + "; ".join(MEDIDAS[m].lower() for m in hechas) + ".")] if hechas else []) + (["No se pudo: " + "; ".join(fallos)] if fallos else []))
    if hechas:
        alerter.emit("info", "discrecion", "revertida", msg, key=f"discrecion:off:{int(core.now())}")
    return {"ok": not fallos, "mensaje": msg}
