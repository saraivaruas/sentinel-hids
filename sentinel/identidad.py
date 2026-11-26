"""Identidad del equipo en la red: dirección MAC e IP (por ahora solo Linux con NetworkManager).

Las funciones aceptan `run` (el ejecutor de comandos) para probarse sin tocar la red.
"""
from __future__ import annotations

import glob
import os
import re
import secrets
import shutil
import time

from . import core, plataforma

TIPOS = ("802-3-ethernet", "802-11-wireless")
ROTADORES = re.compile(r"(?<![a-z])(change[-_]?(mac|ip)(?![a-z])|macchanger)", re.I)   # «exchange-ip» no cuenta
CRON = ("/etc/crontab", "/etc/cron.d/*", "/var/spool/cron/crontabs/*")
# lo que «retirar» sabe quitar del método antiguo
CRON_SISTEMA = ("/etc/crontab", "/etc/cron.d/*")
CRON_USUARIOS = "/var/spool/cron/crontabs"
UNIDAD_ANTIGUA = "/etc/systemd/system/macchanger.service"
CARPETAS_SCRIPTS = ("/usr/local/bin", "/usr/local/sbin")
SCRIPT_ANTIGUO = re.compile(r"change[-_]?(mac|ip)(\.sh)?", re.I)         # el nombre completo del archivo
REGISTROS = "/var/log"
TEMPORIZADOR = "sentinel-identidad.timer"
ENLACE = "/etc/systemd/system/timers.target.wants/" + TEMPORIZADOR
HORAS = (1, 168)                                           # entre una hora y una semana


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


def cada_horas(cfg) -> int:
    try:
        n = cfg.getint("identidad", "cada_horas", fallback=2)
    except ValueError:
        n = 2
    return max(HORAS[0], min(HORAS[1], n))


def activa(cfg) -> bool:
    return cfg.get("identidad", "activo", fallback="no").strip().lower() == "yes"


def estado(cfg, run=core.run) -> dict:
    """Foto de solo lectura. Con «error» no vacío, no se puede rotar."""
    plan = {"activo": activa(cfg), "cada_horas": cada_horas(cfg), "ultimo_intento": _guardado().get("ultimo_intento", 0)}
    if plataforma.ES_MAC:
        return {**plan, "error": "La rotación de MAC e IP todavía no está disponible en macOS."}
    dev = interfaz(cfg, run)
    if not dev:
        return {**plan, "error": "No encuentro la interfaz de red con salida a internet. Indícala en [identidad] interfaz."}
    rc, out = run(["nmcli", "-g", "GENERAL.CON-UUID", "device", "show", dev], 10)
    uuid = out.strip()
    if rc != 0 or not uuid:
        return {**plan, "error": f"NetworkManager no administra {dev} (hace falta «nmcli» y una conexión activa)."}
    base = leer(uuid, ["connection.type"], run) or {}
    tipo = base.get("connection.type", "")
    if tipo not in TIPOS:
        return {**plan, "error": f"{dev} no es una conexión por cable ni Wi-Fi ({tipo or 'tipo desconocido'})."}
    v = leer(uuid, ["ipv4.method", "ipv4.dhcp-send-hostname"], run) or {}
    actual, fabrica = macs(dev, run)
    otros, completo = otros_rotadores(run)
    return {**plan, "error": "", "interfaz": dev, "conexion": uuid, "tipo": tipo, "mac": actual, "mac_fabrica": fabrica,
            "aleatoria": actual != fabrica, "ip": direccion(dev, run), "puerta": puerta(dev, run),
            "metodo": v.get("ipv4.method", ""), "envia_nombre": v.get("ipv4.dhcp-send-hostname", "") != "no",
            "otros": otros, "cron_revisado": completo, "restaurable": uuid in _guardado()["originales"]}


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
    core.atomic_write_json(_archivo(), d, share=True)
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
    valores = {**original, prop: original[prop] or "permanent"}
    if "nombre" in (core.read_json(os.path.join(core.state_dir(), "discrecion.json"), {}) or {}).get("aplicado", {}):
        valores.update({"ipv4.dhcp-send-hostname": "no", "ipv6.dhcp-send-hostname": "no"})    # el modo discreto sigue mandando
    ok, salida = _aplicar(uuid, dev, valores, run)
    if not ok:
        return {"ok": False, "mensaje": f"No pude restaurar {dev}: {salida}"}
    if not original[prop]:
        run(["nmcli", "connection", "modify", uuid, prop, ""], 20)
    del d["originales"][uuid]
    core.atomic_write_json(_archivo(), d, share=True)
    msg = f"Identidad restaurada en {dev}: MAC {macs(dev, run)[0]} · IP {direccion(dev, run) or 'ninguna'}"
    alerter.emit("info", "identidad", "restaurada", msg, key=f"identidad:rest:{int(core.now())}")
    return {"ok": True, "mensaje": msg}


def programada(cfg, alerter, run=core.run) -> dict | None:
    """La llama el temporizador: rota solo si la rotación está activada y ya pasó el intervalo. None = no tocaba."""
    if not activa(cfg) or core.now() - _guardado().get("ultimo_intento", 0) < cada_horas(cfg) * 3600 - 60:
        return None
    return rotar(cfg, alerter, run)


def _aceptar_cambios(cfg, alerter, rutas: list[str] | None = None) -> None:
    """Lo que Sentinel cambia por orden del usuario no se reporta como ataque."""
    from . import fim
    vigia = fim.Fim(cfg, alerter, core.Allow(cfg))
    if vigia.load() is not None:
        vigia.accept(rutas or [core.conf_path(), ENLACE])


def activar(cfg, horas: int, alerter, run=core.run) -> dict:
    """Enciende la rotación cada `horas`. El primer cambio llega al cumplirse el intervalo, no en este momento."""
    e = estado(cfg, run)
    if e["error"]:
        return {"ok": False, "mensaje": e["error"]}
    if not HORAS[0] <= horas <= HORAS[1]:
        return {"ok": False, "mensaje": f"El intervalo va de {HORAS[0]} a {HORAS[1]} horas."}
    if e["otros"]:
        return {"ok": False, "mensaje": "No se activó: otros programas ya cambian la MAC o la IP y se pisarían. Para retirarlos (con copia): sudo sentinel identidad retirar\n- " + "\n- ".join(e["otros"])}
    core.set_setting("identidad", "cada_horas", str(horas))
    core.set_setting("identidad", "activo", "yes")
    d = _guardado()
    d["ultimo_intento"] = core.now()
    core.atomic_write_json(_archivo(), d, share=True)
    rc, out = run(["systemctl", "enable", "--now", TEMPORIZADOR], 30)
    if rc != 0:
        core.set_setting("identidad", "activo", "no")
    _aceptar_cambios(cfg, alerter)
    if rc != 0:
        return {"ok": False, "mensaje": f"No se activó: no pude encender el temporizador ({out.strip() or 'sin detalle'})."}
    msg = f"Cambio de MAC e IP activado: cada {horas} h. El primero será dentro de {horas} h."
    alerter.emit("info", "identidad", "activada", msg, key=f"identidad:on:{int(core.now())}")
    return {"ok": True, "mensaje": msg}


def desactivar(cfg, alerter, run=core.run) -> dict:
    core.set_setting("identidad", "activo", "no")
    rc, out = run(["systemctl", "disable", "--now", TEMPORIZADOR], 30)
    _aceptar_cambios(cfg, alerter)
    msg = "Cambio programado de MAC e IP apagado. La MAC actual se mantiene; para volver a la de fábrica: sudo sentinel identidad restaurar"
    if rc != 0:
        msg += f" (aviso: no pude apagar el temporizador: {out.strip() or 'sin detalle'}; aunque siga, no cambiará nada)"
    alerter.emit("info", "identidad", "desactivada", msg, key=f"identidad:off:{int(core.now())}")
    return {"ok": True, "mensaje": msg}


# ---------- retirar el método antiguo (scripts sueltos, cron y macchanger.service), con copia y vuelta atrás
def _separar(texto: str) -> tuple[list[str], str]:
    """(líneas activas que rotan, el resto del archivo tal cual)."""
    fuera, resto = [], []
    for linea in texto.splitlines(keepends=True):
        if not linea.lstrip().startswith("#") and ROTADORES.search(linea):
            fuera.append(linea.strip())
        else:
            resto.append(linea)
    return fuera, "".join(resto)


def _es_script(ruta: str) -> bool:
    try:
        with open(ruta, "rb") as f:
            return os.path.isfile(ruta) and f.read(2) == b"#!"
    except OSError:
        return False


def plan_retiro(run=core.run) -> dict:
    """Qué se quitaría. «completo» es falso si faltan permisos para verlo todo."""
    plan = {"servicio": UNIDAD_ANTIGUA if os.path.isfile(UNIDAD_ANTIGUA) else "", "crontabs": {}, "cron": {}, "scripts": [], "registros": [], "completo": True}
    try:
        usuarios = sorted(os.listdir(CRON_USUARIOS)) if os.path.isdir(CRON_USUARIOS) else []
    except PermissionError:
        usuarios, plan["completo"] = [], False
    for u in usuarios:
        rc, texto = run(["crontab", "-u", u, "-l"], 10)
        if rc != 0:
            plan["completo"] = False
            continue
        fuera, resto = _separar(texto)
        if fuera:
            plan["crontabs"][u] = {"quitar": fuera, "antes": texto, "despues": resto}
    for patron in CRON_SISTEMA:
        for ruta in sorted(glob.glob(patron)):
            try:
                with open(ruta, encoding="utf-8") as f:
                    fuera, resto = _separar(f.read())
            except (OSError, UnicodeDecodeError):
                plan["completo"] = False
                continue
            if fuera:
                plan["cron"][ruta] = {"quitar": fuera, "despues": resto}
    for carpeta in CARPETAS_SCRIPTS:
        for ruta in sorted(glob.glob(os.path.join(carpeta, "*"))):
            nombre = os.path.basename(ruta)
            if SCRIPT_ANTIGUO.fullmatch(nombre) and _es_script(ruta):
                plan["scripts"].append(ruta)
                registro = os.path.join(REGISTROS, os.path.splitext(nombre)[0] + ".log")
                if os.path.isfile(registro):
                    plan["registros"].append(registro)
    return plan


def hay_algo(plan: dict) -> bool:
    return any(plan[k] for k in ("servicio", "crontabs", "cron", "scripts", "registros"))


def describir(plan: dict) -> list[str]:
    out = [f"Tarea de {u}: {x}" for u, v in plan["crontabs"].items() for x in v["quitar"]]
    out += [f"Línea de {r}: {x}" for r, v in plan["cron"].items() for x in v["quitar"]]
    if plan["servicio"]:
        out.append(f"Servicio: {plan['servicio']}")
    return out + [f"Archivo: {r}" for r in plan["scripts"] + plan["registros"]]


def _respaldos() -> str:
    return os.path.join(core.state_dir(), "retirados")


def retirar(cfg, alerter, run=core.run) -> dict:
    """Quita el método antiguo. Primero copia todo; con `devolver` queda como estaba."""
    plan = plan_retiro(run)
    if not plan["completo"]:
        return {"ok": False, "mensaje": "No pude revisar todas las tareas programadas (hace falta administrador). No se cambió nada."}
    if not hay_algo(plan):
        return {"ok": True, "mensaje": "No queda nada del método antiguo."}
    base = carpeta = os.path.join(_respaldos(), time.strftime("%Y%m%d-%H%M%S"))
    n = 1
    while os.path.exists(carpeta):
        n += 1
        carpeta = f"{base}-{n}"
    core.ensure_dir(carpeta, 0o700)
    archivos = [r for r in [*plan["cron"], plan["servicio"], *plan["scripts"], *plan["registros"]] if r]
    manifiesto = {"archivos": [], "crontabs": [], "servicio": False, "devuelto": False}
    for i, ruta in enumerate(archivos):
        copia = os.path.join(carpeta, f"{i:02d}-{os.path.basename(ruta)}")
        shutil.copy2(ruta, copia)
        st = os.stat(ruta)
        manifiesto["archivos"].append({"ruta": ruta, "copia": copia, "uid": st.st_uid, "gid": st.st_gid})
    for u, v in plan["crontabs"].items():
        copia = os.path.join(carpeta, f"crontab-{u}")
        with open(copia, "w", encoding="utf-8") as f:
            f.write(v["antes"])
        manifiesto["crontabs"].append({"usuario": u, "copia": copia})
    if plan["servicio"]:
        manifiesto["servicio"] = run(["systemctl", "is-enabled", "macchanger.service"], 5)[1].strip() == "enabled"
    core.atomic_write_json(os.path.join(carpeta, "manifiesto.json"), manifiesto)      # antes de tocar nada

    def fallo(que: str, salida: str) -> dict:
        return {"ok": False, "mensaje": f"No pude {que}: {salida.strip() or 'sin detalle'}. Para dejarlo como estaba: sudo sentinel identidad devolver", "carpeta": carpeta}

    for u, v in plan["crontabs"].items():
        nuevo = os.path.join(carpeta, f"crontab-{u}.nuevo")
        with open(nuevo, "w", encoding="utf-8") as f:
            f.write(v["despues"])
        rc, out = run(["crontab", "-u", u, nuevo], 15)
        if rc != 0:
            return fallo(f"cambiar las tareas de {u}", out)
    for ruta, v in plan["cron"].items():
        with open(ruta, "w", encoding="utf-8") as f:                                  # conserva dueño y permisos
            f.write(v["despues"])
    if plan["servicio"]:
        rc, out = run(["systemctl", "disable", "macchanger.service"], 30)
        if rc != 0:
            return fallo("desactivar macchanger.service", out)
        os.remove(plan["servicio"])
        run(["systemctl", "daemon-reload"], 30)
    for ruta in plan["scripts"] + plan["registros"]:
        os.remove(ruta)
    _aceptar_cambios(cfg, alerter, archivos + [os.path.join(os.path.dirname(UNIDAD_ANTIGUA), "multi-user.target.wants", "macchanger.service")])
    msg = f"Método antiguo retirado ({len(describir(plan))} elementos). Copia en {carpeta}. Para deshacerlo: sudo sentinel identidad devolver"
    alerter.emit("info", "identidad", "retirado", msg, key=f"identidad:retirado:{int(core.now())}")
    return {"ok": True, "mensaje": msg, "carpeta": carpeta}


def devolver(cfg, alerter, run=core.run) -> dict:
    """Repone lo último que quitó `retirar`."""
    if activa(cfg):
        return {"ok": False, "mensaje": "El cambio programado de Sentinel está activado y se pisarían. Apágalo antes: sudo sentinel identidad desactivar"}
    for ruta in sorted(glob.glob(os.path.join(_respaldos(), "*", "manifiesto.json")), reverse=True):
        m = core.read_json(ruta)
        if m and not m.get("devuelto"):
            break
    else:
        return {"ok": False, "mensaje": "No hay nada que devolver."}
    for a in m["archivos"]:
        shutil.copy2(a["copia"], a["ruta"])
        try:
            os.chown(a["ruta"], a["uid"], a["gid"])
        except OSError:
            pass
    errores = []
    for c in m["crontabs"]:
        rc, out = run(["crontab", "-u", c["usuario"], c["copia"]], 15)
        if rc != 0:
            errores.append(f"tareas de {c['usuario']}: {out.strip()}")
    if m["servicio"]:
        run(["systemctl", "daemon-reload"], 30)
        rc, out = run(["systemctl", "enable", "macchanger.service"], 30)
        if rc != 0:
            errores.append(f"macchanger.service: {out.strip()}")
    _aceptar_cambios(cfg, alerter, [a["ruta"] for a in m["archivos"]] + [os.path.join(os.path.dirname(UNIDAD_ANTIGUA), "multi-user.target.wants", "macchanger.service")])
    if errores:
        return {"ok": False, "mensaje": "Se repusieron los archivos, pero falló: " + "; ".join(errores)}
    m["devuelto"] = True
    core.atomic_write_json(ruta, m)
    msg = "Se repuso el método antiguo tal como estaba."
    alerter.emit("info", "identidad", "devuelto", msg, key=f"identidad:devuelto:{int(core.now())}")
    return {"ok": True, "mensaje": msg}
