"""Cortafuegos de puertos en macOS, con pf: decide qué puertos aceptan conexiones nuevas desde fuera.

Las reglas van en un ancla propia («com.apple/sentinel-fw»), sin tocar /etc/pf.conf. Solo se rechazan las conexiones
NUEVAS que llegan: lo ya iniciado sigue, lo que sale del equipo se permite, y también el loopback, el ping, DHCP,
mDNS y Tailscale. Aplicar «a prueba» se deshace solo si no se confirma, y tras un reinicio el monitor repone lo confirmado.
"""
from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
import time

from .. import core, hostcheck, pf
from . import exposure

ANCLA = "com.apple/sentinel-fw"
LOCAL = "pass in quick on lo0 all"
SSHD_CONFIG = "/etc/ssh/sshd_config"


def _fw():
    from .. import firewall          # lo común con Linux (pendientes, foto, marca de cambios propios)
    return firewall


def estado_path() -> str:
    return os.path.join(core.state_dir(), "fw_mac.json")


def ssh_ports() -> dict:
    """En macOS el puerto de SSH lo abre launchd: se mira si el servicio está encendido y qué puerto dice su configuración."""
    if core.run(["launchctl", "print", "system/com.openssh.sshd"], 15)[0] != 0:
        return {"ports": [], "sessions": []}
    try:
        with open(SSHD_CONFIG, encoding="utf-8", errors="ignore") as f:
            puertos = [int(x) for x in re.findall(r"^\s*Port\s+(\d+)", f.read(), re.M)]
    except OSError:
        puertos = []
    return {"ports": puertos or [22], "sessions": []}


def deseado(conf: dict, ssh: dict) -> dict:
    restrict = conf.get("restrict", {})
    tcp = (set(conf["allow_tcp"]) | (set(ssh["ports"]) if conf["keep_ssh"] else set())) - set(restrict)
    return {"tcp": sorted(tcp), "udp": sorted(set(conf["allow_udp"])), "restrict": {str(p): list(s) for p, s in sorted(restrict.items())}}


def reglas(d: dict) -> str:
    lista = lambda puertos: "{ " + ", ".join(map(str, puertos)) + " }"
    r = ["pass out quick on ! lo0 all keep state", LOCAL,
         "pass in quick inet proto icmp all", "pass in quick inet6 proto icmp6 all",
         "pass in quick proto udp from any port 67 to any port 68", "pass in quick proto udp from any port 547 to any port 546",
         "pass in quick proto udp from any to any port 5353", "pass in quick inet from 100.64.0.0/10 to any"]
    if d["tcp"]:
        r.append(f"pass in quick proto tcp from any to any port {lista(d['tcp'])}")
    if d["udp"]:
        r.append(f"pass in quick proto udp from any to any port {lista(d['udp'])}")
    for puerto, origenes in d["restrict"].items():
        r += [f"pass in quick proto tcp from {o} to any port {int(puerto)}" for o in origenes]
    r += ["block return in proto tcp from any to any flags S/SA", "block return in proto udp from any to any"]
    return "\n".join(r) + "\n"


def activo() -> bool:
    return "block" in core.run(["pfctl", "-a", ANCLA, "-sr"], 15)[1]


def _cargar(texto: str) -> str:
    return pf.preparar(core.run, core.state_dir(), ancla=ANCLA, reglas=texto, marca=None, archivo="pf-sentinel-fw.conf")


def _regla(puerto, proto: str, desde: str = "Anywhere", comentario: str = "") -> dict:
    return {"label": f"{puerto}/{proto}", "port": int(puerto), "action": "ALLOW", "dir": "IN", "from": desde, "comment": comentario, "iface": "", "v6": False}


def _reglas_de(d: dict) -> list[dict]:
    return ([_regla(p, "tcp") for p in d["tcp"]] + [_regla(p, "udp") for p in d["udp"]]
            + [_regla(p, "tcp", o) for p, origenes in d["restrict"].items() for o in origenes])


def _escuchando() -> str:
    salida = ""
    for filtro in (["-iTCP", "-sTCP:LISTEN"], ["-iUDP"]):
        rc, out = core.run(["lsof", "-nP", *filtro, "-F", "pcPn"], 30)
        salida += hostcheck.lsof_a_ss(out if rc in (0, 1) else "")
    return salida


def state(conf: dict) -> dict:
    """La misma forma de foto que en Linux, para el panel y la línea de comandos."""
    rc, out = core.run(["pfctl", "-s", "info"], 15)
    if rc != 0:
        return {"ok": False, "error": "no pude leer pf (hace falta administrador)", "backend": "pf", "conf": conf, "time": core.iso()}
    ssh, ss = ssh_ports(), _escuchando()
    quiero = deseado(conf, ssh)
    aplicado = core.read_json(estado_path()) if activo() else None
    escuchan = exposure.parse_ss(ss)
    abiertos = set(quiero["tcp"] + quiero["udp"]) if aplicado else {e["port"] for e in escuchan}
    expuestos = exposure.analyze(ss, abiertos, [], False)
    if not aplicado:
        for e in expuestos:
            if e["status"] == "abierto":
                e["advice"] = "El cortafuegos de puertos de Sentinel no está aplicado: según la configuración de macOS puede recibir conexiones."
        permitidos = set(quiero["tcp"] + quiero["udp"]) | {int(p) for p in quiero["restrict"]}
        sobran = [_regla(e["port"], e["proto"], comentario=f"{e.get('proc') or '?'} escucha: dejará de aceptar conexiones de fuera")
                  for e in expuestos if not e["local"] and e["status"] == "abierto" and e["port"] not in permitidos and e["port"] < 49152]
        faltan = quiero["tcp"] + quiero["udp"]
        faltan_desde = [[int(p), o] for p, origenes in quiero["restrict"].items() for o in origenes]
        reglas_ahora = []
    else:
        antes, ahora = _reglas_de(aplicado), _reglas_de(quiero)
        clave = lambda r: (r["label"], r["from"])
        sobran = [r for r in antes if clave(r) not in {clave(x) for x in ahora}]
        nuevas = [r for r in ahora if clave(r) not in {clave(x) for x in antes}]
        faltan = [r["port"] for r in nuevas if r["from"] == "Anywhere"]
        faltan_desde = [[r["port"], r["from"]] for r in nuevas if r["from"] != "Anywhere"]
        reglas_ahora = antes
    vistos, unicos = set(), []
    for r in sobran:
        if (r["label"], r["from"]) not in vistos:
            vistos.add((r["label"], r["from"])); unicos.append(r)
    texto = ["Cortafuegos: pf" + ("" if aplicado else " (las reglas de puertos de Sentinel no están aplicadas)"),
             "Puertos que quedarán abiertos desde afuera: " + (", ".join(map(str, quiero["tcp"] + quiero["udp"])) or "ninguno")]
    texto += [f"  • se cerrará  {r['label']}  {r['comment']}".rstrip() for r in unicos] or ["  • no hay puertos que cerrar"]
    texto += [f"  • se abrirá   {p}" for p in faltan] + [f"  • se abrirá   {p}/tcp solo desde {o}" for p, o in faltan_desde]
    ser = lambda rs: [{k: r[k] for k in ("label", "port", "action", "from", "comment", "v6")} for r in rs]
    return {"ok": True, "backend": "pf", "conf": conf, "ssh": ssh, "time": core.iso(), "needs_harden": False, "safe": True, "activo": bool(aplicado),
            "plan": {"remove": ser(unicos), "review": [], "missing": faltan, "missing_from": faltan_desde, "keep_ports": sorted(set(quiero["tcp"] + quiero["udp"]) | {int(p) for p in quiero["restrict"]})},
            "pending": _fw().pending(), "rules": ser(reglas_ahora), "listening": expuestos, "docker": [], "docker_protected": False,
            "exposed_count": sum(1 for e in expuestos if e["status"] == "abierto" and not aplicado), "text": texto}


def apply(conf: dict, probar: int = 0) -> list[str]:
    fw = _fw()
    binario = shutil.which("sentinel") or "/usr/local/bin/sentinel"
    if probar and not os.path.exists(binario):
        return ["No se aplicó nada: para probar con reversión automática Sentinel tiene que estar instalado."]
    quiero = deseado(conf, ssh_ports())
    copia = os.path.join(core.state_dir(), "firewall-copia-" + time.strftime("%Y%m%d-%H%M%S"))
    anterior = core.read_json(estado_path())
    core.atomic_write_json(os.path.join(copia, "fw_mac.json"), anterior if anterior and anterior.get("confirmado") else {}, 0o600)
    error = _cargar(reglas(quiero))
    if error:
        return [f"No se aplicó: {error}"]
    core.atomic_write_json(estado_path(), dict(quiero, confirmado=not probar), 0o600)
    fw.mark_applied()
    log = [f"Copia del estado anterior en {copia}", "Puertos abiertos desde fuera: " + (", ".join(map(str, quiero["tcp"] + quiero["udp"])) or "ninguno")]
    if probar:
        core.atomic_write_json(fw.pending_path(), {"copy": copia, "deadline": core.now() + probar, "seconds": probar}, 0o640, share=True)
        orden = f"sleep {int(probar)}; exec {shlex.quote(binario)} firewall restaurar --pendiente"
        try:
            subprocess.Popen(["/bin/sh", "-c", orden], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        except OSError:
            return log + ["No pude programar la reversión automática; deshago los cambios.", *restore(copia)]
        log.append(f"Cambios aplicados A PRUEBA: confírmalos en {probar} s con  sudo sentinel firewall confirmar  o se revertirán solos.")
    return log


def confirm() -> list[str]:
    fw = _fw()
    pendiente = core.read_json(fw.pending_path(), None)
    e = core.read_json(estado_path())
    if not pendiente or not e:
        return ["No había cambios pendientes de confirmar."]
    core.atomic_write_json(estado_path(), dict(e, confirmado=True), 0o600)
    try:
        os.remove(fw.pending_path())
    except OSError:
        pass
    return ["Cambios confirmados: ya no se revertirán."]


def restore(d: str | None = None, use_pending: bool = False) -> list[str]:
    """Vuelve a como estaba antes de aplicar (la copia pendiente, la indicada o la más reciente)."""
    fw = _fw()
    p = core.read_json(fw.pending_path(), None)
    if use_pending:
        if not p or p.get("deadline", 0) > core.now() + 2:          # ya se confirmó, o es la prueba de un cambio posterior
            return ["No había cambios pendientes de revertir."]
        d = p.get("copy")
    if not d:
        base = core.state_dir()
        copias = sorted(x for x in os.listdir(base) if x.startswith("firewall-copia-")) if os.path.isdir(base) else []
        d = os.path.join(base, copias[-1]) if copias else None
    anterior = core.read_json(os.path.join(d, "fw_mac.json")) if d else None
    if anterior:
        error = _cargar(reglas(anterior))
        if error:
            return [f"No pude restaurar: {error}"]
        core.atomic_write_json(estado_path(), anterior, 0o600)
        log = ["Restauradas las reglas anteriores de Sentinel."]
    else:
        rc, out = core.run(["pfctl", "-a", ANCLA, "-F", "rules"], 15)
        if rc != 0:
            return [f"No pude quitar las reglas: {out.strip()[-160:]}"]
        if os.path.exists(estado_path()):
            os.remove(estado_path())
        log = ["Quitadas las reglas de puertos de Sentinel: todo queda como antes."]
    for f in (fw.pending_path(),):
        if os.path.exists(f):
            os.remove(f)
    fw.mark_applied()
    return log


def reafirmar() -> None:
    """Lo llama el monitor: repone las reglas confirmadas tras un reinicio y revierte una prueba que venció sin confirmarse."""
    e = core.read_json(estado_path())
    if not e or not core.is_root():
        return
    if not e.get("confirmado"):
        p = core.read_json(_fw().pending_path(), None)
        if not p or p.get("deadline", 0) <= core.now():
            restore((p or {}).get("copy"))
        return
    if not activo():
        _cargar(reglas(e))
        _fw().mark_applied()
