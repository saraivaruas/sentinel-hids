"""Módulo Firewall: decide qué puertos quedan abiertos desde afuera y lo aplica con ufw o iptables.

Es independiente de la detección de Sentinel (que solo avisa y bloquea IPs): se configura en [firewall] y por defecto solo muestra el plan."""
from __future__ import annotations

import os
import re
import shutil
import time

from .. import core
from . import exposure, iptables, ufw

BACKENDS = {"ufw": ufw, "iptables": iptables}


def settings(cfg=None) -> dict:
    cfg = cfg or core.load_config()
    g = lambda k, d="": cfg.get("firewall", k, fallback=d)
    return {"backend": g("backend", "auto"), "allow_tcp": [int(x) for x in core.csv(g("allow_tcp", "80,443")) if x.isdigit()],
            "allow_udp": [int(x) for x in core.csv(g("allow_udp", "")) if x.isdigit()], "keep_ssh": g("keep_ssh", "yes").lower() in ("yes", "true", "1", "si", "sí")}


def pick(name: str = "auto"):
    """auto = ufw si está activo; si no, iptables."""
    if name in BACKENDS:
        return BACKENDS[name] if BACKENDS[name].available() else None
    if ufw.available() and ufw.active():
        return ufw
    return iptables if iptables.available() else (ufw if ufw.available() else None)


def ssh_ports(ss_text: str | None = None) -> dict:
    """Puertos donde este equipo SIRVE ssh (sshd escuchando) y desde qué IPs hay sesiones abiertas ahora.
    Las conexiones ssh que este equipo hace hacia otros (despliegues) son salientes y no dependen de estas reglas."""
    if ss_text is None:
        rc, ss_text = core.run(["ss", "-tlnpH"])
    ports = set()
    for line in ss_text.splitlines():
        if "sshd" in line:
            m = re.search(r":(\d+)\s", line)
            if m:
                ports.add(int(m.group(1)))
    sessions = []
    if ports:
        rc, est = core.run(["ss", "-tnH", "state", "established"])
        for line in est.splitlines():
            f = line.split()
            if len(f) >= 4 and any(f[2].rsplit(":", 1)[-1] == str(p) for p in ports):
                sessions.append(f[3].rsplit(":", 1)[0].strip("[]"))
    return {"ports": sorted(ports), "sessions": sorted(set(sessions))}


def plan(rules: list[dict], conf: dict, ssh: dict, outgoing_ok: bool = True) -> dict:
    """Qué reglas sobran, cuáles faltan y cuáles se dejan (sin tocar nada)."""
    keep_ports = set(conf["allow_tcp"]) | set(conf["allow_udp"]) | (set(ssh.get("ports", [])) if conf["keep_ssh"] else set())
    remove, keep, review = [], [], []
    for r in rules:
        if r["action"] != "ALLOW" or r["dir"] != "IN":
            keep.append(r); continue
        local = r["from"].startswith(("127.", "::1")) or r["iface"] in ("lo", "tailscale0")
        if local or r["port"] in keep_ports:
            keep.append(r)
        elif r["from"].lower().startswith("anywhere"):
            remove.append(r)
        else:
            review.append(r)          # permiso para un equipo concreto: lo decide una persona
    present = {r["port"] for r in rules if r["action"] == "ALLOW" and r["dir"] == "IN" and r["from"].lower().startswith("anywhere") and r["port"]}
    missing = sorted(p for p in keep_ports if p not in present)
    return {"remove": remove, "keep": keep, "review": review, "missing": missing, "keep_ports": sorted(keep_ports), "ssh": ssh, "safe": outgoing_ok}


def describe(p: dict, backend: str = "") -> list[str]:
    L = [f"Cortafuegos: {backend or '—'}", "Puertos que quedarán abiertos desde afuera: " + (", ".join(map(str, p["keep_ports"])) or "ninguno")
         + (f"  (SSH que sirve este equipo: {p['ssh']['ports']})" if p["ssh"]["ports"] else "  (este equipo no sirve SSH: tus conexiones ssh hacia otros servidores no se tocan)")]
    if p["ssh"]["sessions"]:
        L.append("Sesiones SSH abiertas ahora desde: " + ", ".join(p["ssh"]["sessions"]) + " (se mantienen)")
    L += [f"  • se cerrará  {r['label']}  {r['comment']}".rstrip() for r in p["remove"]] or ["  • no hay reglas que cerrar"]
    L += [f"  • se abrirá   {m}/tcp" for m in p["missing"]]
    L += [f"  • revisar a mano (permite a un equipo concreto): {r['label']} desde {r['from']}" for r in p["review"]]
    if not p["safe"]:
        L.append("  ! El tráfico saliente no está permitido por defecto: no se aplica nada para no cortar tus despliegues por SSH.")
    return L


def state(cfg=None) -> dict:
    """Foto completa (la toma root; el panel la lee): backend, reglas, plan y puertos escuchando."""
    conf = settings(cfg)
    be = pick(conf["backend"])
    if be is None:
        return {"ok": False, "error": "No hay ufw ni iptables instalado", "conf": conf, "time": core.iso()}
    rules, err = be.rules()
    if err:
        return {"ok": False, "error": err, "backend": be.NAME, "conf": conf, "time": core.iso()}
    ssh = ssh_ports()
    p = plan(rules, conf, ssh, be.outgoing_allowed())
    rc, ss = core.run(["ss", "-tulnpH"])
    open_now = {r["port"] for r in rules if r["action"] == "ALLOW" and r["from"].lower().startswith("anywhere") and r["port"]}
    docker, dprot = exposure.docker_published()
    expo = exposure.analyze(ss, open_now, docker, dprot)
    ser = lambda rs: [{k: r[k] for k in ("label", "port", "action", "from", "comment", "v6")} for r in rs]
    return {"ok": True, "backend": be.NAME, "conf": conf, "ssh": ssh, "time": core.iso(), "needs_harden": be.NAME == "iptables" and be.policy() == "ACCEPT", "safe": p["safe"],
            "plan": {"remove": ser(p["remove"]), "review": ser(p["review"]), "missing": p["missing"], "keep_ports": p["keep_ports"]},
            "rules": ser(rules), "listening": expo, "docker": docker, "docker_protected": dprot, "exposed_count": sum(1 for e in expo if e["status"] in ("docker", "abierto")), "text": describe(p, be.NAME)}


def snapshot_path() -> str:
    return os.path.join(core.state_dir(), "firewall.json")


def save_snapshot(cfg=None) -> dict:
    s = state(cfg)
    core.atomic_write_json(snapshot_path(), s, 0o640, share=True)
    return s


def apply(cfg=None, harden: bool = False, state_dir: str | None = None, conf_dirs: list[str] | None = None) -> list[str]:
    """Aplica el plan: copia de las reglas, abre lo que falta, cierra lo que sobra y comprueba que el SSH siga permitido."""
    if not core.is_root():
        return ["Necesita administrador: ejecuta  sudo sentinel firewall aplicar"]
    conf = settings(cfg)
    be = pick(conf["backend"])
    if be is None:
        return ["No hay ufw ni iptables instalado."]
    rules, err = be.rules()
    if err:
        return [f"No pude leer las reglas: {err}"]
    ssh = ssh_ports()
    p = plan(rules, conf, ssh, be.outgoing_allowed())
    if not p["safe"]:
        return ["No se aplicó nada (el tráfico saliente no está permitido: podría cortar tus despliegues por SSH)."]
    d = os.path.join(state_dir or core.state_dir(), "firewall-copia-" + time.strftime("%Y%m%d-%H%M%S"))
    log = []
    try:
        os.makedirs(d, exist_ok=True)
        for f in (conf_dirs if conf_dirs is not None else be.files()):
            if os.path.exists(f):
                shutil.copy2(f, d)
        if be.NAME == "iptables":
            for fam, tool in iptables.TOOLS:
                if shutil.which(tool):
                    rc, out = core.run([tool + "-save"])
                    open(os.path.join(d, f"{tool}.rules"), "w").write(out)
    except OSError as e:
        return [f"No se aplicó nada: no pude guardar la copia de las reglas ({e.strerror})"]
    log.append(f"Copia de las reglas en {d}")
    for port in p["missing"]:
        rc, out = be.allow(port, "udp" if port in conf["allow_udp"] and port not in conf["allow_tcp"] else "tcp")
        log.append(f"abrir {port}: {'ok' if rc == 0 else out.strip()}")
    for r, rc, out in be.delete_all(p["remove"]):
        log.append(f"cerrar {r['label']}: {'ok' if rc == 0 else out.strip()}")
    if harden:
        log += be.harden()
    after, _ = be.rules()
    still = {r["port"] for r in after if r["action"] == "ALLOW"}
    for port in (ssh["ports"] if conf["keep_ssh"] else []):
        if port not in still:
            be.allow(port); log.append(f"SSH {port}/tcp se había perdido: restaurado")
    sv = be.save()
    if sv:
        log.append(sv)
    return log


def set_config(key: str, value: str, path: str | None = None) -> None:
    """Cambia un valor de [firewall] en sentinel.conf (valida antes de escribir)."""
    if key == "backend" and value not in ("auto", "ufw", "iptables"):
        raise ValueError("backend inválido")
    elif key in ("allow_tcp", "allow_udp"):
        vals = core.csv(value)
        if not all(v.isdigit() and 1 <= int(v) <= 65535 for v in vals) or len(vals) > 20:
            raise ValueError("puertos inválidos")
        value = ",".join(vals)
    elif key == "keep_ssh":
        if value not in ("yes", "no"):
            raise ValueError("keep_ssh: yes o no")
    else:
        raise ValueError("clave desconocida")
    path = path or core.conf_path()
    txt = open(path, encoding="utf-8").read() if os.path.exists(path) else ""
    m = re.search(r"^\[firewall\]\s*$", txt, re.M)
    if not m:
        txt = txt.rstrip("\n") + f"\n\n[firewall]\n{key} = {value}\n"
    else:
        end = re.search(r"^\[", txt[m.end():], re.M)
        sec_end = m.end() + end.start() if end else len(txt)
        sec = txt[m.end():sec_end]
        k = re.search(rf"^{key}\s*=.*$", sec, re.M)
        sec = sec[:k.start()] + f"{key} = {value}" + sec[k.end():] if k else sec.rstrip("\n") + f"\n{key} = {value}\n" + ("\n" if end else "")
        txt = txt[:m.end()] + sec + txt[sec_end:]
    with open(path, "w", encoding="utf-8") as f:
        f.write(txt)
