"""Cierre de puertos: deja el cortafuegos (ufw) permitiendo desde afuera solo web (80 y 443) y el SSH que el equipo realmente sirve.

Nunca abre nada que no sea 80, 443 o el puerto de sshd; por defecto solo muestra el plan, y aplicarlo guarda una copia de las reglas."""
from __future__ import annotations

import os
import re
import shutil
import time

from . import core

WEB = (80, 443)
RULE = re.compile(r"^\[\s*(\d+)\]\s+(.+?)\s{2,}(ALLOW|DENY|REJECT|LIMIT)(?: (IN|OUT|FWD))?\s+(.+?)(?:\s+#\s*(.*))?\s*$")


def parse_rules(text: str) -> list[dict]:
    """Interpreta «ufw status numbered»."""
    out = []
    for line in text.splitlines():
        m = RULE.match(line.strip())
        if not m:
            continue
        num, to, action, direction, frm, comment = m.groups()
        pm = re.match(r"^(\d+)(?::\d+)?(?:/(tcp|udp))?(?:\s+\(v6\))?$", to.strip())
        out.append({"num": int(num), "to": to.strip(), "port": int(pm.group(1)) if pm else None, "action": action, "dir": direction or "IN",
                    "from": frm.strip(), "comment": comment or "", "v6": "(v6)" in to or "(v6)" in frm,
                    "iface": (re.search(r"on (\S+)", to) or re.search(r"on (\S+)", frm) or [None, None])[1]})
    return out


def ssh_ports(sshd_config: str = "/etc/ssh/sshd_config", ss_text: str | None = None) -> dict:
    """Puertos en los que este equipo SIRVE ssh (sshd escuchando) y desde qué IPs hay sesiones abiertas ahora."""
    if ss_text is None:
        rc, ss_text = core.run(["ss", "-tlnpH"])
    ports = set()
    for line in ss_text.splitlines():
        if "sshd" in line:
            m = re.search(r":(\d+)\s+\S+\s+users", line) or re.search(r":(\d+)\s", line)
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


def plan(rules: list[dict], ssh: dict, default_out_allow: bool = True) -> dict:
    """Qué reglas sobran, cuáles faltan y cuáles se dejan (sin tocar nada)."""
    keep_ports = set(WEB) | set(ssh.get("ports", []))
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
    return {"remove": remove, "keep": keep, "review": review, "missing": missing, "keep_ports": sorted(keep_ports), "ssh": ssh, "safe": default_out_allow}


def describe(p: dict) -> list[str]:
    L = ["Puertos que quedarán abiertos desde afuera: " + ", ".join(map(str, p["keep_ports"])) + (f"  (SSH del equipo: {p['ssh']['ports']})" if p["ssh"]["ports"] else "  (este equipo no sirve SSH: tus conexiones ssh hacia otros servidores no se tocan)")]
    if p["ssh"]["sessions"]:
        L.append("Sesiones SSH abiertas ahora desde: " + ", ".join(p["ssh"]["sessions"]) + " (se mantienen)")
    L += [f"  • se cerrará  [{r['num']}] {r['to']}  {r['comment']}" for r in p["remove"]] or ["  • no hay reglas que cerrar"]
    L += [f"  • se abrirá   {m}/tcp" for m in p["missing"]]
    L += [f"  • revisar a mano (permite a un equipo concreto): [{r['num']}] {r['to']} desde {r['from']}" for r in p["review"]]
    if not p["safe"]:
        L.append("  ! El tráfico saliente no está permitido por defecto: no se aplica nada para no cortar tus despliegues por SSH.")
    return L


def apply(p: dict, state_dir: str | None = None, ufw_dir: str = "/etc/ufw") -> list[str]:
    """Aplica el plan con ufw: primero abre lo que falta, luego cierra (de mayor a menor número) y comprueba que el SSH siga permitido."""
    if not core.is_root():
        return ["Necesita administrador: ejecuta  sudo sentinel puertos --aplicar"]
    if not p["safe"]:
        return ["No se aplicó nada (el tráfico saliente no está permitido)."]
    log = []
    d = os.path.join(state_dir or core.state_dir(), "ufw-copia-" + time.strftime("%Y%m%d-%H%M%S"))
    os.makedirs(d, exist_ok=True)
    try:
        for f in ("user.rules", "user6.rules"):
            if os.path.exists(os.path.join(ufw_dir, f)):
                shutil.copy2(os.path.join(ufw_dir, f), d)
    except OSError as e:
        return [f"No se aplicó nada: no pude guardar la copia de las reglas ({e.strerror})"]
    log.append(f"Copia de las reglas en {d}")
    for port in p["missing"]:
        rc, out = core.run(["ufw", "allow", f"{port}/tcp"]); log.append(f"abrir {port}/tcp: {'ok' if rc == 0 else out.strip()}")
    for r in sorted(p["remove"], key=lambda r: -r["num"]):
        rc, out = core.run(["ufw", "--force", "delete", str(r["num"])]); log.append(f"cerrar [{r['num']}] {r['to']}: {'ok' if rc == 0 else out.strip()}")
    rc, out = core.run(["ufw", "status", "numbered"])
    after = {r["port"] for r in parse_rules(out) if r["action"] == "ALLOW"}
    for port in p["ssh"]["ports"]:
        if port not in after:
            core.run(["ufw", "allow", f"{port}/tcp"]); log.append(f"SSH {port}/tcp se había perdido: restaurado")
    return log
