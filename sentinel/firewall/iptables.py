"""Cortafuegos iptables/ip6tables (para equipos sin ufw). Mismo contrato que ufw.py."""
from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess

from .. import core

NAME = "iptables"
TOOLS = (("4", "iptables"), ("6", "ip6tables"))
COMMENT = "sentinel-fw"


def available() -> bool:
    return bool(shutil.which("iptables"))


def active() -> bool:
    return available()


def parse_rules(text: str, fam: str = "4") -> list[dict]:
    """Interpreta «iptables -S INPUT»: solo las reglas que mencionan un puerto de destino; el resto se deja como está."""
    out = []
    for n, line in enumerate(text.splitlines(), 1):
        if not line.startswith("-A INPUT "):
            continue
        try:
            t = shlex.split(line)
        except ValueError:
            continue
        o = {t[i]: t[i + 1] for i in range(len(t) - 1) if t[i] in ("-p", "-s", "-i", "--dport", "-j", "--comment", "--dports")}
        port = o.get("--dport")
        if not port or not port.isdigit():
            continue
        action = {"ACCEPT": "ALLOW", "DROP": "DENY", "REJECT": "DENY"}.get(o.get("-j", ""), "OTHER")
        src = o.get("-s", "Anywhere"); src = "Anywhere" if src in ("0.0.0.0/0", "::/0") else src
        out.append({"id": (fam, line[3:]), "num": n, "to": f"{port}/{o.get('-p', '')}", "port": int(port), "proto": o.get("-p", ""), "action": action, "dir": "IN", "from": src,
                    "comment": o.get("--comment", ""), "v6": fam == "6", "iface": o.get("-i"), "label": f"{'ip6tables' if fam == '6' else 'iptables'}: {line[3:]}"})
    return out


def rules() -> tuple[list[dict], str]:
    allr, err = [], ""
    for fam, tool in TOOLS:
        if not shutil.which(tool):
            continue
        rc, out = core.run([tool, "-S", "INPUT"])
        if rc != 0:
            err = out.strip(); continue
        allr += parse_rules(out, fam)
    return allr, err


def policy(tool: str = "iptables") -> str:
    rc, out = core.run([tool, "-S", "INPUT"])
    m = re.search(r"^-P INPUT (\w+)", out, re.M)
    return m.group(1) if rc == 0 and m else ""


def outgoing_allowed() -> bool:
    rc, out = core.run(["iptables", "-S", "OUTPUT"])
    return bool(re.search(r"^-P OUTPUT ACCEPT", out, re.M))


def files() -> list[str]:
    return []


def allow(port: int, proto: str = "tcp", src: str | None = None, limit: bool = False) -> tuple[int, str]:
    worst = (0, "")
    for fam, tool in TOOLS:
        if shutil.which(tool):
            if src and (":" in src) != (fam == "6"):
                continue                      # el origen es de la otra familia (IPv4/IPv6)
            rc, o = core.run([tool, "-I", "INPUT", "1", *(["-s", src] if src else []), "-p", proto, "--dport", str(port), "-m", "comment", "--comment", COMMENT, "-j", "ACCEPT"])
            if rc != 0:
                worst = (rc, o)
    return worst


def delete_all(rs: list[dict]) -> list[tuple[dict, int, str]]:
    out = []
    for r in rs:
        fam, spec = r["id"]
        rc, o = core.run([dict(TOOLS)[fam], "-D", "INPUT"] + shlex.split(spec)[1:]); out.append((r, rc, o))
    return out


def harden() -> list[str]:
    """Si la política de entrada es ACCEPT no hay nada «cerrado»: deja pasar lo local y lo ya iniciado y recién entonces pone DROP."""
    log = []
    for fam, tool in TOOLS:
        if not shutil.which(tool) or policy(tool) != "ACCEPT":
            continue
        core.run([tool, "-I", "INPUT", "1", "-i", "lo", "-m", "comment", "--comment", COMMENT, "-j", "ACCEPT"])
        core.run([tool, "-I", "INPUT", "2", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-m", "comment", "--comment", COMMENT, "-j", "ACCEPT"])
        rc, o = core.run([tool, "-P", "INPUT", "DROP"]); log.append(f"{tool}: política de entrada = DROP" if rc == 0 else o.strip())
    return log


def restore(d: str) -> list[str]:
    log = []
    for fam, tool in TOOLS:
        f = os.path.join(d, f"{tool}.rules")
        if shutil.which(tool + "-restore") and os.path.exists(f):
            try:
                r = subprocess.run([tool + "-restore"], stdin=open(f), capture_output=True, text=True, timeout=30, check=False)
                log.append(f"{tool}: restaurado" if r.returncode == 0 else r.stderr.strip())
            except (OSError, subprocess.SubprocessError) as e:
                log.append(str(e))
    return log


def save() -> str:
    for cmd in (["netfilter-persistent", "save"], ["service", "iptables-persistent", "save"]):
        if shutil.which(cmd[0]) and core.run(cmd)[0] == 0:
            return "reglas guardadas para que sigan tras reiniciar"
    return "Aviso: iptables no guarda las reglas solo; instala «iptables-persistent» para que sobrevivan a un reinicio"
