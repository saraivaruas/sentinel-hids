"""Exposición real: cruza lo que escucha el equipo con lo que permite el firewall y con los puertos que publica Docker
(Docker abre puertos por su cuenta y esas reglas saltan el firewall de la entrada)."""
from __future__ import annotations

import re
import shutil

from .. import core

PRIVATE_PREFIX = ("100.", "fd7a:", "10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.", "172.2", "172.30.", "172.31.", "169.254.", "fe80:")
LOOP = ("127.", "[::1]", "::1")


def parse_ss(text: str) -> list[dict]:
    """Interpreta «ss -tulnpH»."""
    out, seen = [], set()
    for line in text.splitlines():
        f = line.split()
        if len(f) < 5 or not f[4].rsplit(":", 1)[-1].isdigit():
            continue
        addr, port = f[4].rsplit(":", 1)
        m = re.search(r'users:\(\("([^"]+)"', line)
        k = (f[0], int(port), addr)
        if k in seen:
            continue
        seen.add(k)
        out.append({"proto": f[0], "port": int(port), "addr": addr, "proc": m.group(1) if m else ""})
    return out


def parse_docker(text: str) -> list[dict]:
    """Interpreta «docker ps --format '{{.Names}}\\t{{.Ports}}'»: solo los puertos publicados hacia el equipo."""
    out = []
    for line in text.splitlines():
        name, _, ports = line.partition("\t")
        for seg in ports.split(","):
            m = re.match(r"^\s*(\[?[\w.:]*\]?):(\d+)->(\d+)/(tcp|udp)\s*$", seg)
            if not m:
                continue
            host, hport, cport, proto = m.groups()
            out.append({"name": name.strip(), "host": host or "0.0.0.0", "port": int(hport), "cport": int(cport), "proto": proto, "all": host in ("0.0.0.0", "::", "", "[::]", ":")})
    return out


def docker_published() -> tuple[list[dict], bool]:
    """(puertos publicados, ¿hay reglas DROP en DOCKER-USER que los protejan?)."""
    if not shutil.which("docker"):
        return [], False
    rc, out = core.run(["docker", "ps", "--format", "{{.Names}}\t{{.Ports}}"], 15)
    if rc != 0:
        return [], False
    prot = False
    if shutil.which("iptables"):
        rc, o = core.run(["iptables", "-S", "DOCKER-USER"])
        prot = rc == 0 and bool(re.search(r"-j (DROP|REJECT)", o))
    return parse_docker(out), prot


def status_of(item: dict, open_ports: set[int], docker_ports: dict[int, str], protected: bool) -> tuple[str, str]:
    a, p = item["addr"], item["port"]
    if a.startswith(LOOP) or a.startswith("127.0.0.53"):
        return "local", ""
    if p in docker_ports and item["proto"] == "tcp" and not protected:
        return "docker", f"El contenedor «{docker_ports[p]}» lo publica en todas las interfaces y Docker salta el firewall. Publícalo como 127.0.0.1:{p}:… en tu docker-compose, o agrega una regla en DOCKER-USER."
    if "%tailscale0" in a or a.startswith(("100.", "fd7a:")):
        return "privada", ""
    if p in open_ports:
        return "abierto", "Es un puerto que elegiste dejar abierto."
    return "bloqueado", ("El firewall lo bloquea desde afuera, pero escucha en todas las interfaces: si solo lo usas en este equipo, configúralo para escuchar en 127.0.0.1 y así no depende del firewall." if a in ("0.0.0.0", "*", "[::]", "::") else "")


def analyze(ss_text: str, open_ports: set[int], docker: list[dict], protected: bool = False) -> list[dict]:
    items = parse_ss(ss_text)
    docker_ports = {d["port"]: d["name"] for d in docker if d["all"]}
    have = {(i["proto"], i["port"]) for i in items}
    for d in docker:                       # publicados por Docker sin proceso que escuche (reglas NAT)
        if d["all"] and (d["proto"], d["port"]) not in have:
            items.append({"proto": d["proto"], "port": d["port"], "addr": "0.0.0.0", "proc": "docker"})
    out = []
    for i in items:
        st, adv = status_of(i, open_ports, docker_ports, protected)
        out.append(dict(i, status=st, advice=adv, local=st == "local"))
    order = {"docker": 0, "abierto": 1, "bloqueado": 2, "privada": 3, "local": 4}
    return sorted(out, key=lambda x: (order[x["status"]], x["port"]))
