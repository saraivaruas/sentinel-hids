#!/usr/bin/env python3
"""Prueba real en macOS del bloqueo con pf: conexiones de verdad entre direcciones de prueba del propio equipo.

SOLO para equipos desechables (la CI `mac-bloqueo`): enciende pf y añade direcciones a lo0. Necesita sudo.
"""
import os
import socket
import sys
import threading

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [RAIZ, os.path.join(RAIZ, "tests")]
from helpers import Env  # noqa: E402
from sentinel import core, pf  # noqa: E402

# (familia, atacante, vecino que no se bloquea, este equipo) — rangos reservados para documentación
CASOS = [
    (socket.AF_INET, "203.0.113.10", "203.0.113.12", "203.0.113.11"),
    (socket.AF_INET6, "2001:db8::10", "2001:db8::12", "2001:db8::11"),
]
fallos: list[str] = []


def comprobar(nombre: str, ok: bool) -> None:
    print(("OK    " if ok else "FALLO ") + nombre, flush=True)
    if not ok:
        fallos.append(nombre)


def servidor(familia: int, ip: str) -> socket.socket:
    s = socket.socket(familia, socket.SOCK_STREAM)
    s.bind((ip, 0))
    s.listen(50)

    def atender():
        while True:
            try:
                c, _ = s.accept()
            except OSError:
                return
            threading.Thread(target=eco, args=(c,), daemon=True).start()

    def eco(c):
        try:
            while True:
                d = c.recv(100)
                if not d:
                    return
                c.sendall(d)
        except OSError:
            pass

    threading.Thread(target=atender, daemon=True).start()
    return s


def conecta(familia: int, desde: str, destino: tuple):
    c = socket.socket(familia, socket.SOCK_STREAM)
    c.settimeout(3)
    try:
        c.bind((desde, 0))
        c.connect(destino[:2])
        c.sendall(b"hola")
        if c.recv(100) == b"hola":
            return c
    except OSError:
        pass
    c.close()
    return None


def sigue_viva(c: socket.socket) -> bool:
    try:
        c.sendall(b"otra")
        return c.recv(100) == b"otra"
    except OSError:
        return False


def main() -> int:
    for _, atacante, vecino, equipo in CASOS:
        for ip in (atacante, vecino, equipo):
            if ":" in ip:
                core.run(["ifconfig", "lo0", "inet6", ip, "prefixlen", "128", "alias"])
            else:
                core.run(["ifconfig", "lo0", "alias", ip, "255.255.255.255"])
    e = Env()
    e.cfg.set("ban", "backend", "auto")
    b = core.Banner(e.cfg, e.alerter, e.allow)
    comprobar("el motor automático es pf", b.backend() == "pf")
    for familia, atacante, vecino, equipo in CASOS:
        destino = servidor(familia, equipo).getsockname()
        abierta = conecta(familia, atacante, destino)
        comprobar(f"{atacante}: conecta antes del bloqueo", abierta is not None)
        comprobar(f"{atacante}: Sentinel lo bloquea", b.ban(atacante, "prueba real", 3600))
        comprobar(f"{atacante}: ya no puede conectar", conecta(familia, atacante, destino) is None)
        comprobar(f"{atacante}: se corta la conexión que tenía abierta", abierta is not None and not sigue_viva(abierta))
        comprobar(f"{vecino}: otra dirección sigue entrando", conecta(familia, vecino, destino) is not None)
        core.run(["pfctl", "-a", pf.ANCLA, "-F", "all"])  # como tras reiniciar: sin reglas ni tabla
        core.run(["pfctl", "-a", pf.ANCLA, "-t", pf.TABLA, "-T", "kill"])
        comprobar(f"{atacante}: sin reglas vuelve a entrar", conecta(familia, atacante, destino) is not None)
        comprobar(f"{atacante}: Sentinel repone el bloqueo", atacante in b.reafirmar())
        comprobar(f"{atacante}: bloqueado otra vez", conecta(familia, atacante, destino) is None)
        b.unban(atacante)
        comprobar(f"{atacante}: liberado, vuelve a conectar", conecta(familia, atacante, destino) is not None)
        b.ban(atacante, "caducidad", 3600)
        b.bans[atacante]["until"] = 0
        b.expire()
        comprobar(f"{atacante}: al caducar vuelve a conectar", conecta(familia, atacante, destino) is not None)
    for x in e.events():
        print("evento:", x["sev"], x["kind"], "|", x["msg"])
    print("--- pf ---")
    print(core.run(["pfctl", "-s", "info"])[1])
    print(core.run(["pfctl", "-sr"])[1])
    print(core.run(["pfctl", "-a", pf.ANCLA, "-sr"])[1])
    e.close()
    print(f"{len(fallos)} comprobaciones fallidas" if fallos else "Todas las comprobaciones pasaron.")
    return 1 if fallos else 0


if __name__ == "__main__":
    if os.environ.get("GITHUB_ACTIONS") != "true":
        sys.exit("Esta prueba cambia el cortafuegos: solo se ejecuta en la CI (GITHUB_ACTIONS=true).")
    sys.exit(main())
