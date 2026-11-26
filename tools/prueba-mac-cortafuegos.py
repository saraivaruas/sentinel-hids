#!/usr/bin/env python3
"""Prueba real en macOS del cortafuegos de puertos (pf): conexiones de verdad que deben seguir o rechazarse.

SOLO para equipos desechables (la CI `mac-bloqueo`): cambia el cortafuegos y añade direcciones a lo0. Necesita sudo.
Las conexiones de prueba van por lo0, así que aquí se quita la regla que deja pasar el loopback.
"""
import os
import socket
import sys
import threading
import time
import urllib.request

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [RAIZ, os.path.join(RAIZ, "tests")]
from helpers import Env  # noqa: E402
from sentinel import core, firewall  # noqa: E402
from sentinel.firewall import pf_mac  # noqa: E402

ATACANTE, EQUIPO, ABIERTO, CERRADO = "203.0.113.10", "203.0.113.11", 18080, 18081
fallos: list[str] = []


def comprobar(nombre: str, ok: bool, detalle: str = "") -> None:
    print(("OK    " if ok else "FALLO ") + nombre + ("" if ok or not detalle else f" — {detalle[:500]}"), flush=True)
    if not ok:
        fallos.append(nombre)


def servidor(puerto: int) -> None:
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((EQUIPO, puerto))
    s.listen(50)

    def eco(c):
        try:
            while True:
                d = c.recv(100)
                if not d:
                    return
                c.sendall(d)
        except OSError:
            pass

    def atender():
        while True:
            c, _ = s.accept()
            threading.Thread(target=eco, args=(c,), daemon=True).start()

    threading.Thread(target=atender, daemon=True).start()


def conecta(puerto: int):
    c = socket.socket()
    c.settimeout(3)
    try:
        c.bind((ATACANTE, 0))
        c.connect((EQUIPO, puerto))
        c.sendall(b"hola")
        if c.recv(100) == b"hola":
            return c
    except OSError:
        pass
    c.close()
    return None


def viva(c) -> bool:
    try:
        c.sendall(b"otra")
        return c.recv(100) == b"otra"
    except OSError:
        return False


def sale_a_internet() -> bool:
    try:
        urllib.request.urlopen("https://api.github.com", timeout=20).read(50)
        return True
    except urllib.error.HTTPError:
        return True                      # respondió (por ejemplo, límite de consultas): la conexión salió
    except OSError:
        return False


def main() -> int:
    for ip in (ATACANTE, EQUIPO):
        core.run(["ifconfig", "lo0", "alias", ip, "255.255.255.255"])
    os.makedirs("/usr/local/bin", exist_ok=True)
    if not os.path.exists("/usr/local/bin/sentinel"):
        os.symlink(os.path.join(RAIZ, "bin", "sentinel"), "/usr/local/bin/sentinel")        # la reversión programada lo ejecuta
    pf_mac.LOCAL = ""
    e = Env(extra=f"[firewall]\nprofile = custom\nallow_tcp = {ABIERTO}\n")
    cfg = e.cfg
    for p in (ABIERTO, CERRADO):
        servidor(p)
    previa = conecta(CERRADO)
    comprobar("antes: los dos puertos aceptan conexiones", previa is not None and conecta(ABIERTO) is not None)
    s = firewall.state(cfg)
    comprobar("el plan anuncia el puerto que se cerrará", s.get("ok") and CERRADO in [r["port"] for r in s["plan"]["remove"]], str(s.get("plan") or s))
    log = firewall.apply(cfg, probar=25)
    print("\n".join(log))
    print(core.run(["pfctl", "-a", pf_mac.ANCLA, "-sr"])[1])
    comprobar("a prueba: el puerto elegido sigue abierto", conecta(ABIERTO) is not None)
    comprobar("a prueba: el otro puerto rechaza conexiones nuevas", conecta(CERRADO) is None)
    comprobar("a prueba: la conexión que ya estaba abierta sigue", previa is not None and viva(previa))
    comprobar("a prueba: se puede salir a internet", sale_a_internet())
    comprobar("el estado dice que está aplicado", firewall.state(cfg).get("activo") is True)
    time.sleep(35)
    comprobar("sin confirmar, se revierte solo", conecta(CERRADO) is not None, core.run(["pfctl", "-a", pf_mac.ANCLA, "-sr"])[1])
    firewall.apply(cfg)
    comprobar("aplicado: cerrado", conecta(CERRADO) is None and conecta(ABIERTO) is not None)
    core.run(["pfctl", "-a", pf_mac.ANCLA, "-F", "rules"])                              # como tras reiniciar
    comprobar("sin reglas vuelve a abrirse", conecta(CERRADO) is not None)
    pf_mac.reafirmar()
    comprobar("el monitor repone lo confirmado", conecta(CERRADO) is None)
    cfg.set("ban", "backend", "auto")
    b = core.Banner(cfg, e.alerter, e.allow)
    comprobar("bloquear una IP cierra también el puerto abierto", b.ban(ATACANTE, "prueba", 600) and conecta(ABIERTO) is None)
    b.unban(ATACANTE)
    comprobar("al liberarla vuelve a entrar", conecta(ABIERTO) is not None)
    print("\n".join(firewall.restore()))
    comprobar("restaurar lo deja como antes", conecta(CERRADO) is not None)
    core.run(["pfctl", "-a", pf_mac.ANCLA, "-F", "rules"])
    e.close()
    print(f"{len(fallos)} comprobaciones fallidas" if fallos else "Todas las comprobaciones pasaron.")
    return 1 if fallos else 0


if __name__ == "__main__":
    if os.environ.get("GITHUB_ACTIONS") != "true":
        sys.exit("Esta prueba cambia el cortafuegos: solo se ejecuta en la CI (GITHUB_ACTIONS=true).")
    sys.exit(main())
