#!/usr/bin/env python3
"""Prueba real en macOS de la captura de paquetes (BPF): un escaneo de puertos de verdad por lo0 y tráfico real por la red.

SOLO para equipos desechables (la CI `mac-captura`): añade direcciones de prueba a lo0. Necesita sudo.
"""
import os
import socket
import sys
import threading
import time
import urllib.request
from unittest import mock

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [RAIZ, os.path.join(RAIZ, "tests")]
from helpers import Env  # noqa: E402
from sentinel import core, intel as intel_mod, packets  # noqa: E402

fallos: list[str] = []


def comprobar(nombre: str, ok: bool, detalle: str = "") -> None:
    print(("OK    " if ok else "FALLO ") + nombre + (f" — {detalle}" if detalle else ""), flush=True)
    if not ok:
        fallos.append(nombre)


def capturar(interfaz: str, generar):
    e = Env()
    e.cfg.set("packets", "interface", interfaz)
    it = intel_mod.Intel(e.cfg); it.geo.mode = "off"
    w = packets.PacketWatcher(e.cfg, core.Alerter(e.cfg, quiet=True), e.allow, mock.Mock(), it)
    w.local = set()                     # en lo0 el atacante de prueba también es una dirección «propia»
    parar = threading.Event()
    hilo = threading.Thread(target=w.run, args=(parar.is_set,), daemon=True); hilo.start()
    time.sleep(2)
    generar()
    time.sleep(3)
    parar.set(); hilo.join(10)
    eventos = core.read_events(0, "info")
    e.close()
    return w, eventos


def escaneo() -> None:
    for puerto in range(20000, 20040):
        s = socket.socket()
        s.settimeout(0.3)
        s.bind(("203.0.113.9", 0))
        try:
            s.connect(("203.0.113.11", puerto))
        except OSError:
            pass
        s.close()


def navegar() -> None:
    for _ in range(3):
        try:
            urllib.request.urlopen("https://api.github.com", timeout=15).read(100)
        except OSError:
            pass


def main() -> int:
    for ip in ("203.0.113.9", "203.0.113.11"):
        core.run(["ifconfig", "lo0", "alias", ip, "255.255.255.255"])
    w, eventos = capturar("lo0", escaneo)
    print("lo0:", w.stats)
    comprobar("captura en lo0 sin errores", not any(x["kind"] == "no_disponible" for x in eventos), str([x["msg"] for x in eventos]))
    comprobar("detecta el escaneo de puertos real", any(x["kind"] == "escaneo_syn" and "203.0.113.9" in x["msg"] for x in eventos), str([x["msg"] for x in eventos]))
    comprobar("pide bloquear al atacante", any(c[0][0] == "203.0.113.9" for c in w.banner.ban.call_args_list))
    iface = packets.PacketWatcher.interfaz_mac()
    w, eventos = capturar("", navegar)
    print(iface, ":", w.stats)
    comprobar(f"captura tráfico real en {iface}", w.stats["vistos"] > 0)
    comprobar("navegar normal no se confunde con un ataque", w.stats["detectados"] == 0, str([x["msg"] for x in eventos]))
    comprobar("reconoce las direcciones propias", "127.0.0.1" in packets.PacketWatcher._local_addrs())
    print(f"{len(fallos)} comprobaciones fallidas" if fallos else "Todas las comprobaciones pasaron.")
    return 1 if fallos else 0


if __name__ == "__main__":
    if os.environ.get("GITHUB_ACTIONS") != "true":
        sys.exit("Esta prueba añade direcciones de red: solo se ejecuta en la CI (GITHUB_ACTIONS=true).")
    sys.exit(main())
