#!/usr/bin/env python3
"""Prueba real en macOS: escucha el registro del sistema con el detector de Sentinel mientras la CI
(`mac-registro`) provoca accesos fallidos, y comprueba que salgan las alertas.

Uso: prueba-mac-accesos.py FIN   (escucha hasta que exista el archivo FIN). No bloquea nada ni toca el sistema.
"""
import os
import sys
import threading
import time

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [RAIZ, os.path.join(RAIZ, "tests")]
from helpers import Env  # noqa: E402
from sentinel import authwatch  # noqa: E402

ESPERADAS = {"fuerza_bruta", "acceso_tras_ataque", "sudo_fallido", "su_fallido"}


def main() -> int:
    fin = sys.argv[1]
    e = Env()
    a = authwatch.AuthWatch(e.cfg, e.alerter, e.allow, e.banner)
    original = a.handle

    def handle(ident, msg, *args, **kw):
        print("recibido:", ident, "|", msg[:200], flush=True)
        original(ident, msg, *args, **kw)

    a.handle = handle
    threading.Thread(target=a.follow, daemon=True).start()
    limite = time.time() + 180
    while not os.path.exists(fin) and time.time() < limite:
        time.sleep(1)
    eventos = e.events()
    for x in eventos:
        print("ALERTA:", x["sev"], x["kind"], "|", x["msg"])
    faltan = ESPERADAS - {x["kind"] for x in eventos}
    e.close()
    print("Faltan alertas: " + ", ".join(sorted(faltan)) if faltan else "Salieron todas las alertas esperadas.")
    return 1 if faltan else 0


if __name__ == "__main__":
    sys.exit(main())
