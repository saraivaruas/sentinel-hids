#!/usr/bin/env python3
"""Prueba real en macOS del panel instalado: abre cada página de datos, lanza una acción y muestra una notificación.

Se ejecuta como el usuario del equipo (no como root), con Sentinel ya instalado (la CI `mac-instalar`).
"""
import json
import os
import subprocess
import sys
import time
import urllib.request

sys.path.insert(0, "/opt/sentinel")
from sentinel import core, ui  # noqa: E402

PUERTO = 8799
PAGINAS = ("overview", "events", "settings", "firewall", "audit", "attackers", "update", "packets", "correo", "inicio", "endurecer", "ia", "requisitos", "glossary", "identidad", "servers")
fallos: list[str] = []


def comprobar(nombre: str, ok: bool, detalle: str = "") -> None:
    print(("OK    " if ok else "FALLO ") + nombre + ("" if ok or not detalle else f" — {detalle[:600]}"), flush=True)
    if not ok:
        fallos.append(nombre)


def main() -> int:
    panel = subprocess.Popen(["/usr/local/bin/sentinel", "ui", "--sin-abrir", "--port", str(PUERTO)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        time.sleep(5)
        token = ui.load_token()
        base = f"http://127.0.0.1:{PUERTO}"

        def pedir(ruta, cuerpo=None):
            req = urllib.request.Request(base + ruta, data=None if cuerpo is None else json.dumps(cuerpo).encode(),
                                         headers={"Cookie": f"sentinel_t={token}", "Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=120) as r:
                return json.loads(r.read())
        for p in PAGINAS:
            try:
                d = pedir(f"/api/{p}")
                comprobar(f"la página «{p}» responde", True)
                if p == "overview":
                    comprobar("el panel ve el monitor vivo", bool(d.get("alive")), json.dumps(d.get("services")))
                    comprobar("el panel no muestra errores de systemctl", "systemctl" not in json.dumps(d), json.dumps(d))
                if p in ("settings", "correo", "inicio", "requisitos", "identidad"):
                    print(f"   {p}:", json.dumps(d, ensure_ascii=False)[:500])
            except Exception as e:
                comprobar(f"la página «{p}» responde", False, f"{type(e).__name__}: {e}")
        try:
            r = pedir("/api/action", {"name": "scan"})
            comprobar("el botón «Revisar ahora» funciona", bool(r.get("ok")), json.dumps(r, ensure_ascii=False))
        except Exception as e:
            comprobar("el botón «Revisar ahora» funciona", False, f"{type(e).__name__}: {e}")
    finally:
        panel.terminate()
        print("--- salida del panel ---")
        print(panel.communicate(timeout=20)[0][-3000:])
    uid, yo = os.getuid(), core.pwd.getpwuid(os.getuid()).pw_name
    quien = core.Alerter(core.load_config(), quiet=True).desktop_target()
    print("pantalla:", os.stat("/dev/console").st_uid, "destinatario:", quien, "yo:", uid, yo)
    cmd = core.Alerter.aviso_mac_cmd("Sentinel · prueba", 'texto con "comillas" y -guiones', yo, uid, False)
    rc, out = core.run(cmd, 30)
    comprobar("la notificación se envía", rc == 0, out)
    rc, out = core.run(["osascript", "-e", "on run argv", "-e", "return item 2 of argv", "-e", "end run", "--", "uno", "-dos"], 30)
    comprobar("el texto llega como dato", out.strip() == "-dos", out)
    comprobar("la aplicación está en Aplicaciones", os.access("/Applications/Sentinel.app/Contents/MacOS/Sentinel", os.X_OK))
    print(f"{len(fallos)} comprobaciones fallidas" if fallos else "Todas las comprobaciones del panel pasaron.")
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())
