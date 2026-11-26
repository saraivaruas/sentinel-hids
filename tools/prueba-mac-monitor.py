#!/usr/bin/env python3
"""Prueba real en macOS del monitor completo, como correrá instalado: con administrador, rutas reales y
valores por defecto. Provoca cambios y accesos fallidos y comprueba que salgan las alertas y ningún error.

SOLO para equipos desechables (la CI `mac-monitor`): escribe en /Library/LaunchDaemons y /etc/sentinel.
"""
import json
import os
import signal
import subprocess
import sys
import time

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EVENTOS = "/var/log/sentinel/events.jsonl"
DEMONIO = "/Library/LaunchDaemons/com.ejemplo.intruso.plist"
fallos: list[str] = []


def comprobar(nombre: str, ok: bool) -> None:
    print(("OK    " if ok else "FALLO ") + nombre, flush=True)
    if not ok:
        fallos.append(nombre)


def eventos() -> list[dict]:
    try:
        with open(EVENTOS, encoding="utf-8") as f:
            return [json.loads(ln) for ln in f if ln.strip()]
    except OSError:
        return []


def esperar(condicion, segundos: int) -> bool:
    limite = time.time() + segundos
    while time.time() < limite:
        if condicion():
            return True
        time.sleep(1)
    return False


def hay(tipo: str = "", texto: str = "") -> bool:
    return any((not tipo or e["kind"] == tipo) and texto in e["msg"] for e in eventos())


def sentinel(*args: str) -> None:
    print(f"\n===== sentinel {' '.join(args)}", flush=True)
    r = subprocess.run([sys.executable, "-m", "sentinel", *args], cwd=RAIZ, capture_output=True, text=True, timeout=300, stdin=subprocess.DEVNULL)
    print(r.stdout[-4000:])
    if r.stderr:
        print("--- errores ---\n" + r.stderr[-3000:])
    comprobar(f"sentinel {args[0]} no se cae", "Traceback" not in r.stderr)


def main() -> int:
    os.makedirs("/etc/sentinel", exist_ok=True)
    with open("/etc/sentinel/sentinel.conf", "w", encoding="utf-8") as f:
        f.write("[general]\ndesktop_user =\n[fim]\npoll_seconds = 5\n[hostcheck]\ninterval_seconds = 30\n[update]\ncheck = no\n[intel]\ngeo_mode = off\n")
    salida = open("/tmp/monitor.txt", "w", encoding="utf-8")
    monitor = subprocess.Popen([sys.executable, "-u", "-m", "sentinel", "monitor"], cwd=RAIZ, stdout=salida, stderr=subprocess.STDOUT)
    try:
        comprobar("el monitor arranca", esperar(lambda: hay("inicio"), 180))
        comprobar("vigila los archivos en vivo", hay("inicio", "en vivo de archivos: sí"))
        time.sleep(20)  # primera pasada del sondeo y del registro

        with open(DEMONIO, "w", encoding="utf-8") as f:
            f.write("<plist/>\n")
        comprobar("avisa de un programa de arranque nuevo en LaunchDaemons", esperar(lambda: hay(texto=DEMONIO), 60))

        for i in range(6):
            subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", f"noexiste{i}@127.0.0.1", "true"], capture_output=True, timeout=30)
            time.sleep(1)
        comprobar("avisa de la fuerza bruta por SSH", esperar(lambda: hay("fuerza_bruta"), 60))
        time.sleep(40)  # una revisión del equipo más

        sentinel("status")
        sentinel("hostcheck")
        sentinel("scan")
        sentinel("equipo")
        sentinel("requisitos")
        comprobar("el monitor sigue vivo", monitor.poll() is None)
    finally:
        monitor.send_signal(signal.SIGTERM)
        try:
            monitor.wait(30)
            comprobar("se detiene al pedírselo", True)
        except subprocess.TimeoutExpired:
            monitor.kill()
            comprobar("se detiene al pedírselo", False)
        if os.path.exists(DEMONIO):
            os.remove(DEMONIO)
    print("\n===== salida del monitor")
    print(open("/tmp/monitor.txt", encoding="utf-8").read()[-4000:])
    print("===== eventos")
    for e in eventos():
        print("evento:", e["sev"], f"{e['source']}/{e['kind']}", "|", e["msg"][:220])
    comprobar("ningún módulo informó un error", not any(e["source"] == "monitor" and e["kind"] == "error" for e in eventos()))
    print(f"{len(fallos)} comprobaciones fallidas: {fallos}" if fallos else "Todas las comprobaciones pasaron.")
    return 1 if fallos else 0


if __name__ == "__main__":
    if os.environ.get("GITHUB_ACTIONS") != "true":
        sys.exit("Esta prueba escribe en carpetas del sistema: solo se ejecuta en la CI (GITHUB_ACTIONS=true).")
    sys.exit(main())
