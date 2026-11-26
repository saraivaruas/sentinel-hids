"""Bloqueo de IP en macOS con pf, el cortafuegos del sistema.

Sentinel no toca /etc/pf.conf: carga sus reglas en un ancla propia dentro de «com.apple/*», que las reglas
de macOS ya incluyen. Las IPs bloqueadas van en una tabla. Todo esto se pierde al reiniciar el equipo, por
eso el monitor lo vuelve a poner. Las funciones reciben `run` (el ejecutor de comandos) para probarse sin pf.
"""
from __future__ import annotations

import os

ANCLA = "com.apple/sentinel"
TABLA = "sentinel"
REGLAS = f"table <{TABLA}> persist\nblock drop in quick from <{TABLA}> to any\n"
SISTEMA = "/etc/pf.conf"
INCLUYE = 'anchor "com.apple/*"'


def tabla(accion: str, ip: str) -> list[str]:
    """Comando para añadir («add») o quitar («delete») una IP de la tabla de bloqueadas."""
    return ["pfctl", "-a", ANCLA, "-t", TABLA, "-T", accion, ip]


def preparar(run, carpeta: str) -> str:
    """Deja pf encendido y con las reglas de Sentinel. Devuelve "" si quedó listo, o el motivo si no se pudo."""
    rc, principal = run(["pfctl", "-sr"])
    if rc != 0:
        return f"no pude leer las reglas de pf: {principal.strip()[-160:]}"
    if INCLUYE not in principal:
        vacias = not any(ln.startswith(("block", "pass", "anchor", "scrub", "match")) for ln in principal.splitlines())
        if vacias:  # nadie ha cargado reglas: se cargan las del sistema
            run(["pfctl", "-f", SISTEMA])
            rc, principal = run(["pfctl", "-sr"])
        if INCLUYE not in principal:
            return "las reglas principales de pf no incluyen «com.apple/*»: el bloqueo no tendría efecto"
    cargar = f"<{TABLA}>" not in run(["pfctl", "-a", ANCLA, "-sr"])[1]
    if cargar:
        archivo = os.path.join(carpeta, "pf-sentinel.conf")
        try:
            os.makedirs(carpeta, exist_ok=True)
            with open(archivo, "w", encoding="utf-8") as f:
                f.write(REGLAS)
        except OSError as e:
            return f"no pude escribir las reglas de pf ({e.strerror})"
        rc, out = run(["pfctl", "-a", ANCLA, "-f", archivo])
        if rc != 0:
            return f"pf rechazó las reglas: {out.strip()[-160:]}"
    if cargar or "Status: Enabled" not in run(["pfctl", "-s", "info"])[1]:
        rc, out = run(["pfctl", "-E"])  # enciende pf y anota que Sentinel lo necesita encendido
        if rc != 0:
            return f"no pude encender pf: {out.strip()[-160:]}"
    return ""
