"""«Esto es normal»: convierte un evento en la acción que lo deja como aceptado (lista blanca o referencia nueva), solo para tipos de evento donde eso es seguro.

Nunca se ofrece para fuerza bruta, escaneos, puertas traseras ni nada que sea un ataque: ahí no hay nada que «aceptar»."""
from __future__ import annotations

from . import core


def args_for(e: dict) -> list[str] | None:
    """Argumentos de `sentinel` que aceptan este evento, o None si no corresponde."""
    kind, data = e.get("kind"), e.get("data") or {}
    if e.get("source") == "host":
        if kind in ("puerto_nuevo", "puerto_expuesto"):
            proc, port, proto = data.get("proc"), data.get("port"), data.get("proto")
            if proc and proto == "udp" and (port or 0) >= 32768:
                return ["allow", "proc", proc]
            return ["allow", "port", str(port)] if port else None
        if kind == "lector_de_teclado" and data.get("proc"):
            return ["allow", "proc", data["proc"]]
        if kind in ("usb_nuevo", "modulo_nuevo"):
            return ["baseline", "host"]
        return None
    if e.get("source") == "fim" and kind in ("added", "modified", "removed", "link", "perm", "type"):
        if data.get("signatures") or e.get("sev") == "critical":
            return None                       # una posible puerta trasera no se «acepta» con un botón
        path = data.get("path")
        return ["baseline", "accept", path] if isinstance(path, str) and path.startswith("/") else None
    return None


def find_event(epoch: float, key: str, path: str | None = None) -> dict | None:
    for e in core.read_events(epoch - 2):
        if e.get("key") == key and abs(e.get("epoch", 0) - epoch) < 2:
            return e
    return None
