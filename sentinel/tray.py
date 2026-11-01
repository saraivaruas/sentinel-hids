"""Ícono en la barra del sistema (junto al reloj): cambia de color según el estado y abre el panel con un clic. Se inicia solo al abrir la sesión.

Usa AppIndicator (viene en Ubuntu/GNOME con la extensión de íconos de bandeja, y en KDE, XFCE y Cinnamon). Si no está disponible, no hace nada."""
from __future__ import annotations

import glob
import importlib.util
import os
import subprocess
import sys

from . import core

COLORS = {"protegido": "#16a34a", "revision": "#d97706", "atencion": "#ea580c", "peligro": "#dc2626", "desconocido": "#64748b"}
TEXTO = {"protegido": "Protegido", "revision": "Para revisar", "atencion": "Requiere atención", "peligro": "Posible intrusión", "desconocido": "Sin datos"}


def available() -> bool:
    return bool(importlib.util.find_spec("gi")) and bool(glob.glob("/usr/lib/*/girepository-1.0/*AppIndicator3-0.1.typelib"))


def icon_svg(level: str) -> str:
    """Escudo del color del estado (un archivo por nivel, en la carpeta de caché del usuario)."""
    c = COLORS.get(level, COLORS["desconocido"])
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path d="M12 2 4 5.5v6c0 5 3.4 8.600 8 10 4.600-1.400 8-5 8-10v-6z" fill="{c}"/>'
            f'<path d="m8.500 12 2.500 2.500 4.500-5" fill="none" stroke="#fff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>')


def icon_file(level: str) -> str:
    d = os.path.join(os.environ.get("XDG_CACHE_HOME", os.path.expanduser("~/.cache")), "sentinel")
    os.makedirs(d, exist_ok=True)
    p = os.path.join(d, f"tray-{level}.svg")
    with open(p, "w", encoding="utf-8") as f:
        f.write(icon_svg(level))
    return p


def estado() -> tuple[str, str]:
    """(nivel, resumen) a partir de los mismos datos que el panel; nunca falla."""
    try:
        from . import ui
        o = ui.Data().overview()
        c = o["counts24"]
        extra = f"{c['critical']} crítica(s), {c['high']} alta(s) en 24 h" if c["critical"] or c["high"] else "sin eventos graves en 24 h"
        return o["level"], f"Sentinel · {TEXTO[o['level']]} — {extra}"
    except Exception:
        return "desconocido", "Sentinel · sin datos"


def run() -> int:
    if not available() or not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
        return 0
    import gi
    gi.require_version("Gtk", "3.0")
    try:
        gi.require_version("AyatanaAppIndicator3", "0.1")
        from gi.repository import AyatanaAppIndicator3 as AI
    except (ValueError, ImportError):
        gi.require_version("AppIndicator3", "0.1")
        from gi.repository import AppIndicator3 as AI
    from gi.repository import GLib, Gtk

    nivel, resumen = estado()
    ind = AI.Indicator.new("sentinel", icon_file(nivel), AI.IndicatorCategory.SYSTEM_SERVICES)
    ind.set_status(AI.IndicatorStatus.ACTIVE)
    menu = Gtk.Menu()
    cab = Gtk.MenuItem(label=resumen); cab.set_sensitive(False); menu.append(cab)
    menu.append(Gtk.SeparatorMenuItem())

    def abrir(_w=None):
        subprocess.Popen(["sentinel", "ui"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    it = Gtk.MenuItem(label="Abrir el panel"); it.connect("activate", abrir); menu.append(it)
    sal = Gtk.MenuItem(label="Quitar este ícono"); sal.connect("activate", lambda *_: Gtk.main_quit()); menu.append(sal)
    menu.show_all()
    ind.set_menu(menu)
    ind.set_title("Sentinel")
    ult = [nivel]

    def refrescar():
        n, r = estado()
        cab.set_label(r)
        if n != ult[0]:
            ult[0] = n
            ind.set_icon_full(icon_file(n), TEXTO[n]) if hasattr(ind, "set_icon_full") else ind.set_icon(icon_file(n))
        return True
    GLib.timeout_add_seconds(20, refrescar)
    Gtk.main()
    return 0


if __name__ == "__main__":
    sys.exit(run())
