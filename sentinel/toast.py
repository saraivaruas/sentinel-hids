"""Aviso en la esquina inferior derecha de la pantalla (X11): aparece unos segundos y se cierra solo. Corre con el usuario de la sesión gráfica.

Si GTK no está disponible, Sentinel usa las notificaciones normales del escritorio (notify-send)."""
from __future__ import annotations

import glob
import importlib.util
import os
import signal
import sys

COLORS = {"info": "#64748b", "low": "#2563eb", "medium": "#d97706", "high": "#ea580c", "critical": "#dc2626"}
LABEL = {"info": "Info", "low": "Baja", "medium": "Media", "high": "Alta", "critical": "Crítica"}
MARGIN = 18
WIDTH = 380


def available() -> bool:
    """¿Hay GTK 3 con Python en este equipo? (no lo importa: puede llamarse desde el servicio sin pantalla)."""
    return bool(importlib.util.find_spec("gi")) and bool(glob.glob("/usr/lib/*/girepository-1.0/Gtk-3.0.typelib") or glob.glob("/usr/lib/girepository-1.0/Gtk-3.0.typelib"))


def pid_path() -> str:
    return os.path.join(os.environ.get("XDG_RUNTIME_DIR", "/tmp"), "sentinel-toast.pid")


def corner(area: tuple[int, int, int, int], size: tuple[int, int], margin: int = MARGIN) -> tuple[int, int]:
    """Posición (x, y) de una ventana de `size` en la esquina inferior derecha del área útil `area` = (x, y, ancho, alto)."""
    ax, ay, aw, ah = area
    return ax + aw - size[0] - margin, ay + ah - size[1] - margin


def usable(geo: tuple[int, int, int, int], work: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    """Parte del monitor que realmente se ve: GDK a veces entrega el área útil de TODA la pantalla (varios monitores), así que se intersecta con el monitor."""
    x1, y1 = max(geo[0], work[0]), max(geo[1], work[1])
    x2, y2 = min(geo[0] + geo[2], work[0] + work[2]), min(geo[1] + geo[3], work[1] + work[3])
    return (x1, y1, x2 - x1, y2 - y1) if x2 > x1 and y2 > y1 else geo


def show(title: str, msg: str, sev: str = "medium", secs: int = 8) -> int:
    import gi
    gi.require_version("Gtk", "3.0")
    gi.require_version("Gdk", "3.0")
    from gi.repository import Gdk, GLib, Gtk

    try:                                         # un aviso nuevo reemplaza al anterior (no se apilan ni molestan)
        old = int(open(pid_path()).read())
        if old != os.getpid():
            os.kill(old, signal.SIGTERM)
    except (OSError, ValueError):
        pass
    try:
        open(pid_path(), "w").write(str(os.getpid()))
    except OSError:
        pass
    if not Gdk.Display.get_default():
        return 2
    col = COLORS.get(sev, COLORS["medium"])
    css = Gtk.CssProvider()
    css.load_from_data(f"""
      .toast {{ background: #111827; border-left: 5px solid {col}; border-radius: 10px; padding: 12px 16px; }}
      .toast .t {{ color: #f9fafb; font-weight: 700; font-size: 11pt; }}
      .toast .m {{ color: #d1d5db; font-size: 10pt; }}
      .toast .s {{ color: {col}; font-weight: 700; font-size: 9pt; }}
      .toast .f {{ color: #6b7280; font-size: 8pt; }}
    """.encode())
    Gtk.StyleContext.add_provider_for_screen(Gdk.Screen.get_default(), css, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)
    win = Gtk.Window(type=Gtk.WindowType.POPUP)
    win.set_keep_above(True)
    win.set_accept_focus(False)
    win.set_skip_taskbar_hint(True)
    win.set_default_size(WIDTH, -1)
    box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
    box.get_style_context().add_class("toast")
    head = Gtk.Label(xalign=0); head.set_markup(f"<span foreground='{col}' weight='bold'>●  {GLib.markup_escape_text(LABEL.get(sev, sev))}</span>")
    t = Gtk.Label(label=title, xalign=0); t.get_style_context().add_class("t"); t.set_line_wrap(True); t.set_max_width_chars(44)
    m = Gtk.Label(label=msg, xalign=0); m.get_style_context().add_class("m"); m.set_line_wrap(True); m.set_max_width_chars(48); m.set_lines(5); m.set_ellipsize(3)
    f = Gtk.Label(label="Sentinel · clic para cerrar", xalign=0); f.get_style_context().add_class("f")
    for w in (head, t, m, f):
        box.pack_start(w, False, False, 0)
    ev = Gtk.EventBox(); ev.add(box); ev.connect("button-press-event", lambda *a: Gtk.main_quit())
    win.add(ev)
    win.show_all()
    disp = Gdk.Display.get_default()
    mon = disp.get_primary_monitor() or disp.get_monitor(0)
    wa, g = mon.get_workarea(), mon.get_geometry()
    area = usable((g.x, g.y, g.width, g.height), (wa.x, wa.y, wa.width, wa.height))
    last = [None]

    def place(w, alloc=None):                      # el alto real se conoce al repartir el espacio (texto con saltos de línea)
        size = w.get_size()
        if size != last[0]:
            last[0] = size
            w.move(*corner(area, size))
    win.connect("size-allocate", place)
    place(win)
    GLib.timeout_add_seconds(max(2, secs), Gtk.main_quit)
    Gtk.main()
    try:
        os.remove(pid_path())
    except OSError:
        pass
    return 0


def main(argv: list[str]) -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="sentinel toast")
    ap.add_argument("--sev", default="medium"); ap.add_argument("--seg", type=int, default=8); ap.add_argument("--titulo", default="Sentinel"); ap.add_argument("mensaje")
    a = ap.parse_args(argv)
    return show(a.titulo[:120], a.mensaje[:400], a.sev, a.seg)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
