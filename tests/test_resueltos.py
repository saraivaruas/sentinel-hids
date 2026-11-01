from __future__ import annotations

import os
import time
import unittest
import unittest.mock as m

from helpers import Env, core
from sentinel import cli, report, ui


def hora(h, mi=0):
    return time.mktime((2026, 11, 1, h, mi, 0, 0, 0, -1))


class SilencioTests(unittest.TestCase):
    def cfg(self, a, b):
        e = Env(); self.addCleanup(e.close)
        e.cfg.set("general", "quiet_from", a); e.cfg.set("general", "quiet_to", b)
        return e.cfg

    def test_ventana_que_cruza_la_medianoche(self):
        c = self.cfg("22:00", "07:00")
        for h, esperado in ((23, True), (0, True), (6, True), (7, False), (12, False), (21, False), (22, True)):
            self.assertEqual(core.in_quiet(c, hora(h)), esperado, h)

    def test_ventana_del_mismo_dia_y_sin_ventana(self):
        c = self.cfg("13:00", "15:30")
        self.assertTrue(core.in_quiet(c, hora(14))); self.assertFalse(core.in_quiet(c, hora(16)))
        for a, b in (("", ""), ("22:00", ""), ("10:00", "10:00"), ("xx", "07:00")):
            self.assertFalse(core.in_quiet(self.cfg(a, b), hora(23)), (a, b))

    def test_de_noche_solo_suenan_las_criticas(self):
        e = Env(); e.cfg.set("general", "enable_desktop", "yes"); e.cfg.set("general", "quiet_from", "00:00"); e.cfg.set("general", "quiet_to", "23:59")
        al = core.Alerter(e.cfg, quiet=False)
        with m.patch.object(al, "desktop") as d, m.patch.object(al, "popup"):
            al._channels(core.Event("high", "host", "x", "m")); self.assertFalse(d.called)             # en silencio: no
            al._channels(core.Event("critical", "host", "x", "m")); self.assertTrue(d.called)          # crítica: sí
        e.close()

    def test_horas_ajustables_con_validacion(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "s.conf"); open(p, "w").write("[general]\nnotify_min = medium\n")
            core.set_setting("general", "quiet_from", "22:30", p); core.set_setting("general", "quiet_to", "07:00", p)
            self.assertEqual(core.load_config(p).get("general", "quiet_from"), "22:30")
            for v in ("25:00", "7:00", "22:60", "mañana"):
                with self.assertRaises(ValueError):
                    core.set_setting("general", "quiet_from", v, p)


class ResueltosTests(unittest.TestCase):
    def test_resolver_saca_el_evento_de_los_conteos_y_del_informe(self):
        e = Env()
        try:
            with m.patch.dict(os.environ, {"SENTINEL_LOG": os.path.dirname(e.alerter.path)}):
                x = e.alerter.emit("high", "host", "puerto_nuevo", "Nuevo puerto", key="k1", port=1)
                y = e.alerter.emit("high", "auth", "fuerza_bruta", "5 intentos", key="k2")
                d = ui.Data(e.cfg)
                with m.patch.object(d, "services", return_value={}):
                    self.assertEqual(d.overview()["counts24"]["high"], 2)
                    core.resolve_event("k1", x.epoch)
                    self.assertEqual(d.overview()["counts24"]["high"], 1)                                # k1 ya no cuenta; k2 sí
                self.assertEqual([r["key"] for r in report.relevant(core.read_events(0))], ["k2"])
                lista = {r["key"]: r["resolved"] for r in d.events(24, "info", "", 50)}
                self.assertEqual(lista, {"k1": True, "k2": False})                                       # sigue en el historial, marcado
        finally:
            e.close()

    def test_accion_resolver_busca_el_evento_y_pide_pin(self):
        e = Env()
        try:
            with m.patch.dict(os.environ, {"SENTINEL_LOG": os.path.dirname(e.alerter.path)}):
                x = e.alerter.emit("high", "host", "puerto_nuevo", "Nuevo puerto", key="k1")
                self.assertEqual(ui.build_action({"name": "resolver", "epoch": x.epoch, "key": "k1"}), ["resolver", "k1", str(x.epoch)])
                with self.assertRaises(ValueError):
                    ui.build_action({"name": "resolver", "epoch": x.epoch, "key": "falso"})
        finally:
            e.close()
        import argparse
        self.assertTrue(cli._protected(argparse.Namespace(fn=cli.cmd_resolver)))                        # con PIN configurado exige el PIN


if __name__ == "__main__":
    unittest.main()
