"""`sentinel status` debe decir lo mismo que el panel (el 14-nov-2026 mostraba «0 elementos · falta baseline» y contaba avisos ya revisados)."""
import io
import os
import unittest
from contextlib import redirect_stdout
from unittest import mock

from helpers import Env, core
from sentinel import cli


class StatusTests(unittest.TestCase):
    def setUp(self):
        linux = mock.patch.object(cli.plataforma, "ES_MAC", False); linux.start(); self.addCleanup(linux.stop)   # simulan las respuestas de systemd

    def status(self):
        out = io.StringIO()
        with redirect_stdout(out), mock.patch.object(core, "run", return_value=(0, "active")):
            cli.main(["status"])
        return out.getvalue()

    def test_la_referencia_se_muestra_sin_ser_root_desde_el_resumen_publico(self):
        e = Env()
        try:
            core.atomic_write_json(os.path.join(core.state_dir(), "fim_meta.json"), {"created": "2026-10-30T11:07:14-0300", "count": 20591}, 0o644)
            t = self.status()
            self.assertIn("20,591 elementos", t); self.assertNotIn("falta", t)
        finally:
            e.close()

    def test_sin_referencia_explica_que_hacer(self):
        e = Env()
        try:
            self.assertIn("sudo sentinel baseline init", self.status())
        finally:
            e.close()

    def test_los_avisos_ya_revisados_no_cuentan_ni_se_listan_y_el_veredicto_coincide_con_el_panel(self):
        e = Env()
        try:
            core.atomic_write_json(os.path.join(core.state_dir(), "heartbeat.json"), {"epoch": core.now(), "pid": 1, "version": core.VERSION}, 0o644)       # monitor vivo
            ev = e.alerter.emit("high", "fim", "removed", "se borró algo", key="k1")
            self.assertIn("REQUIERE ATENCIÓN", self.status())
            core.resolve_event(ev.key, ev.epoch)
            t = self.status()
            self.assertIn("PROTEGIDO", t); self.assertNotIn("se borró algo", t); self.assertIn("0 alta", t)
        finally:
            e.close()


if __name__ == "__main__":
    unittest.main()
