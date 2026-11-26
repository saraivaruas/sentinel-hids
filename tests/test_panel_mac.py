import os
import tempfile
import unittest
from unittest import mock

from helpers import Env, core
from sentinel import ui


class PanelMacTests(unittest.TestCase):
    def setUp(self):
        self.e = Env(); self.addCleanup(self.e.close)
        d = tempfile.TemporaryDirectory(); self.addCleanup(d.cleanup); self.bin = os.path.join(d.name, "sentinel")
        for n in ("sentinel", "askpass"):
            open(os.path.join(d.name, n), "w").close()
        self.vistos = []
        for p in (mock.patch.object(ui.plataforma, "ES_MAC", True), mock.patch.object(core, "is_root", return_value=False), mock.patch.object(ui, "sentinel_bin", return_value=self.bin)):
            p.start(); self.addCleanup(p.stop)

    def accion(self, body, rc=0, err=""):
        def run(cmd, **k):
            self.vistos.append((cmd, k)); return mock.Mock(returncode=rc, stdout="", stderr=err)
        with mock.patch.object(ui.subprocess, "run", side_effect=run):
            return ui.run_action(body)

    def test_pide_la_clave_con_la_ventana_del_sistema(self):
        self.assertTrue(self.accion({"name": "scan"})["ok"])
        cmd, k = self.vistos[0]
        self.assertEqual(cmd[:2], ["sudo", "-A"]); self.assertEqual(os.path.basename(k["env"]["SUDO_ASKPASS"]), "askpass"); self.assertNotIn("pkexec", cmd)

    def test_el_pin_sigue_viajando_por_la_entrada_estandar(self):
        self.accion({"name": "scan", "pin": "123456"})
        cmd, k = self.vistos[0]
        self.assertIn("--pin-stdin", cmd); self.assertEqual(k["input"], "123456\n"); self.assertNotIn("123456", " ".join(cmd))

    def test_cancelar_la_clave_no_cuenta_como_hecho(self):
        r = self.accion({"name": "scan"}, rc=1, err="sudo: no password was provided")
        self.assertFalse(r["ok"]); self.assertIn("No se autorizó", r["out"])

    def test_la_ventana_de_clave_viene_con_el_programa_y_es_ejecutable(self):
        p = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "bin", "askpass")
        self.assertTrue(os.access(p, os.X_OK))
        with open(p, encoding="utf-8") as f:
            self.assertIn("with hidden answer", f.read())


if __name__ == "__main__":
    unittest.main()
