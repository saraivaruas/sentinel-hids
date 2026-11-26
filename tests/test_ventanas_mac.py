import unittest
from unittest import mock

from helpers import Env, core
from sentinel import plataforma


class VentanasMacTests(unittest.TestCase):
    def setUp(self):
        self.e = Env(); self.addCleanup(self.e.close)
        self.a = core.Alerter(self.e.cfg, quiet=True)
        for p in (mock.patch.object(plataforma, "ES_MAC", True), mock.patch.object(core.Alerter, "desktop_target", return_value=("ana", 501)),
                  mock.patch.object(core, "is_root", return_value=True), mock.patch("shutil.which", return_value="/usr/bin/osascript")):
            p.start(); self.addCleanup(p.stop)

    def test_ventana_de_alerta_con_el_texto_como_dato(self):
        malo = 'x" buttons {"ok"}\ndo shell script "rm -rf /"'
        c = self.a.popup_mac_cmd(core.Event("high", "auth", "fuerza_bruta", malo), "ana", 501, True)
        self.assertEqual(c[:6], ["launchctl", "asuser", "501", "sudo", "-u", "ana"]); self.assertEqual(c[-3], "--")
        self.assertIn(malo, c[-1]); self.assertFalse(any("rm -rf" in x for x in c[:-1])); self.assertTrue(any("giving up after 120" in x for x in c))
        critica = self.a.popup_mac_cmd(core.Event("critical", "fim", "added", "x"), "ana", 501, False)
        self.assertEqual(critica[0], "osascript"); self.assertFalse(any("giving up" in x for x in critica))     # las críticas no se cierran solas

    def test_abrir_panel_solo_si_se_pulsa_ese_boton(self):
        for salida, veces in ((b"button returned:Abrir panel, gave up:false\n", 1), (b"button returned:Cerrar, gave up:false\n", 0), (b"button returned:, gave up:true\n", 0)):
            with mock.patch.object(core.subprocess, "run", return_value=mock.Mock(returncode=0, stdout=salida)), mock.patch.object(core.subprocess, "Popen") as abrir:
                self.a.popup(core.Event("high", "auth", "x", "m"), force=True)
                self.a.last_popup.join(5)
            self.assertEqual(abrir.call_count, veces, salida)
            if veces:
                self.assertEqual(abrir.call_args[0][0][-3:], ["open", "-a", "Sentinel"])


if __name__ == "__main__":
    unittest.main()
