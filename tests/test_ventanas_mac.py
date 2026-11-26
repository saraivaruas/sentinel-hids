import unittest
from unittest import mock

from helpers import Env, core
from sentinel import pin, plataforma


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

    def preguntar(self, rc, salida):
        with mock.patch("sys.stdin.isatty", return_value=False), mock.patch("builtins.open", side_effect=OSError), \
             mock.patch.object(pin.subprocess, "run", return_value=mock.Mock(returncode=rc, stdout=salida)) as run:
            return pin.ask("PIN de Sentinel: "), run

    def test_pide_el_pin_con_una_ventana_si_no_hay_terminal(self):
        r, run = self.preguntar(0, "secreto-1\n")
        self.assertEqual(r, "secreto-1")
        c = run.call_args[0][0]
        self.assertTrue(any("hidden answer" in x for x in c)); self.assertNotIn("zenity", c)

    def test_cancelar_la_ventana_del_pin_no_devuelve_nada(self):
        self.assertIsNone(self.preguntar(1, "")[0])


if __name__ == "__main__":
    unittest.main()
