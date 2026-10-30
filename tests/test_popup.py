import unittest
from unittest import mock

from helpers import Env, core


class PopupTests(unittest.TestCase):
    def setUp(self):
        self.e = Env(extra="")
        self.e.cfg.set("general", "enable_desktop", "yes")
        self.a = core.Alerter(self.e.cfg, quiet=True)
        self.ev = core.Event("high", "auth", "fuerza_bruta", "35 intentos fallidos desde 203.0.113.9 <b>x</b>")

    def tearDown(self):
        self.e.close()

    def test_comando_de_la_ventana(self):
        cmd = self.a.popup_cmd(self.ev, "jorge", 1000, root=True)
        self.assertEqual(cmd[:5], ["runuser", "-u", "jorge", "--", "env"])
        self.assertIn("zenity", cmd); self.assertIn("--no-markup", cmd)            # el texto hostil no se interpreta como formato
        self.assertIn("--ok-label=Abrir panel", cmd); self.assertIn("--timeout=120", cmd)
        self.assertTrue(any(c.startswith("DBUS_SESSION_BUS_ADDRESS=") for c in cmd))
        self.assertTrue(any("35 intentos" in c for c in cmd))

    def test_las_criticas_no_se_cierran_solas(self):
        ev = core.Event("critical", "fim", "added", "puerta trasera")
        cmd = self.a.popup_cmd(ev, "jorge", 1000, root=False)
        self.assertFalse(any(c.startswith("--timeout") for c in cmd)); self.assertIn("--icon-name=dialog-error", cmd)
        self.assertEqual(cmd[0], "env")

    def test_solo_desde_la_gravedad_configurada_y_con_limite_por_minuto(self):
        with mock.patch.object(core.shutil, "which", return_value="/usr/bin/zenity"), mock.patch.object(core.Alerter, "desktop_target", return_value=("jorge", 1000)), \
             mock.patch.object(core.threading, "Thread") as th:
            self.assertEqual(sum(self.a.popup(self.ev) for _ in range(6)), 3)         # máximo 3 por minuto
            self.assertEqual(th.call_count, 3)
            self.assertTrue(self.a.popup(self.ev, force=True))                       # la prueba ignora el límite
            for k in ("media", "baja"):
                pass
            medium = core.Event("medium", "host", "x", "m")
            self.a._channels  # noqa: B018
        al = core.Alerter(self.e.cfg, quiet=False)
        with mock.patch.object(al, "popup") as pop, mock.patch.object(al, "desktop"):
            al._channels(core.Event("medium", "host", "x", "m")); self.assertFalse(pop.called)      # media: solo notificación
            al._channels(core.Event("high", "host", "x", "m")); self.assertTrue(pop.called)         # alta: ventana

    def test_sin_zenity_o_sin_sesion_no_falla(self):
        with mock.patch.object(core.shutil, "which", return_value=None):
            self.assertFalse(self.a.popup(self.ev))
        with mock.patch.object(core.shutil, "which", return_value="/usr/bin/zenity"), mock.patch.object(core.Alerter, "desktop_target", return_value=None):
            self.assertFalse(self.a.popup(self.ev))

    def test_variables_de_pantalla(self):
        env = core.Alerter.desktop_env(1000)
        self.assertEqual(env["XDG_RUNTIME_DIR"], "/run/user/1000"); self.assertIn("DBUS_SESSION_BUS_ADDRESS", env)


if __name__ == "__main__":
    unittest.main()
