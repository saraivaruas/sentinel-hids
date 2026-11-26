import os
import plistlib
import tempfile
import unittest
from unittest import mock

import helpers  # noqa: F401  (pone el proyecto en sys.path)
from sentinel import cli, core, equipo, plataforma, servicio


class ServicioTests(unittest.TestCase):
    def setUp(self):
        d = tempfile.TemporaryDirectory(); self.addCleanup(d.cleanup); self.d = d.name
        p = mock.patch.dict(os.environ, {"SENTINEL_LAUNCHD_DIR": self.d}); p.start(); self.addCleanup(p.stop)
        self.cargadas, self.calls = set(), []

    def mac(self, es=True):
        return mock.patch.object(plataforma, "ES_MAC", es)

    def launchctl(self, c, t=20):
        self.calls.append(c)
        nombre = c[-1].rsplit(".", 1)[-1] if c[1] != "bootstrap" else c[-1].rsplit(".", 2)[-2]
        if c[1] == "print":
            return (0, "\tstate = running\n") if nombre in self.cargadas else (113, "Could not find service")
        if c[1] == "bootstrap":
            self.cargadas.add(nombre)
        if c[1] == "bootout":
            self.cargadas.discard(nombre)
        return 0, ""

    def test_el_monitor_arranca_solo_y_se_reinicia(self):
        p = servicio.escribir("monitor", "/usr/bin/python3")
        with open(p, "rb") as f:
            d = plistlib.load(f)
        self.assertTrue(d["RunAtLoad"] and d["KeepAlive"])
        self.assertEqual(d["Label"], "io.github.saraivaruas.sentinel.monitor")
        self.assertEqual(d["ProgramArguments"][:2], ["/usr/bin/python3", "-I"]); self.assertEqual(d["ProgramArguments"][-2:], ["/opt/sentinel", "monitor"])
        self.assertNotIn("/opt/homebrew", d["EnvironmentVariables"]["PATH"])       # root no ejecuta programas que un usuario pueda cambiar
        self.assertEqual(os.stat(p).st_mode & 0o777, 0o644)

    def test_horarios_de_las_tareas(self):
        self.assertEqual(servicio.definicion("scan", "py")["StartInterval"], 1800)
        self.assertEqual(servicio.definicion("equipo", "py", horas=["07:30", "22:05"])["StartCalendarInterval"], [{"Hour": 7, "Minute": 30}, {"Hour": 22, "Minute": 5}])
        self.assertEqual(servicio.definicion("report", "py")["StartCalendarInterval"]["Weekday"], 1)

    def test_iniciar_estado_y_detener_en_macos(self):
        for n in servicio.TAREAS:
            servicio.escribir(n, "/usr/bin/python3")
        with self.mac():
            self.assertEqual(servicio.estado("sentinel-monitor", self.launchctl), "inactive")
            self.assertEqual(servicio.iniciar(self.launchctl), [])
            self.assertEqual(self.cargadas, set(servicio.TAREAS))
            self.assertEqual(servicio.estado("sentinel-monitor", self.launchctl), "active")
            self.assertEqual(servicio.estado("sentinel-scan.timer", self.launchctl), "active")
            self.assertEqual(servicio.estado("crowdsec", self.launchctl), "not-found")
            self.assertEqual(servicio.detener(self.launchctl), []); self.assertEqual(self.cargadas, set())

    def test_avisa_si_falta_instalar(self):
        with self.mac():
            self.assertEqual(len(servicio.iniciar(self.launchctl)), 4)
            self.assertEqual(servicio.estado("sentinel-monitor", self.launchctl), "not-found")

    def test_detener_e_iniciar_desde_la_linea_de_comandos(self):
        e = helpers.Env(); self.addCleanup(e.close)
        for n in servicio.TAREAS:
            servicio.escribir(n, "/usr/bin/python3")
        self.cargadas.update(servicio.TAREAS)
        with self.mac(), mock.patch.object(core, "is_root", return_value=True), mock.patch.object(core, "run", side_effect=self.launchctl), \
             mock.patch.object(cli.pin, "authorize_stop"), mock.patch.object(cli.pin, "revoke_stop"), mock.patch("builtins.print"):
            self.assertEqual(cli.cmd_detener(None), 0); self.assertEqual(self.cargadas, set())
            self.assertEqual(cli.cmd_iniciar(None), 0); self.assertEqual(self.cargadas, set(servicio.TAREAS))
        self.assertFalse([c for c in self.calls if c[0] == "systemctl"])

    def test_cambiar_el_horario_del_informe_en_macos(self):
        e = helpers.Env(); self.addCleanup(e.close)
        servicio.escribir("equipo", "/usr/bin/python3"); self.cargadas.add("equipo")
        with self.mac():
            ok, msg = equipo.aplicar_horario("07:30,19:00", self.launchctl)
        self.assertTrue(ok, msg)
        with open(servicio.ruta("equipo"), "rb") as f:
            self.assertEqual(plistlib.load(f)["StartCalendarInterval"], [{"Hour": 7, "Minute": 30}, {"Hour": 19, "Minute": 0}])
        self.assertIn("equipo", self.cargadas)
        self.assertFalse([c for c in self.calls if c[0] == "systemctl"])

    def test_en_linux_sigue_preguntando_a_systemd(self):
        with self.mac(False):
            self.assertEqual(servicio.estado("sentinel-monitor", lambda c, t=20: (self.calls.append(c) or (0, "active\n"))), "active")
        self.assertEqual(self.calls, [["systemctl", "is-active", "sentinel-monitor"]])


if __name__ == "__main__":
    unittest.main()
