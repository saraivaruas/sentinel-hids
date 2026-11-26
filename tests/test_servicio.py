import os
import plistlib
import tempfile
import unittest
from unittest import mock

import helpers  # noqa: F401  (pone el proyecto en sys.path)
from sentinel import plataforma, servicio


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

    def test_en_linux_sigue_preguntando_a_systemd(self):
        with self.mac(False):
            self.assertEqual(servicio.estado("sentinel-monitor", lambda c, t=20: (self.calls.append(c) or (0, "active\n"))), "active")
        self.assertEqual(self.calls, [["systemctl", "is-active", "sentinel-monitor"]])


if __name__ == "__main__":
    unittest.main()
