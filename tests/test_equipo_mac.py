import json
import unittest
from unittest import mock

from helpers import Env, core
from sentinel import equipo, equipo_mac, plataforma


def linea(ruta, msg):
    return json.dumps({"processImagePath": ruta, "senderImagePath": ruta, "eventMessage": msg})


REGISTRO = "\n".join(
    [linea("/usr/libexec/sshd-session", f"Failed password for root from 203.0.113.9 port {i} ssh2") for i in range(11)]
    + [linea("/usr/bin/sudo", "ana : 3 incorrect password attempts ; *** ; USER=root"), linea("/usr/bin/su", "BAD SU ana to root on /dev/ttys001")])
PS = "  10 /usr/bin/nc -l 4444\n  11 -zsh\n  12 /opt/homebrew/bin/ngrok http 3000\n"


class InformeMacTests(unittest.TestCase):
    def setUp(self):
        self.e = Env(); self.addCleanup(self.e.close)
        self.calls = []

        def run(c, t=20):
            self.calls.append(c[0])
            if c[0] == "log":
                return 0, REGISTRO
            if c[0] == "ps":
                return 0, PS
            if c[0] == "lsof" and "-sTCP:ESTABLISHED" in c:
                return 0, "p77\ncCurioso\nf3\nPTCP\nn192.168.1.2:50000->198.51.100.7:4444\n"
            if c[0] == "lsof":
                return 1, ""
            if c[0] in ("systemctl", "ss", "journalctl", "dpkg", "apt-get", "ip", "lastb"):
                return 127, f"[Errno 2] No such file or directory: '{c[0]}'"
            return 0, ""
        for p in (mock.patch.object(core, "run", side_effect=run), mock.patch.object(plataforma, "ES_MAC", True), mock.patch.object(core, "is_root", return_value=True),
                  mock.patch.object(equipo_mac.hostcheck, "proc_scan", return_value=[]), mock.patch.object(equipo.Revision, "tmp_ejecutables", lambda s: None)):
            p.start(); self.addCleanup(p.stop)
        self.inf = equipo.revisar(self.e.cfg)
        self.texto = equipo.a_texto(self.inf)

    def hallazgos(self, area):
        return [h.texto for h in self.inf.unicos() if h.area == area]

    def test_no_usa_herramientas_de_linux_ni_falla(self):
        self.assertFalse(set(self.calls) & {"systemctl", "ss", "journalctl", "dpkg", "apt-get", "ip", "lastb"}, self.calls)
        self.assertNotIn("(falló)", self.texto); self.assertNotIn("/proc", self.texto)

    def test_no_da_por_bueno_lo_que_no_revisa(self):
        for frase in ("coinciden con su hash original", "Actualizaciones de seguridad pendientes: 0"):
            self.assertNotIn(frase, self.texto)
        self.assertIn(equipo_mac.NO_REVISADO, self.texto)

    def test_lee_los_accesos_fallidos_del_registro_de_macos(self):
        self.assertIn("Fallos remotos (SSH): 11 · fallos locales (sudo y su): 2", self.texto)
        self.assertIn("fuerza bruta", self.hallazgos("autenticación")[0])

    def test_conexiones_procesos_y_tuneles(self):
        self.assertTrue(any("198.51.100.7:4444" in t and "Curioso" in t for t in self.hallazgos("conexiones")))
        self.assertTrue(any("(nc)" in t for t in self.hallazgos("shell reversa")))
        self.assertTrue(any("ngrok" in t for t in self.hallazgos("túneles")))


if __name__ == "__main__":
    unittest.main()
