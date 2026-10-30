import unittest

from helpers import Env, core


class CoreTests(unittest.TestCase):
    def setUp(self):
        self.e = Env()

    def tearDown(self):
        self.e.close()

    def test_ips_protegidas(self):
        a = self.e.allow
        for ip in ("127.0.0.1", "192.168.1.20", "10.0.0.5", "172.20.0.2", "100.101.102.103", "::1", "fe80::1", "no-es-ip"):
            self.assertTrue(a.ip_protected(ip), ip)
        for ip in ("8.8.8.8", "203.0.113.9", "2001:4860:4860::8888"):
            self.assertFalse(a.ip_protected(ip), ip)

    def test_lista_blanca_de_ips(self):
        e = Env(extra="[allow]\nips = 203.0.113.0/24")
        try:
            self.assertTrue(e.allow.ip_protected("203.0.113.77"))
        finally:
            e.close()

    def test_evento_se_guarda_y_no_se_repite(self):
        a = self.e.alerter
        self.assertIsNotNone(a.emit("high", "t", "k", "uno", key="x"))
        self.assertIsNone(a.emit("high", "t", "k", "uno", key="x"))      # duplicado dentro de la ventana
        self.assertIsNotNone(a.emit("critical", "t", "k", "uno", key="x"))  # las críticas siempre pasan
        self.assertEqual(len(self.e.events()), 2)

    def test_filtro_por_gravedad(self):
        a = self.e.alerter
        a.emit("low", "t", "a", "baja", key="1"); a.emit("high", "t", "b", "alta", key="2")
        self.assertEqual([x["kind"] for x in self.e.events("high")], ["b"])

    def test_no_bloquea_protegidas_ni_sin_permiso(self):
        self.assertFalse(self.e.banner.ban("192.168.1.9", "prueba"))
        self.assertFalse(self.e.banner.ban("203.0.113.9", "prueba"))     # backend none: solo simula
        kinds = [x["kind"] for x in self.e.events()]
        self.assertIn("protegida", kinds); self.assertIn("simulado", kinds)

    def test_log_privado(self):
        self.e.alerter.emit("info", "t", "k", "m", key="p")
        import os, stat
        self.assertEqual(stat.S_IMODE(os.stat(self.e.alerter.path).st_mode), 0o640)
