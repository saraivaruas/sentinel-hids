import unittest

from helpers import Env
from sentinel import authwatch


class AuthTests(unittest.TestCase):
    def setUp(self):
        self.e = Env()
        self.a = authwatch.AuthWatch(self.e.cfg, self.e.alerter, self.e.allow, self.e.banner)

    def tearDown(self):
        self.e.close()

    def kinds(self):
        return [x["kind"] for x in self.e.events()]

    def test_fuerza_bruta_y_bloqueo(self):
        for i in range(5):
            self.a.handle("sshd", f"Failed password for invalid user admin from 203.0.113.9 port {4000 + i} ssh2", 1000 + i)
        self.assertIn("fuerza_bruta", self.kinds()); self.assertIn("simulado", self.kinds())   # backend none: solo simula

    def test_bajo_el_umbral_no_alerta(self):
        for i in range(4):
            self.a.handle("sshd", "Failed password for root from 203.0.113.9 port 22 ssh2", 1000 + i)
        self.assertNotIn("fuerza_bruta", self.kinds())

    def test_ventana_de_tiempo(self):
        for i in range(5):
            self.a.handle("sshd", "Failed password for root from 203.0.113.9 port 22 ssh2", 1000 + i * 400)   # muy espaciados
        self.assertNotIn("fuerza_bruta", self.kinds())

    def test_red_local_no_se_bloquea(self):
        for i in range(8):
            self.a.handle("sshd", "Failed password for jorge from 192.168.1.50 port 22 ssh2", 1000 + i)
        self.assertIn("fuerza_bruta", self.kinds()); self.assertIn("protegida", self.kinds()); self.assertNotIn("simulado", self.kinds())

    def test_acceso_tras_ataque_es_critico(self):
        for i in range(4):
            self.a.handle("sshd", "Failed password for jorge from 203.0.113.9 port 22 ssh2", 1000 + i)
        self.a.handle("sshd", "Accepted password for jorge from 203.0.113.9 port 22 ssh2", 1010)
        self.assertEqual([x["sev"] for x in self.e.events() if x["kind"] == "acceso_tras_ataque"], ["critical"])

    def test_root_remoto(self):
        self.a.handle("sshd", "Accepted publickey for root from 198.51.100.4 port 5555 ssh2", 5)
        self.assertIn("root_remoto", self.kinds())

    def test_escaneo_de_puertos_por_ufw(self):
        for p in range(1, 15):
            self.a.handle("kernel", f"[UFW BLOCK] IN=wlo1 OUT= MAC=aa SRC=198.51.100.77 DST=10.0.0.2 LEN=60 PROTO=TCP SPT=4444 DPT={p} WINDOW=64", 2000 + p * 0.5, kernel=True)
        self.assertIn("escaneo_de_puertos", self.kinds())

    def test_escaneo_local_baja_gravedad_y_no_bloquea(self):
        for p in range(1, 15):
            self.a.handle("kernel", f"[UFW BLOCK] SRC=192.168.1.99 DST=192.168.1.2 PROTO=TCP DPT={p}", 2000 + p, kernel=True)
        ev = [x for x in self.e.events() if x["kind"] == "escaneo_de_puertos"]
        self.assertEqual([x["sev"] for x in ev], ["low"])

    def test_sudo_fallido(self):
        self.a.handle("sudo", "jorge : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/jorge ; USER=root ; COMMAND=/bin/ls", 1)
        self.assertIn("sudo_fallido", self.kinds())
