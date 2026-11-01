import os
import tempfile
import unittest
from unittest import mock

from helpers import core
from sentinel import ports

UFW = """Estado: activo

     Hasta                      Acción      Desde
     -----                      ------      -----
[ 1] 5001/tcp                   DENY IN     Anywhere
[ 2] Anywhere on lo             ALLOW IN    Anywhere
[ 3] Anywhere                   DENY IN     192.168.0.5
[ 4] 80/tcp                     ALLOW IN    Anywhere
[ 5] 1234                       ALLOW IN    127.0.0.1
[ 6] 2222/tcp                   ALLOW IN    Anywhere                   # sentinel-senuelo
[ 7] 5900/tcp                   ALLOW IN    Anywhere                   # sentinel-senuelo
[ 8] 9200/tcp                   ALLOW IN    10.0.0.7
[ 9] 80/tcp (v6)                ALLOW IN    Anywhere (v6)
[10] 2222/tcp (v6)              ALLOW IN    Anywhere (v6)              # sentinel-senuelo
"""
SSHD = 'LISTEN 0 128 0.0.0.0:2200 0.0.0.0:* users:(("sshd",pid=9,fd=3))\nLISTEN 0 128 0.0.0.0:9200 0.0.0.0:* users:(("java",pid=8,fd=3))\n'


class PortsTests(unittest.TestCase):
    def test_parseo(self):
        r = ports.parse_rules(UFW)
        self.assertEqual(len(r), 10)
        self.assertEqual(r[5]["port"], 2222); self.assertEqual(r[5]["comment"], "sentinel-senuelo"); self.assertTrue(r[9]["v6"])
        self.assertEqual(r[1]["iface"], "lo")

    def test_plan_cierra_senuelos_y_abre_443(self):
        p = ports.plan(ports.parse_rules(UFW), {"ports": [], "sessions": []})
        self.assertEqual([r["num"] for r in p["remove"]], [6, 7, 10])
        self.assertEqual(p["missing"], [443])
        self.assertEqual([r["num"] for r in p["review"]], [8])        # permiso a un equipo concreto: se deja a una persona
        self.assertIn(5, [r["num"] for r in p["keep"]])               # reglas locales no se tocan

    def test_mantiene_ssh_si_el_equipo_lo_sirve(self):
        ssh = ports.ssh_ports(ss_text=SSHD)
        self.assertEqual(ssh["ports"], [2200])
        p = ports.plan(ports.parse_rules(UFW), ssh)
        self.assertIn(2200, p["missing"]); self.assertEqual(p["keep_ports"], [80, 443, 2200])
        self.assertTrue(any("SSH" in l for l in ports.describe(p)))

    def test_ssh_con_puerto_ya_permitido_no_se_cierra(self):
        txt = UFW.replace("2222/tcp                   ALLOW IN    Anywhere  ", "2200/tcp                   ALLOW IN    Anywhere  ", 1)
        p = ports.plan(ports.parse_rules(txt), {"ports": [2200], "sessions": ["10.0.0.9"]})
        self.assertNotIn(6, [r["num"] for r in p["remove"]]); self.assertNotIn(2200, p["missing"])

    def test_sin_saliente_no_aplica(self):
        p = ports.plan(ports.parse_rules(UFW), {"ports": [], "sessions": []}, default_out_allow=False)
        with mock.patch.object(core, "is_root", return_value=True), mock.patch.object(core, "run") as run:
            self.assertIn("No se aplicó nada", ports.apply(p)[0]); run.assert_not_called()

    def test_aplica_en_orden_y_con_copia(self):
        p = ports.plan(ports.parse_rules(UFW), {"ports": [], "sessions": []})
        calls = []
        def run(cmd, timeout=20):
            calls.append(cmd); return 0, UFW if cmd[:3] == ["ufw", "status", "numbered"] else ""
        with tempfile.TemporaryDirectory() as d, mock.patch.object(core, "is_root", return_value=True), mock.patch.object(core, "run", side_effect=run):
            conf = os.path.join(d, "ufw"); os.makedirs(conf); open(os.path.join(conf, "user.rules"), "w").write("x")
            ports.apply(p, d, conf); self.assertTrue(any(n.startswith("ufw-copia-") for n in os.listdir(d)))
        self.assertEqual(calls[0], ["ufw", "allow", "443/tcp"])                       # primero abre
        self.assertEqual([c[3] for c in calls if c[:3] == ["ufw", "--force", "delete"]], ["10", "7", "6"])   # luego cierra de mayor a menor


if __name__ == "__main__":
    unittest.main()
