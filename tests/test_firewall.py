import os
import tempfile
import unittest
from unittest import mock

from helpers import core
from sentinel import firewall
from sentinel.firewall import iptables, ufw

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


CONF = {"backend": "auto", "allow_tcp": [80, 443], "allow_udp": [], "keep_ssh": True}
IPT = """-P INPUT ACCEPT
-A INPUT -i lo -j ACCEPT
-A INPUT -p tcp -m tcp --dport 80 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 2222 -m comment --comment "sentinel-senuelo" -j ACCEPT
-A INPUT -s 10.0.0.7/32 -p tcp -m tcp --dport 9200 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 3306 -j DROP
"""


class FirewallTests(unittest.TestCase):
    def plan(self, txt=UFW, ssh=None, conf=CONF, out=True):
        return firewall.plan(ufw.parse_rules(txt), conf, ssh or {"ports": [], "sessions": []}, out)

    def test_parseo_ufw(self):
        r = ufw.parse_rules(UFW)
        self.assertEqual(len(r), 10)
        self.assertEqual(r[5]["port"], 2222); self.assertEqual(r[5]["comment"], "sentinel-senuelo"); self.assertTrue(r[9]["v6"]); self.assertEqual(r[1]["iface"], "lo")

    def test_plan_cierra_senuelos_y_abre_443(self):
        p = self.plan()
        self.assertEqual([r["id"] for r in p["remove"]], [6, 7, 10]); self.assertEqual(p["missing"], [443])
        self.assertEqual([r["id"] for r in p["review"]], [8])
        self.assertIn(5, [r["id"] for r in p["keep"]])

    def test_puertos_permitidos_son_configurables(self):
        p = self.plan(conf=dict(CONF, allow_tcp=[80, 443, 5900]))
        self.assertNotIn(7, [r["id"] for r in p["remove"]]); self.assertIn(5900, p["keep_ports"])

    def test_mantiene_ssh_si_el_equipo_lo_sirve(self):
        ssh = firewall.ssh_ports(ss_text=SSHD)
        self.assertEqual(ssh["ports"], [2200])
        p = self.plan(ssh=ssh)
        self.assertIn(2200, p["missing"]); self.assertEqual(p["keep_ports"], [80, 443, 2200])
        self.assertTrue(any("SSH" in l for l in firewall.describe(p, "ufw")))
        self.assertNotIn(2200, self.plan(ssh=ssh, conf=dict(CONF, keep_ssh=False))["keep_ports"])

    def test_sin_saliente_no_aplica(self):
        with mock.patch.object(core, "is_root", return_value=True), mock.patch.object(ufw, "rules", return_value=(ufw.parse_rules(UFW), "")), \
             mock.patch.object(ufw, "outgoing_allowed", return_value=False), mock.patch.object(core, "run", return_value=(0, "")) as run, mock.patch.object(firewall, "pick", return_value=ufw):
            self.assertIn("No se aplicó nada", firewall.apply(core.load_config())[0])
            self.assertTrue(all(c.args[0][0] == "ss" for c in run.call_args_list))      # solo lee; no cambia reglas

    def test_aplica_en_orden_y_con_copia(self):
        calls = []
        def run(cmd, timeout=20):
            calls.append(cmd); return 0, UFW if cmd[:3] == ["ufw", "status", "numbered"] else ""
        with tempfile.TemporaryDirectory() as d, mock.patch.object(core, "is_root", return_value=True), mock.patch.object(core, "run", side_effect=run), \
             mock.patch.object(firewall, "pick", return_value=ufw), mock.patch.object(ufw, "outgoing_allowed", return_value=True):
            f = os.path.join(d, "user.rules"); open(f, "w").write("x")
            log = firewall.apply(core.load_config(), state_dir=d, conf_dirs=[f])
            self.assertTrue(any(n.startswith("firewall-copia-") for n in os.listdir(d)))
        self.assertTrue(log[0].startswith("Copia"))
        ufw_calls = [c for c in calls if c[0] == "ufw" and c[1] in ("allow", "--force")]
        self.assertEqual(ufw_calls[0], ["ufw", "allow", "443/tcp"])
        self.assertEqual([c[3] for c in ufw_calls if c[1] == "--force"], ["10", "7", "6"])

    def test_iptables(self):
        r = iptables.parse_rules(IPT)
        self.assertEqual([x["port"] for x in r], [80, 2222, 9200, 3306])
        p = firewall.plan(r, CONF, {"ports": [], "sessions": []})
        self.assertEqual([x["port"] for x in p["remove"]], [2222]); self.assertEqual([x["port"] for x in p["review"]], [9200]); self.assertEqual(p["missing"], [443])
        calls = []
        with mock.patch.object(core, "run", side_effect=lambda c, t=20: (calls.append(c) or (0, ""))), mock.patch("shutil.which", return_value="/sbin/x"):
            iptables.delete_all(p["remove"])
        self.assertEqual(calls[0], ["iptables", "-D", "INPUT", "-p", "tcp", "-m", "tcp", "--dport", "2222", "-m", "comment", "--comment", "sentinel-senuelo", "-j", "ACCEPT"])

    def test_iptables_endurecer_deja_pasar_lo_local_antes_del_drop(self):
        calls = []
        def run(c, t=20):
            calls.append(c); return 0, "-P INPUT ACCEPT\n" if c[1] == "-S" else ""
        with mock.patch.object(core, "run", side_effect=run), mock.patch("shutil.which", side_effect=lambda t: "/sbin/iptables" if t == "iptables" else None):
            iptables.harden()
        flat = [" ".join(c) for c in calls]
        self.assertLess(next(i for i, c in enumerate(flat) if "-i lo" in c), next(i for i, c in enumerate(flat) if "-P INPUT DROP" in c))
        self.assertTrue(any("ESTABLISHED,RELATED" in c for c in flat))

    def test_configuracion(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "s.conf"); open(p, "w").write("[ban]\nbackend = auto\n\n[fim]\nwww = /x\n")
            firewall.set_config("allow_tcp", "80, 443,8080", p); firewall.set_config("allow_tcp", "80,443", p); firewall.set_config("keep_ssh", "no", p)
            cfg = core.load_config(p)
            self.assertEqual(firewall.settings(cfg)["allow_tcp"], [80, 443]); self.assertFalse(firewall.settings(cfg)["keep_ssh"]); self.assertEqual(cfg.get("fim", "www"), "/x")
            for k, v in (("allow_tcp", "80;rm"), ("allow_tcp", "70000"), ("backend", "x"), ("zzz", "1")):
                with self.assertRaises(ValueError):
                    firewall.set_config(k, v, p)


if __name__ == "__main__":
    unittest.main()
