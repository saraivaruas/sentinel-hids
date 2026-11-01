import os
import tempfile
import unittest
from unittest import mock

from helpers import core
from sentinel import firewall
from sentinel.firewall import exposure, iptables, ufw

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

    SS = """tcp LISTEN 0 4096 0.0.0.0:443 0.0.0.0:* users:(("nginx",pid=1,fd=6))
tcp LISTEN 0 4096 0.0.0.0:9200 0.0.0.0:* users:(("java",pid=2,fd=6))
tcp LISTEN 0 4096 0.0.0.0:8080 0.0.0.0:* users:(("docker-proxy",pid=3,fd=4))
tcp LISTEN 0 4096 127.0.0.1:3306 0.0.0.0:*
tcp LISTEN 0 4096 100.71.15.101%tailscale0:52047 0.0.0.0:*
udp UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:*
"""
    DOCKER = "web\t0.0.0.0:8080->80/tcp, :::8080->80/tcp\ndb\t33060/tcp, 127.0.0.1:3307->3306/tcp\napi\t0.0.0.0:9000->9000/tcp\n"

    def test_docker_publicado(self):
        d = exposure.parse_docker(self.DOCKER)
        self.assertEqual([(x["name"], x["port"], x["all"]) for x in d], [("web", 8080, True), ("web", 8080, True), ("db", 3307, False), ("api", 9000, True)])

    def test_exposicion_real(self):
        res = exposure.analyze(self.SS, {443}, exposure.parse_docker(self.DOCKER))
        st = {(r["proto"], r["port"]): r["status"] for r in res}
        self.assertEqual(st[("tcp", 8080)], "docker"); self.assertEqual(st[("tcp", 9000)], "docker")      # Docker salta el firewall (aunque no haya proceso que escuche)
        self.assertEqual(st[("tcp", 443)], "abierto"); self.assertEqual(st[("tcp", 9200)], "bloqueado")
        self.assertEqual(st[("tcp", 3306)], "local"); self.assertEqual(st[("tcp", 52047)], "privada"); self.assertEqual(st[("udp", 53)], "local")
        self.assertEqual(res[0]["status"], "docker")                                                        # lo más grave primero
        self.assertIn("127.0.0.1", next(r for r in res if r["port"] == 9200)["advice"])
        self.assertIn("web", next(r for r in res if r["port"] == 8080)["advice"])
        self.assertEqual(exposure.analyze(self.SS, {443}, exposure.parse_docker(self.DOCKER), True)[0]["status"] != "docker", True)   # con DROP en DOCKER-USER ya no se marca

    def _apply_prueba(self, d, run_rc=0):
        calls = []
        def run(cmd, timeout=20):
            calls.append(cmd); return (run_rc if cmd[0] == "systemd-run" else 0), UFW if cmd[:3] == ["ufw", "status", "numbered"] else ""
        f = os.path.join(d, "user.rules"); open(f, "w").write("x")
        env = {"SENTINEL_STATE": d}
        with mock.patch.dict(os.environ, env), mock.patch.object(core, "is_root", return_value=True), mock.patch.object(core, "run", side_effect=run), \
             mock.patch.object(firewall, "pick", return_value=ufw), mock.patch.object(ufw, "outgoing_allowed", return_value=True), \
             mock.patch.object(firewall.shutil, "which", return_value="/usr/bin/x"), mock.patch.object(os.path, "isdir", return_value=True):
            log = firewall.apply(core.load_config(), state_dir=d, conf_dirs=[f], probar=60)
        return log, calls

    def test_aplicar_a_prueba_programa_la_reversion(self):
        with tempfile.TemporaryDirectory() as d:
            log, calls = self._apply_prueba(d)
            sr = next(c for c in calls if c[0] == "systemd-run")
            self.assertIn("--on-active", sr); self.assertIn("60s", sr); self.assertEqual(sr[-3:], ["firewall", "restaurar", "--pendiente"])
            with mock.patch.dict(os.environ, {"SENTINEL_STATE": d}):
                pend = firewall.pending()
            self.assertTrue(pend and pend["seconds"] == 60 and os.path.isdir(pend["copy"])); self.assertTrue(any("A PRUEBA" in l for l in log))

    def test_si_no_se_puede_programar_la_reversion_se_deshace(self):
        with tempfile.TemporaryDirectory() as d:
            restored = []
            with mock.patch.object(ufw, "restore", side_effect=lambda x: restored.append(x) or ["ok"]):
                log, calls = self._apply_prueba(d, run_rc=1)
            self.assertTrue(restored); self.assertTrue(any("deshago" in l for l in log))

    def test_confirmar_cancela_la_reversion(self):
        with tempfile.TemporaryDirectory() as d, mock.patch.dict(os.environ, {"SENTINEL_STATE": d}):
            core.atomic_write_json(firewall.pending_path(), {"copy": d, "deadline": core.now() + 50, "seconds": 60})
            calls = []
            with mock.patch.object(core, "run", side_effect=lambda c, t=20: calls.append(c) or (0, "")):
                self.assertIn("confirmados", firewall.confirm()[0])
            self.assertIn(["systemctl", "stop", "sentinel-fw-revert.timer"], calls); self.assertIsNone(firewall.pending())

    def test_restaurar_usa_la_copia_pendiente(self):
        with tempfile.TemporaryDirectory() as d, mock.patch.dict(os.environ, {"SENTINEL_STATE": d}):
            c = os.path.join(d, "firewall-copia-1"); os.makedirs(c)
            core.atomic_write_json(firewall.pending_path(), {"copy": c, "deadline": core.now() + 50, "seconds": 60})
            got = []
            with mock.patch.object(core, "is_root", return_value=True), mock.patch.object(core, "run", return_value=(0, "")), mock.patch.object(firewall, "pick", return_value=ufw), \
                 mock.patch.object(ufw, "restore", side_effect=lambda x: got.append(x) or ["ufw recargado"]):
                log = firewall.restore(use_pending=True)
            self.assertEqual(got, [c]); self.assertIsNone(firewall.pending())

    def test_puertos_por_origen(self):
        txt = UFW.replace("[ 8] 9200/tcp                   ALLOW IN    10.0.0.7", "[ 8] 9200/tcp                   ALLOW IN    10.0.0.0/8") + "[11] 22/tcp                     ALLOW IN    Anywhere\n"
        conf = dict(CONF, restrict=firewall.parse_restrict("22=100.64.0.0/10|203.0.113.7, 9200=10.0.0.0/8"))
        p = firewall.plan(ufw.parse_rules(txt), conf, {"ports": [], "sessions": []})
        self.assertIn(11, [r["id"] for r in p["remove"]])                       # 22 abierto a cualquiera sobra
        self.assertIn(8, [r["id"] for r in p["keep"]]); self.assertEqual(p["review"], [])      # 9200 desde 10.0.0.0/8 es lo pedido
        self.assertEqual(p["missing_from"], [(22, "100.64.0.0/10"), (22, "203.0.113.7/32")])
        self.assertNotIn(22, p["missing"]); self.assertTrue(any("solo desde 203.0.113.7/32" in l for l in firewall.describe(p, "ufw")))
        calls = []
        with mock.patch.object(core, "run", side_effect=lambda c, t=20: calls.append(c) or (0, "")):
            ufw.allow(22, "tcp", "100.64.0.0/10")
        self.assertEqual(calls[0], ["ufw", "allow", "from", "100.64.0.0/10", "to", "any", "port", "22", "proto", "tcp"])

    def test_perfiles_y_validacion(self):
        cfg = core.load_config(); cfg.set("firewall", "profile", "estacion")
        self.assertEqual(firewall.settings(cfg)["allow_tcp"], [])
        cfg.set("firewall", "profile", "web"); self.assertEqual(firewall.settings(cfg)["allow_tcp"], [80, 443])
        self.assertEqual(firewall.parse_restrict("22=bad|10.0.0.1, x=1, 80="), {22: ["10.0.0.1/32"]})
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "s.conf"); open(p, "w").write("[fim]\nwww = /x\n")
            firewall.set_config("restrict", "22=100.64.0.0/10|203.0.113.7", p); firewall.set_config("profile", "web", p); firewall.set_config("ssh_limit", "yes", p)
            self.assertEqual(firewall.settings(core.load_config(p))["restrict"], {22: ["100.64.0.0/10", "203.0.113.7/32"]})
            for k, v in (("restrict", "22=nada"), ("restrict", "22=10.0.0.1|zzz"), ("profile", "x"), ("ssh_limit", "tal vez")):
                with self.assertRaises(ValueError):
                    firewall.set_config(k, v, p)

    def test_ssh_con_limite_de_intentos(self):
        calls = []
        with mock.patch.object(core, "run", side_effect=lambda c, t=20: calls.append(c) or (0, "")):
            ufw.allow(22, "tcp", limit=True); ufw.allow(80, "tcp")
        self.assertEqual(calls, [["ufw", "limit", "22/tcp"], ["ufw", "allow", "80/tcp"]])


if __name__ == "__main__":
    unittest.main()
