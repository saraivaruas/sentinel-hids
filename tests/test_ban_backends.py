import unittest
from unittest import mock

from helpers import Env, core


class BanBackendTests(unittest.TestCase):
    def _ban(self, backend, ip="203.0.113.9"):
        e = Env()
        e.cfg.set("ban", "backend", backend)
        b = core.Banner(e.cfg, e.alerter, e.allow)
        calls = []
        with mock.patch.object(core, "is_root", return_value=True), mock.patch.object(core, "run", side_effect=lambda c, t=20: (calls.append(c) or (0, ""))):
            ok = b.ban(ip, "prueba", 3600)
            b.bans[ip]["until"] = 0
            b.expire()
        e.close()
        return ok, calls

    def test_firewalld_con_caducidad_propia(self):
        ok, calls = self._ban("firewalld")
        self.assertTrue(ok); self.assertEqual(calls[0][0], "firewall-cmd")
        self.assertIn("--timeout=3600", calls[0]); self.assertIn('source address="203.0.113.9"', calls[0][1])
        self.assertEqual(len(calls), 1)                                      # al caducar no hace falta deshacer nada

    def test_iptables_bloquea_y_al_caducar_borra_la_regla(self):
        ok, calls = self._ban("iptables")
        self.assertTrue(ok); self.assertEqual(calls[0][:4], ["iptables", "-I", "INPUT", "1"]); self.assertEqual(calls[1][:3], ["iptables", "-D", "INPUT"])

    def test_iptables_ipv6(self):
        ok, calls = self._ban("iptables", "2001:db8::5")
        self.assertEqual(calls[0][0], "ip6tables")

    def test_ufw_y_crowdsec(self):
        ok, calls = self._ban("ufw"); self.assertEqual(calls[0][:3], ["ufw", "insert", "1"]); self.assertEqual(calls[1][:2], ["ufw", "delete"])
        ok, calls = self._ban("crowdsec"); self.assertEqual(calls[0][:3], ["cscli", "decisions", "add"]); self.assertIn("--reason", calls[0]); self.assertEqual(len(calls), 1)

    def test_deteccion_automatica(self):
        e = Env()
        try:
            b = core.Banner(e.cfg, e.alerter, e.allow)
            fake = lambda activos, tiene: (mock.patch.object(core, "run", side_effect=lambda c, t=20: (0, "active\n" if c[-1] in activos else "inactive\n")),
                                           mock.patch.object(core.shutil, "which", side_effect=lambda n: f"/usr/bin/{n}" if n in tiene else None))
            for activos, tiene, esperado in (({"crowdsec"}, {"cscli", "firewall-cmd"}, "crowdsec"), ({"firewalld"}, {"firewall-cmd"}, "firewalld"), (set(), {"iptables"}, "iptables"), (set(), set(), "none")):
                p1, p2 = fake(activos, tiene)
                with p1, p2:
                    e.cfg.set("ban", "backend", "auto")
                    self.assertEqual(b.backend(), esperado)
        finally:
            e.close()


if __name__ == "__main__":
    unittest.main()
