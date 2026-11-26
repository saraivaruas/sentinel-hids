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
            linux = mock.patch.object(core.plataforma, "ES_MAC", False)
            linux.start(); self.addCleanup(linux.stop)
            for activos, tiene, esperado in (({"crowdsec"}, {"cscli", "firewall-cmd"}, "crowdsec"), ({"firewalld"}, {"firewall-cmd"}, "firewalld"), (set(), {"iptables"}, "iptables"), (set(), set(), "none")):
                p1, p2 = fake(activos, tiene)
                with p1, p2:
                    e.cfg.set("ban", "backend", "auto")
                    self.assertEqual(b.backend(), esperado)
        finally:
            e.close()

    def test_macos_elige_pf(self):
        e = Env()
        try:
            e.cfg.set("ban", "backend", "auto")
            with mock.patch.object(core.plataforma, "ES_MAC", True), mock.patch.object(core.shutil, "which", return_value="/sbin/pfctl"):
                self.assertEqual(core.Banner(e.cfg, e.alerter, e.allow).backend(), "pf")
        finally:
            e.close()


class PfTests(unittest.TestCase):
    """pf simulado: recuerda si las reglas están cargadas, si está encendido y qué IPs hay en la tabla."""

    def setUp(self):
        self.e = Env()
        self.e.cfg.set("ban", "backend", "pf")
        self.principal, self.cargado, self.encendido, self.tabla, self.calls = 'anchor "com.apple/*" all\n', False, False, set(), []
        hay_pf = mock.patch.object(core.shutil, "which", side_effect=lambda n: "/sbin/pfctl" if n == "pfctl" else None)    # igual en cualquier equipo
        for p in (hay_pf, mock.patch.object(core, "is_root", return_value=True), mock.patch.object(core, "run", side_effect=self.pfctl)):
            p.start(); self.addCleanup(p.stop)
        self.b = core.Banner(self.e.cfg, self.e.alerter, self.e.allow)

    def tearDown(self):
        self.e.close()

    def pfctl(self, c, t=20):
        self.calls.append(c)
        if c == ["pfctl", "-sr"]:
            return 0, self.principal
        if c == ["pfctl", "-s", "info"]:
            return 0, "Status: Enabled" if self.encendido else "Status: Disabled"
        if c == ["pfctl", "-E"]:
            self.encendido = True
        elif c[-1] == "-sr":
            return 0, "block drop in quick from <sentinel> to any\n" if self.cargado else ""
        elif "-f" in c and "-a" in c:
            self.cargado = True
        elif "add" in c:
            self.tabla.add(c[-1])
        elif "delete" in c:
            self.tabla.discard(c[-1])
        return 0, ""

    def test_bloquea_corta_conexiones_y_libera_al_caducar(self):
        self.assertTrue(self.b.ban("203.0.113.9", "prueba", 3600))
        self.assertTrue(self.cargado and self.encendido)
        self.assertEqual(self.tabla, {"203.0.113.9"}); self.assertIn(["pfctl", "-k", "203.0.113.9"], self.calls)
        self.b.bans["203.0.113.9"]["until"] = 0
        self.b.expire()
        self.assertEqual(self.tabla, set())

    def test_no_recarga_si_ya_esta_listo(self):
        self.b.ban("203.0.113.9", "prueba", 3600)
        self.calls.clear()
        self.b.ban("203.0.113.10", "prueba", 3600)
        self.assertNotIn(["pfctl", "-E"], self.calls); self.assertFalse([c for c in self.calls if "-f" in c])

    def test_repone_los_bloqueos_tras_reiniciar(self):
        self.b.ban("203.0.113.9", "prueba", 3600)
        self.cargado, self.encendido, self.tabla = False, False, set()
        self.assertEqual(self.b.reafirmar(), ["203.0.113.9"])
        self.assertTrue(self.cargado and self.encendido); self.assertEqual(self.tabla, {"203.0.113.9"})

    def test_no_repone_lo_liberado_desde_otro_proceso(self):
        self.b.ban("203.0.113.9", "prueba", 3600)
        core.Banner(self.e.cfg, self.e.alerter, self.e.allow).unban("203.0.113.9")
        self.assertEqual(self.b.reafirmar(), []); self.assertEqual(self.tabla, set())

    def test_si_pf_no_incluye_el_ancla_avisa_y_no_finge(self):
        self.principal = "block drop all\n"
        self.assertFalse(self.b.ban("203.0.113.9", "prueba", 3600))
        self.assertEqual(self.b.bans, {})
        self.assertIn("fallo", [x["kind"] for x in self.e.events()])
        self.assertNotIn(["pfctl", "-f", "/etc/pf.conf"], self.calls)        # no pisa reglas ajenas


if __name__ == "__main__":
    unittest.main()
