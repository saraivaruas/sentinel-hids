"""Cortafuegos de puertos en macOS, con pf simulado: nunca toca el equipo que corre las pruebas."""
import unittest
from unittest import mock

from helpers import Env, core
from sentinel import firewall, plataforma
from sentinel.firewall import pf_mac

LSOF = "p1\ncnginx\nf3\nPTCP\nn*:80\np2\ncjava\nf4\nPTCP\nn*:9200\np3\ncpostgres\nf5\nPTCP\nn127.0.0.1:5432\n"


class PfMacTests(unittest.TestCase):
    def setUp(self):
        self.e = Env(extra="[firewall]\nallow_tcp = 80\nprofile = custom\n"); self.addCleanup(self.e.close)
        self.cargado, self.ssh, self.calls = "", True, []
        for p in (mock.patch.object(plataforma, "ES_MAC", True), mock.patch.object(core, "is_root", return_value=True),
                  mock.patch.object(core, "run", side_effect=self.sistema), mock.patch.object(pf_mac.shutil, "which", return_value="/usr/local/bin/sentinel"),
                  mock.patch.object(pf_mac.os.path, "exists", side_effect=self.existe), mock.patch.object(pf_mac, "SSHD_CONFIG", "/no/existe"),    # no leer el SSH real
                  mock.patch.object(pf_mac.subprocess, "Popen")):
            m = p.start(); self.addCleanup(p.stop)
        self.popen = m

    _existe = staticmethod(pf_mac.os.path.exists)

    def existe(self, ruta):
        return True if ruta == "/usr/local/bin/sentinel" else self._existe(ruta)

    def sistema(self, c, t=20):
        self.calls.append(c)
        if c[0] == "launchctl":
            return (0, "") if self.ssh else (113, "")
        if c[0] == "lsof":
            return (0, LSOF) if "-iTCP" in c else (1, "")
        if c == ["pfctl", "-sr"]:
            return 0, 'anchor "com.apple/*" all\n'
        if c == ["pfctl", "-s", "info"]:
            return 0, "Status: Enabled"
        if c[:3] == ["pfctl", "-a", pf_mac.ANCLA]:
            if c[3] == "-sr":
                return 0, self.cargado
            if c[3] == "-f":
                with open(c[4], encoding="utf-8") as f:
                    self.cargado = f.read()
            if c[3] == "-F":
                self.cargado = ""
        return 0, ""

    def test_las_reglas_abren_solo_lo_elegido_y_no_cortan_lo_iniciado(self):
        r = pf_mac.reglas(pf_mac.deseado(firewall.settings(self.e.cfg), {"ports": [22], "sessions": []}))
        self.assertIn("pass in quick proto tcp from any to any port { 22, 80 }", r)
        self.assertIn("block return in proto tcp from any to any flags S/SA", r)          # solo conexiones nuevas
        self.assertIn("pass out quick on ! lo0 all keep state", r); self.assertIn("pass in quick on lo0 all", r)
        self.assertLess(r.index("port { 22, 80 }"), r.index("block return"))

    def test_puertos_limitados_a_un_origen(self):
        d = pf_mac.deseado({"allow_tcp": [22], "allow_udp": [], "keep_ssh": True, "restrict": {22: ["100.64.0.0/10"]}}, {"ports": [22], "sessions": []})
        r = pf_mac.reglas(d)
        self.assertEqual(d["tcp"], []); self.assertIn("pass in quick proto tcp from 100.64.0.0/10 to any port 22", r); self.assertNotIn("from any to any port { 22", r)

    def test_el_plan_muestra_lo_que_se_va_a_cerrar(self):
        s = firewall.state(self.e.cfg)
        self.assertTrue(s["ok"]); self.assertEqual(s["backend"], "pf"); self.assertFalse(s["activo"])
        self.assertEqual([r["port"] for r in s["plan"]["remove"]], [9200])               # 80 se queda; 5432 solo escucha en el equipo
        self.assertEqual(s["plan"]["keep_ports"], [22, 80])
        self.assertFalse([c for c in self.calls if "-f" in c])                            # mirar no cambia nada

    def test_aplicar_a_prueba_y_confirmar(self):
        log = firewall.apply(self.e.cfg, probar=60)
        self.assertTrue(any("A PRUEBA" in x for x in log), log); self.assertIn("block return", self.cargado)
        self.assertIn("firewall restaurar --pendiente", self.popen.call_args[0][0][-1])
        self.assertTrue(firewall.pending()); self.assertTrue(firewall.state(self.e.cfg)["activo"])
        self.assertIn("confirmados", firewall.confirm()[0]); self.assertIsNone(firewall.pending())
        self.assertIn("No había", firewall.restore(use_pending=True)[0]); self.assertIn("block return", self.cargado)       # la reversión programada ya no hace nada

    def test_si_no_se_confirma_vuelve_atras(self):
        firewall.apply(self.e.cfg, probar=60)
        p = core.read_json(firewall.pending_path()); core.atomic_write_json(firewall.pending_path(), dict(p, deadline=core.now() - 1))
        firewall.restore(use_pending=True)
        self.assertEqual(self.cargado, ""); self.assertIsNone(core.read_json(pf_mac.estado_path()))

    def test_el_monitor_revierte_una_prueba_vencida_y_repone_lo_confirmado(self):
        firewall.apply(self.e.cfg, probar=60)
        p = core.read_json(firewall.pending_path()); core.atomic_write_json(firewall.pending_path(), dict(p, deadline=core.now() - 1))
        pf_mac.reafirmar(); self.assertEqual(self.cargado, "")
        firewall.apply(self.e.cfg)
        self.cargado = ""                                                                # como tras reiniciar
        pf_mac.reafirmar(); self.assertIn("block return", self.cargado)

    def test_restaurar_vuelve_a_las_reglas_confirmadas_anteriores(self):
        firewall.apply(self.e.cfg)
        antes = self.cargado
        self.e.cfg.set("firewall", "allow_tcp", "80,8080")
        with mock.patch.object(pf_mac.time, "strftime", return_value="99999999-000000"):
            firewall.apply(self.e.cfg)
        self.assertIn("8080", self.cargado)
        firewall.restore()
        self.assertEqual(self.cargado, antes)


if __name__ == "__main__":
    unittest.main()
