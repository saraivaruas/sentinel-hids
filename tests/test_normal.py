from __future__ import annotations

import json
import os
import unittest
import unittest.mock as m

from helpers import Env, core
from sentinel import cli, hostcheck, normal, ui

SS = 'tcp   LISTEN 0 511  0.0.0.0:80      0.0.0.0:* users:(("nginx",pid=2,fd=6))\n'


def ev(source, kind, sev="medium", **data):
    return {"source": source, "kind": kind, "sev": sev, "data": data}


class NormalTests(unittest.TestCase):
    def test_que_se_puede_marcar_como_normal(self):
        self.assertEqual(normal.args_for(ev("host", "puerto_nuevo", port=8081, proto="tcp", proc="node")), ["allow", "port", "8081"])
        self.assertEqual(normal.args_for(ev("host", "puerto_nuevo", port=41099, proto="udp", proc="syncthing")), ["allow", "proc", "syncthing"])
        self.assertEqual(normal.args_for(ev("host", "lector_de_teclado", proc="acpid")), ["allow", "proc", "acpid"])
        self.assertEqual(normal.args_for(ev("host", "usb_nuevo", usb="x")), ["baseline", "host"])
        self.assertEqual(normal.args_for(ev("fim", "modified", "high", path="/etc/hosts")), ["baseline", "accept", "/etc/hosts"])

    def test_los_ataques_no_se_aceptan(self):
        for e in (ev("auth", "fuerza_bruta", "high", ip="1.2.3.4"), ev("packets", "escaneo_syn", "high"), ev("fim", "added", "critical", path="/var/www/html/x.php"),
                  ev("fim", "added", "high", path="/var/www/html/x.php", signatures=["php: eval"]), ev("host", "usuario_nuevo", "high"), ev("host", "uid0", "critical"),
                  ev("fim", "modified", "high", path="relativo/x")):
            self.assertIsNone(normal.args_for(e), e)


class AccionNormalTests(unittest.TestCase):
    def test_la_accion_se_busca_en_el_registro_no_en_lo_que_manda_el_navegador(self):
        e = Env()
        try:
            with m.patch.dict(os.environ, {"SENTINEL_LOG": os.path.dirname(e.alerter.path)}):
                x = e.alerter.emit("medium", "host", "puerto_nuevo", "Nuevo puerto tcp/8081", key="k1", port=8081, proto="tcp", proc="node")
                self.assertEqual(ui.build_action({"name": "normal", "epoch": x.epoch, "key": "k1"}), ["allow", "port", "8081"])
                for malo in ({"name": "normal", "epoch": x.epoch, "key": "otra"}, {"name": "normal", "epoch": 1, "key": "k1"}, {"name": "normal"}):
                    with self.assertRaises((ValueError, TypeError)):
                        ui.build_action(malo)
        finally:
            e.close()


class AprendizajeTests(unittest.TestCase):
    def run_host(self, e, hc, base_ss, cur_ss):
        base = {"listeners": hostcheck.parse_listeners(base_ss), "usb": [], "modules": [], "accounts": {"users": [], "uid0": [], "empty": []}}
        core.atomic_write_json(hc.path, base)
        with m.patch.object(hostcheck, "listeners", return_value=hostcheck.parse_listeners(cur_ss)), m.patch.object(hostcheck, "accounts", return_value=base["accounts"]), \
             m.patch.object(hostcheck, "proc_scan", return_value=[]), m.patch.object(hostcheck, "input_readers", return_value=[]), m.patch.object(hostcheck, "suspicious_connections", return_value=[]), \
             m.patch.object(hostcheck, "usb_devices", return_value=["1:2 Ratón"]), m.patch.object(hostcheck, "kernel_modules", return_value=["mod_x"]):
            return [(x.kind, x.sev) for x in hc.run()]

    def test_en_modo_aprendizaje_lo_nuevo_se_acepta_sin_avisar(self):
        e = Env()
        try:
            hc = hostcheck.HostCheck(e.cfg, e.alerter, e.allow)
            nuevo = SS + 'tcp LISTEN 0 1 0.0.0.0:4444 0.0.0.0:* users:(("nc",pid=9,fd=3))\n'
            self.assertIn(("puerto_nuevo", "high"), self.run_host(e, hc, SS, nuevo))                       # sin aprendizaje: avisa
            core.atomic_write_json(hostcheck.learn_path(), {"until": core.now() + 3600})
            self.assertEqual([k for k, s in self.run_host(e, hc, SS, nuevo) if s != "info"], [])           # con aprendizaje: lo acepta
            self.assertIn("tcp/4444", core.read_json(hc.path)["listeners"])                                # y lo recuerda
            core.atomic_write_json(hostcheck.learn_path(), {"until": core.now() - 5})
            self.assertTrue(hostcheck.learning_until() == 0)
        finally:
            e.close()

    def test_el_aprendizaje_no_acepta_cuentas_ni_archivos(self):
        e = Env()
        try:
            hc = hostcheck.HostCheck(e.cfg, e.alerter, e.allow)
            core.atomic_write_json(hostcheck.learn_path(), {"until": core.now() + 3600})
            base = {"listeners": {}, "usb": [], "modules": [], "accounts": {"users": [], "uid0": [], "empty": []}}
            core.atomic_write_json(hc.path, base)
            cuentas = {"users": ["intruso"], "uid0": ["intruso"], "empty": []}
            with m.patch.object(hostcheck, "listeners", return_value={}), m.patch.object(hostcheck, "accounts", return_value=cuentas), m.patch.object(hostcheck, "proc_scan", return_value=[]), \
                 m.patch.object(hostcheck, "input_readers", return_value=[]), m.patch.object(hostcheck, "suspicious_connections", return_value=[]), \
                 m.patch.object(hostcheck, "usb_devices", return_value=[]), m.patch.object(hostcheck, "kernel_modules", return_value=[]):
                kinds = [x.kind for x in hc.run()]
            self.assertIn("uid0", kinds); self.assertIn("usuario_nuevo", kinds)
        finally:
            e.close()


if __name__ == "__main__":
    unittest.main()
