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


class AjustesTests(unittest.TestCase):
    def test_set_setting_cambia_solo_lo_pedido(self):
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "s.conf")
            with open(p, "w") as f:
                f.write("[general]\nnotify_min = medium\nemail_to = a@b.cl\n\n[ban]\nbackend = auto\n")
            core.set_setting("general", "notify_min", "high", p); core.set_setting("general", "popup_min", "never", p)
            with open(p) as f:
                txt = f.read()
            self.assertIn("notify_min = high", txt); self.assertIn("email_to = a@b.cl", txt); self.assertIn("[ban]\nbackend = auto", txt)
            self.assertEqual(core.load_config(p).get("general", "popup_min"), "never")
            for bad in (("general", "email_to", "x"), ("general", "notify_min", "ultra"), ("ban", "backend", "none"), ("general", "notify_seconds", "1")):
                with self.assertRaises(ValueError):
                    core.set_setting(*bad, path=p)


class InformeTests(unittest.TestCase):
    def ev(self, i, path, kind="removed"):
        return {"sev": "high", "source": "fim", "kind": kind, "msg": f"{path}: eliminado", "ts": "2026-11-01T15:04:0%d" % i, "epoch": i, "key": f"k{i}", "data": {}}

    def test_agrupa_eventos_repetidos_de_una_carpeta(self):
        from sentinel import report
        evs = [self.ev(i, f"/etc/systemd/system/sentinel-{n}.service") for i, n in enumerate(["a", "b", "c", "a", "b", "c"])]
        evs.append({"sev": "high", "source": "auth", "kind": "fuerza_bruta", "msg": "5 intentos desde 1.2.3.4", "ts": "x", "epoch": 9, "key": "z", "data": {}})
        out = report.group_events(evs)
        self.assertEqual(len(out), 2)
        g = next(e for e in out if e.get("grouped"))
        self.assertIn("3 archivos eliminados en /etc/systemd/system", g["msg"]); self.assertIn("avisado 6 veces", g["msg"])
        self.assertEqual(len(report.group_events(evs[:2])), 2)                         # pocos eventos: se dejan tal cual

    def test_eliminado_explica_que_significa(self):
        from sentinel import fim
        out = fim.diff({"/etc/x": {"type": "f", "mode": 0o644, "uid": 0, "gid": 0, "size": 1, "sha": "a", "mtime": 1, "ino": 1}}, {}, [])
        self.assertIn("ya no existe", out[0]["detail"])

    def test_el_informe_solo_cuenta_hallazgos_reales(self):
        from sentinel import report
        mk = lambda src, kind, sev: {"sev": sev, "source": src, "kind": kind, "msg": "m", "ts": "t", "epoch": 1, "key": kind, "data": {}}
        evs = [mk("test", "prueba", "medium"), mk("monitor", "inicio", "info"), mk("fim", "modified", "info"), mk("host", "usb_nuevo", "low"), mk("auth", "fuerza_bruta", "high")]
        self.assertEqual([e["kind"] for e in report.relevant(evs)], ["usb_nuevo", "fuerza_bruta"])

    def test_cambios_del_firewall_y_servicios_propios_no_son_alta(self):
        from sentinel import fim
        r = lambda path, kind, sev="high", pkg=False, sigs=(): fim.reclassify(path, kind, sev, "x", pkg, list(sigs))[0]
        self.assertEqual(r("/etc/ufw/user.rules", "modified"), "low")
        self.assertEqual(r("/etc/systemd/system/sentinel-monitor.service", "removed"), "low")
        self.assertEqual(r("/etc/systemd/system/timers.target.wants/sentinel-scan.timer", "link"), "low")
        self.assertEqual(r("/opt/sentinel/sentinel/core.py", "modified", pkg=True), "info")
        # lo que sí debe seguir avisando
        self.assertEqual(r("/etc/ssh/sshd_config", "modified"), "high")
        self.assertEqual(r("/etc/systemd/system/backdoor.service", "added"), "high")
        self.assertEqual(r("/etc/systemd/system/otro.service", "removed"), "high")
        self.assertEqual(r("/etc/ufw/user.rules", "modified", sigs=["php: x"]), "high")
