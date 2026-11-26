"""Falsos positivos que se corrigieron en el origen (el 13-nov-2026 el informe del equipo marcó ALTO por cosas normales)."""
import argparse
import io
import json
import os
import unittest
from contextlib import redirect_stdout
from unittest import mock

from helpers import Env, core
from sentinel import cli, equipo, firewall, hostcheck, mailer, packets, pin, pkgcheck

AQUI = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class FirewallTests(unittest.TestCase):
    def test_regla_del_loopback_no_se_avisa_pero_una_abierta_a_todos_si(self):
        e = Env()
        try:
            r = lambda label, frm: {"label": label, "port": None, "action": "ALLOW", "from": frm, "comment": "", "v6": False}
            os.makedirs(core.state_dir(), exist_ok=True)
            json.dump({"ok": True, "rules": []}, open(firewall.snapshot_path(), "w"))
            nuevo = {"ok": True, "rules": [r("[4] Anywhere on lo", "Anywhere"), r("[5] Anywhere (v6) on lo", "Anywhere (v6)"), r("[10] 80/tcp", "Anywhere")], "listening": []}
            with mock.patch.object(firewall, "save_snapshot", return_value=nuevo):
                firewall.watch(e.cfg, e.alerter)
            msgs = [ev["msg"] for ev in e.events() if ev["source"] == "firewall"]
            self.assertEqual(len(msgs), 1, msgs); self.assertIn("80/tcp", msgs[0]); self.assertIn("abierta a cualquiera", msgs[0])
        finally:
            e.close()

    def test_quitar_la_regla_del_loopback_tampoco_avisa(self):
        e = Env()
        try:
            lo = {"label": "[4] Anywhere on lo", "port": None, "action": "ALLOW", "from": "Anywhere", "comment": "", "v6": False}
            os.makedirs(core.state_dir(), exist_ok=True)
            json.dump({"ok": True, "rules": [lo]}, open(firewall.snapshot_path(), "w"))
            with mock.patch.object(firewall, "save_snapshot", return_value={"ok": True, "rules": [], "listening": []}):
                firewall.watch(e.cfg, e.alerter)
            self.assertEqual([ev for ev in e.events() if ev["source"] == "firewall"], [])
        finally:
            e.close()


class PaquetesTests(unittest.TestCase):
    def pkt(self, **k):
        return {"proto": "udp", "sport": 19302, "dport": 40000, "flags": None, "size": 60, **k}

    def test_udp_hacia_un_puerto_en_que_el_equipo_escucha_es_una_respuesta_no_un_escaneo(self):
        """Meet/WebRTC/STUN de Google (74.125.x) contestaba a muchos puertos de Chrome y se bloqueó como «escaneo UDP»."""
        with mock.patch.object(packets, "bound_udp_ports", return_value={40000}):
            self.assertIsNone(packets.interesting(self.pkt()))
            self.assertEqual(packets.interesting(self.pkt(dport=40001)), "udp")             # a un puerto sin nada escuchando sí cuenta

    def test_un_escaneo_real_sigue_detectandose(self):
        d = packets.Detector(Env().cfg)
        with mock.patch.object(packets, "bound_udp_ports", return_value=set()):
            found = []
            for i in range(25):
                kind = packets.interesting(self.pkt(sport=5000 + i, dport=2000 + i))
                found += d.feed("203.0.113.9", kind, self.pkt(sport=5000 + i, dport=2000 + i), 1_700_000_000.0 + i)
        self.assertTrue(any(f["kind"] == "escaneo_udp" for f in found))

    def test_lee_los_puertos_udp_en_uso(self):
        linux = mock.patch.object(packets.plataforma, "ES_MAC", False); linux.start(); self.addCleanup(linux.stop)     # lee /proc
        packets._bound["t"] = 0
        txt = "  sl  local_address rem_address\n  0: 00000000:1F90 00000000:0000 07\n  1: 0100007F:0035 00000000:0000 07\n"
        with mock.patch("builtins.open", mock.mock_open(read_data=txt)):
            self.assertEqual(packets.bound_udp_ports(0), {0x1F90, 0x35})


def fake_proc(exe, comm, cmdline=b"x\x00"):
    real = open

    def fake_open(path, *a, **k):
        if path == "/proc/4242/comm":
            return __import__("io").StringIO(comm + "\n")
        if path == "/proc/4242/cmdline":
            return __import__("io").BytesIO(cmdline)
        return real(path, *a, **k)
    return [mock.patch("os.listdir", return_value=["4242"]), mock.patch("os.readlink", return_value=exe), mock.patch("builtins.open", side_effect=fake_open)]


class ProcesosTests(unittest.TestCase):
    def scan(self, exe, comm="prog", cmdline=b"x\x00"):
        ps = fake_proc(exe, comm, cmdline) + [mock.patch.object(hostcheck.plataforma, "tiene_proc", return_value=True)]   # se simula /proc también en macOS
        for p in ps:
            p.start(); self.addCleanup(p.stop)
        return hostcheck.proc_scan(["/tmp", "/var/tmp", "/dev/shm", "/run/user"], ["xmrig"], set())

    def test_claude_o_node_actualizado_no_es_binario_borrado_sospechoso(self):
        r = self.scan("/home/jorge/.npm-global/lib/node_modules/@anthropic-ai/claude-code/bin/claude (deleted)", "claude")
        self.assertEqual([(x["sev"], x["kind"]) for x in r], [("low", "reinicio_pendiente")])

    def test_dotnet_recompilado_no_es_binario_borrado_sospechoso(self):
        r = self.scan("/home/jorge/proyectos/Api/bin/Debug/net10.0/Api (deleted)", "Api")
        self.assertEqual([(x["sev"], x["kind"]) for x in r], [("low", "reinicio_pendiente")])

    def test_binario_borrado_en_tmp_o_en_el_home_sin_origen_conocido_sigue_siendo_alto(self):
        for exe in ("/tmp/.x/backdoor (deleted)", "/dev/shm/a (deleted)", "/home/jorge/.cache/../Descargas/raro (deleted)"):
            self.assertEqual([x["sev"] for x in self.scan(exe)], ["high"] if "cache" not in exe else ["low"], exe)
        self.assertEqual([x["kind"] for x in self.scan("/home/jorge/Descargas/raro (deleted)")], ["binario_borrado"])

    def test_sentinel_no_se_reporta_a_si_mismo(self):
        r = self.scan("/tmp/sentinel-extra (deleted)", "python3", b"/usr/bin/python3\x00-m\x00sentinel\x00monitor\x00")
        self.assertEqual(r, [])


class PkgcheckTests(unittest.TestCase):
    def test_los_archivos_de_sentinel_que_coinciden_con_su_paquete_son_oficiales(self):
        import hashlib, tempfile
        d = tempfile.mkdtemp(); self.addCleanup(__import__("shutil").rmtree, d, True)
        info = os.path.join(d, "info"); os.makedirs(info)
        open(os.path.join(d, "status"), "w").write("x")
        datos = b"print('hola')\n"
        open(os.path.join(info, "sentinel.md5sums"), "w").write(f"{hashlib.md5(datos).hexdigest()}  opt/sentinel/sentinel/modulo.py\n")
        real = open

        def fake_open(path, *a, **k):
            return __import__("io").BytesIO(datos) if path == "/opt/sentinel/sentinel/modulo.py" else real(path, *a, **k)
        with mock.patch("builtins.open", side_effect=fake_open):
            self.assertTrue(pkgcheck.is_pristine("/opt/sentinel/sentinel/modulo.py", info))
        with mock.patch("builtins.open", side_effect=lambda p, *a, **k: __import__("io").BytesIO(b"MODIFICADO") if p == "/opt/sentinel/sentinel/modulo.py" else real(p, *a, **k)):
            self.assertFalse(pkgcheck.is_pristine("/opt/sentinel/sentinel/modulo.py", info))      # si alguien lo tocó, el aviso se mantiene


class CliCorreoTests(unittest.TestCase):
    def setUp(self):
        self.e = Env()
        for p in (mock.patch.object(core, "is_root", return_value=True), mock.patch.object(pin, "required", return_value=False)):
            p.start(); self.addCleanup(p.stop)

    def tearDown(self):
        self.e.close()

    def run_cli(self, args, stdin=""):
        out = io.StringIO()
        with redirect_stdout(out), mock.patch("sys.stdin", io.StringIO(stdin)):
            rc = cli.main(args)
        return rc, out.getvalue()

    def test_configurar_guarda_ajustes_y_la_contrasena_aparte_sin_espacios_de_gmail(self):
        with mock.patch.object(mailer, "test", return_value=(True, "Correo enviado")):
            rc, out = self.run_cli(["smtp", "configurar", "--host", "smtp.gmail.com", "--puerto", "587", "--seguridad", "starttls", "--usuario", "a@gmail.com", "--de", "a@gmail.com",
                                    "--para", "j@x.cl,k@x.cl", "--password-stdin"], "abcd efgh ijkl mnop\n")
        self.assertEqual(rc, 0, out)
        cfg = core.load_config()
        self.assertEqual((cfg.get("smtp", "host"), cfg.get("smtp", "enabled"), cfg.get("smtp", "to")), ("smtp.gmail.com", "yes", "j@x.cl,k@x.cl"))
        self.assertEqual(mailer.password(), "abcdefghijklmnop")
        self.assertNotIn("abcd", open(os.environ["SENTINEL_CONF"]).read()); self.assertNotIn("abcd", out)

    def test_configurar_rechaza_valores_invalidos(self):
        rc, out = self.run_cli(["smtp", "configurar", "--host", "no es un host;rm", "--puerto", "587", "--seguridad", "starttls", "--usuario", "", "--de", "a@b.cl", "--para", "j@x.cl"])
        self.assertEqual(rc, 1)

    def test_importar_desde_msmtprc(self):
        p = os.path.join(self.e.dir, "msmtprc")
        open(p, "w").write("host smtp.gmail.com\nport 587\nuser a@gmail.com\npassword abcd efgh ijkl mnop\nfrom a@gmail.com\n")
        with mock.patch.object(mailer, "test", return_value=(True, "ok")):
            rc, out = self.run_cli(["smtp", "importar", "--desde", p, "--para", "j@x.cl"])
        self.assertEqual(rc, 0, out); self.assertEqual(mailer.password(), "abcdefghijklmnop"); self.assertNotIn("abcd", out)

    def test_estado_no_muestra_la_contrasena_y_quitar_la_borra(self):
        mailer.set_password("secretoSECRETO12")
        rc, out = self.run_cli(["smtp", "estado"]); self.assertNotIn("secretoSECRETO12", out); self.assertIn("guardada", out)
        rc, out = self.run_cli(["smtp", "quitar"]); self.assertEqual(rc, 0); self.assertEqual(mailer.password(), "")

    def test_los_cambios_de_smtp_piden_el_pin_y_estado_o_probar_no(self):
        for accion, protegido in (("configurar", True), ("importar", True), ("quitar", True), ("estado", False), ("probar", False)):
            self.assertEqual(cli._protected(argparse.Namespace(fn=cli.cmd_smtp, accion=accion)), protegido, accion)
        self.assertTrue(cli._protected(argparse.Namespace(fn=cli.cmd_equipo, aceptar=True, horario=None)))
        self.assertFalse(cli._protected(argparse.Namespace(fn=cli.cmd_equipo, aceptar=False, horario=None)))

    def test_equipo_programado_guarda_el_informe_y_avisa_si_falta_el_smtp(self):
        inf = equipo.Informe(); inf.sec("s"); inf.hall("BAJO", "x", "algo")
        with mock.patch.object(equipo, "revisar", return_value=inf):
            rc, out = self.run_cli(["equipo", "--programado"])
        self.assertEqual(rc, 0); self.assertIn("SMTP sin configurar", out); self.assertIn("Informe guardado", out)
        with mock.patch.object(equipo, "revisar", return_value=inf):
            rc, out = self.run_cli(["equipo", "--enviar"])
        self.assertEqual(rc, 1)                                                # pedido a mano sin SMTP: es un error

    def test_equipo_enviar_manda_el_informe(self):
        inf = equipo.Informe(); inf.sec("s")
        self.e.cfg  # noqa
        with mock.patch.object(equipo, "revisar", return_value=inf), mock.patch.object(mailer, "configured", return_value=True), mock.patch.object(equipo, "enviar", return_value=(True, "Correo enviado a x")) as env:
            rc, out = self.run_cli(["equipo", "--enviar"])
        self.assertEqual(rc, 0); env.assert_called_once(); self.assertIn("Correo enviado", out)


class UnidadesTests(unittest.TestCase):
    def test_el_temporizador_corre_a_las_08_16_y_23_y_recupera_lo_perdido(self):
        t = open(os.path.join(AQUI, "systemd", "sentinel-equipo.timer"), encoding="utf-8").read()
        for h in ("08:00:00", "16:00:00", "23:00:00"):
            self.assertIn(f"OnCalendar=*-*-* {h}", t)
        self.assertIn("Persistent=true", t)
        self.assertIn("-m sentinel equipo --programado", open(os.path.join(AQUI, "systemd", "sentinel-equipo.service"), encoding="utf-8").read())

    def test_la_unidad_se_instala_activa_y_desinstala_en_todos_los_scripts(self):
        for f in ("install.sh", "uninstall.sh", "packaging/debian/postinst", "packaging/debian/prerm"):
            self.assertIn("sentinel-equipo.timer", open(os.path.join(AQUI, f), encoding="utf-8").read(), f)


if __name__ == "__main__":
    unittest.main()
