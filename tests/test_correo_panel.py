"""Panel «Correo e informes»: configurar el SMTP y cambiar el horario del informe sin tocar la línea de comandos."""
import argparse
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest import mock

from helpers import Env, core
from sentinel import cli, equipo, mailer, pin, ui

BUENO = {"name": "smtp_guardar", "host": "smtp.gmail.com", "puerto": "587", "seguridad": "starttls", "usuario": "a@gmail.com", "de": "a@gmail.com", "para": "j@x.cl, k@x.cl", "clave": "abcd efgh ijkl mnop"}


class AccionesTests(unittest.TestCase):
    def test_smtp_guardar_valido_no_lleva_la_contrasena_en_los_argumentos(self):
        args = ui.build_action(BUENO)
        self.assertEqual(args[:2], ["smtp", "configurar"]); self.assertIn("--password-stdin", args)
        self.assertNotIn("abcd", " ".join(args))                                       # la contraseña viaja por la entrada estándar, nunca en la lista de procesos

    def test_sin_contrasena_nueva_conserva_la_guardada(self):
        self.assertNotIn("--password-stdin", ui.build_action(dict(BUENO, clave="")))

    def test_rechaza_valores_peligrosos_o_incompletos(self):
        for k, v in (("host", "x;rm -rf /"), ("host", ""), ("puerto", "99999"), ("puerto", "abc"), ("seguridad", "ninguna"), ("para", ""), ("para", "no-es-correo"), ("de", "malo"), ("usuario", "a b"), ("clave", "a\nb")):
            with self.assertRaises(ValueError, msg=(k, v)):
                ui.build_action(dict(BUENO, **{k: v}))

    def test_horario_valido_e_invalido(self):
        self.assertEqual(ui.build_action({"name": "equipo_horario", "horas": "23:00, 08:00,16:00,08:00"}), ["equipo", "--horario", "08:00,16:00,23:00"])
        for malo in ("", "25:00", "8:00", "08:00,xx", "01:00,02:00,03:00,04:00,05:00,06:00,07:00"):
            with self.assertRaises(ValueError, msg=malo):
                ui.build_action({"name": "equipo_horario", "horas": malo})

    def test_otras_acciones_son_cerradas(self):
        self.assertEqual(ui.build_action({"name": "smtp_probar"}), ["smtp", "probar"])
        self.assertEqual(ui.build_action({"name": "smtp_quitar"}), ["smtp", "quitar"])
        self.assertEqual(ui.build_action({"name": "equipo_enviar"}), ["equipo", "--enviar"])
        self.assertEqual(ui.build_action({"name": "requisitos_instalar"}), ["requisitos", "--instalar", "--si"])

    def ejecutar(self, body):
        with mock.patch.object(ui, "sentinel_bin", return_value="/usr/bin/sentinel"), mock.patch.object(core, "is_root", return_value=True), \
             mock.patch("os.path.realpath", side_effect=lambda p: p), mock.patch("subprocess.run") as run:
            run.return_value.returncode = 0; run.return_value.stdout = "ok"; run.return_value.stderr = ""
            ui.run_action(body)
        return run.call_args

    def test_la_contrasena_llega_por_stdin_despues_del_pin(self):
        llamada = self.ejecutar(dict(BUENO, pin="654321"))
        self.assertEqual(llamada.kwargs["input"], "654321\nabcd efgh ijkl mnop\n"); self.assertIn("--pin-stdin", llamada.args[0])
        self.assertNotIn("abcd", " ".join(llamada.args[0])); self.assertNotIn("654321", " ".join(llamada.args[0]))

    def test_sin_pin_configurado_la_contrasena_es_la_primera_linea(self):
        llamada = self.ejecutar(BUENO)
        self.assertEqual(llamada.kwargs["input"], "abcd efgh ijkl mnop\n"); self.assertIn("--pin-stdin", llamada.args[0])

    def test_sin_contrasena_no_se_abre_la_entrada(self):
        llamada = self.ejecutar(dict(BUENO, clave=""))
        self.assertIsNone(llamada.kwargs["input"]); self.assertNotIn("--pin-stdin", llamada.args[0])


class CorreoDatosTests(unittest.TestCase):
    def test_los_datos_del_panel_nunca_incluyen_la_contrasena(self):
        e = Env(extra="[smtp]\nenabled = yes\nhost = smtp.gmail.com\nuser = a@gmail.com\nsender = a@gmail.com\nto = j@x.cl")
        try:
            mailer.set_password("claveSECRETA1234")
            with mock.patch.object(core, "run", return_value=(0, "Sat 2026-11-14 16:00:00 -03")):
                d = ui.Data(e.cfg).correo()
            self.assertNotIn("claveSECRETA1234", json.dumps(d))
            self.assertEqual(d["smtp"]["host"], "smtp.gmail.com"); self.assertTrue(d["smtp"]["ok"]); self.assertEqual(d["equipo"]["horas"], ["08:00", "16:00", "23:00"])
            self.assertTrue(d["equipo"]["enviar"])
        finally:
            e.close()


class HorarioTests(unittest.TestCase):
    def setUp(self):
        self.e = Env()
        self.dir = tempfile.mkdtemp()
        self.env = mock.patch.dict(os.environ, {"SENTINEL_SYSTEMD_DIR": self.dir}); self.env.start()
        linux = mock.patch.object(equipo.plataforma, "ES_MAC", False); linux.start(); self.addCleanup(linux.stop)   # estas pruebas son de systemd
        self.llamadas = []

    def tearDown(self):
        self.env.stop(); self.e.close()

    def ejecutar(self, cmd, timeout=30):
        self.llamadas.append(cmd); return 0, ""

    def test_horas_validas(self):
        self.assertEqual(equipo.horas_validas("23:00 , 08:00,16:00"), ["08:00", "16:00", "23:00"])
        for malo in ("", "24:00", "8:00", "08:60", "a", "01:00,02:00,03:00,04:00,05:00,06:00,07:00"):
            self.assertIsNone(equipo.horas_validas(malo), malo)

    def test_un_horario_distinto_escribe_el_dropin_y_recarga_el_temporizador(self):
        ok, msg = equipo.aplicar_horario("07:30,19:00", self.ejecutar)
        self.assertTrue(ok, msg); self.assertIn("07:30, 19:00", msg)
        txt = open(os.path.join(self.dir, "sentinel-equipo.timer.d", "horario.conf")).read()
        self.assertIn("OnCalendar=\n", txt); self.assertIn("OnCalendar=*-*-* 07:30:00", txt); self.assertIn("OnCalendar=*-*-* 19:00:00", txt)
        self.assertEqual(core.load_config().get("equipo", "horas"), "07:30,19:00")
        self.assertIn(["systemctl", "daemon-reload"], self.llamadas); self.assertIn(["systemctl", "restart", "sentinel-equipo.timer"], self.llamadas)

    def test_volver_al_horario_de_fabrica_borra_el_dropin(self):
        equipo.aplicar_horario("07:30", self.ejecutar)
        ok, _ = equipo.aplicar_horario("08:00,16:00,23:00", self.ejecutar)
        self.assertTrue(ok); self.assertFalse(os.path.exists(os.path.join(self.dir, "sentinel-equipo.timer.d", "horario.conf")))

    def test_un_horario_invalido_no_toca_nada(self):
        ok, msg = equipo.aplicar_horario("99:99", self.ejecutar)
        self.assertFalse(ok); self.assertIn("no válido", msg); self.assertEqual(self.llamadas, []); self.assertEqual(os.listdir(self.dir), [])

    def test_el_ajuste_horas_solo_acepta_horas_validas(self):
        ok = core.EDITABLE[("equipo", "horas")]
        self.assertTrue(ok("08:00") and ok("08:00,16:00,23:00")); self.assertFalse(ok("8:00") or ok("08:00;rm") or ok("25:00") or ok(""))

    def test_cli_horario_pide_administrador_y_el_pin(self):
        err = io.StringIO()
        with mock.patch("sys.stderr", err), mock.patch.object(core, "is_root", return_value=False):
            rc = cli.main(["equipo", "--horario", "09:00"])
        self.assertEqual(rc, 1); self.assertIn("administrador", err.getvalue())
        self.assertTrue(cli._protected(argparse.Namespace(fn=cli.cmd_equipo, aceptar=False, horario="09:00")))
        self.assertFalse(cli._protected(argparse.Namespace(fn=cli.cmd_equipo, aceptar=False, horario=None)))

    def test_cli_horario_como_root(self):
        out = io.StringIO()
        with redirect_stdout(out), mock.patch.object(core, "is_root", return_value=True), mock.patch.object(pin, "required", return_value=False), \
             mock.patch.object(equipo, "aplicar_horario", return_value=(True, "Horario guardado")) as ap:
            rc = cli.main(["equipo", "--horario", "09:00,21:00"])
        self.assertEqual(rc, 0); ap.assert_called_once_with("09:00,21:00")


class ContrasenaPorStdinTests(unittest.TestCase):
    def test_desde_el_panel_la_contrasena_es_la_linea_despues_del_pin(self):
        e = Env()
        try:
            pin._stdin_lines = None
            out = io.StringIO()
            with redirect_stdout(out), mock.patch.object(core, "is_root", return_value=True), mock.patch.object(pin, "required", return_value=True), \
                 mock.patch.object(pin, "verify", return_value=(True, "")), mock.patch("sys.stdin", io.StringIO("654321\nabcd efgh ijkl mnop\n")), mock.patch.object(mailer, "test", return_value=(True, "ok")):
                rc = cli.main(["--pin-stdin", "smtp", "configurar", "--host", "smtp.gmail.com", "--puerto", "587", "--seguridad", "starttls", "--usuario", "a@gmail.com",
                               "--de", "a@gmail.com", "--para", "j@x.cl", "--password-stdin"])
            self.assertEqual(rc, 0, out.getvalue()); self.assertEqual(mailer.password(), "abcdefghijklmnop")
        finally:
            pin._stdin_lines = None
            e.close()


if __name__ == "__main__":
    unittest.main()
