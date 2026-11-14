import os
import smtplib
import stat
import unittest
from unittest import mock

from helpers import Env, core
from sentinel import mailer


def conf(extra=""):
    return Env(extra=f"[smtp]\nenabled = yes\nhost = smtp.ejemplo.cl\nport = 587\nsecurity = starttls\nuser = alertas@ejemplo.cl\nsender = alertas@ejemplo.cl\nto = jorge@ejemplo.cl, otro@ejemplo.cl\n{extra}")


class MailerTests(unittest.TestCase):
    def setUp(self):
        self.e = conf()

    def tearDown(self):
        self.e.close()

    def test_ajustes_y_destinatarios(self):
        s = mailer.settings(self.e.cfg)
        self.assertEqual((s["host"], s["port"], s["security"], s["enabled"]), ("smtp.ejemplo.cl", 587, "starttls", True))
        self.assertEqual(s["to"], ["jorge@ejemplo.cl", "otro@ejemplo.cl"])

    def test_destinatario_cae_a_general_email_to(self):
        e = Env(extra="[smtp]\nenabled = yes\nhost = h.cl\nsender = a@b.cl")
        try:
            e.cfg.set("general", "email_to", "fallback@ejemplo.cl")
            self.assertEqual(mailer.settings(e.cfg)["to"], ["fallback@ejemplo.cl"])
        finally:
            e.close()

    def test_sin_contrasena_no_esta_configurado_y_con_ella_si(self):
        self.assertFalse(mailer.configured(self.e.cfg))
        mailer.set_password("abcdabcdabcdabcd")
        self.assertTrue(mailer.configured(self.e.cfg))

    def test_la_contrasena_queda_solo_para_root_y_no_en_sentinel_conf(self):
        mailer.set_password("claveSecreta1234")
        modo = stat.S_IMODE(os.stat(mailer.secret_path()).st_mode)
        self.assertEqual(modo, 0o600)
        self.assertNotIn("claveSecreta1234", open(os.environ["SENTINEL_CONF"]).read())
        self.assertEqual(mailer.password(), "claveSecreta1234")
        self.assertNotIn("claveSecreta1234", str(mailer.estado(self.e.cfg)))          # el estado nunca la muestra
        mailer.clear_password(); self.assertEqual(mailer.password(), "")

    def test_sin_ser_root_la_contrasena_guardada_no_se_reporta_como_faltante(self):
        """Sin sudo no se lee /etc/sentinel/smtp.pass, pero existe: el estado decía «falta» y mandaba a reconfigurar."""
        mailer.set_password("abcdabcdabcdabcd")
        with mock.patch.object(mailer, "password", return_value=""):                # lo que ve un usuario sin permiso
            e = mailer.estado(self.e.cfg)
            ok, msg = mailer.send(self.e.cfg, "a", "b")
        self.assertIn("solo root", e["password"]); self.assertTrue(e["ok"])
        self.assertFalse(ok); self.assertIn("solo root puede leerla", msg)
        mailer.clear_password()
        self.assertEqual(mailer.estado(self.e.cfg)["password"], "falta")

    def test_contrasena_con_salto_de_linea_se_rechaza(self):
        with self.assertRaises(ValueError):
            mailer.set_password("a\nb")

    def test_mensaje_con_adjuntos_y_sin_inyeccion_de_cabeceras(self):
        m = mailer.build_message("Asunto\r\nBcc: malo@x.cl", "texto", "a@b.cl", ["c@d.cl"], html="<b>hola</b>", attachments=[("r.txt", b"datos", "text/plain")])
        self.assertNotIn("\n", m["Subject"]); self.assertIsNone(m["Bcc"])
        self.assertEqual([p.get_filename() for p in m.iter_attachments()], ["r.txt"])

    def test_envio_usa_starttls_login_y_destinatarios(self):
        mailer.set_password("abcdabcdabcdabcd")
        with mock.patch("smtplib.SMTP") as smtp:
            srv = smtp.return_value
            ok, msg = mailer.send(self.e.cfg, "Hola", "cuerpo")
        self.assertTrue(ok, msg)
        smtp.assert_called_once_with("smtp.ejemplo.cl", 587, timeout=25)
        srv.starttls.assert_called_once(); srv.login.assert_called_once_with("alertas@ejemplo.cl", "abcdabcdabcdabcd")
        self.assertEqual(srv.send_message.call_args.kwargs["to_addrs"], ["jorge@ejemplo.cl", "otro@ejemplo.cl"])

    def test_ssl_usa_smtp_ssl(self):
        e = conf("")
        e.close()
        e = Env(extra="[smtp]\nenabled = yes\nhost = h.cl\nport = 465\nsecurity = ssl\nuser = u@h.cl\nsender = u@h.cl\nto = d@h.cl")
        try:
            mailer.set_password("x" * 16)
            with mock.patch("smtplib.SMTP_SSL") as s, mock.patch("smtplib.SMTP") as plain:
                ok, _ = mailer.send(e.cfg, "a", "b")
            self.assertTrue(ok); s.assert_called_once(); plain.assert_not_called()
        finally:
            e.close()

    def test_contrasena_mala_da_mensaje_claro(self):
        mailer.set_password("mala")
        with mock.patch("smtplib.SMTP") as smtp:
            smtp.return_value.login.side_effect = smtplib.SMTPAuthenticationError(535, b"bad")
            ok, msg = mailer.send(self.e.cfg, "a", "b")
        self.assertFalse(ok); self.assertIn("contraseña de aplicación", msg)

    def test_servidor_caido_no_lanza_excepcion(self):
        mailer.set_password("x" * 16)
        with mock.patch("smtplib.SMTP", side_effect=ConnectionRefusedError(111, "Connection refused")):
            ok, msg = mailer.send(self.e.cfg, "a", "b")
        self.assertFalse(ok); self.assertIn("No pude conectar", msg)

    def test_no_manda_credenciales_sin_cifrado_a_un_servidor_remoto(self):
        e = Env(extra="[smtp]\nenabled = yes\nhost = remoto.cl\nsecurity = none\nuser = u@x.cl\nsender = u@x.cl\nto = d@x.cl")
        try:
            mailer.set_password("x" * 16)
            with mock.patch("smtplib.SMTP") as smtp:
                ok, msg = mailer.send(e.cfg, "a", "b")
            self.assertFalse(ok); smtp.assert_not_called(); self.assertIn("sin cifrado", msg)
        finally:
            e.close()

    def test_sin_configurar_explica_que_hacer(self):
        e = Env()
        try:
            ok, msg = mailer.send(e.cfg, "a", "b")
            self.assertFalse(ok); self.assertIn("sentinel smtp configurar", msg)
        finally:
            e.close()

    def test_importar_de_msmtprc(self):
        p = os.path.join(self.e.dir, "msmtprc")
        open(p, "w").write("defaults\ntls on\nlogfile ~/x.log\naccount gmail\nhost smtp.gmail.com\nport 587\nuser a@gmail.com\npassword abcd efgh ijkl mnop\nfrom a@gmail.com\n")
        v = mailer.from_msmtp(p)
        self.assertEqual((v["host"], v["port"], v["security"], v["user"], v["sender"]), ("smtp.gmail.com", "587", "starttls", "a@gmail.com", "a@gmail.com"))
        self.assertEqual(v["password"], "abcd efgh ijkl mnop")
        open(p, "w").write("host smtp.x.cl\nport 465\ntls_starttls off\nuser u\npassword p\n")
        self.assertEqual(mailer.from_msmtp(p)["security"], "ssl")


class AlerterEmailTests(unittest.TestCase):
    def test_alerta_por_smtp_con_tope_por_hora_y_criticas_siempre(self):
        e = Env(extra="[smtp]\nenabled = yes\nhost = h.cl\nsender = a@b.cl\nto = d@b.cl")
        try:
            e.cfg.set("general", "email_min", "high"); e.cfg.set("general", "email_max_per_hour", "2")
            al = core.Alerter(e.cfg, quiet=False)
            enviados = []
            with mock.patch.object(mailer, "send", side_effect=lambda *a, **k: enviados.append(a[1]) or (True, "ok")), \
                 mock.patch.object(core.threading, "Thread", side_effect=lambda target, args, daemon: mock.Mock(start=lambda: target(*args))):
                for i in range(4):
                    al.emit("high", "t", "k", f"alta {i}", key=f"a{i}")
                al.emit("critical", "t", "k", "critica", key="c1")
            self.assertEqual(len(enviados), 3)            # 2 altas (tope) + 1 crítica
            self.assertIn("[Sentinel CRÍTICA] k", enviados)
        finally:
            e.close()

    def test_sin_smtp_usa_el_comando_mail_como_antes(self):
        e = Env()
        try:
            e.cfg.set("general", "email_to", "x@y.cl"); e.cfg.set("general", "email_min", "high")
            al = core.Alerter(e.cfg, quiet=False)
            with mock.patch("shutil.which", return_value="/usr/bin/mail"), mock.patch("subprocess.run") as run:
                al.emit("high", "t", "k", "algo", key="z")
            self.assertEqual(run.call_args.args[0][0], "mail")
        finally:
            e.close()


if __name__ == "__main__":
    unittest.main()
