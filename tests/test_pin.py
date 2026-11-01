import io
import json
import os
import stat
import tempfile
import unittest
from unittest import mock

from helpers import Env, core
from sentinel import cli, monitor, pin


class PinTests(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.env = mock.patch.dict(os.environ, {"SENTINEL_PIN": os.path.join(self.d, "pin"), "SENTINEL_STATE": self.d})
        self.env.start()
        self.root = mock.patch.object(core, "is_root", return_value=True); self.root.start()
        self.it = mock.patch.object(pin, "ITERS", 1000); self.it.start()
        pin._stdin_lines = None

    def tearDown(self):
        self.it.stop(); self.root.stop(); self.env.stop()

    def test_sin_pin_todo_se_permite(self):
        self.assertFalse(pin.required()); self.assertEqual(pin.verify("x"), (True, ""))

    def test_guardar_verificar_y_cambiar(self):
        self.assertEqual(pin.set_pin("corto")[0], False)                             # mínimo 6
        self.assertTrue(pin.set_pin("secreto-1")[0]); self.assertTrue(pin.required())
        self.assertEqual(stat.S_IMODE(os.stat(pin.pin_path()).st_mode), 0o600)
        raw = open(pin.pin_path()).read(); self.assertNotIn("secreto-1", raw); self.assertIn("pbkdf2_sha256", raw)   # nunca el PIN en claro
        self.assertTrue(pin.verify("secreto-1")[0]); self.assertFalse(pin.verify("otro")[0])
        self.assertFalse(pin.set_pin("nuevo-pin-2", "malo")[0]); self.assertTrue(pin.set_pin("nuevo-pin-2", "secreto-1")[0])
        self.assertTrue(pin.verify("nuevo-pin-2")[0]); self.assertFalse(pin.verify("secreto-1")[0])
        self.assertTrue(json.load(open(os.path.join(self.d, "pin_state.json")))["enabled"])

    def test_bloqueo_tras_cinco_errores(self):
        pin.set_pin("secreto-1")
        for _ in range(5):
            pin.verify("mal")
        ok, msg = pin.verify("secreto-1")
        self.assertFalse(ok); self.assertIn("espera", msg)                          # ni el PIN correcto entra durante el bloqueo
        with mock.patch.object(core, "now", return_value=core.now() + 700):
            self.assertTrue(pin.verify("secreto-1")[0])

    def test_quitar_exige_el_pin(self):
        pin.set_pin("secreto-1")
        self.assertFalse(pin.clear("mal")[0]); self.assertTrue(pin.required())
        self.assertTrue(pin.clear("secreto-1")[0]); self.assertFalse(pin.required())

    def test_permiso_temporal_para_detener(self):
        self.assertFalse(pin.stop_authorized()); pin.authorize_stop(5); self.assertTrue(pin.stop_authorized())
        pin.revoke_stop(); self.assertFalse(pin.stop_authorized())


class GateTests(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.env = mock.patch.dict(os.environ, {"SENTINEL_PIN": os.path.join(self.d, "pin"), "SENTINEL_STATE": self.d, "SENTINEL_CONF": os.path.join(self.d, "s.conf"), "SENTINEL_LOG": self.d})
        self.env.start(); self.root = mock.patch.object(core, "is_root", return_value=True); self.root.start()
        self.it = mock.patch.object(pin, "ITERS", 1000); self.it.start()
        pin._stdin_lines = None; pin.set_pin("secreto-1"); open(os.path.join(self.d, "s.conf"), "w").write("[general]\nnotify_min = medium\nenable_desktop = no\nenable_journal = no\n")

    def tearDown(self):
        self.it.stop(); self.root.stop(); self.env.stop()

    def run_cli(self, args, stdin=""):
        pin._stdin_lines = None
        with mock.patch("sys.stdin", io.StringIO(stdin)), mock.patch("sys.stdout", io.StringIO()), mock.patch("sys.stderr", io.StringIO()) as err:
            code = cli.main(args)
        return code, err.getvalue()

    def test_comandos_protegidos_piden_el_pin(self):
        for args in (["config", "general.notify_min=high"], ["allow", "ip", "1.2.3.4"], ["baseline", "init"], ["bans", "unban", "1.2.3.4"], ["senuelos", "desactivar"], ["detener"], ["pin", "quitar"]):
            code, err = self.run_cli(["--pin-stdin", *args], "equivocado\n")
            self.assertEqual(code, 2, args); self.assertTrue("PIN incorrecto" in err or "espera" in err, err)       # tras 5 errores entra el bloqueo

    def test_con_el_pin_correcto_pasa(self):
        code, _ = self.run_cli(["--pin-stdin", "config", "general.notify_min=high"], "secreto-1\n")
        self.assertEqual(code, 0); self.assertIn("notify_min = high", open(os.environ["SENTINEL_CONF"]).read())

    def test_sin_forma_de_preguntar_no_pasa(self):
        with mock.patch.object(pin, "ask", return_value=None):
            code, err = self.run_cli(["config", "general.notify_min=high"])
        self.assertEqual(code, 2); self.assertIn("necesita el PIN", err)

    def test_lo_que_no_debilita_no_pide_pin(self):
        for args in (["status"], ["events"], ["bans"], ["firewall", "plan"], ["firewall", "restaurar", "--pendiente"], ["pin", "estado"]):
            self.assertIsNone(cli.gate(cli.argparse.Namespace(fn=getattr(cli, {"status": "cmd_status", "events": "cmd_events", "bans": "cmd_bans", "firewall": "cmd_firewall", "pin": "cmd_pin"}[args[0]]),
                                                               pin_stdin=True, action="list", accion=args[1] if len(args) > 1 else "", pendiente="--pendiente" in args, instalar=False)), args)

    def test_cambiar_el_pin_por_stdin(self):
        code, _ = self.run_cli(["--pin-stdin", "pin", "establecer"], "secreto-1\nnuevo-pin-9\n")
        self.assertEqual(code, 0); self.assertTrue(pin.verify("nuevo-pin-9")[0])

    def test_verificar_y_autorizar_para_desinstalar(self):
        self.assertEqual(self.run_cli(["--pin-stdin", "pin", "verificar"], "mal\n")[0], 1); self.assertFalse(pin.stop_authorized())
        self.assertEqual(self.run_cli(["--pin-stdin", "pin", "verificar"], "secreto-1\n")[0], 0); self.assertTrue(pin.stop_authorized())


class MonitorTermTests(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.env = mock.patch.dict(os.environ, {"SENTINEL_PIN": os.path.join(self.d, "pin"), "SENTINEL_STATE": self.d, "SENTINEL_LOG": self.d, "SENTINEL_CONF": os.path.join(self.d, "c")})
        self.env.start(); self.root = mock.patch.object(core, "is_root", return_value=True); self.root.start()
        self.it = mock.patch.object(pin, "ITERS", 1000); self.it.start()

    def tearDown(self):
        self.it.stop(); self.root.stop(); self.env.stop()

    def mon(self):
        m = monitor.Monitor.__new__(monitor.Monitor)
        m.stop = monitor.threading.Event(); m.alerter = mock.Mock()
        return m

    def test_sin_pin_se_detiene_normal(self):
        m = self.mon(); m._on_term(); self.assertTrue(m.stop.is_set())

    def test_con_pin_y_sin_permiso_sigue_y_avisa(self):
        pin.set_pin("secreto-1"); m = self.mon()
        with mock.patch.object(pin, "shutting_down", return_value=False):
            m._on_term()
        self.assertFalse(m.stop.is_set()); sev, src, kind = m.alerter.emit.call_args[0][:3]
        self.assertEqual((sev, kind), ("critical", "intento_detener"))

    def test_con_permiso_o_apagando_el_equipo_se_detiene(self):
        pin.set_pin("secreto-1")
        m = self.mon(); pin.authorize_stop(); m._on_term(); self.assertTrue(m.stop.is_set())
        pin.revoke_stop(); m2 = self.mon()
        with mock.patch.object(pin, "shutting_down", return_value=True):
            m2._on_term()
        self.assertTrue(m2.stop.is_set())


if __name__ == "__main__":
    unittest.main()
