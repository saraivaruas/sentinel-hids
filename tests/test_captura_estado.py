"""Estado de la captura de paquetes: el panel decía «captura apagada» con la captura funcionando (el 14-nov-2026)."""
import os
import unittest
from unittest import mock

from helpers import Env, core
from sentinel import cli, intel as intel_mod, packets


def estado_path():
    return os.path.join(core.state_dir(), "packets_stats.json")


class CapturaEstadoTests(unittest.TestCase):
    def watcher(self):
        e = Env()
        it = intel_mod.Intel(e.cfg); it.geo.mode = "off"
        w = packets.PacketWatcher(e.cfg, core.Alerter(e.cfg, quiet=True), e.allow, mock.Mock(), it); w.local = set()
        self.addCleanup(e.close)
        return w

    def test_el_estado_se_actualiza_aunque_no_haya_nada_sospechoso(self):
        """Antes flush() salía sin escribir si no había nada que guardar: en una red tranquila el archivo quedaba viejo."""
        w = self.watcher()
        w.stats.update(vistos=123, activo=True)
        self.assertEqual(w.pending, {}); self.assertEqual(w.recent, [])
        w.flush()
        s = core.read_json(estado_path())
        self.assertEqual(s["vistos"], 123); self.assertTrue(s["activo"]); self.assertLess(core.now() - s["ts"], 5)

    def test_un_escaneo_detectado_se_cuenta(self):
        w = self.watcher()
        with mock.patch.object(w, "intel") as it, mock.patch.object(w, "banner"):
            it.geo_text.return_value = ""
            w._report("203.0.113.9", {"kind": "escaneo_udp", "n": 20, "detail": "20 puertos", "packets": []}, 1_700_000_000.0)
        self.assertEqual(w.stats["detectados"], 1); self.assertIsNotNone(w.stats["ultima_deteccion"])

    def test_sin_permiso_para_capturar_lo_dice_y_no_falla(self):
        w = self.watcher()
        with mock.patch("socket.socket", side_effect=PermissionError):
            w.run(lambda: True)
        s = core.read_json(estado_path())
        self.assertFalse(s["activo"]); self.assertEqual(s["motivo"], "PermissionError")

    def test_la_captura_deja_el_estado_activo_al_empezar_y_apagado_al_terminar(self):
        w = self.watcher()
        sock = mock.Mock(); sock.recvfrom.side_effect = __import__("socket").timeout
        vistos = []
        with mock.patch("socket.socket", return_value=sock):
            def parar():
                vistos.append(core.read_json(estado_path()))          # estado mientras corre
                return True
            w.run(parar)
        self.assertTrue(vistos[0]["activo"])
        self.assertFalse(core.read_json(estado_path())["activo"])

    def test_el_texto_de_estado_distingue_activa_sin_senal_apagada_y_sin_datos(self):
        e = Env()
        try:
            self.assertIn("sin datos todavía", cli.estado_captura())
            core.atomic_write_json(estado_path(), {"vistos": 12345, "interesantes": 100, "detectados": 0, "desde": "2026-11-14T08:00:00-0300", "activo": True, "ts": core.now()})
            t = cli.estado_captura(); self.assertIn("ACTIVA", t); self.assertIn("12,345", t); self.assertIn("sin novedades", t)
            core.atomic_write_json(estado_path(), {"vistos": 1, "detectados": 2, "desde": "x", "activo": True, "ts": core.now()})
            self.assertIn("2 escaneo(s) detectado(s)", cli.estado_captura()); self.assertNotIn("sin novedades", cli.estado_captura())
            core.atomic_write_json(estado_path(), {"vistos": 1, "activo": True, "ts": core.now() - 3600})
            self.assertIn("SIN SEÑAL desde hace 60 min", cli.estado_captura())
            core.atomic_write_json(estado_path(), {"vistos": 1, "activo": False, "motivo": "PermissionError", "ts": core.now()})
            self.assertIn("APAGADA (PermissionError)", cli.estado_captura())
        finally:
            e.close()


if __name__ == "__main__":
    unittest.main()
