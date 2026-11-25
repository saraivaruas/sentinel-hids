"""Vigilancia en vivo por sondeo (la de macOS): se prueba en todos los sistemas llamando al sondeo directamente."""
import queue
import threading
import time
import unittest
from unittest import mock

from helpers import Env, core
from sentinel import monitor


class SondeoTests(unittest.TestCase):
    def setUp(self):
        self.e = Env()
        self.e.cfg.set("fim", "poll_seconds", "1")
        self.m = monitor.Monitor(self.e.cfg)
        self.addCleanup(self.e.close)
        self.addCleanup(self.m.stop.set)

    def esperar(self, ruta, segundos=8):
        fin = time.time() + segundos
        self.vistos = []
        while time.time() < fin:
            try:
                p = self.m.q.get(timeout=0.5)
            except queue.Empty:
                continue
            self.vistos.append(p)
            if p == ruta:
                return True
        return False

    def test_el_sondeo_avisa_de_un_archivo_nuevo_y_respeta_el_filtro(self):
        t = threading.Thread(target=self.m._sondeo, args=(lambda p: not p.endswith(".tmp"),), daemon=True); t.start()
        time.sleep(1.5)                                             # deja que haga la primera foto
        ruido = self.e.write("a.tmp", "x"); real = self.e.write("sudoers", "x")
        self.assertTrue(self.esperar(real))
        self.assertNotIn(ruido, self.vistos)                        # el filtro dejó fuera el .tmp
        self.m.stop.set(); t.join(5)

    def test_live_fim_usa_el_sondeo_en_macos_sin_inotify(self):
        with mock.patch("shutil.which", return_value=None), mock.patch.object(monitor.plataforma, "ES_MAC", True), \
                mock.patch.object(self.m, "_sondeo") as s, mock.patch.object(self.m, "_consume"):
            self.assertTrue(self.m.live_fim())
            time.sleep(0.2)
            s.assert_called_once()

    def test_live_fim_sin_inotify_en_linux_sigue_siendo_periodico(self):
        with mock.patch("shutil.which", return_value=None), mock.patch.object(monitor.plataforma, "ES_MAC", False):
            self.assertFalse(self.m.live_fim())


if __name__ == "__main__":
    unittest.main()
