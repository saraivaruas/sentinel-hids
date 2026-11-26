import os
import sys
import tempfile
import unittest
from unittest import mock

import helpers  # noqa: F401  (pone el proyecto en sys.path)
from sentinel import core, plataforma


class PlataformaTests(unittest.TestCase):
    def test_coincide_con_el_sistema_real(self):
        self.assertEqual(plataforma.ES_MAC, sys.platform == "darwin")
        self.assertEqual(plataforma.ES_LINUX, sys.platform.startswith("linux"))
        self.assertIn(plataforma.nombre(), ("macOS", "Linux", sys.platform))

    def test_nombre_segun_la_plataforma(self):
        with mock.patch.object(plataforma, "ES_MAC", True), mock.patch.object(plataforma, "ES_LINUX", False):
            self.assertEqual(plataforma.nombre(), "macOS")
        with mock.patch.object(plataforma, "ES_MAC", False), mock.patch.object(plataforma, "ES_LINUX", True):
            self.assertEqual(plataforma.nombre(), "Linux")

    def test_proc_solo_en_linux(self):
        if plataforma.ES_MAC:
            self.assertFalse(plataforma.tiene_proc())
        if plataforma.ES_LINUX:
            self.assertTrue(plataforma.tiene_proc())

    def test_valores_por_defecto_segun_el_sistema(self):
        with tempfile.TemporaryDirectory() as d:
            conf = os.path.join(d, "s.conf")
            with mock.patch.object(plataforma, "ES_MAC", True):
                mac = core.load_config(conf)
                with open(conf, "w", encoding="utf-8") as f:
                    f.write("[fim]\nwww = /mi/web\n")
                propia = core.load_config(conf)
            with mock.patch.object(plataforma, "ES_MAC", False):
                linux = core.load_config(os.path.join(d, "no-existe"))
        self.assertIn("/Library/LaunchDaemons", mac.get("fim", "paths")); self.assertNotIn("/etc/ufw", mac.get("fim", "paths"))
        self.assertNotIn("5900", mac.get("honeypot", "ports")); self.assertIn("/opt/homebrew", mac.get("weblog", "paths"))
        self.assertEqual(mac.get("auth", "fail_threshold"), "5")                      # lo demás no cambia
        self.assertEqual(propia.get("fim", "www"), "/mi/web")                         # lo que escribe la persona manda
        self.assertIn("/etc/ufw", linux.get("fim", "paths")); self.assertIn("5900", linux.get("honeypot", "ports"))


if __name__ == "__main__":
    unittest.main()
