import sys
import unittest
from unittest import mock

import helpers  # noqa: F401  (pone el proyecto en sys.path)
from sentinel import plataforma


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


if __name__ == "__main__":
    unittest.main()
