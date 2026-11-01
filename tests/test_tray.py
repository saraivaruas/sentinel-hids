from __future__ import annotations

import os
import tempfile
import unittest
import unittest.mock as mock
import xml.dom.minidom

from helpers import Env, core  # noqa: F401
from sentinel import tray


class TrayTests(unittest.TestCase):
    def test_un_icono_por_nivel_con_su_color(self):
        for nivel, color in tray.COLORS.items():
            svg = tray.icon_svg(nivel)
            xml.dom.minidom.parseString(svg)                                  # es un SVG válido
            self.assertIn(color, svg)
        self.assertEqual(tray.icon_svg("inventado"), tray.icon_svg("desconocido"))

    def test_los_iconos_se_guardan_en_la_cache_del_usuario(self):
        with tempfile.TemporaryDirectory() as d, mock.patch.dict(os.environ, {"XDG_CACHE_HOME": d}):
            p = tray.icon_file("peligro")
            self.assertTrue(p.startswith(d) and os.path.exists(p)); self.assertIn("#dc2626", open(p).read())

    def test_el_estado_sale_de_los_datos_del_panel_y_nunca_falla(self):
        e = Env()
        try:
            nivel, txt = tray.estado()
            self.assertIn(nivel, tray.COLORS); self.assertTrue(txt.startswith("Sentinel"))
        finally:
            e.close()
        with mock.patch("sentinel.ui.Data", side_effect=RuntimeError("roto")):
            self.assertEqual(tray.estado(), ("desconocido", "Sentinel · sin datos"))

    def test_sin_pantalla_no_hace_nada(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(tray.run(), 0)

    def test_el_archivo_de_inicio_automatico_es_valido(self):
        p = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "desktop", "sentinel-tray.desktop")
        t = open(p).read()
        self.assertIn("Exec=sentinel tray", t); self.assertIn("NoDisplay=true", t)


if __name__ == "__main__":
    unittest.main()
