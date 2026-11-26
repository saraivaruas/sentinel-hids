"""Panel: apartado «Privacidad de red» de Ajustes."""
import os
import re
import unittest
from unittest import mock

from helpers import Env
from sentinel import cli, identidad, ui

UI = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "sentinel", "ui")


def leer(nombre):
    with open(os.path.join(UI, nombre), encoding="utf-8") as f:
        return f.read()


class PrivacidadDeRedTests(unittest.TestCase):
    def test_acciones(self):
        self.assertEqual(ui.build_action({"name": "identidad_activar", "horas": "4"}), ["identidad", "activar", "--cada", "4"])
        self.assertEqual(ui.build_action({"name": "identidad_desactivar"}), ["identidad", "desactivar"])
        self.assertEqual(ui.build_action({"name": "identidad_rotar"}), ["identidad", "rotar", "--si"])
        self.assertEqual(ui.build_action({"name": "identidad_restaurar"}), ["identidad", "restaurar", "--si"])

    def test_intervalo_invalido(self):
        for malo in ("", "0", "169", "-1", "2.5", "2; reboot", None, "²"):
            with self.assertRaises(ValueError, msg=malo):
                ui.build_action({"name": "identidad_activar", "horas": malo})

    def test_los_datos_son_solo_lectura(self):
        e = Env()
        try:
            with mock.patch.object(identidad, "estado", return_value={"activo": False, "error": ""}) as estado:
                self.assertEqual(ui.Data(e.cfg).identidad(), {"activo": False, "error": ""})
            estado.assert_called_once()
        finally:
            e.close()

    def test_la_pagina_tiene_lo_que_usa_el_programa(self):
        html, js = leer("index.html"), leer("app.js")
        for ident in set(re.findall(r'\$\("#(id-[a-z]+)"\)', js)):
            self.assertIn(f'id="{ident}"', html, ident)
        pin = js.split("const NEEDS_PIN")[1].split(";")[0]
        for accion in ("identidad_activar", "identidad_desactivar", "identidad_rotar", "identidad_restaurar"):
            self.assertIn(f'"{accion}"', pin)
        self.assertTrue(callable(cli.cmd_identidad))


if __name__ == "__main__":
    unittest.main()
