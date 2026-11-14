"""Panel: página «Endurecimiento» y «Primeros pasos»."""
import unittest
from unittest import mock

from helpers import Env, core
from sentinel import endurecer, ia, ui


class AccionesTests(unittest.TestCase):
    def test_aplicar_valida_perfil_y_medidas(self):
        ids = [endurecer.MEDIDAS[0].id]
        self.assertEqual(ui.build_action({"name": "endurecer_aplicar", "perfil": "recomendado", "ids": ids}), ["endurecer", "aplicar", "--perfil", "recomendado", "--solo", ids[0], "--si"])
        for malo in ({"perfil": "x", "ids": ids}, {"perfil": "basico", "ids": []}, {"perfil": "basico", "ids": ["no-existe"]}, {"perfil": "basico", "ids": ["a;rm"]}, {"perfil": "basico", "ids": "todo"}, {"perfil": "basico"}):
            with self.assertRaises(ValueError, msg=malo):
                ui.build_action({"name": "endurecer_aplicar", **malo})

    def test_revertir(self):
        self.assertEqual(ui.build_action({"name": "endurecer_revertir"}), ["endurecer", "revertir"])


class DatosTests(unittest.TestCase):
    def test_endurecer_lista_solo_lectura_con_todos_los_campos(self):
        e = Env()
        try:
            with mock.patch.object(endurecer, "plan", wraps=endurecer.plan) as plan:
                d = ui.Data(e.cfg).endurecer("basico")
            plan.assert_called_once(); self.assertEqual(d["perfil"], "basico")
            self.assertTrue(d["medidas"]); self.assertTrue(all({"id", "titulo", "estado", "detalle", "que_hace", "por_que", "riesgo"} <= set(m) for m in d["medidas"]))
            self.assertEqual(ui.Data(e.cfg).endurecer("raro")["perfil"], "recomendado")
        finally:
            e.close()

    def test_primeros_pasos(self):
        e = Env()
        try:
            with mock.patch.dict("os.environ", {"SENTINEL_FAKE_MISSING": "inotify"}):
                d = ui.Data(e.cfg).inicio()
            por = {p["id"]: p for p in d["pasos"]}
            self.assertEqual(set(por), {"requisitos", "pin", "correo", "endurecer", "ia"})
            self.assertFalse(por["requisitos"]["ok"]); self.assertTrue(por["requisitos"]["obligatorio"]); self.assertFalse(por["ia"]["ok"])
            self.assertTrue(all(p["vista"] for p in d["pasos"])); self.assertEqual(d["total"], 5)
        finally:
            e.close()


if __name__ == "__main__":
    unittest.main()
