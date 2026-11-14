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


class SoloLecturaTests(unittest.TestCase):
    def test_en_flatpak_no_ejecuta_nada(self):
        with mock.patch("os.path.exists", side_effect=lambda p: p == "/.flatpak-info"), mock.patch("subprocess.run") as run:
            r = ui.run_action({"name": "scan"})
        run.assert_not_called(); self.assertFalse(r["ok"]); self.assertIn("solo lectura", r["out"])

    def test_el_monitor_reconoce_el_lanzador_como_propio(self):
        from sentinel import hostcheck
        con = mock.mock_open(read_data=b"python3\x00-I\x00-c\x00import sys; from sentinel.cli import main\x00/snap/sentinel-hids/1/opt/sentinel\x00ui\x00")
        with mock.patch("builtins.open", con):
            self.assertTrue(hostcheck._es_de_sentinel("/proc/1"))


if __name__ == "__main__":
    unittest.main()
