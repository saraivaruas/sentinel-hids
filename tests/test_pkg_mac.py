import os
import subprocess
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MAC = os.path.join(ROOT, "packaging", "macos")


class PaqueteMacTests(unittest.TestCase):
    def leer(self, nombre):
        with open(os.path.join(MAC, nombre), encoding="utf-8") as f:
            return f.read()

    def test_los_scripts_son_ejecutables_y_sin_errores_de_sintaxis(self):
        for n in ("build-pkg.sh", "postinstall"):
            p = os.path.join(MAC, n)
            self.assertTrue(os.access(p, os.X_OK), n)
            self.assertEqual(subprocess.run(["bash", "-n", p], capture_output=True).returncode, 0, n)

    def test_el_paquete_lleva_todo_lo_que_usa_el_instalador(self):
        build = self.leer("build-pkg.sh")
        for pieza in ("sentinel", "bin", "yara", "packaging", "README.md", "install-mac.sh", "uninstall-mac.sh"):
            self.assertIn(f'"$AQUI/{pieza}"', build, pieza)
        self.assertIn("sentinel-src/install-mac.sh", self.leer("postinstall"))


if __name__ == "__main__":
    unittest.main()
