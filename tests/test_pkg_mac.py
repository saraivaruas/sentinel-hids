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

    def test_python_fijado_con_huella_para_los_dos_procesadores(self):
        filas = [ln.split() for ln in self.leer("python-runtime.txt").splitlines() if ln.strip() and not ln.startswith("#")]
        self.assertEqual(sorted(f[0] for f in filas), ["arm64", "x86_64"])
        for arq, huella, url in filas:
            self.assertRegex(huella, r"^[0-9a-f]{64}$")
            self.assertTrue(url.startswith("https://github.com/astral-sh/python-build-standalone/releases/download/"), url)
            self.assertIn({"arm64": "aarch64-apple-darwin", "x86_64": "x86_64-apple-darwin"}[arq], url)
        build = self.leer("build-pkg.sh")
        self.assertLess(build.index("shasum -a 256 -c"), build.index('cp "$archivo"'))        # primero se comprueba, luego se incluye


if __name__ == "__main__":
    unittest.main()
