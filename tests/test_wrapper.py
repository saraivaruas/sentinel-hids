import os
import shutil
import subprocess
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class WrapperTests(unittest.TestCase):
    def test_no_ejecuta_codigo_de_la_carpeta_actual(self):
        """Seguridad: un paquete falso «sentinel» en el directorio de trabajo no debe ejecutarse (ni con sudo)."""
        d = tempfile.mkdtemp(); marca = os.path.join(d, "EJECUTADO")
        os.makedirs(os.path.join(d, "sentinel"))
        open(os.path.join(d, "sentinel", "__init__.py"), "w").write(f"open({marca!r}, 'w').write('x')\n")
        open(os.path.join(d, "sentinel", "__main__.py"), "w").write(f"open({marca!r}, 'w').write('x')\n")
        env = dict(os.environ, PYTHONPATH=d)                       # tampoco debe hacerle caso a PYTHONPATH
        r = subprocess.run([os.path.join(ROOT, "bin", "sentinel"), "--help"], cwd=d, capture_output=True, text=True, env=env, timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr); self.assertIn("Sentinel", r.stdout)
        self.assertFalse(os.path.exists(marca), "se ejecutó el código de la carpeta actual")

    def test_funciona_desde_cualquier_carpeta_y_con_argumentos(self):
        d = tempfile.mkdtemp()
        r = subprocess.run([os.path.join(ROOT, "bin", "sentinel"), "update", "--help"], cwd=d, capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0); self.assertIn("--instalar", r.stdout)
        self.assertEqual(subprocess.run([os.path.join(ROOT, "bin", "sentinel"), "esto-no-existe"], cwd=d, capture_output=True, timeout=30).returncode, 2)

    def test_enlace_simbolico_como_en_la_instalacion(self):
        d = tempfile.mkdtemp(); link = os.path.join(d, "sentinel-link"); os.symlink(os.path.join(ROOT, "bin", "sentinel"), link)
        self.assertEqual(subprocess.run([link, "--help"], cwd=d, capture_output=True, timeout=30).returncode, 0)

    def test_el_lanzador_usa_el_python_anotado_por_el_instalador(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "bin")); shutil.copy(os.path.join(ROOT, "bin", "sentinel"), os.path.join(d, "bin", "sentinel"))
            falso = os.path.join(d, "mi-python")
            with open(falso, "w") as f:
                f.write("#!/bin/sh\necho PYTHON-ELEGIDO\n")
            os.chmod(falso, 0o755)
            with open(os.path.join(d, "python"), "w") as f:
                f.write(falso + "\n")
            r = subprocess.run([os.path.join(d, "bin", "sentinel"), "status"], capture_output=True, text=True, timeout=30)
        self.assertEqual(r.stdout.strip(), "PYTHON-ELEGIDO", r.stderr)


if __name__ == "__main__":
    unittest.main()
