import os
import plistlib
import shutil
import subprocess
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class InstalarMacTests(unittest.TestCase):
    def correr(self, uname, *args):
        return subprocess.run(["bash", os.path.join(ROOT, "install-mac.sh"), *args], capture_output=True, text=True, timeout=30, env=dict(os.environ, SENTINEL_FAKE_UNAME=uname))

    def test_en_linux_no_hace_nada(self):
        r = self.correr("Linux", "--dry-run")
        self.assertEqual(r.returncode, 1); self.assertIn("install.sh", r.stdout)

    def test_simulacion_muestra_los_pasos_en_orden(self):
        r = self.correr("Darwin", "--dry-run")
        self.assertEqual(r.returncode, 0, r.stderr)
        s = r.stdout
        # las tareas se escriben antes de la referencia: así Sentinel no se reporta a sí mismo como programa de arranque nuevo
        ref = s.index("bin/sentinel baseline ")                                  # «init» o «accept», según haya ya una referencia en este equipo
        self.assertLess(s.index("servicio.instalar"), ref); self.assertLess(ref, s.index("servicio.iniciar"))
        self.assertTrue(all("[simulación]" in ln for ln in s.splitlines() if "rm -rf" in ln))

    def test_deja_el_panel_en_aplicaciones(self):
        r = self.correr("Darwin", "--dry-run")
        self.assertIn("/Applications/Sentinel.app/Contents/MacOS/Sentinel", r.stdout)
        with open(os.path.join(ROOT, "packaging", "macos", "Info.plist"), "rb") as f:
            d = plistlib.load(f)
        self.assertEqual(d["CFBundleExecutable"], "Sentinel")
        self.assertTrue(os.access(os.path.join(ROOT, "packaging", "macos", "abrir-panel"), os.X_OK))

    def test_icono_de_la_barra_de_menu_antes_de_la_referencia(self):
        s = self.correr("Darwin", "--dry-run").stdout
        self.assertLess(s.index("sentinel-barra"), s.index("bin/sentinel baseline "))     # así su arranque no sale como programa nuevo
        with open(os.path.join(ROOT, "packaging", "macos", "barra.plist"), "rb") as f:
            d = plistlib.load(f)
        self.assertEqual(d["ProgramArguments"], ["/opt/sentinel/bin/sentinel-barra"]); self.assertEqual(d["LimitLoadToSessionType"], "Aqua"); self.assertNotIn("UserName", d)

    def test_con_python_incluido_no_hacen_falta_las_herramientas_de_apple(self):
        with tempfile.TemporaryDirectory() as d:
            shutil.copy(os.path.join(ROOT, "install-mac.sh"), d)
            os.makedirs(os.path.join(d, "runtime"))
            open(os.path.join(d, "runtime", os.uname().machine + ".tar.gz"), "w").close()
            r = subprocess.run(["bash", os.path.join(d, "install-mac.sh"), "--dry-run"], capture_output=True, text=True, timeout=30, env=dict(os.environ, SENTINEL_FAKE_UNAME="Darwin"))
        self.assertEqual(r.returncode, 0, r.stderr); s = r.stdout
        self.assertIn("Python: /opt/sentinel/runtime/bin/python3", s); self.assertNotIn("/usr/bin/python3", s)
        self.assertLess(s.index("instalar el Python incluido"), s.index("precompilar")); self.assertLess(s.index("precompilar"), s.index("bin/sentinel baseline "))
        self.assertLess(s.index("rm -rf /opt/sentinel"), s.index("instalar el Python incluido"))      # no se borra después de copiarlo

    def test_con_el_icono_ya_compilado_no_se_compila(self):
        with tempfile.TemporaryDirectory() as d:
            shutil.copy(os.path.join(ROOT, "install-mac.sh"), d)
            os.makedirs(os.path.join(d, "prebuilt"))
            open(os.path.join(d, "prebuilt", "sentinel-barra"), "w").close()
            s = subprocess.run(["bash", os.path.join(d, "install-mac.sh"), "--dry-run"], capture_output=True, text=True, timeout=30, env=dict(os.environ, SENTINEL_FAKE_UNAME="Darwin")).stdout
        self.assertIn("copiar el icono ya compilado", s)
        self.assertIn("compilar sentinel-barra", self.correr("Darwin", "--dry-run").stdout)       # desde el código se sigue compilando

    def test_sin_python_incluido_sigue_usando_el_del_sistema(self):
        s = self.correr("Darwin", "--dry-run").stdout
        self.assertNotIn("runtime", s); self.assertIn("precompilar", s)


if __name__ == "__main__":
    unittest.main()
