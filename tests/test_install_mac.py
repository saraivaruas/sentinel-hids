import os
import plistlib
import subprocess
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


if __name__ == "__main__":
    unittest.main()
