import os
import stat
import subprocess
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class GuiInstallerTests(unittest.TestCase):
    """Corre install-gui.sh con zenity y pkexec simulados: comprueba qué ventanas muestra y qué le pide al sistema."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.log = os.path.join(self.d, "calls.log")
        self.shim("zenity", '''#!/bin/bash
echo "zenity $*" >> "$SHIM_LOG"
case "$1" in
  --question) [ "${ZENITY_QUESTION_RC:-0}" = 0 ] && exit 0 || exit 1;;
  --list) echo "${ZENITY_LIST:-Instalar las dependencias que falten|Retirar la versión 1 de Sentinel (con copia de respaldo)}"; exit 0;;
  --progress) cat > /dev/null; exit 0;;
  *) cat > /dev/null 2>&1 < /dev/null; exit 0;;
esac''')
        self.shim("pkexec", '''#!/bin/bash
echo "pkexec $*" >> "$SHIM_LOG"
echo "== 1/8 Dependencias"; echo "== 8/8 Cortafuegos"; exit "${PKEXEC_RC:-0}"''')
        self.shim("sentinel", '#!/bin/bash\necho "sentinel $*" >> "$SHIM_LOG"\nexit 0')

    def shim(self, name, body):
        p = os.path.join(self.d, name)
        open(p, "w").write(body); os.chmod(p, os.stat(p).st_mode | stat.S_IEXEC)

    def run_gui(self, **env):
        e = dict(os.environ, PATH=f"{self.d}:{os.environ['PATH']}", SHIM_LOG=self.log, SENTINEL_GUI_TIMEOUT="1", **env)
        r = subprocess.run([os.path.join(ROOT, "install-gui.sh")], capture_output=True, text=True, env=e, timeout=60)
        calls = open(self.log).read() if os.path.exists(self.log) else ""
        return r.returncode, calls

    def test_flujo_normal(self):
        rc, calls = self.run_gui()
        self.assertEqual(rc, 0)
        starts = [l for l in calls.splitlines() if l.startswith(("zenity ", "pkexec ", "sentinel "))]
        self.assertTrue(starts[0].startswith("zenity --question"))               # bienvenida
        self.assertIn("zenity --list", calls); self.assertIn("pkexec", calls)   # opciones y autorización del sistema
        self.assertIn(os.path.join(ROOT, "install.sh"), calls)
        self.assertIn("zenity --progress", calls); self.assertIn("sentinel test", calls)   # avance y alerta de prueba
        self.assertNotIn("--exponer-senuelos", calls); self.assertNotIn("--sin-dependencias", calls)

    def test_opciones_elegidas_se_traducen_a_banderas(self):
        rc, calls = self.run_gui(ZENITY_LIST="Abrir los puertos señuelo hacia Internet (avanzado)")
        line = [l for l in calls.splitlines() if l.startswith("pkexec")][0]
        self.assertIn("--sin-dependencias", line); self.assertIn("--sin-limpiar", line); self.assertIn("--exponer-senuelos", line)

    def test_cancelar_en_la_bienvenida_no_pide_nada(self):
        rc, calls = self.run_gui(ZENITY_QUESTION_RC="1")
        self.assertNotIn("pkexec", calls); self.assertEqual(rc, 0)

    def test_autorizacion_rechazada(self):
        rc, calls = self.run_gui(PKEXEC_RC="126")
        self.assertEqual(rc, 1); self.assertIn("zenity --warning", calls); self.assertNotIn("sentinel test", calls)

    def test_instalacion_fallida_muestra_el_detalle(self):
        rc, calls = self.run_gui(PKEXEC_RC="3")
        self.assertEqual(rc, 3); self.assertIn("zenity --error", calls); self.assertIn("zenity --text-info", calls)


if __name__ == "__main__":
    unittest.main()
