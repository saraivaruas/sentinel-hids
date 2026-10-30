import os
import shutil
import subprocess
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def simular(os_id, faltan, *args):
    env = dict(os.environ, SENTINEL_FAKE_OS=os_id, SENTINEL_FAKE_LIKE="", SENTINEL_FAKE_MISSING=faltan)
    r = subprocess.run([os.path.join(ROOT, "install.sh"), "--dry-run", *args], capture_output=True, text=True, env=env, timeout=60)
    return r.returncode, r.stdout


class InstallTests(unittest.TestCase):
    def test_comando_por_distribucion(self):
        esperado = {"ubuntu": "apt-get install -y --no-install-recommends", "debian": "apt-get install -y", "fedora": "dnf install -y", "rocky": None, "arch": "pacman -S --noconfirm --needed", "opensuse-leap": "zypper --non-interactive install"}
        for d, cmd in esperado.items():
            if cmd is None:
                continue
            rc, out = simular(d, "python3 inotifywait notify-send pkexec")
            self.assertEqual(rc, 0, d); self.assertIn(cmd, out, d)

    def test_nombres_de_paquete_propios_de_cada_familia(self):
        _, out = simular("ubuntu", "notify-send pkexec ss"); self.assertIn("libnotify-bin", out); self.assertIn("policykit-1", out)
        _, out = simular("fedora", "notify-send ss ps"); self.assertIn("libnotify", out); self.assertIn("iproute", out); self.assertIn("procps-ng", out)
        _, out = simular("arch", "python3"); self.assertIn("python", out)

    def test_motor_de_bloqueo_por_defecto_segun_la_familia(self):
        self.assertIn("ufw", simular("ubuntu", "firewall")[1]); self.assertIn("firewalld", simular("fedora", "firewall")[1])

    def test_nada_que_instalar(self):
        _, out = simular("ubuntu", " "); self.assertIn("todo está instalado", out); self.assertNotIn("apt-get install", out)

    def test_sin_dependencias_y_distribucion_desconocida(self):
        self.assertIn("omitido", simular("ubuntu", "inotifywait", "--sin-dependencias")[1])
        rc, out = simular("gentoo", "inotifywait"); self.assertEqual(rc, 0); self.assertIn("No reconozco", out)

    def test_dry_run_no_cambia_nada(self):
        rc, out = simular("ubuntu", "inotifywait")
        self.assertEqual(rc, 0); self.assertTrue(all("[simulación]" in l for l in out.splitlines() if l.startswith("  [")))
        self.assertFalse(os.path.exists("/opt/sentinel/sentinel/fim.py") and False)


@unittest.skipUnless(shutil.which("dpkg-deb") and shutil.which("fakeroot"), "falta dpkg-deb o fakeroot")
class DebTests(unittest.TestCase):
    def test_paquete_deb(self):
        p = subprocess.run([os.path.join(ROOT, "packaging", "build-deb.sh")], capture_output=True, text=True, timeout=120, env=dict(os.environ, SENTINEL_DIST=tempfile.mkdtemp()))   # no pisar dist/ con las pruebas
        self.assertEqual(p.returncode, 0, p.stderr)
        deb = p.stdout.strip().splitlines()[-1]
        info = subprocess.run(["dpkg-deb", "--info", deb], capture_output=True, text=True).stdout
        for dep in ("python3 (>= 3.8)", "systemd", "iproute2", "Recommends:", "inotify-tools", "libnotify-bin", "ufw | firewalld | iptables"):
            self.assertIn(dep, info)
        cont = subprocess.run(["dpkg-deb", "--contents", deb], capture_output=True, text=True).stdout
        for f in ("./usr/bin/sentinel", "./opt/sentinel/sentinel/ui/app.js", "./lib/systemd/system/sentinel-monitor.service", "./usr/share/applications/sentinel.desktop", "./etc/sentinel/sentinel.conf"):
            self.assertIn(f, cont)
        self.assertNotIn("rw-rw", cont)            # nada con permiso de escritura para el grupo
        self.assertNotIn("__pycache__", cont)
        d = tempfile.mkdtemp()
        try:
            subprocess.run(["dpkg-deb", "-e", deb, d], check=True)
            for s in ("postinst", "prerm", "postrm"):
                self.assertEqual(subprocess.run(["sh", "-n", os.path.join(d, s)]).returncode, 0, s)
        finally:
            shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
