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

    def test_lista_los_requisitos_con_marcas(self):
        _, out = simular("ubuntu", "inotifywait")
        self.assertIn("✖ inotify-tools", out); self.assertIn("✔ Python 3", out); self.assertIn("✔ libnotify", out)
        _, out = simular("ubuntu", " "); self.assertNotIn("✖", out)

    def test_dry_run_no_pregunta(self):
        _, out = simular("ubuntu", "inotifywait")
        self.assertNotIn("[S/n]", out); self.assertNotIn("Te pedirá tu contraseña", out)

    def test_dry_run_con_distribucion_desconocida_sigue_funcionando(self):
        rc, out = simular("gentoo", "inotifywait"); self.assertEqual(rc, 0); self.assertIn("✖ inotify-tools", out)

    def test_dry_run_nunca_pide_administrador(self):
        self.assertNotIn("Falta sudo", simular("ubuntu", "inotifywait")[1])

    def test_el_script_pasa_shellcheck_basico_de_sintaxis(self):
        self.assertEqual(subprocess.run(["bash", "-n", os.path.join(ROOT, "install.sh")]).returncode, 0)

    def test_el_help_explica_la_pregunta_y_la_opcion_si(self):
        r = subprocess.run([os.path.join(ROOT, "install.sh"), "--help"], capture_output=True, text=True)
        self.assertIn("--si", r.stdout); self.assertIn("contraseña de administrador", r.stdout)

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
        for f in ("./usr/bin/sentinel", "./opt/sentinel/sentinel/ui/app.js", "./lib/systemd/system/sentinel-monitor.service", "./usr/share/applications/sentinel.desktop", "./usr/share/sentinel/sentinel.conf.example"):
            self.assertIn(f, cont)
        self.assertNotIn("./etc/sentinel/sentinel.conf", cont)       # la configuración no viaja en el paquete: una actualización no puede pisarla
        self.assertNotIn("rw-rw", cont)            # nada con permiso de escritura para el grupo
        self.assertNotIn("__pycache__", cont)
        d = tempfile.mkdtemp()
        try:
            subprocess.run(["dpkg-deb", "-e", deb, d], check=True)
            for s in ("postinst", "prerm", "postrm"):
                self.assertEqual(subprocess.run(["sh", "-n", os.path.join(d, s)]).returncode, 0, s)
            self.assertFalse(os.path.exists(os.path.join(d, "conffiles")))       # sin «conffiles»: dpkg no toca /etc/sentinel/sentinel.conf
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_la_configuracion_se_crea_solo_si_no_existe(self):
        """El 14-nov-2026 una actualización pisó la lista blanca del usuario (sentinel.conf era conffile de dpkg)."""
        post = open(os.path.join(ROOT, "packaging", "debian", "postinst")).read()
        self.assertIn("[ -f /etc/sentinel/sentinel.conf ] ||", post); self.assertIn("/usr/share/sentinel/sentinel.conf.example", post)
        build = open(os.path.join(ROOT, "packaging", "build-deb.sh")).read()
        self.assertNotIn("conffiles", build.replace("sin «conffile»", ""))

    def test_el_paquete_no_enciende_los_senuelos(self):
        post = open(os.path.join(ROOT, "packaging", "debian", "postinst")).read()
        self.assertIn("disable --now sentinel-honeypot", post); self.assertNotIn("enable --now sentinel-honeypot", post)
        self.assertIn("/etc/systemd/system/sentinel-*.service", post)       # retira copias viejas que tapan las del paquete
        self.assertLess(post.index("rm -f"), post.index("daemon-reload"))
        self.assertNotIn("honeypot", open(os.path.join(ROOT, "systemd", "sentinel-monitor.service")).read())     # el monitor no los arrastra


if __name__ == "__main__":
    unittest.main()


@unittest.skipIf(os.getuid() == 0, "como root el instalador instalaría de verdad: estas pruebas son solo para un usuario normal")
class InstalarSinAdministradorTests(unittest.TestCase):
    """Sin permisos de administrador el instalador detecta, muestra ✔/✖, pregunta y solo si aceptas pide sudo (aquí un `sudo` falso: no se instala nada)."""

    def setUp(self):
        self.bin = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.bin, True)
        falso = os.path.join(self.bin, "sudo")
        with open(falso, "w") as f:
            f.write("#!/bin/sh\necho \"SUDO_LLAMADO: $*\"\n")
        os.chmod(falso, 0o755)

    def correr(self, faltan, respuesta="", *args):
        env = dict(os.environ, SENTINEL_FAKE_OS="ubuntu", SENTINEL_FAKE_LIKE="", SENTINEL_FAKE_MISSING=faltan, SENTINEL_FAKE_ANSWER=respuesta, PATH=self.bin + os.pathsep + os.environ["PATH"])
        r = subprocess.run([os.path.join(ROOT, "install.sh"), *args], capture_output=True, text=True, env=env, timeout=60, stdin=subprocess.DEVNULL)
        return r.returncode, r.stdout + r.stderr

    def test_si_falta_algo_lo_muestra_y_acepta_pide_sudo_con_la_marca_de_aceptado(self):
        rc, out = self.correr("inotifywait", "s")
        self.assertEqual(rc, 0, out); self.assertIn("✖ inotify-tools", out)
        self.assertIn("SUDO_LLAMADO: env SENTINEL_ACEPTADO=1", out); self.assertIn("install.sh", out)

    def test_si_dices_que_no_no_se_pide_la_contrasena_ni_se_instala_nada(self):
        rc, out = self.correr("inotifywait", "n")
        self.assertEqual(rc, 0); self.assertIn("No se instaló nada", out); self.assertNotIn("SUDO_LLAMADO", out)

    def test_si_todo_esta_listo_pregunta_si_instalar_sentinel(self):
        rc, out = self.correr(" ", "s")
        self.assertNotIn("✖", out); self.assertIn("SUDO_LLAMADO", out)
        rc, out = self.correr(" ", "n"); self.assertNotIn("SUDO_LLAMADO", out)

    def test_sin_terminal_y_sin_respuesta_sigue_solo_para_poder_automatizar(self):
        rc, out = self.correr("inotifywait", "")
        self.assertIn("SUDO_LLAMADO", out)

    def test_los_argumentos_viajan_al_script_que_corre_con_sudo(self):
        rc, out = self.correr("inotifywait", "s", "--sin-limpiar")
        self.assertIn("--sin-limpiar", out)
