import io
import json
import re
import unittest
from contextlib import redirect_stdout
from unittest import mock

from helpers import Env, core
from sentinel import cli, requisitos as rq


class RequisitosTests(unittest.TestCase):
    def estado_con_faltas(self, *ids):
        # Hermético: todo «instalado» salvo lo que se pide que falte, sin depender de lo que tenga el equipo que corre las pruebas (CI incluido).
        with mock.patch.dict("os.environ", {"SENTINEL_FAKE_MISSING": ",".join(ids)}), \
             mock.patch.multiple(rq, REQUISITOS=[rq.Requisito(**{**r.__dict__, "esta": (lambda: True)}) for r in rq.REQUISITOS]):
            return rq.estado()

    def test_lo_que_se_detecta_se_marca_y_lo_que_falta_tambien(self):
        d = {r.id: ok for r, ok in self.estado_con_faltas("inotify", "zenity")}
        self.assertFalse(d["inotify"]); self.assertFalse(d["zenity"]); self.assertTrue(d["python3"])

    def test_solo_se_ofrece_instalar_lo_obligatorio_y_recomendado(self):
        lista = self.estado_con_faltas("inotify", "zenity", "crowdsec")
        self.assertEqual([r.id for r in rq.faltan(lista=lista)], ["inotify"])           # zenity y crowdsec son opcionales

    def test_paquetes_por_gestor_y_lo_que_no_se_puede_instalar_con_el_gestor(self):
        pend = [r for r in rq.REQUISITOS if r.id in ("inotify", "notify", "crowdsec", "unattended")]
        self.assertEqual(rq.paquetes_para(pend, "apt")[0], ["inotify-tools", "libnotify-bin", "unattended-upgrades"])
        self.assertEqual([r.id for r in rq.paquetes_para(pend, "apt")[1]], ["crowdsec"])          # CrowdSec no está en los repositorios: se explica cómo conseguirlo
        paquetes, sin = rq.paquetes_para(pend, "dnf")
        self.assertEqual(paquetes, ["inotify-tools", "libnotify"]); self.assertEqual({r.id for r in sin}, {"crowdsec", "unattended"})

    def test_cada_requisito_con_gestor_tiene_nombres_validos(self):
        for r in rq.REQUISITOS:
            for g, ps in r.paquetes.items():
                self.assertIn(g, rq.GESTORES)
                self.assertTrue(ps and all(isinstance(p, str) and p and " " not in p for p in ps), (r.id, g))
            self.assertIn(r.nivel, (rq.OBLIGATORIO, rq.RECOMENDADO, rq.OPCIONAL)); self.assertTrue(r.para_que)

    def test_comando_de_instalacion_con_y_sin_sudo_sin_preguntas(self):
        self.assertEqual(rq.comando_instalar("apt", ["a", "b"], True), ["sudo", "env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "install", "-y", "--no-install-recommends", "a", "b"])
        self.assertEqual(rq.comando_instalar("dnf", ["a"], False), ["dnf", "install", "-y", "a"])
        self.assertEqual(rq.comando_instalar("pacman", ["a"], False)[:3], ["pacman", "-S", "--noconfirm"])

    def test_detecta_la_familia_de_la_distribucion(self):
        for ident, like, esperado in (("ubuntu", "debian", "apt"), ("debian", "", "apt"), ("linuxmint", "ubuntu debian", "apt"), ("fedora", "", "dnf"), ("rocky", "rhel centos fedora", "dnf"),
                                      ("arch", "", "pacman"), ("manjaro", "arch", "pacman"), ("opensuse-leap", "suse opensuse", "zypper"), ("gentoo", "", "")):
            self.assertEqual(rq.gestor(id_falso=ident, like_falso=like), esperado, ident)

    def test_resumen_para_el_panel(self):
        d = rq.como_dict(self.estado_con_faltas("polkit"), "apt")
        self.assertEqual(d["paquetes"], ["policykit-1"]); self.assertTrue(d["resumen"]["obligatorios_ok"]); self.assertEqual(d["resumen"]["faltan"], ["polkit"])
        self.assertFalse(rq.como_dict(self.estado_con_faltas("python3"), "apt")["resumen"]["obligatorios_ok"])


class RequisitosCliTests(unittest.TestCase):
    def correr(self, *args, entrada="", tty=False, root=False, faltan=""):
        out = io.StringIO()
        with redirect_stdout(out), mock.patch.dict("os.environ", {"SENTINEL_FAKE_MISSING": faltan}), mock.patch.object(core, "is_root", return_value=root), \
             mock.patch("sys.stdin.isatty", return_value=tty), mock.patch("sys.stdout.isatty", return_value=tty), mock.patch("builtins.input", return_value=entrada), \
             mock.patch("shutil.which", return_value="/usr/bin/sudo"), mock.patch.object(rq, "gestor", return_value="apt"), mock.patch("subprocess.run") as run:
            run.return_value.returncode = 0
            rc = cli.main(["requisitos", *args])
        return rc, re.sub(r"\x1b\[[0-9;]*m", "", out.getvalue()), run

    def test_con_todo_instalado_lo_dice_y_no_pregunta(self):
        rc, out, run = self.correr(tty=True)
        self.assertEqual(rc, 0); self.assertIn("✔", out); self.assertIn("Todo lo necesario ya está instalado", out); run.assert_not_called()

    def test_si_falta_algo_pregunta_y_si_aceptas_instala_con_sudo(self):
        rc, out, run = self.correr(tty=True, entrada="", faltan="inotify")                # Enter = sí
        self.assertIn("✖ inotify-tools", out); self.assertIn("Se instalaría con apt: inotify-tools", out)
        cmds = [c.args[0] for c in run.call_args_list]
        self.assertEqual(cmds[0], ["sudo", "apt-get", "update", "-qq"])
        self.assertEqual(cmds[1][:4], ["sudo", "env", "DEBIAN_FRONTEND=noninteractive", "apt-get"]); self.assertIn("inotify-tools", cmds[1])

    def test_si_dices_que_no_no_se_instala_nada(self):
        rc, out, run = self.correr(tty=True, entrada="n", faltan="inotify")
        self.assertIn("No se instaló nada", out); run.assert_not_called(); self.assertEqual(rc, 0)       # lo faltante era solo recomendado

    def test_sin_lo_obligatorio_y_diciendo_que_no_avisa_que_no_funcionara(self):
        rc, out, run = self.correr(tty=True, entrada="n", faltan="python3")
        self.assertEqual(rc, 1); self.assertIn("Sentinel no podrá funcionar", out)

    def test_sin_terminal_no_instala_solo_explica_como(self):
        rc, out, run = self.correr(faltan="inotify")
        self.assertIn("sentinel requisitos --instalar", out); run.assert_not_called()

    def test_con_si_instala_sin_preguntar_y_como_root_sin_sudo(self):                      # lo que usa el panel (pkexec ya lo hizo root)
        rc, out, run = self.correr("--instalar", "--si", root=True, faltan="inotify,notify")
        cmds = [c.args[0] for c in run.call_args_list]
        self.assertEqual(cmds[0], ["apt-get", "update", "-qq"]); self.assertNotIn("sudo", cmds[1]); self.assertIn("libnotify-bin", cmds[1])

    def test_json_para_otros_programas(self):
        rc, out, run = self.correr("--json", faltan="zenity")
        d = json.loads(out)
        self.assertEqual(d["gestor"], "apt"); self.assertTrue(any(x["id"] == "zenity" and not x["ok"] for x in d["requisitos"]))


if __name__ == "__main__":
    unittest.main()
