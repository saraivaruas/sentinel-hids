"""Retirar el método antiguo de rotación (cron, macchanger.service y scripts sueltos) y poder deshacerlo."""
import os
import unittest
from unittest import mock

import helpers
from sentinel import cli, core, identidad

CRONTAB = "# m h dom mon dow orden\n0 10-22/2 * * * /usr/local/bin/change-mac.sh\n30 2 * * * /usr/bin/respaldo\n"


class RetiroTests(unittest.TestCase):
    def setUp(self):
        self.env = helpers.Env(); self.addCleanup(self.env.close)
        d = self.env.dir
        self.bin, self.log, self.spool, self.crond, self.systemd = (os.path.join(d, x) for x in ("bin", "varlog", "spool", "crond", "systemd"))
        for x in (self.bin, self.log, self.spool, self.crond, self.systemd):
            os.makedirs(x)
        self.unidad = self.escribir(self.systemd, "macchanger.service", "[Service]\nExecStart=/usr/local/bin/change-mac.sh\n")
        self.script_mac = self.escribir(self.bin, "change-mac.sh", "#!/bin/bash\nmacchanger -r eth0\n", 0o755)
        self.script_ip = self.escribir(self.bin, "change-ip.sh", "#!/bin/bash\n", 0o755)
        self.ajeno = self.escribir(self.bin, "exchange-ip.sh", "#!/bin/bash\n", 0o755)
        self.binario = self.escribir(self.bin, "macchanger", "\x7fELF", 0o755)
        self.registro = self.escribir(self.log, "change-ip.log", "")
        self.cron = self.escribir(self.crond, "propio", "MAILTO=root\n@reboot root /usr/bin/macchanger -r eth0\n0 3 * * * root /usr/bin/otra\n")
        self.escribir(self.spool, "root", "")
        self.gancho = self.escribir(d, "gancho", "#!/bin/sh\n", 0o755)
        self.ajuste = self.escribir(d, "macchanger.default", '# comentario\nENABLE_ON_POST_UP_DOWN=true\nINTERFACE="wlo1"\n')
        self.crontab = CRONTAB
        self.habilitado, self.falla_crontab = True, False
        for k, v in (("UNIDAD_ANTIGUA", self.unidad), ("CARPETAS_SCRIPTS", (self.bin,)), ("REGISTROS", self.log), ("CRON_USUARIOS", self.spool),
                     ("CRON_SISTEMA", (os.path.join(self.crond, "*"),)), ("GANCHO", self.gancho), ("AJUSTE_GANCHO", self.ajuste)):
            p = mock.patch.object(identidad, k, v); p.start(); self.addCleanup(p.stop)

    def escribir(self, base, nombre, texto, modo=0o644):
        ruta = os.path.join(base, nombre)
        with open(ruta, "w", encoding="utf-8") as f:
            f.write(texto)
        os.chmod(ruta, modo)
        return ruta

    def leer(self, ruta):
        with open(ruta, encoding="utf-8") as f:
            return f.read()

    def run_(self, c, t=20):
        if c[:2] == ["crontab", "-u"]:
            if c[3] == "-l":
                return 0, self.crontab
            if self.falla_crontab:
                return 1, "errors in crontab file"
            self.crontab = self.leer(c[3])
            return 0, ""
        if c[:2] == ["systemctl", "is-enabled"]:
            return 0, "enabled\n" if self.habilitado else "disabled\n"
        if c[:2] in (["systemctl", "disable"], ["systemctl", "enable"]):
            self.habilitado = c[1] == "enable"
        return 0, ""

    def test_el_plan_solo_toca_lo_antiguo_y_no_cambia_nada(self):
        plan = identidad.plan_retiro(self.run_)
        self.assertEqual(plan["scripts"], [self.script_ip, self.script_mac])            # ni «exchange-ip» ni el programa macchanger
        self.assertEqual(plan["crontabs"]["root"]["quitar"], ["0 10-22/2 * * * /usr/local/bin/change-mac.sh"])
        self.assertEqual(plan["registros"], [self.registro])
        self.assertTrue(os.path.exists(self.script_mac)); self.assertEqual(self.crontab, CRONTAB)

    def test_retirar_conserva_las_demas_tareas(self):
        r = identidad.retirar(self.env.cfg, self.env.alerter, self.run_)
        self.assertTrue(r["ok"], r)
        for ruta in (self.unidad, self.script_mac, self.script_ip, self.registro):
            self.assertFalse(os.path.exists(ruta), ruta)
        self.assertTrue(os.path.exists(self.ajeno) and os.path.exists(self.binario))
        self.assertEqual(self.crontab, "# m h dom mon dow orden\n30 2 * * * /usr/bin/respaldo\n")
        self.assertEqual(self.leer(self.cron), "MAILTO=root\n0 3 * * * root /usr/bin/otra\n")
        self.assertFalse(self.habilitado)
        self.assertEqual(self.leer(self.ajuste), '# comentario\nENABLE_ON_POST_UP_DOWN=false\nINTERFACE="wlo1"\n')
        self.assertTrue(os.path.exists(self.gancho))                                       # el archivo del paquete no se toca
        self.assertEqual(os.stat(r["carpeta"]).st_mode & 0o777, 0o700)
        self.assertIn("No queda nada", identidad.retirar(self.env.cfg, self.env.alerter, self.run_)["mensaje"])

    def test_devolver_deja_todo_como_estaba(self):
        antes = {r: (self.leer(r), os.stat(r).st_mode) for r in (self.unidad, self.script_mac, self.script_ip, self.registro, self.cron, self.ajuste)}
        identidad.retirar(self.env.cfg, self.env.alerter, self.run_)
        r = identidad.devolver(self.env.cfg, self.env.alerter, self.run_)
        self.assertTrue(r["ok"], r)
        self.assertEqual({r: (self.leer(r), os.stat(r).st_mode) for r in antes}, antes)
        self.assertEqual((self.crontab, self.habilitado), (CRONTAB, True))
        self.assertFalse(identidad.devolver(self.env.cfg, self.env.alerter, self.run_)["ok"])

    def test_si_falla_el_cron_no_borra_los_scripts(self):
        self.falla_crontab = True
        r = identidad.retirar(self.env.cfg, self.env.alerter, self.run_)
        self.assertFalse(r["ok"]); self.assertIn("devolver", r["mensaje"])
        self.assertTrue(os.path.exists(self.script_mac) and os.path.exists(self.unidad)); self.assertTrue(self.habilitado)

    def test_sin_permisos_no_cambia_nada(self):
        r = identidad.retirar(self.env.cfg, self.env.alerter, lambda c, t=20: (1, "must be privileged"))
        self.assertFalse(r["ok"]); self.assertTrue(os.path.exists(self.script_mac))

    def test_no_devuelve_con_la_rotacion_activada(self):
        identidad.retirar(self.env.cfg, self.env.alerter, self.run_)
        core.set_setting("identidad", "activo", "yes")
        self.assertFalse(identidad.devolver(core.load_config(), self.env.alerter, self.run_)["ok"])
        self.assertFalse(os.path.exists(self.script_mac))

    def test_piden_el_pin(self):
        for accion in ("retirar", "devolver"):
            self.assertTrue(cli._protected(mock.Mock(accion=accion, fn=cli.cmd_identidad, programado=False)), accion)


if __name__ == "__main__":
    unittest.main()
