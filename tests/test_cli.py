import io
import os
import unittest
import unittest.mock
from contextlib import redirect_stdout

from helpers import Env
from sentinel import cli


class CliTests(unittest.TestCase):
    def run_cli(self, *args):
        out = io.StringIO()
        with redirect_stdout(out):
            rc = cli.main(list(args))
        return rc, out.getvalue()

    def test_flujo_completo(self):
        from sentinel import hostcheck
        quiet = [unittest.mock.patch.object(hostcheck, n, return_value=v) for n, v in (("proc_scan", []), ("input_readers", []), ("suspicious_connections", []))]
        for q in quiet: q.start(); self.addCleanup(q.stop)
        e = Env()
        try:
            e.write("etc/passwd", "root:x:0:0\n")
            rc, out = self.run_cli("baseline", "init"); self.assertEqual(rc, 0)
            rc, out = self.run_cli("scan", "--quiet"); self.assertEqual(rc, 0); self.assertIn("Sin novedades", out)
            e.write("etc/passwd", "root:x:0:0\nmalo:x:0:0\n")
            rc, out = self.run_cli("scan", "--quiet"); self.assertEqual(rc, 1); self.assertIn("passwd", out)   # media: la ruta de prueba no es /etc
            rc, out = self.run_cli("events", "--min", "medium"); self.assertIn("fim/modified", out)
            self.run_cli("baseline", "accept")
            rc, out = self.run_cli("scan", "--quiet"); self.assertEqual(rc, 0)
        finally:
            e.close()

    def test_lista_blanca_edita_el_archivo(self):
        e = Env(extra="[allow]\nips =\nprocs =\nports =\npaths =")
        try:
            self.run_cli("allow", "ip", "203.0.113.5"); self.run_cli("allow", "port", "3000"); self.run_cli("allow", "port", "3000")
            txt = open(os.environ["SENTINEL_CONF"]).read()
            self.assertIn("ips = 203.0.113.5", txt); self.assertEqual(txt.count("3000"), 1)
        finally:
            e.close()

    def test_auditoria_corre_completa(self):
        e = Env()
        try:
            from sentinel import audit
            import json
            rapidas = [c for c in audit.CHECKS if c[0] in ("firewall", "ids", "auditd", "ssh", "sysctl", "login_defs", "docker", "legacy", "authlog")]
            with unittest.mock.patch.object(audit, "CHECKS", rapidas):
                rc, out = self.run_cli("audit", "--json")
            r = json.loads(out); self.assertTrue(0 <= r["score"] <= 100); self.assertEqual(len(r["checks"]), len(rapidas))
            self.assertEqual(len(audit.CHECKS), 16)       # el conjunto completo sigue ahí
        finally:
            e.close()


if __name__ == "__main__":
    unittest.main()
