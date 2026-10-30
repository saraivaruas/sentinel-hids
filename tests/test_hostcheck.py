import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

from helpers import Env, core
from sentinel import hostcheck

SS = """tcp   LISTEN 0 4096 127.0.0.1:631   0.0.0.0:* users:(("cupsd",pid=1,fd=7))
tcp   LISTEN 0 511  0.0.0.0:80      0.0.0.0:* users:(("nginx",pid=2,fd=6))
tcp   LISTEN 0 511     [::]:80         [::]:* users:(("nginx",pid=2,fd=7))
tcp   LISTEN 0 4096 [::1]:5432      [::]:*
udp   UNCONN 0 0 127.0.0.53%lo:53  0.0.0.0:* users:(("systemd-resolve",pid=3,fd=13))
udp   UNCONN 0 0   0.0.0.0:5353    0.0.0.0:*
"""


class HostTests(unittest.TestCase):
    def test_parseo_de_puertos(self):
        r = hostcheck.parse_listeners(SS)
        self.assertEqual(r["tcp/80"]["scope"], "todas las interfaces"); self.assertEqual(r["tcp/80"]["proc"], "nginx")
        self.assertEqual(r["tcp/631"]["scope"], "solo local"); self.assertEqual(r["tcp/5432"]["scope"], "solo local")
        self.assertEqual(r["udp/53"]["scope"], "solo local"); self.assertIn("udp/5353", r)

    def test_puerto_nuevo_y_exposicion(self):
        e = Env()
        try:
            hc = hostcheck.HostCheck(e.cfg, e.alerter, e.allow)
            base = {"listeners": hostcheck.parse_listeners(SS), "usb": [], "modules": [], "accounts": {"users": [], "uid0": [], "empty": []}}
            core.atomic_write_json(hc.path, base)
            nuevo = SS + 'tcp LISTEN 0 1 0.0.0.0:4444 0.0.0.0:* users:(("nc",pid=9,fd=3))\n'.replace("tcp LISTEN", "tcp   LISTEN")
            expuesto = nuevo.replace("127.0.0.1:631", "0.0.0.0:631")
            import unittest.mock as m
            with m.patch.object(hostcheck, "listeners", return_value=hostcheck.parse_listeners(expuesto)), m.patch.object(hostcheck, "accounts", return_value=base["accounts"]), \
                 m.patch.object(hostcheck, "proc_scan", return_value=[]), m.patch.object(hostcheck, "input_readers", return_value=[]), m.patch.object(hostcheck, "suspicious_connections", return_value=[]):
                kinds = sorted(ev.kind for ev in hc.run())
            self.assertIn("puerto_nuevo", kinds); self.assertIn("puerto_expuesto", kinds)
        finally:
            e.close()

    def test_proceso_desde_carpeta_temporal_y_binario_borrado(self):
        d = tempfile.mkdtemp(prefix="sent_proc_", dir="/tmp")
        exe = os.path.join(d, "trabajo")
        shutil.copy(shutil.which("sleep"), exe)
        p = subprocess.Popen([exe, "30"])
        try:
            time.sleep(0.3)
            found = {x["kind"] for x in hostcheck.proc_scan(["/tmp"], [], set()) if x["pid"] == p.pid}
            self.assertIn("ejecuta_desde_temporal", found)
            os.remove(exe)
            found = {x["kind"] for x in hostcheck.proc_scan(["/nada"], [], set()) if x["pid"] == p.pid}
            self.assertIn("binario_borrado", found)
        finally:
            p.kill(); shutil.rmtree(d, ignore_errors=True)

    def test_nombre_de_minero(self):
        d = tempfile.mkdtemp(prefix="sent_min_", dir="/var/tmp")
        exe = os.path.join(d, "xmrig")
        shutil.copy(shutil.which("sleep"), exe)
        p = subprocess.Popen([exe, "30"])
        try:
            time.sleep(0.3)
            self.assertIn("minero", {x["kind"] for x in hostcheck.proc_scan([], ["xmrig"], set()) if x["pid"] == p.pid})
            self.assertEqual([x for x in hostcheck.proc_scan([], ["xmrig"], {"xmrig"}) if x["pid"] == p.pid], [])   # lista blanca
        finally:
            p.kill(); shutil.rmtree(d, ignore_errors=True)


class SuidTests(unittest.TestCase):
    def test_detecta_suid_en_una_carpeta_y_omite_node_modules(self):
        d = tempfile.mkdtemp(prefix="sent_suid_")
        try:
            os.makedirs(os.path.join(d, "node_modules"))
            for rel in ("bueno", "node_modules/ignorado"):
                p = os.path.join(d, rel); open(p, "w").write("x"); os.chmod(p, 0o4755)
            self.assertEqual(hostcheck.suid_files([d]), [os.path.join(d, "bueno")])
        finally:
            shutil.rmtree(d, ignore_errors=True)
