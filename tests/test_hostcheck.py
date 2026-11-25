import os
import pwd
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from helpers import Env, core
from sentinel import hostcheck, plataforma

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

    def _run_con(self, base_ss, cur_ss):
        import unittest.mock as m
        e = Env()
        try:
            hc = hostcheck.HostCheck(e.cfg, e.alerter, e.allow)
            base = {"listeners": hostcheck.parse_listeners(base_ss), "usb": [], "modules": [], "accounts": {"users": [], "uid0": [], "empty": []}}
            core.atomic_write_json(hc.path, base)
            with m.patch.object(hostcheck, "listeners", return_value=hostcheck.parse_listeners(cur_ss)), m.patch.object(hostcheck, "accounts", return_value=base["accounts"]), \
                 m.patch.object(hostcheck, "proc_scan", return_value=[]), m.patch.object(hostcheck, "input_readers", return_value=[]), m.patch.object(hostcheck, "suspicious_connections", return_value=[]), \
                 m.patch.object(hostcheck, "usb_devices", return_value=[]), m.patch.object(hostcheck, "kernel_modules", return_value=[]):
                return [(ev.kind, ev.sev) for ev in hc.run()]
        finally:
            e.close()

    def test_puertos_udp_efimeros_no_son_ruido(self):
        base = SS + 'udp UNCONN 0 0 0.0.0.0:41099 0.0.0.0:* users:(("syncthing",pid=5,fd=3))\n'
        cur = SS + 'udp UNCONN 0 0 0.0.0.0:38330 0.0.0.0:* users:(("syncthing",pid=5,fd=3))\n'          # syncthing eligió otro puerto alto al reiniciar
        self.assertEqual(self._run_con(base, cur), [])
        raro = SS + 'udp UNCONN 0 0 0.0.0.0:38330 0.0.0.0:* users:(("desconocido",pid=6,fd=3))\n'       # otro programa escuchando en todas las interfaces: sí avisa
        self.assertEqual(self._run_con(base, raro), [("puerto_nuevo", "high")])
        tcp = SS + 'tcp LISTEN 0 1 0.0.0.0:4444 0.0.0.0:* users:(("nc",pid=9,fd=3))\n'
        self.assertEqual(self._run_con(base, tcp), [("puerto_nuevo", "high")])                            # un puerto TCP nuevo expuesto siempre avisa

    def test_puerto_nuevo_solo_local_es_gravedad_baja(self):
        self.assertEqual(self._run_con(SS, SS + 'tcp LISTEN 0 1 127.0.0.1:8081 0.0.0.0:* users:(("node",pid=8,fd=3))\n'), [("puerto_nuevo", "low")])

    def test_proceso_desde_carpeta_temporal_y_binario_borrado(self):
        d = tempfile.mkdtemp(prefix="sent_proc_", dir="/tmp")
        exe = os.path.join(d, "trabajo")
        shutil.copy(shutil.which("sleep"), exe)
        p = subprocess.Popen([exe, "30"])
        try:
            time.sleep(0.3)
            found = {x["kind"] for x in hostcheck.proc_scan(["/tmp"], [], set()) if x["pid"] == p.pid}
            self.assertIn("ejecuta_desde_temporal", found)
            if not plataforma.tiene_proc():
                return                                    # «ejecutable borrado» lo marca solo el kernel de Linux (/proc/PID/exe)
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


LSOF_ESCUCHA = """p312
ccupsd
f7
PTCP
n127.0.0.1:631
f8
PTCP
n[::1]:631
p501
cnginx
f6
PTCP
n*:80
p77
cmDNSResponder
f9
PUDP
n*:5353
"""
LSOF_CONECTADOS = """p900
cminerd
f5
PTCP
n10.0.0.5:51000->203.0.113.7:4444 (ESTABLISHED)
p901
cSafari
f6
PTCP
n10.0.0.5:51001->198.51.100.2:443 (ESTABLISHED)
"""


class LsofTests(unittest.TestCase):
    """Salida de `lsof -F` (macOS) convertida al formato de `ss`; se prueba en todos los sistemas."""

    def test_puertos_en_escucha(self):
        r = hostcheck.parse_listeners(hostcheck.lsof_a_ss(LSOF_ESCUCHA))
        self.assertEqual(r["tcp/631"]["scope"], "solo local"); self.assertEqual(r["tcp/631"]["proc"], "cupsd")
        self.assertEqual(r["tcp/80"]["scope"], "todas las interfaces"); self.assertEqual(r["tcp/80"]["proc"], "nginx")
        self.assertEqual(r["udp/5353"]["proc"], "mDNSResponder")

    def test_conexiones_no_se_cuentan_como_escucha(self):
        self.assertEqual(hostcheck.parse_listeners(hostcheck.lsof_a_ss(LSOF_CONECTADOS)), {})

    def test_conexiones_sospechosas(self):
        with mock.patch.object(hostcheck.plataforma, "ES_MAC", True), mock.patch.object(hostcheck.core, "run", return_value=(0, LSOF_CONECTADOS)):
            self.assertEqual(hostcheck.suspicious_connections({4444}, set()), [{"remote": "203.0.113.7:4444", "proc": "minerd"}])
            self.assertEqual(hostcheck.suspicious_connections({4444}, {"minerd"}), [])


class CuentasMacTests(unittest.TestCase):
    def test_cuentas_con_pwd(self):
        P = lambda n, uid, sh: pwd.struct_passwd((n, "*", uid, uid, "", "/", sh))
        falsas = [P("root", 0, "/bin/sh"), P("jorge", 501, "/bin/zsh"), P("_www", 70, "/usr/bin/false"), P("intruso", 0, "/bin/zsh"), P("nobody", -2, "/usr/bin/false")]
        with mock.patch.object(hostcheck.pwd, "getpwall", return_value=falsas):
            r = hostcheck._cuentas_pwd()
        self.assertEqual(r["users"], ["intruso", "jorge", "root"]); self.assertEqual(r["uid0"], ["intruso"]); self.assertEqual(r["empty"], [])

    def test_accounts_usa_pwd_en_macos(self):
        with mock.patch.object(hostcheck.plataforma, "ES_MAC", True), mock.patch.object(hostcheck, "_cuentas_pwd", return_value={"users": ["x"], "uid0": [], "empty": []}):
            self.assertEqual(hostcheck.accounts()["users"], ["x"])


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

    def test_la_busqueda_en_python_equivale_a_find(self):
        """Es la que usa macOS (su `find` no entiende -perm /6000); se prueba en todos los sistemas."""
        d = tempfile.mkdtemp(prefix="sent_suid_")
        try:
            os.makedirs(os.path.join(d, "node_modules")); os.makedirs(os.path.join(d, "sub"))
            for rel, modo in (("bueno", 0o4755), ("sub/grupo", 0o2755), ("normal", 0o755), ("node_modules/ignorado", 0o4755)):
                p = os.path.join(d, rel); open(p, "w").write("x"); os.chmod(p, modo)
            os.symlink(os.path.join(d, "bueno"), os.path.join(d, "enlace"))          # un enlace no es un archivo SUID
            self.assertEqual(sorted(hostcheck._suid_en_python([d])), sorted([os.path.join(d, "bueno"), os.path.join(d, "sub", "grupo")]))
        finally:
            shutil.rmtree(d, ignore_errors=True)
