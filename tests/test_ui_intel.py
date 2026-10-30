import http.client
import io
import json
import os
import threading
import time
import unittest
from contextlib import redirect_stdout

from helpers import Env, core
from sentinel import cli, incidents, ui


class UiIntelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.e = Env()
        os.environ["XDG_CONFIG_HOME"] = os.path.join(cls.e.dir, "cfg")
        cls.token = ui.load_token()
        st = incidents.Store(); t = time.time()
        for i in range(12):
            st.record_attempt("203.0.113.9", "ssh_clave", user="<img src=x onerror=alert(1)>" if i == 0 else "root", port=22, proto="tcp", ts=t - 60 + i)
        st.set_geo("203.0.113.9", {"country": "Rusia", "country_code": "RU", "city": "Moscú", "org": "Ejemplo"})
        st.ban_started("203.0.113.9", t + 3600, "fuerza bruta", "ufw")
        st.add_packets({("203.0.113.9", "tcp", 22, "SYN"): (t - 5, t, 4, 240)}, [{"ts": t, "ip": "203.0.113.9", "proto": "tcp", "sport": 4000, "dport": 22, "flags": "SYN", "size": 60, "label": "x"}])
        st.close()
        cls.srv = ui.Server(0, cls.token, ui.Data(cls.e.cfg)); cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown(); cls.srv.server_close(); cls.e.close()

    def get(self, path, cookie=True):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        c.request("GET", path, headers={"Host": f"127.0.0.1:{self.port}", **({"Cookie": f"sentinel_t={self.token}"} if cookie else {})})
        r = c.getresponse(); raw = r.read()
        try:
            return r.status, json.loads(raw or b"null")
        except ValueError:
            return r.status, raw

    def test_lista_de_atacantes(self):
        st, d = self.get("/api/attackers")
        self.assertEqual(st, 200); self.assertEqual(d["items"][0]["ip"], "203.0.113.9"); self.assertEqual(d["items"][0]["estado"], "bloqueada")
        self.assertIn("Moscú", d["items"][0]["lugar"]); self.assertEqual(d["stats"]["blocked"], 1)
        self.assertEqual(self.get("/api/attackers?q=Chile")[1]["items"], [])

    def test_expediente_con_explicacion(self):
        st, d = self.get("/api/attacker?ip=203.0.113.9")
        self.assertEqual(st, 200); self.assertEqual(d["dossier"]["by_kind"], {"ssh_clave": 12}); self.assertIn("Adivinar contraseñas", json.dumps(d["explicacion"], ensure_ascii=False))
        self.assertTrue(any("<img" in (u["user"] or "") for u in d["dossier"]["users"]))        # llega como dato; el panel lo muestra como texto
        self.assertEqual(self.get("/api/attacker?ip=198.51.100.1")[0], 404); self.assertEqual(self.get("/api/attacker?ip=no-es-ip")[0], 400)

    def test_paquetes_y_glosario(self):
        st, d = self.get("/api/packets")
        self.assertEqual(d["recientes"][0]["clave"], "toc_toc"); self.assertIn("nino", d["recientes"][0]["info"]); self.assertFalse(d["captura_viva"])
        g = self.get("/api/glossary")[1]
        self.assertIn("toc_toc", g["paquetes"]); self.assertIn("ssh_clave", g["tipos"]); self.assertGreaterEqual(len(g["glosario"]), 10)

    def test_exige_la_llave(self):
        for p in ("/api/attackers", "/api/attacker?ip=203.0.113.9", "/api/packets", "/api/glossary"):
            self.assertEqual(self.get(p, cookie=False)[0], 403, p)

    def test_accion_bloquear_validada(self):
        self.assertEqual(ui.build_action({"name": "ban", "ip": "203.0.113.9", "horas": 24, "motivo": "bloqueo manual"}), ["bans", "ban", "203.0.113.9", "--horas", "24", "--motivo", "bloqueo manual"])
        for bad in ({"name": "ban", "ip": "x; rm"}, {"name": "ban", "ip": "203.0.113.9", "horas": 99999}):
            with self.assertRaises(ValueError):
                ui.build_action(bad)
        self.assertNotIn(";", ui.build_action({"name": "ban", "ip": "203.0.113.9", "motivo": "a; reboot $(x)"})[-1])      # el motivo se limpia

    def test_comandos_de_terminal(self):
        def run(*a):
            o = io.StringIO()
            with redirect_stdout(o):
                rc = cli.main(list(a))
            return rc, o.getvalue()
        rc, out = run("attackers"); self.assertEqual(rc, 0); self.assertIn("203.0.113.9", out); self.assertIn("Moscú", out)
        rc, out = run("attacker", "203.0.113.9"); self.assertIn("¿De dónde viene?", out); self.assertIn("Qué es:", out); self.assertIn("Para qué sirve:", out)
        rc, out = run("attacker", "203.0.113.9", "--tecnico"); self.assertNotIn("Qué es:", out)
        rc, out = run("packets"); self.assertIn("¿QUÉ ES UN PAQUETE?", out); self.assertIn("Toc-toc", out); self.assertIn("203.0.113.9", out)
        self.assertEqual(run("attacker", "198.51.100.1")[0], 1)


if __name__ == "__main__":
    unittest.main()
