import http.client
import json
import os
import threading
import unittest

from helpers import Env, core
from sentinel import ui


class UiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.e = Env()
        os.environ["XDG_CONFIG_HOME"] = os.path.join(cls.e.dir, "cfg")
        cls.token = ui.load_token()
        cls.e.alerter.emit("high", "auth", "fuerza_bruta", "<script>alert(1)</script> desde 203.0.113.9", key="x", ip="203.0.113.9")
        cls.srv = ui.Server(0, cls.token, ui.Data(cls.e.cfg))
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown(); cls.srv.server_close(); cls.e.close()

    def req(self, method, path, headers=None, body=None, cookie=True, host=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        h = {"Host": host or f"127.0.0.1:{self.port}"}
        if cookie:
            h["Cookie"] = f"sentinel_t={self.token}"
        h.update(headers or {})
        c.request(method, path, body=body, headers=h)
        r = c.getresponse()
        data = r.read()
        return r.status, dict(r.getheaders()), data

    def test_sin_llave_no_entra(self):
        self.assertEqual(self.req("GET", "/", cookie=False)[0], 403)
        self.assertEqual(self.req("GET", "/api/overview", cookie=False)[0], 403)
        self.assertEqual(self.req("GET", "/api/overview", headers={"Cookie": "sentinel_t=incorrecta"}, cookie=False)[0], 403)

    def test_llave_en_la_url_pone_cookie_y_redirige(self):
        st, h, _ = self.req("GET", f"/?t={self.token}", cookie=False)
        self.assertEqual(st, 302); self.assertIn("HttpOnly", h["Set-Cookie"]); self.assertIn("SameSite=Strict", h["Set-Cookie"])
        self.assertEqual(self.req("GET", "/?t=mala", cookie=False)[0], 403)

    def test_host_falso_es_rechazado(self):
        """Anti DNS-rebinding: una página externa que apunta a 127.0.0.1 trae otro Host."""
        self.assertEqual(self.req("GET", "/api/overview", host="atacante.example:80")[0], 403)
        self.assertEqual(self.req("GET", "/api/overview", host=f"localhost:{self.port}")[0], 200)

    def test_cabeceras_de_seguridad(self):
        st, h, body = self.req("GET", "/")
        self.assertEqual(st, 200); self.assertIn(b"Sentinel", body)
        self.assertIn("default-src 'self'", h["Content-Security-Policy"]); self.assertEqual(h["X-Frame-Options"], "DENY"); self.assertEqual(h["X-Content-Type-Options"], "nosniff")
        self.assertNotIn(b"<script>", body.replace(b'<script src="/static/app.js">', b""))     # sin scripts en línea

    def test_resumen_trae_datos_y_el_texto_hostil_viaja_como_dato(self):
        st, h, body = self.req("GET", "/api/overview")
        d = json.loads(body)
        for k in ("level", "counts24", "hours", "events", "bans", "services", "top_ips"):
            self.assertIn(k, d)
        self.assertEqual(len(d["hours"]), 24)
        self.assertTrue(any("<script>" in e["msg"] for e in d["events"]))       # llega intacto como JSON; el panel lo muestra con textContent
        self.assertEqual(h["Content-Type"], "application/json; charset=utf-8")
        js = self.req("GET", "/static/app.js")[2].decode()
        self.assertNotIn("innerHTML", js)        # el panel nunca arma HTML con datos

    def test_filtro_de_eventos(self):
        _, _, b = self.req("GET", "/api/events?min=critical&hours=24")
        self.assertEqual(json.loads(b), [])
        _, _, b = self.req("GET", "/api/events?q=203.0.113.9")
        self.assertEqual(len(json.loads(b)), 1)

    def test_post_exige_json_y_mismo_origen(self):
        body = json.dumps({"name": "scan"})
        self.assertEqual(self.req("POST", "/api/action", {"Content-Type": "text/plain"}, body)[0], 403)
        self.assertEqual(self.req("POST", "/api/action", {"Content-Type": "application/json", "Origin": "http://evil.example"}, body)[0], 403)
        self.assertEqual(self.req("POST", "/api/action", {"Content-Type": "application/json"}, body, cookie=False)[0], 403)

    def test_acciones_invalidas_se_rechazan(self):
        for b in ({"name": "rm -rf"}, {"name": "unban", "ip": "no-es-ip; reboot"}, {"name": "baseline_accept", "paths": ["/etc; reboot"]}, {"name": "baseline_accept", "paths": ["relativa"]},
                  {"name": "allow", "tipo": "port", "valor": "99999"}, {"name": "allow", "tipo": "proc", "valor": "a b;c"}, {"name": "allow", "tipo": "ip", "valor": "x"}):
            st, _, body = self.req("POST", "/api/action", {"Content-Type": "application/json"}, json.dumps(b))
            r = json.loads(body)
            self.assertFalse(r["ok"], b); self.assertIn("rechazada", r["out"], b)

    def test_traversal_de_rutas(self):
        for p in ("/static/..%2f..%2fetc%2fpasswd", "/static/../core.py", "/static/app.js/../../core.py", "/static/noexiste.js"):
            self.assertEqual(self.req("GET", p)[0], 404, p)

    def test_argumentos_de_acciones_validas(self):
        self.assertEqual(ui.build_action({"name": "unban", "ip": "203.0.113.9"}), ["bans", "unban", "203.0.113.9"])
        self.assertEqual(ui.build_action({"name": "allow", "tipo": "ip", "valor": "203.0.113.0/24"}), ["allow", "ip", "203.0.113.0/24"])
        self.assertEqual(ui.build_action({"name": "scan_deep"}), ["scan", "--deep", "--quiet"])

    def test_la_llave_es_privada(self):
        import stat
        self.assertEqual(stat.S_IMODE(os.stat(ui.token_path()).st_mode), 0o600); self.assertGreaterEqual(len(self.token), 40)


if __name__ == "__main__":
    unittest.main()
