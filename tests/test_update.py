import hashlib
import http.client
import json
import os
import threading
import unittest
import urllib.error
from unittest import mock

from helpers import Env, core
from sentinel import update, ui

REPO = "saraivaruas/sentinel-hids"
BASE = f"https://github.com/{REPO}/releases/download/v2.2.0/"
DEB = b"contenido-del-paquete"
SUMS = (hashlib.sha256(DEB).hexdigest() + "  sentinel_2.2.0_all.deb\n" + "0" * 64 + "  otro.tar.gz\n")


def release(tag="v2.2.0", **k):
    return {"tag_name": tag, "draft": False, "prerelease": False, "body": "Novedades: expedientes", "html_url": f"https://github.com/{REPO}/releases/tag/{tag}", "published_at": "2026-11-01T00:00:00Z",
            "assets": [{"name": "sentinel_2.2.0_all.deb", "browser_download_url": BASE + "sentinel_2.2.0_all.deb"}, {"name": "SHA256SUMS", "browser_download_url": BASE + "SHA256SUMS"},
                       {"name": "malo.deb", "browser_download_url": "https://evil.example/malo.deb"}], **k}


class VersionTests(unittest.TestCase):
    def test_comparacion(self):
        self.assertTrue(update.vtuple("2.10.0") > update.vtuple("2.9.9")); self.assertTrue(update.vtuple("v2.1.0") > update.vtuple("2.0.0")); self.assertEqual(update.vtuple("2.1"), (2, 1, 0))

    def test_parseo_de_la_publicacion(self):
        r = update.parse_release(release(), REPO)
        self.assertEqual(r["version"], "2.2.0"); self.assertNotIn("malo.deb", r["assets"])        # los archivos de otros servidores se descartan
        self.assertIsNone(update.parse_release(release(draft=True), REPO)); self.assertIsNone(update.parse_release(release(prerelease=True), REPO)); self.assertIsNone(update.parse_release({}, REPO))

    def test_huellas(self):
        self.assertEqual(update.expected_hash(SUMS, "sentinel_2.2.0_all.deb"), hashlib.sha256(DEB).hexdigest()); self.assertIsNone(update.expected_hash(SUMS, "no-existe")); self.assertIsNone(update.expected_hash("basura", "x"))

    def test_redireccion_a_servidor_ajeno_se_rechaza(self):
        class R:
            def __enter__(s): return s
            def __exit__(s, *a): return False
            def geturl(s): return "https://evil.example/archivo"
            def read(s, n): return b"x"
        with mock.patch.object(update.urllib.request, "urlopen", return_value=R()):
            with self.assertRaises(ValueError):
                update._get("https://github.com/x")


class CheckTests(unittest.TestCase):
    def setUp(self):
        self.e = Env()

    def tearDown(self):
        self.e.close()

    def test_detecta_version_nueva_y_usa_cache(self):
        with mock.patch.object(update, "_get", return_value=json.dumps(release()).encode()) as g:
            r = update.check(self.e.cfg, current="2.1.0")
            self.assertEqual((r["available"], r["latest"]), (True, "2.2.0")); self.assertIn("expedientes", r["notes"])
            update.check(self.e.cfg, current="2.1.0"); self.assertEqual(g.call_count, 1)                    # la segunda sale de la caché
            self.assertFalse(update.check(self.e.cfg, force=True, current="2.2.0")["available"])           # ya está al día

    def test_desactivado_no_consulta(self):
        self.e.cfg.set("update", "check", "no")
        with mock.patch.object(update, "_get", side_effect=AssertionError("no debe consultar")):
            self.assertFalse(update.check(self.e.cfg, current="2.1.0")["enabled"])

    def test_errores_comprensibles(self):
        with mock.patch.object(update, "_get", side_effect=urllib.error.HTTPError("u", 404, "x", {}, None)):
            self.assertEqual(update.check(self.e.cfg, force=True, current="2.1.0")["error"], "sin_publicaciones")
        with mock.patch.object(update, "_get", side_effect=urllib.error.URLError("sin red")):
            r = update.check(self.e.cfg, force=True, current="2.1.0"); self.assertEqual(r["error"], "sin_conexion"); self.assertFalse(r["available"])
        self.assertIn("conexión", update.error_text("sin_conexion"))


class InstallTests(unittest.TestCase):
    def setUp(self):
        self.e = Env()
        self.info = {"current": "2.1.0", "latest": "2.2.0", "available": True, "enabled": True, "asset_urls": update.parse_release(release(), REPO)["assets"]}

    def tearDown(self):
        self.e.close()

    def run_install(self, deb=DEB, sums=SUMS, root=True, field="Package: sentinel\nVersion: 2.2.0\n", apt_rc=0):
        get = lambda url, t=8, limit=0: sums.encode() if url.endswith("SHA256SUMS") else deb
        apt = mock.Mock(return_value=mock.Mock(returncode=apt_rc, stdout="", stderr="error de apt"))
        import subprocess
        with mock.patch.object(core, "is_root", return_value=root), mock.patch.object(update, "check", return_value=self.info), mock.patch.object(update, "_get", side_effect=get), \
             mock.patch.object(update.shutil, "which", side_effect=lambda n: f"/usr/bin/{n}"), mock.patch.object(core, "run", return_value=(0, field)), mock.patch.object(subprocess, "run", apt):
            return update.install(self.e.cfg, log=lambda *a: None), apt

    def test_instala_cuando_todo_coincide(self):
        (ok, msg), apt = self.run_install()
        self.assertTrue(ok, msg); cmd = apt.call_args[0][0]
        self.assertEqual(cmd[:3], ["apt-get", "install", "-y"]); self.assertIn("Dpkg::Options::=--force-confold", cmd); self.assertTrue(cmd[-1].endswith("sentinel_2.2.0_all.deb"))

    def test_huella_distinta_no_instala_nada(self):
        (ok, msg), apt = self.run_install(deb=b"archivo-alterado")
        self.assertFalse(ok); self.assertIn("huella", msg.lower()); self.assertFalse(apt.called)

    def test_sin_huella_publicada_no_instala(self):
        (ok, _), apt = self.run_install(sums="nada\n"); self.assertFalse(ok); self.assertFalse(apt.called)

    def test_paquete_con_otro_nombre_o_version_no_instala(self):
        for field in ("Package: otro\nVersion: 2.2.0\n", "Package: sentinel\nVersion: 9.9.9\n"):
            (ok, msg), apt = self.run_install(field=field); self.assertFalse(ok); self.assertFalse(apt.called)

    def test_exige_administrador(self):
        (ok, msg), apt = self.run_install(root=False); self.assertFalse(ok); self.assertIn("administrador", msg); self.assertFalse(apt.called)

    def test_si_apt_falla_lo_dice(self):
        (ok, msg), _ = self.run_install(apt_rc=100); self.assertFalse(ok); self.assertIn("falló", msg)

    def test_no_instala_si_ya_esta_al_dia(self):
        self.info["available"] = False
        (ok, msg), apt = self.run_install(); self.assertTrue(ok); self.assertIn("última versión", msg); self.assertFalse(apt.called)

    def test_archivo_de_otro_servidor_en_la_publicacion_se_rechaza(self):
        self.info["asset_urls"]["sentinel_2.2.0_all.deb"] = "https://evil.example/sentinel_2.2.0_all.deb"
        (ok, msg), apt = self.run_install(); self.assertFalse(ok); self.assertFalse(apt.called)


class UiUpdateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.e = Env(); os.environ["XDG_CONFIG_HOME"] = os.path.join(cls.e.dir, "cfg"); cls.token = ui.load_token()
        cls.srv = ui.Server(0, cls.token, ui.Data(cls.e.cfg)); cls.srv.restart_enabled = False; cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown(); cls.srv.server_close(); cls.e.close()

    def call(self, method, path, body=None, cookie=True):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        h = {"Host": f"127.0.0.1:{self.port}", "Content-Type": "application/json"}
        if cookie:
            h["Cookie"] = f"sentinel_t={self.token}"
        c.request(method, path, body=json.dumps(body) if body is not None else None, headers=h)
        r = c.getresponse(); raw = r.read()
        try:
            return r.status, json.loads(raw)
        except ValueError:
            return r.status, raw

    def test_api_de_actualizacion(self):
        core.atomic_write_json(update.cache_path(), {"current": core.VERSION, "latest": "9.0.0", "available": True, "notes": "Novedades", "checked_at": core.now(), "enabled": True}, 0o644)
        st, d = self.call("GET", "/api/update")
        self.assertEqual(st, 200); self.assertEqual((d["available"], d["latest"], d["current"]), (True, "9.0.0", core.VERSION)); self.assertEqual(self.call("GET", "/api/update", cookie=False)[0], 403)
        core.atomic_write_json(update.cache_path(), {"current": core.VERSION, "latest": core.VERSION, "available": True, "checked_at": core.now()}, 0o644)
        self.assertFalse(self.call("GET", "/api/update")[1]["available"])      # igual o menor que la actual: nunca se ofrece

    def test_accion_actualizar(self):
        self.assertEqual(ui.build_action({"name": "update"}), ["update", "--instalar"])
        with mock.patch.object(ui, "run_action", return_value={"ok": True, "out": "listo"}), mock.patch.object(ui.Server, "schedule_restart") as sr:
            self.assertTrue(self.call("POST", "/api/action", {"name": "update"})[1]["ok"]); self.assertTrue(sr.called)
        with mock.patch.object(ui, "run_action", return_value={"ok": False, "out": "falló"}), mock.patch.object(ui.Server, "schedule_restart") as sr:
            self.call("POST", "/api/action", {"name": "update"}); self.assertFalse(sr.called)         # si falla, el panel no se reinicia
        self.assertEqual(self.call("POST", "/api/action", {"name": "update"}, cookie=False)[0], 403)

    def test_el_panel_tiene_el_aviso(self):
        js = self.call("GET", "/static/app.js")[1].decode(); html = self.call("GET", "/")[1].decode()
        for frag in ("loadUpdate", "doUpdate", "/api/update", "sentinel-upd-later"):
            self.assertIn(frag, js)
        for frag in ('id="upd"', 'id="upd-go"', 'id="busy"'):
            self.assertIn(frag, html)


if __name__ == "__main__":
    unittest.main()
