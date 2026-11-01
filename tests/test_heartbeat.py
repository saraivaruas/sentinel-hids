from __future__ import annotations

import os
import tempfile
import unittest
import unittest.mock as m
import urllib.error

from helpers import core  # noqa: F401
from sentinel import heartbeat


class HeartbeatTests(unittest.TestCase):
    def test_direcciones_validas(self):
        for u in ("https://hc-ping.com/1a2b3c4d-1111-2222-3333-444455556666", "https://healthchecks.example.cl:8443/ping/abc", "https://ntfy.sh/mi-tema"):
            self.assertTrue(heartbeat.valid(u), u)
        for u in ("", "http://hc-ping.com/x", "ftp://x.cl/a", "https://127.0.0.1/x", "https://localhost/x", "https://a.cl/x y", "https://a.cl/" + "x" * 400, "javascript:alert(1)", "https://a.cl/x;rm"):
            self.assertFalse(heartbeat.valid(u), u)

    def test_ping_ok_y_fallos(self):
        ok = m.MagicMock(); ok.__enter__.return_value.status = 200
        with m.patch.object(heartbeat.urllib.request, "urlopen", return_value=ok) as up:
            self.assertTrue(heartbeat.ping("https://hc-ping.com/abc"))
            self.assertEqual(up.call_args[0][0].full_url, "https://hc-ping.com/abc")
        with m.patch.object(heartbeat.urllib.request, "urlopen", side_effect=urllib.error.URLError("sin red")):
            self.assertFalse(heartbeat.ping("https://hc-ping.com/abc"))                  # sin red: no rompe nada
        with m.patch.object(heartbeat.urllib.request, "urlopen") as up:
            self.assertFalse(heartbeat.ping("http://inseguro.cl/x")); up.assert_not_called()    # nunca se llama a una dirección no válida

    def test_ajustable_desde_el_panel_con_validacion(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "s.conf"); open(p, "w").write("[general]\nnotify_min = medium\n")
            core.set_setting("alerts", "heartbeat_url", "https://hc-ping.com/abc", p); core.set_setting("general", "email_to", "jorge@inge-innova.com", p)
            core.set_setting("general", "ntfy_url", "https://ntfy.sh/mi-tema-secreto", p)
            cfg = core.load_config(p)
            self.assertEqual(cfg.get("alerts", "heartbeat_url"), "https://hc-ping.com/abc"); self.assertEqual(cfg.get("general", "email_to"), "jorge@inge-innova.com")
            for k, v in (("alerts", "heartbeat_url", ), ):
                pass
            for sec, key, val in (("alerts", "heartbeat_url", "http://x.cl/a"), ("general", "email_to", "no es un correo"), ("general", "ntfy_url", "https://x.cl/a b"), ("general", "email_to", "a@b.cl\\nx")):
                with self.assertRaises(ValueError):
                    core.set_setting(sec, key, val, p)
            core.set_setting("alerts", "heartbeat_url", "", p)                          # vacío = desactivar
            self.assertEqual(core.load_config(p).get("alerts", "heartbeat_url"), "")


if __name__ == "__main__":
    unittest.main()
