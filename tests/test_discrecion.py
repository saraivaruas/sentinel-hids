import os
import unittest
from unittest import mock

import helpers
from sentinel import discrecion, identidad, plataforma

SS = """udp UNCONN 0 0 0.0.0.0:21027 0.0.0.0:* users:(("syncthing",pid=1,fd=1))
udp UNCONN 0 0 224.0.0.251:5353 0.0.0.0:* users:(("chrome",pid=2,fd=1))
udp UNCONN 0 0 127.0.0.53%lo:5355 0.0.0.0:*
tcp LISTEN 0 4096 *:22000 *:* users:(("syncthing",pid=1,fd=2))
tcp LISTEN 0 100 127.0.0.1:3306 0.0.0.0:*
tcp LISTEN 0 100 [::1]:631 [::]:*
tcp LISTEN 0 100 100.71.15.101%tailscale0:52047 0.0.0.0:*
tcp LISTEN 0 100 [fd7a:115c:a1e0::1]%tailscale0:45134 [::]:*
"""
REGLAS4 = "-A ufw-before-input -p icmp --icmp-type echo-request -j ACCEPT\n"
REGLAS6 = "-A ufw6-before-input -p icmpv6 --icmpv6-type echo-request -j DROP\n"


class DiscrecionTests(unittest.TestCase):
    def setUp(self):
        self.env = helpers.Env(); self.addCleanup(self.env.close)
        self.proc = os.path.join(self.env.dir, "proc"); self.ufw = os.path.join(self.env.dir, "ufw")
        os.makedirs(os.path.join(self.proc, "ipv4")); os.makedirs(os.path.join(self.proc, "ipv6", "icmp")); os.makedirs(self.ufw)
        self.escribir(self.proc, "ipv4/icmp_echo_ignore_all", "0\n"); self.escribir(self.proc, "ipv6/icmp/echo_ignore_all", "0\n")
        self.escribir(self.ufw, "ufw.conf", "ENABLED=yes\n"); self.escribir(self.ufw, "before.rules", REGLAS4); self.escribir(self.ufw, "before6.rules", REGLAS6)
        self.estado = {"error": "", "metodo": "auto", "envia_nombre": True}
        for p in (mock.patch.object(plataforma, "ES_MAC", False), mock.patch.object(discrecion, "PROC", self.proc), mock.patch.object(discrecion, "UFW", self.ufw),
                  mock.patch.object(identidad, "estado", lambda cfg, run=None: self.estado)):
            p.start(); self.addCleanup(p.stop)

    def escribir(self, base, rel, texto):
        with open(os.path.join(base, rel), "w", encoding="utf-8") as f:
            f.write(texto)

    def revisar(self, ss=SS):
        calls = []

        def run(c, t=20):
            calls.append(c)
            return 0, ss

        r = discrecion.revisar(self.env.cfg, run)
        self.assertEqual(calls, [["ss", "-H", "-tulnp"]])                 # solo lee
        return {h["id"]: h for h in r["hallazgos"]}

    def test_equipo_que_se_nota(self):
        h = self.revisar()
        self.assertEqual([h[i]["estado"] for i in ("nombre", "anuncios", "puertos", "ping4", "ping6")],
                         ["expuesto", "expuesto", "por comprobar", "expuesto", "discreto"])
        self.assertIn("chrome: mDNS", h["anuncios"]["detalle"]); self.assertIn("syncthing: descubrimiento de Syncthing", h["anuncios"]["detalle"])
        self.assertNotIn("LLMNR", h["anuncios"]["detalle"])                # solo en este equipo
        self.assertIn("syncthing: tcp 22000", h["puertos"]["detalle"])
        for oculto in ("3306", "631", "52047", "45134"):                    # locales o solo por Tailscale
            self.assertNotIn(oculto, h["puertos"]["detalle"])

    def test_equipo_discreto(self):
        self.estado["envia_nombre"] = False
        self.escribir(self.proc, "ipv4/icmp_echo_ignore_all", "1\n")
        h = self.revisar("tcp LISTEN 0 100 127.0.0.1:3306 0.0.0.0:*\n")
        self.assertEqual({x["estado"] for x in h.values()}, {"discreto"})

    def test_sin_cortafuegos_los_puertos_quedan_expuestos(self):
        self.escribir(self.ufw, "ufw.conf", "ENABLED=no\n")
        h = self.revisar()
        self.assertEqual((h["puertos"]["estado"], h["ping4"]["estado"]), ("expuesto", "por comprobar"))

    def test_sin_permiso_para_las_reglas_no_adivina(self):
        real = open

        def sin_permiso(ruta, *a, **k):
            if str(ruta).endswith("before.rules"):
                raise PermissionError
            return real(ruta, *a, **k)

        with mock.patch("builtins.open", sin_permiso):
            r = discrecion.ping(4)
        self.assertEqual(r["estado"], "por comprobar"); self.assertIn("sudo", r["detalle"])

    def test_en_macos_avisa(self):
        with mock.patch.object(plataforma, "ES_MAC", True):
            self.assertIn("macOS", discrecion.revisar(self.env.cfg)["error"])


if __name__ == "__main__":
    unittest.main()
