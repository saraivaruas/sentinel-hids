import os
import unittest
from unittest import mock

import helpers
from sentinel import cli, core, discrecion, identidad, plataforma

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


class ModoDiscretoTests(unittest.TestCase):
    def setUp(self):
        self.env = helpers.Env(); self.addCleanup(self.env.close)
        d = self.env.dir
        self.proc = os.path.join(d, "proc"); os.makedirs(os.path.join(self.proc, "ipv4")); os.makedirs(os.path.join(self.proc, "ipv6", "icmp"))
        for rel, v in (("ipv4/icmp_echo_ignore_all", "0\n"), ("ipv6/icmp/echo_ignore_all", "1\n")):
            with open(os.path.join(self.proc, rel), "w") as f:
                f.write(v)
        self.ping = os.path.join(d, "sysctl.d", "ping.conf"); self.res = os.path.join(d, "resolved.conf.d", "anuncios.conf")
        self.calls, self.fallan, self.avahi = [], set(), "active"
        self.perfil = {"ipv4.dhcp-send-hostname": "yes", "ipv6.dhcp-send-hostname": "yes"}
        for p in (mock.patch.object(plataforma, "ES_MAC", False), mock.patch.object(discrecion, "PROC", self.proc), mock.patch.object(discrecion, "ARCHIVO_PING", self.ping),
                  mock.patch.object(discrecion, "ARCHIVO_ANUNCIOS", self.res), mock.patch.object(identidad, "estado", lambda cfg, run=None: {"error": "", "conexion": "uuid-1"})):
            p.start(); self.addCleanup(p.stop)

    def run_(self, c, t=20):
        self.calls.append(c)
        if c[0] in self.fallan:
            return 1, f"falló {c[0]}"
        if c[:4] == ["nmcli", "--escape", "no", "-g"]:
            return 0, "".join(self.perfil[k] + "\n" for k in c[4].split(","))
        if c[:3] == ["nmcli", "connection", "modify"]:
            self.perfil.update(zip(c[4::2], c[5::2]))
        if c[:2] == ["systemctl", "is-active"]:
            return 0, (self.avahi if "avahi" in c[2] else "active") + "\n"
        if c[:2] == ["systemctl", "disable"]:
            self.avahi = "inactive"
        if c[:2] == ["systemctl", "enable"]:
            self.avahi = "active"
        return 0, ""

    def aplicar(self, solo=None):
        return discrecion.aplicar(self.env.cfg, self.env.alerter, solo, self.run_)

    def revertir(self, solo=None):
        return discrecion.revertir(self.env.cfg, self.env.alerter, solo, self.run_)

    def test_aplicar_todo(self):
        r = self.aplicar()
        self.assertTrue(r["ok"], r)
        self.assertEqual(discrecion.aplicadas(), ["nombre", "anuncios", "ping"])
        self.assertEqual(set(self.perfil.values()), {"no"}); self.assertEqual(self.avahi, "inactive")
        with open(self.ping) as f:
            self.assertIn("net.ipv4.icmp_echo_ignore_all = 1", f.read())
        with open(self.res) as f:
            self.assertIn("LLMNR=no", f.read())
        self.assertFalse([c for c in self.calls if "up" in c])                                # no corta la red

    def test_revertir_repone_lo_que_habia(self):
        self.aplicar(); self.aplicar()                                                       # repetir no pisa lo guardado
        self.calls.clear()
        self.assertTrue(self.revertir()["ok"])
        self.assertEqual(set(self.perfil.values()), {"yes"}); self.assertEqual(self.avahi, "active")
        self.assertFalse(os.path.exists(self.ping) or os.path.exists(self.res))
        self.assertIn(["sysctl", "-w", "net.ipv4.icmp_echo_ignore_all=0"], self.calls)
        self.assertIn(["sysctl", "-w", "net.ipv6.icmp.echo_ignore_all=1"], self.calls)        # ya estaba en 1: se queda
        self.assertEqual(discrecion.aplicadas(), [])

    def test_solo_una_medida(self):
        self.aplicar(["ping"])
        self.assertEqual(discrecion.aplicadas(), ["ping"]); self.assertEqual(self.avahi, "active"); self.assertFalse(os.path.exists(self.res))

    def test_sin_avahi_no_se_enciende_al_deshacer(self):
        self.avahi = "inactive"
        self.aplicar(["anuncios"]); self.revertir()
        self.assertEqual(self.avahi, "inactive")

    def test_si_una_falla_no_deja_restos_y_las_demas_siguen(self):
        self.fallan = {"sysctl"}
        r = self.aplicar()
        self.assertFalse(r["ok"]); self.assertEqual(discrecion.aplicadas(), ["nombre", "anuncios"]); self.assertFalse(os.path.exists(self.ping))

    def test_medida_desconocida(self):
        with self.assertRaises(ValueError):
            self.aplicar(["todo"])

    def test_restaurar_la_mac_no_vuelve_a_enviar_el_nombre(self):
        self.aplicar(["nombre"])
        core.atomic_write_json(identidad._archivo(), {"originales": {"uuid-1": {"802-3-ethernet.cloned-mac-address": "", "ipv4.dhcp-send-hostname": "yes", "ipv6.dhcp-send-hostname": "yes"}}})
        with mock.patch.object(identidad, "estado", lambda cfg, run=None: {"error": "", "conexion": "uuid-1", "interfaz": "enx", "tipo": "802-3-ethernet"}):
            self.assertTrue(identidad.restaurar(self.env.cfg, self.env.alerter, self.run_)["ok"])
        self.assertEqual((self.perfil["ipv4.dhcp-send-hostname"], self.perfil["ipv6.dhcp-send-hostname"]), ("no", "no"))

    def test_pide_el_pin(self):
        for accion, protegido in (("ver", False), ("aplicar", True), ("revertir", True)):
            self.assertEqual(cli._protected(mock.Mock(accion=accion, fn=cli.cmd_discrecion)), protegido, accion)


if __name__ == "__main__":
    unittest.main()
