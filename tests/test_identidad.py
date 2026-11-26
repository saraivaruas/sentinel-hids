import os
import tempfile
import unittest
from unittest import mock

import helpers
from sentinel import cli, core, identidad, plataforma

DEV, UUID = "enx0001", "1111-2222"
FABRICA = "00:e0:4c:00:00:01"


class Red:
    """Imita a `ip`, `nmcli`, `ping` y `systemctl` sobre una conexión por cable."""

    def __init__(self):
        self.calls = []
        self.mac = "aa:62:a8:00:00:01"
        self.ip = "10.20.37.22/24"
        self.tipo = "802-3-ethernet"
        self.entrega_ip = True                       # ¿el DHCP da dirección a una MAC nueva?
        self.hay_temporizador = True
        self.contesta = True                         # ¿la puerta responde al ping?
        self.perfil = {"802-3-ethernet.cloned-mac-address": "", "ipv4.method": "auto", "ipv4.dhcp-client-id": "",
                       "ipv4.dhcp-send-hostname": "yes", "ipv6.dhcp-send-hostname": "yes"}

    def __call__(self, c, t=20):
        self.calls.append(c)
        if c[:4] == ["ip", "route", "show", "default"]:
            return 0, f"default via 10.20.37.1 dev {DEV} proto dhcp metric 100\n"
        if c[:4] == ["ip", "-o", "link", "show"]:
            extra = f" permaddr {FABRICA}" if self.mac != FABRICA else ""
            return 0, f"2: {DEV}: <UP> state UP\\    link/ether {self.mac} brd ff:ff:ff:ff:ff:ff{extra}\n"
        if c[:2] == ["ip", "-4"]:
            return 0, f"2: {DEV}    inet {self.ip} brd 10.20.37.255 scope global\n" if self.ip else ""
        if c[:3] == ["nmcli", "-g", "GENERAL.CON-UUID"]:
            return 0, UUID + "\n"
        if c[:4] == ["nmcli", "--escape", "no", "-g"]:
            v = {"connection.type": self.tipo, **self.perfil}
            return 0, "".join(v.get(k, "") + "\n" for k in c[4].split(","))
        if c[:3] == ["nmcli", "connection", "modify"]:
            self.perfil.update(zip(c[4::2], c[5::2]))
            return 0, ""
        if c[:2] == ["nmcli", "--wait"]:
            v = self.perfil["802-3-ethernet.cloned-mac-address"]
            self.mac = {"permanent": FABRICA, "": self.mac}.get(v, v)
            nueva = self.mac not in ("aa:62:a8:00:00:01", FABRICA)
            self.ip = "" if nueva and not self.entrega_ip else "10.20.37.77/24" if nueva else "10.20.37.22/24"
            return (4, "Error: no se pudo activar") if not self.ip else (0, "")
        if c[0] == "ping":
            return (0 if self.contesta and self.ip else 1), ""
        if c[:2] in (["systemctl", "enable"], ["systemctl", "disable"]):
            return (0, "") if self.hay_temporizador else (1, "Unit file sentinel-identidad.timer does not exist.")
        if c[0] == "systemctl":
            return 1, "disabled\n"
        raise AssertionError(f"comando inesperado: {c}")


class EstadoTests(unittest.TestCase):
    def setUp(self):
        self.env = helpers.Env(); self.addCleanup(self.env.close)
        self.red = Red()
        for p in (mock.patch.object(plataforma, "ES_MAC", False), mock.patch.object(identidad, "CRON", ())):
            p.start(); self.addCleanup(p.stop)

    def test_estado_de_una_conexion_por_cable(self):
        e = identidad.estado(self.env.cfg, self.red)
        self.assertEqual(e["error"], "")
        self.assertEqual((e["interfaz"], e["ip"], e["puerta"]), (DEV, "10.20.37.22/24", "10.20.37.1"))
        self.assertEqual((e["mac"], e["mac_fabrica"], e["aleatoria"], e["envia_nombre"]), (self.red.mac, FABRICA, True, True))
        self.assertFalse([c for c in self.red.calls if "modify" in c or "up" in c])            # solo lee

    def test_mac_de_fabrica_no_cuenta_como_aleatoria(self):
        self.red.mac = FABRICA
        self.assertFalse(identidad.estado(self.env.cfg, self.red)["aleatoria"])

    def test_una_vpn_no_se_rota(self):
        self.red.tipo = "tun"
        self.assertIn("no es una conexión", identidad.estado(self.env.cfg, self.red)["error"])

    def test_en_macos_avisa(self):
        with mock.patch.object(plataforma, "ES_MAC", True):
            self.assertIn("macOS", identidad.estado(self.env.cfg, self.red)["error"])

    def test_detecta_otros_programas_que_rotan(self):
        d = tempfile.mkdtemp(dir=self.env.dir)
        with open(os.path.join(d, "root"), "w") as f:
            f.write("# 0 * * * * /usr/local/bin/change-ip.sh\n0 10-22/2 * * * /usr/local/bin/change-mac.sh\n30 2 * * * /usr/bin/true\n")
        hallados, completo = identidad.otros_rotadores(lambda c, t=20: (0, "enabled\n"), (os.path.join(d, "*"),))
        self.assertTrue(completo)
        self.assertEqual(len(hallados), 2)                                                    # el servicio y la línea activa, no la comentada
        self.assertIn("change-mac.sh", hallados[1])


class RotarTests(unittest.TestCase):
    def setUp(self):
        self.env = helpers.Env(); self.addCleanup(self.env.close)
        self.red = Red()
        for p in (mock.patch.object(plataforma, "ES_MAC", False), mock.patch.object(identidad, "CRON", ()), mock.patch.object(identidad.time, "sleep")):
            p.start(); self.addCleanup(p.stop)

    def test_mac_aleatoria_es_valida(self):
        vistas = {identidad.mac_aleatoria() for _ in range(200)}
        self.assertEqual(len(vistas), 200)
        self.assertTrue(all(int(m[:2], 16) & 0b11 == 0b10 for m in vistas))                  # local y de un solo equipo

    def test_rota_mac_e_ip_sin_enviar_el_nombre(self):
        antes = self.red.mac
        r = identidad.rotar(self.env.cfg, self.env.alerter, self.red)
        self.assertTrue(r["ok"], r)
        self.assertNotEqual(self.red.mac, antes)
        self.assertEqual(r["ip"], "10.20.37.77/24")
        self.assertEqual((self.red.perfil["ipv4.dhcp-send-hostname"], self.red.perfil["ipv4.dhcp-client-id"]), ("no", "mac"))
        self.assertEqual([e["kind"] for e in self.env.events() if e["source"] == "identidad"], ["rotada"])

    def test_sin_ip_vuelve_a_lo_anterior(self):
        antes, perfil = self.red.mac, dict(self.red.perfil)
        self.red.entrega_ip = False                  # una red que solo admite equipos conocidos
        r = identidad.rotar(self.env.cfg, self.env.alerter, self.red)
        self.assertFalse(r["ok"]); self.assertIn("Se volvió a la anterior", r["mensaje"])
        self.assertEqual((self.red.mac, self.red.perfil, self.red.ip), (antes, perfil, "10.20.37.22/24"))

    def test_si_la_puerta_deja_de_responder_vuelve_atras(self):
        antes = self.red.mac
        original = Red.__call__

        def run(c, t=20):
            if c[0] == "ping":
                return (0 if self.red.mac == antes else 1), ""
            return original(self.red, c, t)

        r = identidad.rotar(self.env.cfg, self.env.alerter, run)
        self.assertFalse(r["ok"]); self.assertIn("puerta", r["mensaje"]); self.assertEqual(self.red.mac, antes)

    def test_una_puerta_que_nunca_contesta_no_impide_rotar(self):
        self.red.contesta = False
        self.assertTrue(identidad.rotar(self.env.cfg, self.env.alerter, self.red)["ok"])

    def test_restaurar_vuelve_al_principio_aunque_se_rote_varias_veces(self):
        perfil = dict(self.red.perfil)
        identidad.rotar(self.env.cfg, self.env.alerter, self.red)
        identidad.rotar(self.env.cfg, self.env.alerter, self.red)
        r = identidad.restaurar(self.env.cfg, self.env.alerter, self.red)
        self.assertTrue(r["ok"], r)
        self.assertEqual((self.red.mac, self.red.perfil), (FABRICA, perfil))
        self.assertFalse(identidad.restaurar(self.env.cfg, self.env.alerter, self.red)["ok"])   # ya no queda nada

    def test_cambiar_la_identidad_pide_el_pin(self):
        for accion, protegido in (("estado", False), ("rotar", True), ("restaurar", True), ("activar", True), ("desactivar", True)):
            a = mock.Mock(accion=accion, fn=cli.cmd_identidad, programado=False)
            self.assertEqual(cli._protected(a), protegido, accion)
        self.assertFalse(cli._protected(mock.Mock(accion="rotar", fn=cli.cmd_identidad, programado=True)))   # el temporizador no puede escribir un PIN


class ProgramadaTests(unittest.TestCase):
    def setUp(self):
        self.env = helpers.Env(); self.addCleanup(self.env.close)
        self.red = Red()
        self.otros = []
        for p in (mock.patch.object(plataforma, "ES_MAC", False), mock.patch.object(identidad.time, "sleep"),
                  mock.patch.object(identidad, "otros_rotadores", lambda run=None: (self.otros, True))):
            p.start(); self.addCleanup(p.stop)

    def cfg(self):
        return core.load_config()

    def ordenes(self, verbo):
        return [c for c in self.red.calls if c[:2] == ["systemctl", verbo]]

    def test_apagada_por_defecto_no_toca_nada(self):
        self.assertFalse(identidad.activa(self.cfg()))
        self.assertIsNone(identidad.programada(self.cfg(), self.env.alerter, self.red))
        self.assertEqual(self.red.calls, [])

    def test_activar_enciende_el_temporizador_y_espera_el_intervalo(self):
        antes = self.red.mac
        r = identidad.activar(self.cfg(), 4, self.env.alerter, self.red)
        self.assertTrue(r["ok"], r)
        self.assertEqual((identidad.activa(self.cfg()), identidad.cada_horas(self.cfg())), (True, 4))
        self.assertEqual(self.ordenes("enable"), [["systemctl", "enable", "--now", "sentinel-identidad.timer"]])
        self.assertIsNone(identidad.programada(self.cfg(), self.env.alerter, self.red))      # activar no corta la red
        self.assertEqual(self.red.mac, antes)
        with mock.patch.object(core, "now", return_value=core.now() + 4 * 3600):
            self.assertTrue(identidad.programada(self.cfg(), self.env.alerter, self.red)["ok"])
        self.assertNotEqual(self.red.mac, antes)

    def test_no_se_activa_si_otro_programa_ya_rota(self):
        self.otros = ["/etc/cron.d/x: change-mac.sh"]
        r = identidad.activar(self.cfg(), 2, self.env.alerter, self.red)
        self.assertFalse(r["ok"]); self.assertIn("change-mac.sh", r["mensaje"])
        self.assertFalse(identidad.activa(self.cfg())); self.assertEqual(self.ordenes("enable"), [])

    def test_sin_temporizador_instalado_queda_apagada(self):
        self.red.hay_temporizador = False
        self.assertFalse(identidad.activar(self.cfg(), 2, self.env.alerter, self.red)["ok"])
        self.assertFalse(identidad.activa(self.cfg()))

    def test_intervalo_fuera_de_rango(self):
        for horas in (0, 169):
            self.assertFalse(identidad.activar(self.cfg(), horas, self.env.alerter, self.red)["ok"], horas)

    def test_desactivar(self):
        identidad.activar(self.cfg(), 2, self.env.alerter, self.red)
        self.assertTrue(identidad.desactivar(self.cfg(), self.env.alerter, self.red)["ok"])
        self.assertFalse(identidad.activa(self.cfg()))
        self.assertEqual(self.ordenes("disable"), [["systemctl", "disable", "--now", "sentinel-identidad.timer"]])

    def test_el_paquete_apaga_el_temporizador_al_desinstalar(self):
        raiz = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        for f in ("uninstall.sh", "packaging/debian/prerm"):
            with open(os.path.join(raiz, f), encoding="utf-8") as h:
                self.assertIn("sentinel-identidad.timer", h.read(), f)


if __name__ == "__main__":
    unittest.main()
