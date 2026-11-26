import os
import tempfile
import unittest
from unittest import mock

import helpers
from sentinel import identidad, plataforma

DEV, UUID = "enx0001", "1111-2222"
FABRICA = "00:e0:4c:00:00:01"


class Red:
    """Imita a `ip`, `nmcli`, `ping` y `systemctl` sobre una conexión por cable."""

    def __init__(self):
        self.calls = []
        self.mac = "aa:62:a8:00:00:01"
        self.ip = "10.20.37.22/24"
        self.tipo = "802-3-ethernet"
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


if __name__ == "__main__":
    unittest.main()
