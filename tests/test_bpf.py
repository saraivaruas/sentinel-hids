import socket
import struct
import unittest
from unittest import mock

from helpers import Env, core
from sentinel import bpf, intel as intel_mod, packets


def tcp_syn(src, dst, dport):
    tcp = struct.pack(">HHIIBBHHH", 40000, dport, 0, 0, 5 << 4, 0x02, 1000, 0, 0)
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 40, 0, 0, 64, 6, 0, socket.inet_aton(src), socket.inet_aton(dst))
    return ip + tcp


def registro(paquete):
    cab = bpf.CABECERA.pack(0, 0, len(paquete), len(paquete), 18)
    r = cab + b"\0" * (18 - len(cab)) + paquete
    return r + b"\0" * (bpf.alinear(len(r)) - len(r))


class BpfTests(unittest.TestCase):
    def test_separa_los_paquetes_de_una_lectura(self):
        bloque = registro(b"uno") + registro(b"segundo paquete") + registro(b"3")
        self.assertEqual(list(bpf.trocear(bloque)), [b"uno", b"segundo paquete", b"3"])

    def test_un_bloque_cortado_no_inventa_paquetes(self):
        self.assertEqual(list(bpf.trocear(registro(b"completo") + registro(b"cortado")[:20])), [b"completo"])
        self.assertEqual(list(bpf.trocear(b"\0" * 40)), [])                 # largo de cabecera 0: sin bucle infinito

    def test_quita_la_cabecera_de_enlace(self):
        ip = tcp_syn("203.0.113.9", "203.0.113.11", 22)
        for dlt, trama in ((bpf.DLT_NULL, struct.pack("=I", 2) + ip), (bpf.DLT_EN10MB, b"\0" * 12 + b"\x08\x00" + ip), (bpf.DLT_RAW, ip)):
            p = packets.parse_frame(*bpf.quitar_enlace(trama, dlt))
            self.assertEqual((p["src"], p["dport"], p["flags"]), ("203.0.113.9", 22, "SYN"), dlt)
        self.assertIsNone(bpf.quitar_enlace(ip, 147))

    def vigilante(self):
        e = Env(); self.addCleanup(e.close)
        it = intel_mod.Intel(e.cfg); it.geo.mode = "off"
        e.cfg.set("packets", "interface", "en0")
        with mock.patch.object(packets.plataforma, "ES_MAC", True), mock.patch.object(core, "run", return_value=(0, "")):
            w = packets.PacketWatcher(e.cfg, core.Alerter(e.cfg, quiet=True), e.allow, mock.Mock(), it)
        return w

    def test_en_macos_detecta_un_escaneo_leido_por_bpf(self):
        w = self.vigilante()
        captura = mock.Mock(); captura.leer.return_value = [(tcp_syn("203.0.113.9", "10.0.0.2", puerto), 65534) for puerto in range(1, 31)]
        vueltas = iter([False, True])
        with mock.patch.object(packets.plataforma, "ES_MAC", True), mock.patch.object(packets.bpf, "Captura", return_value=captura) as abrir:
            w.run(lambda: next(vueltas))
        abrir.assert_called_once_with("en0"); captura.cerrar.assert_called_once()
        self.assertEqual(w.stats["detectados"], 1); w.banner.ban.assert_called_once()
        self.assertIn("escaneo_syn", [x["kind"] for x in core.read_events(0, "info")])

    def test_en_macos_sin_permiso_lo_dice(self):
        w = self.vigilante()
        with mock.patch.object(packets.plataforma, "ES_MAC", True), mock.patch.object(packets.bpf, "Captura", side_effect=PermissionError):
            w.run(lambda: True)
        self.assertEqual((w.stats["activo"], w.stats["motivo"]), (False, "PermissionError"))

    def test_direcciones_propias_e_interfaz_en_macos(self):
        salida = {"ifconfig": "lo0: flags=8049\n\tinet 127.0.0.1 netmask 0xff000000\n\tinet6 fe80::1%lo0 prefixlen 64\nen0: flags=8863\n\tinet 192.168.1.5 netmask 0xffffff00\n",
                  "route": "   route to: default\n  interface: en7\n"}
        with mock.patch.object(packets.plataforma, "ES_MAC", True), mock.patch.object(core, "run", side_effect=lambda c, t=20: (0, salida[c[0]])):
            self.assertEqual(packets.PacketWatcher._local_addrs(), {"127.0.0.1", "fe80::1", "192.168.1.5"})
            self.assertEqual(packets.PacketWatcher.interfaz_mac(), "en7")


if __name__ == "__main__":
    unittest.main()
