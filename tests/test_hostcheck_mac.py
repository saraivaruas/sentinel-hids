import unittest
from unittest import mock

from helpers import core
from sentinel import hostcheck, plataforma

IOREG = '''+-o Root  <class IORegistryEntry, id 0x100000100, retain 20>
  +-o AppleT8103USBXHCI@01000000  <class AppleT8103USBXHCI>
    |   "idVendorLabel" = "x"
    +-o USB Keyboard@01100000  <class IOUSBHostDevice, id 0x1000004a1>
    |     {
    |       "idProduct" = 591
    |       "USB Product Name" = "USB Keyboard"
    |       "idVendor" = 1452
    |     }
    +-o Cosa sin nombre@01200000  <class IOUSBHostDevice>
          "idVendor" = 4660
          "idProduct" = 22136
'''
KEXTS = """Index Refs Address            Size       Wired      Name (Version) UUID <Linked Against>
    1  150 0                  0          0          com.apple.kpi.bsd (25.6.0) AAAA <>
  210    0 0xfffffe0007000000 0x4000     0x4000     org.virtualbox.kext.VBoxDrv (7.0.1) BBBB <8 6 5 3 1>
"""
SISTEMA = """2 extension(s)
--- com.apple.system_extension.network_extension
enabled\tactive\tteamID\tbundleID (version)\tname\t[state]
*\t*\tW5364U7YZB\tio.tailscale.ipn.macsys.network-extension (1.70/101)\tTailscale\t[activated enabled]
\t\tABCDE12345\tcom.ejemplo.espia (1.0/1)\tEspia\t[terminated waiting to uninstall on reboot]
"""


class UsbYExtensionesMacTests(unittest.TestCase):
    def test_lee_los_usb_de_ioreg(self):
        self.assertEqual(hostcheck.usb_de_ioreg(IOREG), ["05ac:024f USB Keyboard", "1234:5678"])
        self.assertEqual(hostcheck.usb_de_ioreg(""), [])

    def test_solo_extensiones_que_no_son_de_apple_y_activas(self):
        self.assertEqual(hostcheck.extensiones_de_terceros(KEXTS, SISTEMA), ["kext:org.virtualbox.kext.VBoxDrv", "sysext:io.tailscale.ipn.macsys.network-extension"])

    def test_en_macos_usa_las_herramientas_de_apple(self):
        salida = {"ioreg": IOREG, "kmutil": KEXTS, "systemextensionsctl": SISTEMA}
        with mock.patch.object(plataforma, "ES_MAC", True), mock.patch.object(core, "run", side_effect=lambda c, t=20: (0, salida[c[0]])):
            self.assertEqual(len(hostcheck.usb_devices()), 2); self.assertEqual(len(hostcheck.kernel_modules()), 2)

    def test_si_la_herramienta_falla_no_inventa(self):
        with mock.patch.object(plataforma, "ES_MAC", True), mock.patch.object(core, "run", return_value=(127, "no existe")):
            self.assertEqual((hostcheck.usb_devices(), hostcheck.kernel_modules()), ([], []))


if __name__ == "__main__":
    unittest.main()
