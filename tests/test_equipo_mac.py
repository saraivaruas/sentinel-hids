import json
import os
import plistlib
import tempfile
import unittest
from unittest import mock

from helpers import Env, core
from sentinel import equipo, equipo_mac, plataforma


def linea(ruta, msg):
    return json.dumps({"processImagePath": ruta, "senderImagePath": ruta, "eventMessage": msg})


REGISTRO = "\n".join(
    [linea("/usr/libexec/sshd-session", f"Failed password for root from 203.0.113.9 port {i} ssh2") for i in range(11)]
    + [linea("/usr/bin/sudo", "ana : 3 incorrect password attempts ; *** ; USER=root"), linea("/usr/bin/su", "BAD SU ana to root on /dev/ttys001")])
PS = "  10 /usr/bin/nc -l 4444\n  11 -zsh\n  12 /opt/homebrew/bin/ngrok http 3000\n"


class InformeMacTests(unittest.TestCase):
    def setUp(self):
        self.e = Env(); self.addCleanup(self.e.close)
        self.calls = []

        def run(c, t=20):
            self.calls.append(c[0])
            if c[0] == "log":
                return 0, REGISTRO
            if c[0] == "ps":
                return 0, PS
            if c[0] == "lsof" and "-sTCP:ESTABLISHED" in c:
                return 0, "p77\ncCurioso\nf3\nPTCP\nn192.168.1.2:50000->198.51.100.7:4444\n"
            if c[0] == "lsof":
                return 1, ""
            if c[0] in ("systemctl", "ss", "journalctl", "dpkg", "apt-get", "ip", "lastb"):
                return 127, f"[Errno 2] No such file or directory: '{c[0]}'"
            return 0, ""
        for p in (mock.patch.object(core, "run", side_effect=run), mock.patch.object(plataforma, "ES_MAC", True), mock.patch.object(core, "is_root", return_value=True),
                  mock.patch.object(equipo_mac.hostcheck, "proc_scan", return_value=[]), mock.patch.object(equipo.Revision, "tmp_ejecutables", lambda s: None)):
            p.start(); self.addCleanup(p.stop)
        self.inf = equipo.revisar(self.e.cfg)
        self.texto = equipo.a_texto(self.inf)

    def hallazgos(self, area):
        return [h.texto for h in self.inf.unicos() if h.area == area]

    def test_no_usa_herramientas_de_linux_ni_falla(self):
        self.assertFalse(set(self.calls) & {"systemctl", "ss", "journalctl", "dpkg", "apt-get", "ip", "lastb"}, self.calls)
        self.assertNotIn("(falló)", self.texto); self.assertNotIn("/proc", self.texto)

    def test_no_da_por_bueno_lo_que_no_revisa(self):
        for frase in ("coinciden con su hash original", "Actualizaciones de seguridad pendientes: 0", "No hay actualizaciones pendientes"):
            self.assertNotIn(frase, self.texto)
        self.assertIn("No se pudo consultar si hay actualizaciones", self.texto)          # aquí softwareupdate no responde nada reconocible

    def test_lee_los_accesos_fallidos_del_registro_de_macos(self):
        self.assertIn("Fallos remotos (SSH): 11 · fallos locales (sudo y su): 2", self.texto)
        self.assertIn("fuerza bruta", self.hallazgos("autenticación")[0])

    def test_conexiones_procesos_y_tuneles(self):
        self.assertTrue(any("198.51.100.7:4444" in t and "Curioso" in t for t in self.hallazgos("conexiones")))
        self.assertTrue(any("(nc)" in t for t in self.hallazgos("shell reversa")))
        self.assertTrue(any("ngrok" in t for t in self.hallazgos("túneles")))


class SeccionesMacTests(unittest.TestCase):
    def revision(self, respuestas):
        e = Env(); self.addCleanup(e.close)

        def run(c, t=20):
            return respuestas.get(c[0], (0, ""))
        for p in (mock.patch.object(core, "run", side_effect=run), mock.patch.object(plataforma, "ES_MAC", True)):
            p.start(); self.addCleanup(p.stop)
        return equipo_mac.RevisionMac(e.cfg)

    def test_firma_de_los_programas_de_arranque(self):
        d = tempfile.TemporaryDirectory(); self.addCleanup(d.cleanup)

        def archivo(nombre, datos):
            p = os.path.join(d.name, nombre)
            with open(p, "wb") as f:
                f.write(datos)
            return p
        binario, guion = archivo("espia", b"\xcf\xfa\xed\xfe"), archivo("tarea.sh", b"#!/bin/sh\n")
        for nombre, programa in (("com.x.espia", binario), ("com.x.guion", guion), ("com.x.viejo", "/no/existe")):
            with open(os.path.join(d.name, nombre + ".plist"), "wb") as f:
                plistlib.dump({"Label": nombre, "ProgramArguments": [programa]}, f)
        archivo("roto.plist", b"esto no es un plist")
        r = self.revision({"codesign": (1, "code object is not signed at all")})
        with mock.patch.object(equipo_mac, "CARPETAS_ARRANQUE", (d.name,)), mock.patch.object(r, "_casas", return_value=[]):
            r.paquetes()
        textos = {h.nivel: h.texto for h in r.inf.unicos()}
        self.assertIn("espia", textos["MEDIO"]); self.assertNotIn("tarea.sh", textos["MEDIO"]); self.assertIn("tarea.sh", textos["BAJO"])
        self.assertIn("ya no existe", equipo.a_texto(r.inf))

    def test_actualizaciones_pendientes_y_al_dia(self):
        r = self.revision({"softwareupdate": (0, "Software Update found the following new or updated software:\n* Label: macOS Tahoe 26.8-25H1\n\tTitle: macOS Tahoe, Size: 1K\n")})
        r.actualizaciones()
        self.assertIn("macOS Tahoe 26.8", r.inf.unicos()[0].texto)
        r = self.revision({"softwareupdate": (0, "Software Update Tool\nNo new software available.\n")})
        r.actualizaciones()
        self.assertEqual(r.inf.unicos(), []); self.assertIn("No hay actualizaciones pendientes", equipo.a_texto(r.inf))

    def test_sip_desactivado_es_alto(self):
        r = self.revision({"csrutil": (0, "System Integrity Protection status: disabled."), "spctl": (0, "assessments enabled")})
        r.integridad_extra()
        self.assertEqual([(h.nivel, h.area) for h in r.inf.unicos()], [("ALTO", "SIP")])


if __name__ == "__main__":
    unittest.main()
