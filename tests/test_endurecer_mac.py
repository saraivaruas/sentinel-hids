"""Endurecimiento en macOS sobre un sistema simulado y una carpeta temporal: nunca toca el equipo real."""
import io
import os
import shutil
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest import mock

from helpers import Env, core
from sentinel import cli, endurecer as en, endurecer_mac as mac, pin, plataforma


class MacSimulado:
    """Recuerda los interruptores del sistema y responde como las herramientas de Apple."""

    def __init__(self):
        self.fw, self.sigilo, self.gk, self.invitado = False, False, False, "1"
        self.updates = {"CriticalUpdateInstall": "0", "AutomaticCheckEnabled": "1"}
        self.filevault, self.llamadas, self.terco = "Off", [], False

    def __call__(self, c, t=30):
        self.llamadas.append(c)
        if c[0] == mac.FIREWALL:
            if c[1] == "--getglobalstate":
                return 0, "Firewall is enabled. (State = 1)" if self.fw else "Firewall is disabled. (State = 0)"
            if c[1] == "--getstealthmode":
                return 0, "Firewall stealth mode is " + ("on" if self.sigilo else "off")
            if not self.terco and c[1] == "--setglobalstate":
                self.fw = c[2] == "on"
            if not self.terco and c[1] == "--setstealthmode":
                self.sigilo = c[2] == "on"
        elif c[0] == "spctl":
            if c[1] == "--status":
                return 0, "assessments enabled" if self.gk else "assessments disabled"
            self.gk = c[1] == "--master-enable"
        elif c[:2] == ["defaults", "read"]:
            if c[2] == mac.INICIO:
                return 0, self.invitado + "\n"
            return 0, "{\n" + "".join(f"    {k} = {v};\n" for k, v in self.updates.items()) + "}"
        elif c[:2] == ["defaults", "write"]:
            valor = "1" if c[-1] == "true" else "0"
            if c[2] == mac.INICIO:
                self.invitado = valor
            else:
                self.updates[c[3]] = valor
        elif c[0] == "fdesetup":
            return 0, f"FileVault is {self.filevault}."
        return 0, ""

    def foto(self):
        return (self.fw, self.sigilo, self.gk, self.invitado, dict(self.updates))


class EndurecerMacTests(unittest.TestCase):
    def setUp(self):
        self.e = Env(); self.addCleanup(self.e.close)
        self.raiz = tempfile.mkdtemp(); self.addCleanup(shutil.rmtree, self.raiz, True)
        for ruta in ("etc/ssh/sshd_config", "usr/sbin/sshd"):
            os.makedirs(os.path.dirname(os.path.join(self.raiz, ruta)), exist_ok=True)
            open(os.path.join(self.raiz, ruta), "w").close()
        self.sis = MacSimulado()
        p = mock.patch.object(plataforma, "ES_MAC", True); p.start(); self.addCleanup(p.stop)
        self.ctx = en.Contexto(self.raiz, self.sis)

    def estados(self, perfil="estricto"):
        return {i.medida.id: i.codigo for i in en.plan(perfil, ctx=self.ctx)}

    def test_el_plan_de_mac_no_trae_medidas_de_linux_y_no_cambia_nada(self):
        antes = self.sis.foto()
        s = self.estados()
        self.assertEqual(self.sis.foto(), antes)
        self.assertFalse({"kernel-red", "modulos-raros", "auditoria-basica"} & set(s))
        for i in ("mac-cortafuegos", "mac-gatekeeper", "mac-actualizaciones", "mac-invitado", "mac-sigiloso", "ssh-basico"):
            self.assertEqual(s[i], en.PENDIENTE, i)
        self.assertEqual(s["mac-filevault"], en.BLOQUEADA); self.assertEqual(s["ssh-solo-llaves"], en.BLOQUEADA)       # sin llave no se aplica

    def test_aplicar_y_revertir_deja_todo_como_estaba(self):
        antes = self.sis.foto()
        r = en.aplicar(en.plan("recomendado", ctx=self.ctx), self.ctx)
        self.assertEqual(r["revertidas"], [])
        s = self.estados("recomendado")
        self.assertTrue(all(v == en.APLICADA for k, v in s.items() if k != "mac-filevault"), s)
        conf = os.path.join(self.raiz, "etc/ssh/sshd_config.d/90-sentinel-endurecer.conf")
        self.assertTrue(os.path.exists(conf))
        self.assertEqual(en.revertir(ctx=self.ctx)["error"], "")
        self.assertEqual(self.sis.foto(), antes); self.assertFalse(os.path.exists(conf))

    def test_si_algo_no_se_puede_deshacer_se_dice_y_no_se_finge(self):
        en.aplicar(en.plan("basico", ["mac-cortafuegos", "mac-gatekeeper"], ctx=self.ctx), self.ctx)
        original = self.sis.__call__

        def gatekeeper_terco(c, t=30):                       # como macOS reciente: no deja apagarlo por comando
            if c == ["spctl", "--master-disable"]:
                return 0, "Globally disabling the assessment system needs to be confirmed in System Settings."
            return original(c, t)
        r = en.revertir(ctx=en.Contexto(self.raiz, gatekeeper_terco))
        self.assertEqual([x for x, _ in r["sin_deshacer"]], ["mac-gatekeeper"]); self.assertEqual(r["revertidas"], ["mac-cortafuegos"])
        self.assertFalse(self.sis.fw); self.assertTrue(self.sis.gk)
        out = io.StringIO()
        with mock.patch.object(core, "is_root", return_value=True), mock.patch.object(pin, "required", return_value=False), mock.patch.object(en, "revertir", return_value=r), redirect_stdout(out):
            self.assertEqual(cli.main(["endurecer", "revertir"]), 1)
        self.assertIn("sigue aplicada", out.getvalue()); self.assertNotIn("Todo quedó como estaba", out.getvalue())

    def test_si_el_sistema_no_acepta_un_cambio_se_dice_y_se_deshace(self):
        self.sis.terco = True
        r = en.aplicar(en.plan("basico", ["mac-cortafuegos"], ctx=self.ctx), self.ctx)
        self.assertEqual([x[0] for x in r["revertidas"]], ["mac-cortafuegos"]); self.assertEqual(r["aplicadas"], [])

    def test_con_una_llave_de_un_usuario_de_mac_ya_se_puede_exigir_llave(self):
        ak = os.path.join(self.raiz, "Users/ana/.ssh/authorized_keys")
        os.makedirs(os.path.dirname(ak))
        with open(ak, "w") as f:
            f.write("ssh-ed25519 " + "A" * 40)
        self.assertEqual(self.estados()["ssh-solo-llaves"], en.PENDIENTE)

    def test_lo_que_no_se_reconoce_no_se_toca(self):
        s = {i.medida.id: i.codigo for i in en.plan("recomendado", ctx=en.Contexto(self.raiz, lambda c, t=30: (127, "no existe")))}
        for i in ("mac-cortafuegos", "mac-gatekeeper", "mac-sigiloso", "mac-filevault"):
            self.assertEqual(s[i], en.NO_APLICA, i)


if __name__ == "__main__":
    unittest.main()
