"""Endurecimiento guiado: plan (solo lectura), aplicar con copia y comprobación, revertir. Todo sobre una raíz temporal: nunca toca el sistema real."""
import argparse
import io
import os
import shutil
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest import mock

from helpers import Env, core
from sentinel import cli, endurecer as en, fim, pin


def setUpModule():
    p = mock.patch.object(en.plataforma, "ES_MAC", False); p.start(); unittest.addModuleCleanup(p.stop)      # las medidas son de Linux, también en la CI de Mac


class EnMacTests(unittest.TestCase):
    def test_en_macos_no_ofrece_ni_aplica_medidas_de_linux(self):
        e = Env(); self.addCleanup(e.close)
        out = io.StringIO()
        with mock.patch.object(en.plataforma, "ES_MAC", True), mock.patch.object(core, "is_root", return_value=True), mock.patch.object(pin, "required", return_value=False), mock.patch.object(en, "aplicar") as ap, redirect_stdout(out):
            self.assertEqual(en.plan("estricto"), [])
            self.assertEqual(cli.main(["endurecer", "plan"]), 0)
            self.assertEqual(cli.main(["endurecer", "aplicar", "--si"]), 1)
        self.assertIn("todavía no está disponible en macOS", out.getvalue()); self.assertNotIn("No hay nada pendiente", out.getvalue()); ap.assert_not_called()


class Base(unittest.TestCase):
    def setUp(self):
        self.e = Env()
        self.raiz = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.raiz, True)
        self.llamadas = []
        self.fallar = {}

    def tearDown(self):
        self.e.close()

    def ejecutar(self, cmd, timeout=30):
        self.llamadas.append(cmd)
        return self.fallar.get(tuple(cmd), (0, ""))

    def ctx(self):
        return en.Contexto(self.raiz, self.ejecutar)

    def escribir(self, ruta, texto="x"):
        p = os.path.join(self.raiz, ruta.lstrip("/"))
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            f.write(texto)
        return p

    def sysctl(self, **valores):
        for k, v in valores.items():
            self.escribir("/proc/sys/" + k.replace("__", ".").replace(".", "/"), v + "\n")

    def leer(self, ruta):
        with open(os.path.join(self.raiz, ruta.lstrip("/"))) as f:
            return f.read()

    def estado(self, medida_id, perfil="estricto"):
        return {i.medida.id: i for i in en.plan(perfil, ctx=self.ctx())}[medida_id]


class PlanTests(Base):
    def test_sysctl_pendiente_aplicada_y_no_aplica(self):
        self.assertEqual(self.estado("kernel-proteccion").codigo, en.NO_APLICA)                    # este «kernel» no tiene esos parámetros
        self.sysctl(kernel__randomize_va_space="0", fs__suid_dumpable="2")
        i = self.estado("kernel-proteccion")
        self.assertEqual(i.codigo, en.PENDIENTE); self.assertIn("randomize_va_space=0", i.detalle)
        self.sysctl(kernel__randomize_va_space="2", fs__suid_dumpable="0")
        self.assertEqual(self.estado("kernel-proteccion").codigo, en.APLICADA)

    def test_valores_tolerados_no_se_marcan_como_pendientes(self):
        self.sysctl(kernel__kptr_restrict="1")                       # 1 también es aceptable: no se pide cambiarlo
        self.assertEqual(self.estado("kernel-proteccion").codigo, en.APLICADA)

    def test_los_perfiles_son_acumulativos(self):
        ids = lambda p: {i.medida.id for i in en.plan(p, ctx=self.ctx())}
        self.assertTrue(ids("basico") < ids("recomendado") < ids("estricto"))
        self.assertIn("kernel-red", ids("basico")); self.assertNotIn("sin-volcados", ids("basico")); self.assertIn("sin-volcados", ids("recomendado")); self.assertNotIn("ssh-solo-llaves", ids("recomendado"))
        with self.assertRaises(ValueError):
            en.plan("paranoico", ctx=self.ctx())

    def test_cada_medida_se_explica_en_lenguaje_claro(self):
        for m in en.MEDIDAS:
            self.assertTrue(m.titulo and m.que_hace and m.por_que, m.id); self.assertIn(m.riesgo, ("ninguno", "bajo", "medio")); self.assertIn(m.perfil, en.PERFILES)
        self.assertEqual(len({m.id for m in en.MEDIDAS}), len(en.MEDIDAS))

    def test_el_plan_no_cambia_nada(self):
        self.sysctl(kernel__randomize_va_space="0")
        antes = sorted(os.listdir(self.raiz)); en.plan("estricto", ctx=self.ctx())
        self.assertEqual(sorted(os.listdir(self.raiz)), antes); self.assertEqual(self.llamadas, [])


class AplicarTests(Base):
    def test_aplica_guarda_manifiesto_marca_el_cambio_como_propio_y_es_idempotente(self):
        self.sysctl(net__ipv4__tcp_syncookies="0", net__ipv4__conf__all__rp_filter="1")
        items = en.plan("basico", ["kernel-red"], ctx=self.ctx())
        r = en.aplicar(items, self.ctx())
        self.assertEqual(r["aplicadas"], ["kernel-red"]); self.assertTrue(os.path.isdir(r["carpeta"]))
        txt = self.leer("/etc/sysctl.d/99-sentinel-red.conf")
        self.assertIn("net.ipv4.tcp_syncookies = 1", txt); self.assertIn("rp_filter = 2", txt)
        self.assertNotIn("net.ipv6", txt)                                      # solo los parámetros que este kernel tiene
        self.assertIn(["sysctl", "--system"], self.llamadas)
        self.assertTrue(os.path.exists(os.path.join(r["carpeta"], "manifiesto.json")))
        marca = core.read_json(os.path.join(core.state_dir(), "self_changes.json"))
        self.assertIn("/etc/sysctl.d/99-sentinel-red.conf", marca["paths"])      # el vigilante de archivos no lo reportará como ataque
        self.sysctl(net__ipv4__tcp_syncookies="1", net__ipv4__conf__all__rp_filter="2")          # el kernel ya tiene los valores
        self.assertEqual(en.aplicar(en.plan("basico", ["kernel-red"], ctx=self.ctx()), self.ctx())["aplicadas"], [])

    def test_revertir_borra_lo_creado_y_restaura_lo_que_existia(self):
        self.sysctl(kernel__randomize_va_space="0")
        previo = self.escribir("/etc/modprobe.d/sentinel-endurecer.conf", "# configuración previa del usuario\n")
        items = en.plan("basico", ["kernel-proteccion", "modulos-raros"], ctx=self.ctx())
        r = en.aplicar(items, self.ctx())
        self.assertEqual(set(r["aplicadas"]), {"kernel-proteccion", "modulos-raros"})
        self.assertIn("install cramfs /bin/true", self.leer("/etc/modprobe.d/sentinel-endurecer.conf"))
        rv = en.revertir(ctx=self.ctx())
        self.assertEqual(set(rv["revertidas"]), {"kernel-proteccion", "modulos-raros"}); self.assertEqual(rv["error"], "")
        self.assertFalse(os.path.exists(os.path.join(self.raiz, "etc/sysctl.d/99-sentinel-kernel.conf")))          # no existía: se borra
        self.assertEqual(self.leer("/etc/modprobe.d/sentinel-endurecer.conf"), "# configuración previa del usuario\n")   # existía: se restaura
        self.assertEqual(en.historial(), [])                                       # la tanda ya no figura como aplicada
        self.assertEqual(en.revertir(ctx=self.ctx())["error"], "No hay nada que revertir.")

    def test_las_medidas_bloqueadas_no_se_aplican_y_se_explican(self):
        items = en.plan("recomendado", ["actualizaciones-auto"], ctx=self.ctx())
        self.assertEqual(items[0].codigo, en.BLOQUEADA); self.assertIn("unattended-upgrades", items[0].detalle)
        r = en.aplicar(items, self.ctx())
        self.assertEqual(r["aplicadas"], []); self.assertEqual(r["omitidas"][0][0], "actualizaciones-auto"); self.assertEqual(r["carpeta"], "")
        self.assertFalse(os.path.exists(os.path.join(self.raiz, "etc/apt")))

    def test_auto_actualizaciones_se_aplican_si_el_paquete_esta(self):
        self.escribir("/usr/bin/unattended-upgrade")
        r = en.aplicar(en.plan("recomendado", ["actualizaciones-auto"], ctx=self.ctx()), self.ctx())
        self.assertEqual(r["aplicadas"], ["actualizaciones-auto"]); self.assertIn('Unattended-Upgrade "1"', self.leer("/etc/apt/apt.conf.d/52sentinel-autoupdates"))


class SshTests(Base):
    def test_sin_servidor_ssh_no_aplica_aunque_quede_un_sshd_config_suelto(self):
        self.escribir("/etc/ssh/sshd_config", "PasswordAuthentication no\n")                  # sobró de un sshd desinstalado
        self.assertEqual(self.estado("ssh-basico").codigo, en.NO_APLICA); self.assertEqual(self.estado("ssh-solo-llaves").codigo, en.NO_APLICA)

    def servidor(self):
        self.escribir("/etc/ssh/sshd_config", "# vacío\n"); self.escribir("/usr/sbin/sshd")

    def test_nunca_desactiva_las_contrasenas_si_nadie_tiene_llave(self):
        self.servidor()
        i = self.estado("ssh-solo-llaves")
        self.assertEqual(i.codigo, en.BLOQUEADA); self.assertIn("te quedarías sin poder entrar", i.detalle)
        self.assertEqual(en.aplicar([i], self.ctx())["aplicadas"], []); self.assertFalse(os.path.exists(os.path.join(self.raiz, "etc/ssh/sshd_config.d")))

    def test_con_una_llave_autorizada_si_se_aplica(self):
        self.servidor(); self.escribir("/home/ana/.ssh/authorized_keys", "ssh-ed25519 " + "A" * 60 + " ana@pc\n")
        i = self.estado("ssh-solo-llaves"); self.assertEqual(i.codigo, en.PENDIENTE)
        r = en.aplicar([i], self.ctx())
        self.assertEqual(r["aplicadas"], ["ssh-solo-llaves"]); self.assertIn("PasswordAuthentication no", self.leer("/etc/ssh/sshd_config.d/91-sentinel-solo-llaves.conf"))
        self.assertIn(["sshd", "-t"], self.llamadas); self.assertIn(["systemctl", "reload", "ssh"], self.llamadas)

    def test_si_sshd_rechaza_la_configuracion_se_deshace_sola(self):
        self.servidor(); self.fallar[("sshd", "-t")] = (1, "Bad configuration option")
        r = en.aplicar(en.plan("basico", ["ssh-basico"], ctx=self.ctx()), self.ctx())
        self.assertEqual(r["aplicadas"], []); self.assertEqual(r["revertidas"][0][0], "ssh-basico"); self.assertIn("Bad configuration option", r["revertidas"][0][1])
        self.assertFalse(os.path.exists(os.path.join(self.raiz, "etc/ssh/sshd_config.d/90-sentinel-endurecer.conf")))
        self.assertGreaterEqual(self.llamadas.count(["systemctl", "reload", "ssh"]), 2)       # recargó y volvió a recargar tras deshacer

    def test_ssh_basico_pendiente_y_luego_aplicada(self):
        self.servidor()
        self.assertEqual(self.estado("ssh-basico").codigo, en.PENDIENTE)
        en.aplicar(en.plan("basico", ["ssh-basico"], ctx=self.ctx()), self.ctx())
        self.escribir("/etc/ssh/sshd_config", "PermitRootLogin no\nX11Forwarding no\nPermitEmptyPasswords no\n")
        self.assertEqual(self.estado("ssh-basico").codigo, en.APLICADA)


class VigilanteTests(unittest.TestCase):
    def test_los_cambios_que_hace_el_endurecimiento_no_se_reportan_como_ataque(self):
        e = Env()
        try:
            p = e.write("etc/sysctl.d/99-sentinel-red.conf", "viejo\n")
            f = fim.Fim(e.cfg, e.alerter, e.allow); f.init()
            e.write("etc/sysctl.d/99-sentinel-red.conf", "contenido nuevo bastante más largo\n")
            core.atomic_write_json(os.path.join(core.state_dir(), "self_changes.json"), {"at": core.now(), "paths": [p]}, 0o640)
            res = f.scan()
            self.assertEqual([r["sev"] for r in res if r["path"] == p], ["info"]); self.assertIn("Sentinel", [r["detail"] for r in res if r["path"] == p][0])
            e.write("etc/sysctl.d/99-sentinel-red.conf", "otro cambio ajeno todavía más largo que los anteriores\n"); os.remove(os.path.join(core.state_dir(), "self_changes.json"))
            self.assertNotEqual([r["sev"] for r in f.scan() if r["path"] == p], ["info"])          # un cambio ajeno sigue siendo un aviso
        finally:
            e.close()


class CliTests(Base):
    """La línea de comandos nunca debe tocar el sistema real en las pruebas: `aplicar` se reemplaza por un doble y `plan` lee la raíz temporal."""

    def setUp(self):
        super().setUp()
        real = en.plan
        p = mock.patch.object(en, "plan", side_effect=lambda perfil, solo=None, ctx=None: real(perfil, solo, self.ctx()))
        p.start(); self.addCleanup(p.stop)

    def correr(self, *args, root=False):
        out = io.StringIO()
        with redirect_stdout(out), mock.patch.object(core, "is_root", return_value=root), mock.patch.object(pin, "required", return_value=False), mock.patch("sys.stdin.isatty", return_value=False):
            rc = cli.main(["endurecer", *args])
        return rc, out.getvalue()

    def test_plan_explica_y_no_cambia_nada(self):
        self.sysctl(kernel__randomize_va_space="0")
        rc, out = self.correr("plan", "--perfil", "basico")
        self.assertEqual(rc, 0); self.assertIn("ENDURECIMIENTO · perfil básico", out); self.assertIn("Qué hace:", out); self.assertIn("Para qué:", out); self.assertIn("Nada se ha cambiado", out)
        self.assertNotIn("aplicada:", out)

    def test_aplicar_sin_administrador_se_niega_y_no_aplica(self):
        self.sysctl(kernel__randomize_va_space="0")
        with mock.patch.object(en, "aplicar") as ap:
            rc, out = self.correr("aplicar", "--si")
        self.assertEqual(rc, 1); ap.assert_not_called()

    def test_aplicar_como_root_muestra_el_resultado_y_como_deshacerlo(self):
        self.sysctl(kernel__randomize_va_space="0")
        res = {"aplicadas": ["kernel-proteccion"], "revertidas": [], "omitidas": [("sin-volcados", "algo")], "carpeta": "/var/lib/sentinel/endurecer/20261114-120000"}
        with mock.patch.object(en, "aplicar", return_value=res) as ap, mock.patch.object(core, "Alerter"):
            rc, out = self.correr("aplicar", "--perfil", "basico", "--si", root=True)
        self.assertEqual(rc, 0); ap.assert_called_once()
        self.assertIn("aplicada: kernel-proteccion", out); self.assertIn("omitida: sin-volcados", out); self.assertIn("sudo sentinel endurecer revertir", out)

    def test_una_medida_que_se_deshizo_sola_hace_fallar_el_comando(self):
        self.sysctl(kernel__randomize_va_space="0")
        res = {"aplicadas": [], "revertidas": [("ssh-basico", "sshd rechaza la configuración")], "omitidas": [], "carpeta": ""}
        with mock.patch.object(en, "aplicar", return_value=res), mock.patch.object(core, "Alerter"):
            rc, out = self.correr("aplicar", "--si", root=True)
        self.assertEqual(rc, 1); self.assertIn("se deshizo sola: ssh-basico", out)

    def test_revertir_como_root(self):
        with mock.patch.object(en, "revertir", return_value={"revertidas": ["kernel-red"], "error": ""}) as rv, mock.patch.object(core, "Alerter"):
            rc, out = self.correr("revertir", root=True)
        self.assertEqual(rc, 0); rv.assert_called_once(); self.assertIn("Todo quedó como estaba", out)

    def test_aplicar_y_revertir_estan_protegidos_por_pin_y_plan_no(self):
        for accion, protegido in (("aplicar", True), ("revertir", True), ("plan", False), ("estado", False)):
            self.assertEqual(cli._protected(argparse.Namespace(fn=cli.cmd_endurecer, accion=accion)), protegido, accion)


if __name__ == "__main__":
    unittest.main()
