import json
import os
import struct
import time
import unittest
from unittest import mock

from helpers import Env, core
from sentinel import authwatch, explain, geoip, incidents, intel as intel_mod, packets

DB_REAL = "/home/jorge/Documentos/backlinux/proyectos/Tecnologies SpA/Inge Innova/DataHub_Sistema/geo/dbip-city-lite.mmdb"


def frame(src="203.0.113.9", dst="10.0.0.5", proto=6, flags=0x02, sport=40000, dport=22, ipv6=False, icmp_type=8):
    """Trama Ethernet + IPv4 + TCP/UDP/ICMP armada a mano."""
    eth = b"\xaa" * 6 + b"\xbb" * 6 + b"\x08\x00"
    if proto == 6:
        l4 = struct.pack(">HHIIBBHHH", sport, dport, 0, 0, 5 << 4, flags, 1000, 0, 0)
    elif proto == 17:
        l4 = struct.pack(">HHHH", sport, dport, 8, 0)
    else:
        l4 = struct.pack(">BBHI", icmp_type, 0, 0, 0)
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(l4), 0, 0, 64, proto, 0, bytes(map(int, src.split("."))), bytes(map(int, dst.split("."))))
    return eth + ip + l4


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.e = Env(); self.s = incidents.Store()

    def tearDown(self):
        self.s.close(); self.e.close()

    def test_expediente_completo(self):
        t = time.time()
        for i in range(5):
            self.s.record_attempt("203.0.113.9", "ssh_clave", user=["root", "admin"][i % 2], port=22, proto="tcp", ts=t - 100 + i)
        self.s.record_attempt("203.0.113.9", "escaneo_puertos", port=3306, proto="tcp", n=1)
        self.s.set_geo("203.0.113.9", {"country": "Rusia", "country_code": "RU", "city": "Moscú", "asn": "AS1", "org": "Ejemplo"})
        d = self.s.dossier("203.0.113.9")
        self.assertEqual(d["ip"]["attempts"], 6); self.assertEqual(d["by_kind"], {"ssh_clave": 5, "escaneo_puertos": 1})
        self.assertEqual({u["user"] for u in d["users"]}, {"root", "admin"}); self.assertIn(3306, [p["port"] for p in d["ports"]])
        self.assertEqual(d["ip"]["city"], "Moscú"); self.assertEqual(len(d["timeline"]), 6)

    def test_ciclo_de_bloqueo(self):
        self.s.record_attempt("203.0.113.9", "ssh_clave")
        self.s.ban_started("203.0.113.9", time.time() + 3600, "fuerza bruta", "crowdsec")
        self.assertEqual(self.s.get_ip("203.0.113.9")["status"], "bloqueada")
        self.s.ban_released("203.0.113.9", "usuario")
        b = self.s.dossier("203.0.113.9")["bans"][0]
        self.assertEqual((self.s.get_ip("203.0.113.9")["status"], b["released_by"]), ("liberada", "usuario")); self.assertIsNotNone(b["released_at"])
        self.s.ban_started("203.0.113.9", time.time() - 1, "otra vez", "ufw", manual=True); self.s.ban_released("203.0.113.9", "caducó", expired=True)
        self.assertEqual(self.s.get_ip("203.0.113.9")["status"], "observada")

    def test_paquetes_se_acumulan(self):
        t = time.time()
        self.s.touch_ip("203.0.113.9")
        self.s.add_packets({("203.0.113.9", "tcp", 22, "SYN"): (t, t, 3, 180)}, [{"ts": t, "ip": "203.0.113.9", "proto": "tcp", "dport": 22, "flags": "SYN", "size": 60, "label": "x"}])
        self.s.add_packets({("203.0.113.9", "tcp", 22, "SYN"): (t, t + 5, 2, 120)}, [])
        d = self.s.dossier("203.0.113.9")
        self.assertEqual((d["packet_total"], d["packet_bytes"]), (5, 300)); self.assertEqual(len(self.s.recent_packets()), 1)

    def test_lectura_solo_lectura_y_filtros(self):
        self.s.record_attempt("203.0.113.9", "ssh_clave"); self.s.record_attempt("198.51.100.4", "ssh_clave"); self.s.set_geo("198.51.100.4", {"country": "Chile"})
        ro = incidents.Store(readonly=True)
        try:
            self.assertEqual(len(ro.list_ips()), 2); self.assertEqual([r["ip"] for r in ro.list_ips(q="Chile")], ["198.51.100.4"])
            with self.assertRaises(Exception):
                ro.record_attempt("1.2.3.4", "x")
        finally:
            ro.close()

    def test_limpieza_por_antiguedad(self):
        old = time.time() - 200 * 86400
        self.s.record_attempt("203.0.113.9", "ssh_clave", ts=old); self.s.prune(90)
        self.assertIsNone(self.s.get_ip("203.0.113.9"))


class GeoTests(unittest.TestCase):
    def test_parseo_ripestat_y_rdap(self):
        self.assertEqual(geoip.parse_ripestat({"data": {"resource": "8.8.8.0/24", "asns": [{"asn": 15169, "holder": "GOOGLE - Google LLC"}]}}), {"network": "8.8.8.0/24", "asn": "AS15169", "org": "GOOGLE - Google LLC"})
        self.assertEqual(geoip.parse_rdap({"country": "us", "name": "LVLT-GOGL"})["country"], "Estados Unidos")
        self.assertEqual(geoip.parse_ripestat({}), {})

    def test_red_local_no_consulta_nada(self):
        e = Env()
        try:
            with mock.patch.object(geoip, "_get_json", side_effect=AssertionError("no debe salir a internet")):
                self.assertEqual(geoip.GeoIP(e.cfg).lookup("192.168.1.5")["country"], "Red local")
        finally:
            e.close()

    def test_consulta_en_linea_con_cache(self):
        e = Env()
        try:
            e.cfg.set("intel", "geo_mode", "online")
            g = geoip.GeoIP(e.cfg); g.db = None
            with mock.patch.object(geoip, "_get_json", side_effect=lambda u, t=5: {"data": {"resource": "203.0.113.0/24", "asns": [{"asn": 64500, "holder": "Ejemplo"}]}} if "ripe" in u else {"country": "RU", "name": "X"}) as m, mock.patch.object(geoip, "reverse_dns", return_value="srv.ejemplo.ru"):
                r = g.lookup("203.0.113.9"); calls = m.call_count
                self.assertEqual((r["asn"], r["country"], r["rdns"]), ("AS64500", "Rusia", "srv.ejemplo.ru"))
                g.lookup("203.0.113.9"); self.assertEqual(m.call_count, calls)       # la segunda vez sale de la caché
        finally:
            e.close()

    def test_sin_internet_no_falla(self):
        e = Env()
        try:
            e.cfg.set("intel", "geo_mode", "online"); g = geoip.GeoIP(e.cfg); g.db = None
            with mock.patch.object(geoip, "_get_json", side_effect=OSError("sin red")), mock.patch.object(geoip, "reverse_dns", return_value=None):
                self.assertEqual(g.lookup("203.0.113.9"), {})
        finally:
            e.close()

    @unittest.skipUnless(os.path.exists(DB_REAL), "falta el archivo MMDB de prueba")
    def test_lector_mmdb_con_archivo_real(self):
        db = geoip.MMDB(DB_REAL)
        r = geoip.parse_mmdb_record(db.get("200.14.80.5"))
        self.assertEqual((r["country_code"], r["city"]), ("CL", "Santiago")); self.assertIsNone(db.get("10.1.2.3")); self.assertEqual(geoip.parse_mmdb_record(db.get("1.1.1.1"))["country_code"], "AU")
        self.assertTrue(db.get("2001:4860:4860::8888")); db.close()


class ExplainTests(unittest.TestCase):
    def test_clasificacion_de_paquetes(self):
        c = explain.clasificar_paquete
        self.assertEqual([c("tcp", "SYN"), c("tcp", "NULL"), c("tcp", "FIN"), c("tcp", "FIN+PSH+URG"), c("tcp", "RST"), c("icmp", "ECHO"), c("udp", "")], ["toc_toc", "null", "fin", "xmas", "rst", "ping", "udp"])
        self.assertEqual(c("tcp", "SYN+ACK"), "otro")

    def test_puntaje_coherente(self):
        self.assertEqual(explain.puntaje({"ssh_clave": 2})[1], "bajo")
        self.assertEqual(explain.puntaje({"ssh_clave": 20})[1], "medio")
        self.assertEqual(explain.puntaje({"ssh_clave": 40, "senuelo": 1, "escaneo_puertos": 30})[1], "alto")
        self.assertLessEqual(explain.puntaje({"inundacion_syn": 9, "escaneo_sigiloso": 9, "senuelo": 9}, 999, 999)[0], 100)

    def test_todos_los_textos_existen_y_son_sencillos(self):
        for k, t in {**explain.TIPOS, **explain.PAQUETES}.items():
            for campo in ("nombre", "nino", "peligro"):
                self.assertTrue(t[campo].strip(), (k, campo))
            self.assertIn(t["nivel"], explain.NIVELES)
        self.assertGreaterEqual(len(explain.GLOSARIO), 10)

    def test_informe_de_un_expediente(self):
        e = Env()
        try:
            s = incidents.Store()
            for i in range(30):
                s.record_attempt("203.0.113.9", "ssh_clave", user="root", port=22, proto="tcp")
            s.set_geo("203.0.113.9", {"country": "Rusia", "city": "Moscú", "org": "Ejemplo"}); s.ban_started("203.0.113.9", time.time() + 7200, "fuerza bruta", "ufw")
            r = explain.explicar(s.dossier("203.0.113.9"))
            texto = json.dumps(r, ensure_ascii=False)
            for frag in ("Moscú, Rusia", "30 intentos", "root", "bloqueó", "solo llaves"):
                self.assertIn(frag, texto)
            self.assertIn(r["nivel"], ("medio", "alto"))
        finally:
            e.close()


class PacketTests(unittest.TestCase):
    def test_parseo_de_tramas(self):
        p = packets.parse_frame(frame(flags=0x02))
        self.assertEqual((p["src"], p["dport"], p["flags"], p["proto"]), ("203.0.113.9", 22, "SYN", "tcp"))
        self.assertEqual(packets.parse_frame(frame(flags=0))["flags"], "NULL"); self.assertEqual(packets.parse_frame(frame(flags=0x29))["flags"], "FIN+PSH+URG")
        self.assertEqual(packets.parse_frame(frame(proto=1))["flags"], "ECHO"); self.assertEqual(packets.parse_frame(frame(proto=17, dport=5060))["dport"], 5060)
        self.assertIsNone(packets.parse_frame(b"\x00" * 10)); self.assertIsNone(packets.parse_frame(frame()[:30]))

    def test_tipos_de_enlace(self):
        """Regresión hallada con captura real: la interfaz local (tipo 772) también trae cabecera Ethernet; las TUN/VPN (65534) traen IP pura."""
        f = frame(dport=2222)
        self.assertEqual(packets.parse_frame(f, 772)["dport"], 2222); self.assertEqual(packets.parse_frame(f, 1)["dport"], 2222)
        self.assertEqual(packets.parse_frame(f[14:], 65534)["dport"], 2222)

    def test_solo_interesa_lo_no_solicitado(self):
        i = lambda **k: packets.interesting(packets.parse_frame(frame(**k)))
        self.assertEqual(i(flags=0x02), "toc_toc"); self.assertEqual(i(flags=0), "null"); self.assertEqual(i(flags=0x01), "fin"); self.assertEqual(i(flags=0x29), "xmas"); self.assertEqual(i(proto=1), "ping")
        self.assertIsNone(i(flags=0x10)); self.assertIsNone(i(flags=0x18)); self.assertIsNone(i(flags=0x04))        # ACK, PSH+ACK y RST: tráfico normal
        self.assertIsNone(i(proto=17, sport=53, dport=40000)); self.assertEqual(i(proto=17, sport=40000, dport=5060), "udp")

    def _watcher(self):
        e = Env(); cfg = e.cfg
        it = intel_mod.Intel(cfg); it.geo.mode = "off"
        banner = mock.Mock(); alerter = core.Alerter(cfg, quiet=True)
        w = packets.PacketWatcher(cfg, alerter, e.allow, banner, it); w.local = set()
        return e, w, banner, it

    def test_escaneo_de_puertos_se_detecta_registra_y_bloquea(self):
        e, w, banner, it = self._watcher()
        try:
            t = time.time(); found = []
            for port in range(1, 25):
                found += w.handle(packets.parse_frame(frame(dport=port)), t + port * 0.1)
            self.assertEqual([f["kind"] for f in found], ["escaneo_syn"])               # una sola vez gracias al enfriamiento
            self.assertTrue(banner.ban.called); self.assertEqual(banner.ban.call_args[0][0], "203.0.113.9")
            d = it.store.dossier("203.0.113.9")
            self.assertEqual(list(d["by_kind"]), ["escaneo_syn"]); self.assertGreaterEqual(d["packet_total"], 15)
            self.assertIn("packets/escaneo_syn", [f"{x['source']}/{x['kind']}" for x in e.events()])
        finally:
            e.close()

    def test_escaneo_sigiloso_inundacion_y_ping(self):
        e, w, banner, it = self._watcher()
        try:
            t = time.time()
            k = lambda fr, n, ip: [x["kind"] for i in range(n) for x in w.handle(packets.parse_frame(fr), t + i * 0.01)]
            self.assertEqual(k(frame(src="198.51.100.1", flags=0x29), 4, ""), ["escaneo_sigiloso"])
            self.assertEqual(k(frame(src="198.51.100.2", flags=0x02, dport=80), 310, ""), ["inundacion_syn"])
            self.assertEqual(k(frame(src="198.51.100.3", proto=1), 120, ""), ["ping_masivo"])
        finally:
            e.close()

    def test_la_red_local_y_el_trafico_normal_no_se_cuentan(self):
        e, w, banner, it = self._watcher()
        try:
            t = time.time()
            for port in range(1, 40):
                w.handle(packets.parse_frame(frame(src="192.168.1.50", dport=port)), t)          # red local: protegida
                w.handle(packets.parse_frame(frame(src="203.0.113.7", flags=0x10, dport=port)), t)  # solo ACK: normal
            self.assertFalse(banner.ban.called); self.assertEqual(it.store.list_ips(), [])
            self.assertEqual(w.stats["interesantes"], 0)
        finally:
            e.close()

    def test_un_toc_toc_normal_no_deja_rastro(self):
        e, w, banner, it = self._watcher()
        try:
            w.handle(packets.parse_frame(frame(src="203.0.113.99", dport=443)), time.time())       # un visitante cualquiera
            self.assertEqual(it.store.list_ips(), []); self.assertFalse(banner.ban.called)
        finally:
            e.close()


class IntegrationTests(unittest.TestCase):
    def test_bloqueo_deja_historial_y_ubicacion(self):
        e = Env()
        try:
            e.cfg.set("ban", "backend", "iptables")
            it = intel_mod.Intel(e.cfg); it.geo.mode = "off"
            it.store.set_geo("203.0.113.9", {"country": "Rusia", "city": "Moscú", "geo_source": "test"})
            b = core.Banner(e.cfg, e.alerter, e.allow, it)
            with mock.patch.object(core, "is_root", return_value=True), mock.patch.object(core, "run", return_value=(0, "")):
                self.assertTrue(b.ban("203.0.113.9", "prueba", 3600))
                msg = [x["msg"] for x in e.events() if x["kind"] == "bloqueada"][0]
                self.assertIn("Moscú, Rusia", msg)
                self.assertEqual(it.store.get_ip("203.0.113.9")["status"], "bloqueada")
                b.unban("203.0.113.9", "usuario")
                self.assertEqual(it.store.dossier("203.0.113.9")["bans"][0]["released_by"], "usuario")
                b.ban("203.0.113.9", "otra vez", 3600); b.bans["203.0.113.9"]["until"] = 0; b.expire()
                self.assertEqual(it.store.dossier("203.0.113.9")["bans"][0]["released_by"], "caducó")
        finally:
            e.close()

    def test_fuerza_bruta_registra_cada_intento_con_su_tipo(self):
        e = Env()
        try:
            it = intel_mod.Intel(e.cfg); it.geo.mode = "off"
            a = authwatch.AuthWatch(e.cfg, e.alerter, e.allow, core.Banner(e.cfg, e.alerter, e.allow, it), it)
            for i in range(3):
                a.handle("sshd", f"Failed password for root from 203.0.113.9 port {4000 + i} ssh2", 100 + i)
            a.handle("sshd", "Failed password for invalid user pi from 203.0.113.9 port 4100 ssh2", 104)
            a.handle("sshd", "Failed publickey for ana from 203.0.113.9 port 4200 ssh2", 105)
            d = it.store.dossier("203.0.113.9")
            self.assertEqual(d["by_kind"], {"ssh_clave": 3, "ssh_usuario_invalido": 1, "ssh_llave": 1})
            self.assertEqual({u["user"] for u in d["users"]}, {"root", "pi", "ana"})
            a.handle("sshd", "Failed password for root from 192.168.1.5 port 1 ssh2", 106)
            self.assertIsNone(it.store.get_ip("192.168.1.5"))                      # la red local no genera expediente
        finally:
            e.close()


if __name__ == "__main__":
    unittest.main()
