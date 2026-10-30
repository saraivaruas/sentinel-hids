import asyncio
import json
import os
import unittest

from helpers import Env
from sentinel import honeypot


class HoneypotTests(unittest.TestCase):
    def test_registra_la_ip_real_y_lo_que_envia(self):
        """El fallo de la versión 1: la IP del atacante salía mal (con un punto final y dos líneas)."""
        e = Env(extra="[honeypot]\nports = 0\nbind = 127.0.0.1")
        try:
            log = os.path.join(e.dir, "hp.jsonl")
            hp = honeypot.Honeypot(e.cfg, log)

            async def go():
                srv = await asyncio.start_server(lambda r, w: hp._handle(2222, r, w), "127.0.0.1", 0)
                port = srv.sockets[0].getsockname()[1]
                r, w = await asyncio.open_connection("127.0.0.1", port)
                banner = await r.read(64)
                w.write(b"SSH-2.0-libssh_0.9\r\n"); await w.drain(); w.close()
                await asyncio.sleep(0.4); srv.close(); await srv.wait_closed()
                return banner

            banner = asyncio.run(go())
            self.assertTrue(banner.startswith(b"SSH-2.0-OpenSSH"))
            rec = json.loads(open(log).read().splitlines()[0])
            self.assertEqual(rec["ip"], "127.0.0.1"); self.assertEqual(rec["port"], 2222); self.assertIn("libssh", rec["preview"])
        finally:
            e.close()

    def test_el_monitor_reacciona_al_toque(self):
        from sentinel import monitor
        e = Env()
        try:
            m = monitor.Monitor(e.cfg)
            m.on_decoy({"ip": "203.0.113.50", "port": 2323, "preview": "root"})
            m.on_decoy({"ip": "192.168.1.30", "port": 2323, "preview": ""})
            k = [(x["kind"], x["sev"]) for x in e.events()]
            self.assertIn(("toque", "high"), k); self.assertIn(("toque_red_local", "low"), k)
        finally:
            e.close()

    def test_seguir_el_registro(self):
        import threading, time
        e = Env()
        try:
            log = os.path.join(e.dir, "hp.jsonl"); got = []; stop = threading.Event()
            t = threading.Thread(target=honeypot.follow_log, args=(got.append, log, stop.is_set, 0.1)); t.start()
            time.sleep(0.3); honeypot.record("203.0.113.1", 60009, b"hola", log); time.sleep(0.6); stop.set(); t.join()
            self.assertEqual([g["ip"] for g in got], ["203.0.113.1"])
        finally:
            e.close()
