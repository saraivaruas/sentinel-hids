"""Prueba de captura REAL (necesita root y CAP_NET_RAW; la forma más simple es un contenedor):
  docker run --rm --user 0 --cap-add NET_RAW -v "$PWD:/src:ro" -v "$PWD/tools/prueba_captura_real.py:/t.py:ro" --entrypoint python3 <imagen-con-python3> /t.py

Prueba de captura REAL (dentro de un contenedor, como root): se mandan paquetes de escaneo con origen falso 203.0.113.9 por la interfaz local
y se comprueba que PacketWatcher los ve, los clasifica, los registra y pide el bloqueo."""
import os, socket, struct, sys, threading, time
sys.path.insert(0, os.environ.get("SENTINEL_SRC", "/src"))
os.environ.update(SENTINEL_STATE="/tmp/st", SENTINEL_LOG="/tmp/lg", SENTINEL_CONF="/nonexistent")
from unittest import mock
from sentinel import core, incidents, intel as intel_mod, packets

cfg = core.load_config(); cfg.set("general", "enable_desktop", "no"); cfg.set("general", "enable_journal", "no")
al = core.Alerter(cfg, quiet=True); allow = core.Allow(cfg)
it = intel_mod.Intel(cfg); it.geo.mode = "off"
banner = mock.Mock()
w = packets.PacketWatcher(cfg, al, allow, banner, it); w.local = set()
stop = threading.Event()
th = threading.Thread(target=w.run, args=(stop.is_set,), daemon=True); th.start(); time.sleep(1)

def cksum(b):
    if len(b) % 2: b += b"\0"
    s = sum(struct.unpack(f">{len(b)//2}H", b)); s = (s >> 16) + (s & 0xFFFF); s += s >> 16
    return ~s & 0xFFFF

def tcp_syn(src, dst, dport, flags=0x02):
    sp = 40000
    tcp = struct.pack(">HHIIBBHHH", sp, dport, 0, 0, 5 << 4, flags, 1000, 0, 0)
    pseudo = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack(">BBH", 0, 6, len(tcp))
    tcp = tcp[:16] + struct.pack(">H", cksum(pseudo + tcp)) + tcp[18:]
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 40, 0, 0, 64, 6, 0, socket.inet_aton(src), socket.inet_aton(dst))
    ip = ip[:10] + struct.pack(">H", cksum(ip)) + ip[12:]
    return ip + tcp

s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW); s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
for port in range(1, 31):
    s.sendto(tcp_syn("203.0.113.9", "127.0.0.1", port), ("127.0.0.1", 0)); time.sleep(0.01)
for i in range(4):
    s.sendto(tcp_syn("198.51.100.7", "127.0.0.1", 80 + i, flags=0x29), ("127.0.0.1", 0)); time.sleep(0.01)     # XMAS
time.sleep(2); w.flush(); stop.set(); time.sleep(1.2)

print("captura activa:", w.stats)
for ip in ("203.0.113.9", "198.51.100.7"):
    d = it.store.dossier(ip)
    print(ip, "-> tipos:", d["by_kind"] if d else None, "| paquetes registrados:", d["packet_total"] if d else 0, "| puertos distintos:", d["packet_ports"] if d else 0)
print("pidió bloquear:", [c[0][0] + " por «" + c[0][1][:60] + "»" for c in banner.ban.call_args_list])
print("eventos:", [(e["kind"], e["sev"]) for e in core.read_events(0, "info")])
