"""Captura y análisis de paquetes de red (solo lectura, sin tcpdump ni librerías): detecta escaneos de puertos, escaneos sigilosos, inundaciones y pings masivos.

Solo mira lo «no solicitado» (intentos de conexión, paquetes raros, pings); el tráfico normal de tus conexiones se ignora al instante. No guarda el contenido
de los paquetes, solo quién los mandó, a qué puerta, de qué clase y cuántos. Necesita root (socket AF_PACKET)."""
from __future__ import annotations

import collections
import json
import os
import socket
import struct
import threading
import time

from . import core, explain

FLAGS = ((0x01, "FIN"), (0x02, "SYN"), (0x04, "RST"), (0x08, "PSH"), (0x10, "ACK"), (0x20, "URG"))
ETH_P_ALL = 0x0003


def flag_str(b: int) -> str:
    names = [n for m, n in FLAGS if b & m]
    return "+".join(names) if names else "NULL"


def parse_frame(data: bytes, hatype: int = 1) -> dict | None:
    """Trama -> {src, dst, proto, sport, dport, flags, size, ver}. None si no es IP o está truncada."""
    try:
        off = 0
        if hatype in (1, 772):                                              # Ethernet (772 = interfaz local, también trae cabecera Ethernet)
            et = struct.unpack(">H", data[12:14])[0]
            off = 14
            if et == 0x8100:
                et = struct.unpack(">H", data[16:18])[0]; off = 18
            if et not in (0x0800, 0x86DD):
                return None
        ver = data[off] >> 4
        if len(data) < off + (20 if ver == 4 else 40):
            return None
        if ver == 4:
            ihl = (data[off] & 0x0F) * 4
            total = struct.unpack(">H", data[off + 2:off + 4])[0]
            frag = struct.unpack(">H", data[off + 6:off + 8])[0] & 0x1FFF
            nxt = data[off + 9]
            src, dst = socket.inet_ntop(socket.AF_INET, data[off + 12:off + 16]), socket.inet_ntop(socket.AF_INET, data[off + 16:off + 20])
            l4 = off + ihl; size = total
            if frag:
                return None
        elif ver == 6:
            nxt = data[off + 6]
            src, dst = socket.inet_ntop(socket.AF_INET6, data[off + 8:off + 24]), socket.inet_ntop(socket.AF_INET6, data[off + 24:off + 40])
            l4 = off + 40; size = struct.unpack(">H", data[off + 4:off + 6])[0] + 40
        else:
            return None
        p = {"src": src, "dst": dst, "size": size, "ver": ver, "sport": None, "dport": None, "flags": None}
        if nxt == 6 and len(data) >= l4 + 14:
            p["proto"] = "tcp"; p["sport"], p["dport"] = struct.unpack(">HH", data[l4:l4 + 4]); p["flags"] = flag_str(data[l4 + 13] & 0x3F)
        elif nxt == 17 and len(data) >= l4 + 8:
            p["proto"] = "udp"; p["sport"], p["dport"] = struct.unpack(">HH", data[l4:l4 + 4])
        elif nxt in (1, 58) and len(data) > l4:
            p["proto"] = "icmp"; p["flags"] = {8: "ECHO", 128: "ECHO", 0: "ECHO-REPLY", 129: "ECHO-REPLY"}.get(data[l4], f"TIPO{data[l4]}")
        else:
            return None
        return p
    except (IndexError, struct.error, ValueError, OSError):
        return None


def interesting(p: dict) -> str | None:
    """¿Es un paquete «no solicitado» que vale la pena mirar? Devuelve su nombre sencillo, o None si es tráfico normal."""
    if p["proto"] == "tcp":
        f = set(p["flags"].split("+"))
        if "ACK" in f and "SYN" not in f:
            return None                          # parte de una conversación ya abierta
        if "RST" in f and f != {"RST"}:
            return None
        return None if f == {"RST"} else explain.clasificar_paquete("tcp", p["flags"], p["dport"])
    if p["proto"] == "icmp":
        return "ping" if p["flags"] == "ECHO" else None
    if p["proto"] == "udp":
        return "udp" if (p["sport"] or 0) >= 1024 and (p["dport"] or 0) > 0 else None     # sport bajo = respuesta de un servidor (DNS, QUIC…)
    return None


class Detector:
    """Cuenta, por IP de origen y en ventanas de tiempo, qué paquetes manda y decide si es un escaneo o un ataque."""

    def __init__(self, cfg):
        g = lambda k, d: cfg.getint("packets", k, fallback=d)
        self.scan_ports, self.window = g("syn_scan_ports", 15), g("window", 60)
        self.stealth, self.flood_syn, self.flood_ping, self.udp_ports = g("stealth_count", 3), g("flood_syn", 300), g("flood_ping", 100), g("udp_scan_ports", 20)
        self.cool = g("cooldown", 600)
        self.src: dict[str, collections.deque] = {}
        self.done: dict[tuple, float] = {}

    def feed(self, ip: str, kind: str, p: dict, t: float) -> list[dict]:
        q = self.src.setdefault(ip, collections.deque(maxlen=2000))
        q.append((t, kind, p.get("dport"), p["proto"], p.get("flags") or "", p["size"]))
        while q and t - q[0][0] > self.window:
            q.popleft()
        found = []
        recent = [x for x in q if x[0] > t - 10]
        def fire(k: str, n: int, detail: str):
            if t - self.done.get((ip, k), 0) > self.cool:
                self.done[(ip, k)] = t
                found.append({"kind": k, "n": n, "detail": detail, "packets": list(q)})
        tc = [x for x in q if x[1] == "toc_toc"]
        ports = {x[2] for x in tc}
        if len(ports) >= self.scan_ports:
            fire("escaneo_syn", len(ports), f"{len(tc)} intentos de conexión a {len(ports)} puertos distintos en {self.window}s")
        st = [x for x in q if x[1] in ("null", "fin", "xmas")]
        if len(st) >= self.stealth:
            fire("escaneo_sigiloso", len(st), f"{len(st)} paquetes sigilosos ({', '.join(sorted({x[1] for x in st}))}) hacia {len({x[2] for x in st})} puertos")
        if sum(1 for x in recent if x[1] == "toc_toc") >= self.flood_syn:
            fire("inundacion_syn", sum(1 for x in recent if x[1] == "toc_toc"), f"más de {self.flood_syn} intentos de conexión en 10 segundos")
        if sum(1 for x in recent if x[1] == "ping") >= self.flood_ping:
            fire("ping_masivo", sum(1 for x in recent if x[1] == "ping"), f"más de {self.flood_ping} pings en 10 segundos")
        udp = {x[2] for x in q if x[1] == "udp"}
        if len(udp) >= self.udp_ports:
            fire("escaneo_udp", len(udp), f"mensajes UDP a {len(udp)} puertos distintos en {self.window}s")
        if len(self.src) > 20000:                     # memoria acotada
            for k in sorted(self.src, key=lambda x: self.src[x][-1][0] if self.src[x] else 0)[:5000]:
                self.src.pop(k, None)
        return found


class PacketWatcher:
    def __init__(self, cfg, alerter, allow, banner, intel):
        self.cfg, self.alerter, self.allow, self.banner, self.intel = cfg, alerter, allow, banner, intel
        self.det = Detector(cfg)
        self.known: set[str] = set()
        self.known_at = 0.0
        self.pending: dict = {}
        self.recent: list[dict] = []
        self.stats = {"vistos": 0, "interesantes": 0, "muestreados": 0, "desde": core.iso(), "activo": False}
        self.max_pps = cfg.getint("packets", "max_pps", fallback=30000)
        self._sec, self._cnt = 0, 0
        self.local = self._local_addrs()

    @staticmethod
    def _local_addrs() -> set[str]:
        import re
        rc, out = core.run(["ip", "-o", "addr"], 5)
        return set(re.findall(r"inet6? ([0-9a-fA-F:.]+)/", out)) if rc == 0 else set()

    def refresh_known(self) -> None:
        if core.now() - self.known_at < 30:
            return
        self.known_at = core.now()
        try:
            self.known = {r["ip"] for r in self.intel.store.list_ips(2000)}
        except Exception:
            pass

    def handle(self, p: dict, t: float | None = None) -> list[dict]:
        t = t or core.now()
        self.stats["vistos"] += 1
        ip = p["src"]
        if ip in self.local or self.allow.ip_protected(ip):
            return []
        kind = interesting(p)
        if kind is None:
            return []
        self.stats["interesantes"] += 1
        label = explain.PAQUETES[kind]["nombre"]
        if ip in self.known:                       # a los ya conocidos se les anota todo
            k = (ip, p["proto"], p.get("dport") or 0, p.get("flags") or "")
            a = self.pending.get(k)
            if a:
                a[1], a[2], a[3] = t, a[2] + 1, a[3] + p["size"]
            else:
                self.pending[k] = [t, t, 1, p["size"]]
            self.recent.append({"ts": t, "ip": ip, "proto": p["proto"], "sport": p.get("sport"), "dport": p.get("dport"), "flags": p.get("flags"), "size": p["size"], "label": label})
        found = self.det.feed(ip, kind, p, t)
        for f in found:
            self._report(ip, f, t)
        return found

    def _report(self, ip: str, f: dict, t: float) -> None:
        info = explain.TIPOS[f["kind"]]
        where = self.intel.geo_text(ip)
        self.intel.attempt(ip, f["kind"], n=f["n"], proto="tcp" if f["kind"] != "escaneo_udp" else "udp", detail=f["detail"])
        agg: dict = {}
        for (tt, kind, dport, proto, flags, size) in f["packets"]:
            k = (ip, proto, dport or 0, flags)
            a = agg.setdefault(k, [tt, tt, 0, 0])
            a[1] = tt; a[2] += 1; a[3] += size
        try:
            self.intel.store.add_packets(agg, [])
        except Exception:
            pass
        self.known.add(ip)
        self.alerter.emit("high" if info["nivel"] == "alto" else "medium", "packets", f["kind"], f"{info['nombre']} desde {ip}{f' ({where})' if where else ''}: {f['detail']}", key=f"pkt:{f['kind']}:{ip}:{int(t // 600)}", ip=ip)
        if self.cfg.getboolean("packets", "ban", fallback=True):
            self.banner.ban(ip, f"{info['nombre'].lower()} ({f['detail']})")

    def flush(self) -> None:
        if not self.pending and not self.recent:
            return
        agg, rec, self.pending, self.recent = self.pending, self.recent[-500:], {}, []
        try:
            self.intel.store.add_packets({k: tuple(v) for k, v in agg.items()}, rec)
        except Exception:
            pass
        try:
            core.atomic_write_json(os.path.join(core.state_dir(), "packets_stats.json"), dict(self.stats, ts=core.now()), 0o644)
        except OSError:
            pass

    def run(self, stop=lambda: False) -> None:
        """Bucle de captura. Termina si no hay permiso o la captura no está disponible."""
        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))
        except (AttributeError, PermissionError, OSError) as e:
            self.alerter.emit("low", "packets", "no_disponible", f"Captura de paquetes no disponible ({type(e).__name__}): se usan los registros del cortafuegos", key="pkt:nodisp")
            return
        s.settimeout(1.0)
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 << 20)
        except OSError:
            pass
        iface = self.cfg.get("packets", "interface", fallback="")
        if iface:
            s.bind((iface, 0))
        self.stats["activo"] = True
        last = 0.0
        while not stop():
            try:
                data, addr = s.recvfrom(256)
            except socket.timeout:
                data = None
            except OSError:
                break
            t = time.time()
            if data is not None and addr[2] != 4:                      # 4 = paquete saliente
                sec = int(t)
                if sec != self._sec:
                    self._sec, self._cnt = sec, 0
                self._cnt += 1
                if self._cnt > self.max_pps and self._cnt % 8:           # sobrecarga: se mira 1 de cada 8
                    self.stats["muestreados"] += 1
                else:
                    p = parse_frame(data, addr[3])
                    if p:
                        self.refresh_known()
                        self.handle(p, t)
            if t - last > 5:
                last = t
                self.flush()
        self.stats["activo"] = False
        s.close()
