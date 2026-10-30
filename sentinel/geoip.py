"""Ubicación de una IP: país, ciudad, red y empresa. Sin librerías externas.

Tres fuentes, de la más privada a la menos:
  1. Un archivo MMDB local (por ejemplo DB-IP «City Lite», gratis): no sale nada de tu equipo. Lector escrito en Python puro.
  2. RIPEstat y RDAP (servicios públicos de los registros de internet): se les consulta la IP del atacante para saber a quién pertenece.
  3. DNS inverso (el nombre que la IP declara tener).
Configurable en [intel] geo_mode = auto | offline | online | off. Todo se guarda en caché 30 días."""
from __future__ import annotations

import ipaddress
import json
import mmap
import os
import socket
import struct
import threading
import urllib.request

from . import core

PAISES = {"AR": "Argentina", "AU": "Australia", "AT": "Austria", "BE": "Bélgica", "BR": "Brasil", "BG": "Bulgaria", "CA": "Canadá", "CL": "Chile", "CN": "China", "CO": "Colombia",
          "CZ": "Chequia", "DK": "Dinamarca", "EG": "Egipto", "FI": "Finlandia", "FR": "Francia", "DE": "Alemania", "GR": "Grecia", "HK": "Hong Kong", "HU": "Hungría", "IN": "India",
          "ID": "Indonesia", "IR": "Irán", "IE": "Irlanda", "IL": "Israel", "IT": "Italia", "JP": "Japón", "KR": "Corea del Sur", "LT": "Lituania", "LV": "Letonia", "MX": "México",
          "NL": "Países Bajos", "NO": "Noruega", "PK": "Pakistán", "PE": "Perú", "PH": "Filipinas", "PL": "Polonia", "PT": "Portugal", "RO": "Rumania", "RU": "Rusia", "SG": "Singapur",
          "ZA": "Sudáfrica", "ES": "España", "SE": "Suecia", "CH": "Suiza", "TW": "Taiwán", "TH": "Tailandia", "TR": "Turquía", "UA": "Ucrania", "AE": "Emiratos Árabes", "GB": "Reino Unido",
          "US": "Estados Unidos", "VN": "Vietnam", "VE": "Venezuela", "EC": "Ecuador", "UY": "Uruguay", "PY": "Paraguay", "BO": "Bolivia", "SC": "Seychelles", "NG": "Nigeria"}
DEFAULT_DBS = ("/usr/share/sentinel/dbip-city-lite.mmdb", "/var/lib/sentinel/dbip-city-lite.mmdb")
MARKER = b"\xab\xcd\xefMaxMind.com"


class MMDB:
    """Lector mínimo del formato MaxMind DB (el de GeoLite2 y DB-IP)."""

    def __init__(self, path: str):
        self.f = open(path, "rb")
        self.buf = mmap.mmap(self.f.fileno(), 0, access=mmap.ACCESS_READ)
        i = self.buf.rfind(MARKER)
        if i < 0:
            raise ValueError("no es un archivo MMDB")
        self.meta, _ = self._decode(i + len(MARKER), i + len(MARKER))
        self.nodes = self.meta["node_count"]
        self.rec = self.meta["record_size"]
        self.node_bytes = self.rec * 2 // 8
        self.tree_size = self.node_bytes * self.nodes
        self.data_start = self.tree_size + 16
        self.v6 = self.meta["ip_version"] == 6
        self._v4_start: int | None = None

    def close(self) -> None:
        self.buf.close(); self.f.close()

    def _node(self, n: int, bit: int) -> int:
        o = n * self.node_bytes
        b = self.buf[o:o + self.node_bytes]
        if self.rec == 24:
            return int.from_bytes(b[3 * bit:3 * bit + 3], "big")
        if self.rec == 28:
            return (((b[3] & 0xF0) << 20) | int.from_bytes(b[0:3], "big")) if bit == 0 else (((b[3] & 0x0F) << 24) | int.from_bytes(b[4:7], "big"))
        return int.from_bytes(b[4 * bit:4 * bit + 4], "big")

    def get(self, ip: str):
        a = ipaddress.ip_address(ip)
        bits = int.from_bytes(a.packed, "big")
        n_bits = 32 if a.version == 4 else 128
        node = 0
        if a.version == 4 and self.v6:
            if self._v4_start is None:
                s = 0
                for _ in range(96):
                    if s >= self.nodes:
                        break
                    s = self._node(s, 0)
                self._v4_start = s
            node = self._v4_start
        elif a.version == 6 and not self.v6:
            return None
        for i in range(n_bits):
            if node >= self.nodes:
                break
            node = self._node(node, (bits >> (n_bits - 1 - i)) & 1)
        if node == self.nodes:
            return None
        if node > self.nodes:
            return self._decode(self.tree_size + node - self.nodes, self.data_start)[0]
        return None

    def _decode(self, off: int, base: int):
        b = self.buf
        ctrl = b[off]; off += 1
        t = ctrl >> 5
        if t == 1:                                                    # puntero
            ss, vvv = (ctrl >> 3) & 3, ctrl & 7
            if ss == 3:
                p = int.from_bytes(b[off:off + 4], "big"); off += 4
            else:
                extra = (0, 2048, 526336)[ss]
                nb = ss + 1
                p = ((vvv << (8 * nb)) | int.from_bytes(b[off:off + nb], "big")) + extra; off += nb
            return self._decode(base + p, base)[0], off
        if t == 0:
            t = 7 + b[off]; off += 1
        size = ctrl & 0x1F
        if size == 29:
            size = 29 + b[off]; off += 1
        elif size == 30:
            size = 285 + int.from_bytes(b[off:off + 2], "big"); off += 2
        elif size == 31:
            size = 65821 + int.from_bytes(b[off:off + 3], "big"); off += 3
        if t == 2:
            return bytes(b[off:off + size]).decode("utf-8", "replace"), off + size
        if t == 3:
            return struct.unpack(">d", b[off:off + 8])[0], off + 8
        if t == 15:
            return struct.unpack(">f", b[off:off + 4])[0], off + 4
        if t in (5, 6, 8, 9, 10):
            v = int.from_bytes(b[off:off + size], "big", signed=(t == 8))
            return v, off + size
        if t == 4:
            return bytes(b[off:off + size]), off + size
        if t == 14:
            return bool(size), off
        if t == 7:
            d = {}
            for _ in range(size):
                k, off = self._decode(off, base)
                v, off = self._decode(off, base)
                d[k] = v
            return d, off
        if t == 11:
            arr = []
            for _ in range(size):
                v, off = self._decode(off, base)
                arr.append(v)
            return arr, off
        raise ValueError(f"tipo MMDB no soportado: {t}")


def parse_mmdb_record(r: dict | None) -> dict:
    """Del registro de DB-IP/GeoLite2 a nuestros campos."""
    if not r:
        return {}
    nm = lambda d: ((d or {}).get("names") or {}) if isinstance(d, dict) else {}
    pick = lambda d: nm(d).get("es") or nm(d).get("en")
    code = (r.get("country") or {}).get("iso_code")
    sub = (r.get("subdivisions") or [{}])[0]
    loc = r.get("location") or {}
    return {"country": pick(r.get("country")) or PAISES.get(code or "", code), "country_code": code, "region": pick(sub), "city": pick(r.get("city")),
            "lat": loc.get("latitude"), "lon": loc.get("longitude")}


def parse_ripestat(js: dict) -> dict:
    d = (js or {}).get("data") or {}
    asns = d.get("asns") or []
    out = {"network": d.get("resource") or (d.get("block") or {}).get("resource")}
    if asns:
        out["asn"] = f"AS{asns[0].get('asn')}"
        out["org"] = asns[0].get("holder")
    return {k: v for k, v in out.items() if v}


def parse_rdap(js: dict) -> dict:
    out = {}
    cc = (js or {}).get("country")
    if cc:
        out["country_code"] = cc.upper()
        out["country"] = PAISES.get(cc.upper(), cc.upper())
    if (js or {}).get("name"):
        out["org_rdap"] = js["name"]
    return out


def _get_json(url: str, timeout: float = 5) -> dict:
    req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "sentinel-hids"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read(200_000))


def reverse_dns(ip: str, timeout: float = 2.0) -> str | None:
    res: list = []
    t = threading.Thread(target=lambda: res.append(socket.gethostbyaddr(ip)[0]) if True else None, daemon=True)
    def run():
        try:
            res.append(socket.gethostbyaddr(ip)[0])
        except OSError:
            pass
    t = threading.Thread(target=run, daemon=True); t.start(); t.join(timeout)
    return res[0] if res else None


class GeoIP:
    def __init__(self, cfg=None):
        self.cfg = cfg or core.load_config()
        self.mode = self.cfg.get("intel", "geo_mode", fallback="auto")
        self.allow = core.Allow(self.cfg)
        self.cache_path = os.path.join(core.state_dir(), "geo_cache.json")
        self.cache: dict = core.read_json(self.cache_path, {}) or {}
        self.lock = threading.Lock()
        self.db: MMDB | None = None
        path = self.cfg.get("intel", "geoip_db", fallback="")
        for p in ([path] if path else []) + list(DEFAULT_DBS):
            if p and os.path.exists(p):
                try:
                    self.db = MMDB(p)
                    break
                except (OSError, ValueError):
                    continue

    def cached(self, ip: str) -> dict | None:
        c = self.cache.get(ip)
        return c["geo"] if c and core.now() - c["at"] < 30 * 86400 else None

    def lookup(self, ip: str, network: bool = True) -> dict:
        if self.allow.ip_protected(ip):
            return {"country": "Red local", "country_code": "--", "geo_source": "local"}
        hit = self.cached(ip)
        if hit is not None:
            return hit
        if self.mode == "off":
            return {}
        geo: dict = {"geo_source": []}
        if self.db and self.mode in ("auto", "offline"):
            try:
                geo.update(parse_mmdb_record(self.db.get(ip)))
                geo["geo_source"].append("mmdb")
            except (ValueError, OSError):
                pass
        if network and (self.mode == "online" or (self.mode == "auto" and not self.db)) or (network and self.mode == "auto" and not geo.get("asn")):
            if self.mode != "offline":
                for url, parser, tag in ((f"https://stat.ripe.net/data/prefix-overview/data.json?resource={ip}", parse_ripestat, "ripestat"), (f"https://rdap.org/ip/{ip}", parse_rdap, "rdap")):
                    try:
                        got = parser(_get_json(url))
                        for k, v in got.items():
                            geo.setdefault(k, v)
                        geo["geo_source"].append(tag)
                    except Exception:   # sin red o servicio caído: se sigue con lo que haya
                        continue
        geo.setdefault("org", geo.pop("org_rdap", None)); geo.pop("org_rdap", None)
        geo["rdns"] = reverse_dns(ip) if self.mode != "off" else None
        geo["geo_source"] = "+".join(geo["geo_source"]) or None
        geo = {k: v for k, v in geo.items() if v not in (None, "")}
        if geo.get("geo_source"):
            with self.lock:
                self.cache[ip] = {"geo": geo, "at": core.now()}
                if len(self.cache) > 5000:
                    for k in sorted(self.cache, key=lambda x: self.cache[x]["at"])[:1000]:
                        self.cache.pop(k, None)
                try:
                    core.atomic_write_json(self.cache_path, self.cache, 0o644)
                except OSError:
                    pass
        return geo


def place_text(g: dict | None) -> str:
    """«Moscú, Rusia · AS12345 Empresa» en una línea."""
    g = g or {}
    where = ", ".join(x for x in (g.get("city"), g.get("country")) if x) or "ubicación desconocida"
    net = " · ".join(x for x in (g.get("asn"), g.get("org")) if x)
    return where + (f" · {net}" if net else "")
