"""Expedientes de atacantes: para cada IP guarda de dónde viene, cuántos intentos hizo, de qué tipo, qué paquetes envió y su historial de bloqueos.

Usa SQLite (biblioteca estándar). Lo escribe el monitor (root); el panel lo abre en solo lectura con tu usuario (grupo adm)."""
from __future__ import annotations

import collections
import os
import sqlite3
import threading
import time

from . import core

SCHEMA = """
CREATE TABLE IF NOT EXISTS ips(
  ip TEXT PRIMARY KEY, first_seen REAL, last_seen REAL, attempts INTEGER DEFAULT 0,
  country TEXT, country_code TEXT, region TEXT, city TEXT, lat REAL, lon REAL,
  asn TEXT, org TEXT, rdns TEXT, network TEXT, geo_source TEXT, geo_at REAL, status TEXT DEFAULT 'observada');
CREATE TABLE IF NOT EXISTS attempts(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, ip TEXT, kind TEXT, user TEXT, port INTEGER, proto TEXT, n INTEGER DEFAULT 1, detail TEXT);
CREATE INDEX IF NOT EXISTS ix_att_ip ON attempts(ip, ts);
CREATE TABLE IF NOT EXISTS bans(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT, ts REAL, until REAL, released_at REAL, released_by TEXT, reason TEXT, backend TEXT, manual INTEGER DEFAULT 0);
CREATE INDEX IF NOT EXISTS ix_bans_ip ON bans(ip, ts);
CREATE TABLE IF NOT EXISTS pkt(
  ip TEXT, proto TEXT, dport INTEGER, flags TEXT, first REAL, last REAL, count INTEGER, bytes INTEGER, PRIMARY KEY(ip, proto, dport, flags));
CREATE TABLE IF NOT EXISTS pkt_recent(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, ip TEXT, proto TEXT, sport INTEGER, dport INTEGER, flags TEXT, size INTEGER, label TEXT);
"""
GEO_FIELDS = ("country", "country_code", "region", "city", "lat", "lon", "asn", "org", "rdns", "network", "geo_source")


def db_path() -> str:
    return os.path.join(core.state_dir(), "incidents.db")


class Store:
    def __init__(self, path: str | None = None, readonly: bool = False):
        self.path = path or db_path()
        self.readonly = readonly
        self.lock = threading.RLock()
        if readonly:
            self.db = sqlite3.connect(f"file:{self.path}?mode=ro", uri=True, timeout=5, check_same_thread=False)
        else:
            core.ensure_dir(os.path.dirname(self.path), 0o750)
            new = not os.path.exists(self.path)
            self.db = sqlite3.connect(self.path, timeout=10, check_same_thread=False)
            self.db.executescript(SCHEMA)
            if new:
                os.chmod(self.path, 0o640)
                core.share_with_adm(self.path)
        self.db.row_factory = sqlite3.Row

    def close(self) -> None:
        self.db.close()

    # ---------- escritura
    def _exec(self, sql: str, args=()) -> sqlite3.Cursor:
        with self.lock:
            cur = self.db.execute(sql, args)
            self.db.commit()
            return cur

    def touch_ip(self, ip: str, ts: float | None = None, n: int = 0) -> bool:
        """Registra que se vio una IP. Devuelve True si es la primera vez."""
        ts = ts or core.now()
        with self.lock:
            cur = self.db.execute("UPDATE ips SET last_seen=?, attempts=attempts+? WHERE ip=?", (ts, n, ip))
            new = cur.rowcount == 0
            if new:
                self.db.execute("INSERT INTO ips(ip, first_seen, last_seen, attempts) VALUES(?,?,?,?)", (ip, ts, ts, n))
            self.db.commit()
        return new

    def record_attempt(self, ip: str, kind: str, user: str | None = None, port: int | None = None, proto: str | None = None, n: int = 1, detail: str = "", ts: float | None = None) -> bool:
        ts = ts or core.now()
        new = self.touch_ip(ip, ts, n)
        self._exec("INSERT INTO attempts(ts, ip, kind, user, port, proto, n, detail) VALUES(?,?,?,?,?,?,?,?)", (ts, ip, kind, user, port, proto, n, (detail or "")[:300]))
        return new

    def set_geo(self, ip: str, geo: dict) -> None:
        self.touch_ip(ip)
        vals = [geo.get(k) for k in GEO_FIELDS]
        self._exec(f"UPDATE ips SET {', '.join(k + '=?' for k in GEO_FIELDS)}, geo_at=? WHERE ip=?", (*vals, core.now(), ip))

    def ban_started(self, ip: str, until: float, reason: str, backend: str, manual: bool = False) -> None:
        self.touch_ip(ip)
        self._exec("INSERT INTO bans(ip, ts, until, reason, backend, manual) VALUES(?,?,?,?,?,?)", (ip, core.now(), until, reason, backend, 1 if manual else 0))
        self._exec("UPDATE ips SET status='bloqueada' WHERE ip=?", (ip,))

    def ban_released(self, ip: str, by: str, expired: bool = False) -> None:
        self._exec("UPDATE bans SET released_at=?, released_by=? WHERE ip=? AND released_at IS NULL", (core.now(), by, ip))
        self._exec("UPDATE ips SET status=? WHERE ip=?", ("observada" if expired else "liberada", ip))

    def add_packets(self, agg: dict, recent: list[dict]) -> None:
        """agg: {(ip, proto, dport, flags): [first, last, count, bytes]}; recent: lista de paquetes sueltos."""
        with self.lock:
            for (ip, proto, dport, flags), (first, last, count, size) in agg.items():
                self.db.execute("INSERT INTO pkt(ip, proto, dport, flags, first, last, count, bytes) VALUES(?,?,?,?,?,?,?,?) "
                                "ON CONFLICT(ip, proto, dport, flags) DO UPDATE SET last=excluded.last, count=count+excluded.count, bytes=bytes+excluded.bytes", (ip, proto, dport, flags, first, last, count, size))
                self.db.execute("UPDATE ips SET last_seen=MAX(last_seen, ?) WHERE ip=?", (last, ip))
            for p in recent:
                self.db.execute("INSERT INTO pkt_recent(ts, ip, proto, sport, dport, flags, size, label) VALUES(?,?,?,?,?,?,?,?)", (p["ts"], p["ip"], p["proto"], p.get("sport"), p.get("dport"), p.get("flags"), p.get("size"), p.get("label")))
            self.db.execute("DELETE FROM pkt_recent WHERE id <= (SELECT MAX(id) FROM pkt_recent) - 2000")
            self.db.commit()

    def prune(self, days: int = 90) -> None:
        cut = core.now() - days * 86400
        with self.lock:
            self.db.execute("DELETE FROM attempts WHERE ts < ?", (cut,))
            self.db.execute("DELETE FROM pkt WHERE last < ?", (cut,))
            self.db.execute("DELETE FROM ips WHERE last_seen < ? AND status != 'bloqueada' AND ip NOT IN (SELECT ip FROM bans WHERE until > ?)", (cut, core.now()))
            self.db.commit()

    # ---------- lectura
    def get_ip(self, ip: str) -> dict | None:
        r = self.db.execute("SELECT * FROM ips WHERE ip=?", (ip,)).fetchone()
        return dict(r) if r else None

    def list_ips(self, limit: int = 100, q: str = "", status: str = "") -> list[dict]:
        sql = "SELECT i.*, (SELECT COUNT(*) FROM pkt p WHERE p.ip=i.ip) AS pkt_kinds, (SELECT COALESCE(SUM(count),0) FROM pkt p WHERE p.ip=i.ip) AS pkt_total, " \
              "(SELECT until FROM bans b WHERE b.ip=i.ip AND b.released_at IS NULL ORDER BY ts DESC LIMIT 1) AS ban_until FROM ips i WHERE 1=1"
        args: list = []
        if q:
            sql += " AND (ip LIKE ? OR country LIKE ? OR city LIKE ? OR org LIKE ? OR asn LIKE ?)"
            args += [f"%{q}%"] * 5
        if status:
            sql += " AND status=?"
            args.append(status)
        sql += " ORDER BY last_seen DESC LIMIT ?"
        args.append(limit)
        return [dict(r) for r in self.db.execute(sql, args)]

    def kinds_by_ip(self) -> dict:
        out: dict = {}
        for r in self.db.execute("SELECT ip, kind, SUM(n) AS n FROM attempts GROUP BY ip, kind"):
            out.setdefault(r["ip"], {})[r["kind"]] = r["n"]
        return out

    def dossier(self, ip: str) -> dict | None:
        row = self.get_ip(ip)
        if not row:
            return None
        q = lambda sql, *a: [dict(r) for r in self.db.execute(sql, a)]
        by_kind = {r["kind"]: r["n"] for r in q("SELECT kind, SUM(n) AS n FROM attempts WHERE ip=? GROUP BY kind ORDER BY n DESC", ip)}
        users = q("SELECT user, SUM(n) AS n FROM attempts WHERE ip=? AND user IS NOT NULL AND user != '' GROUP BY user ORDER BY n DESC LIMIT 15", ip)
        ports = q("SELECT port, proto, SUM(n) AS n FROM attempts WHERE ip=? AND port IS NOT NULL GROUP BY port, proto ORDER BY n DESC LIMIT 25", ip)
        pk = q("SELECT proto, dport, flags, first, last, count, bytes FROM pkt WHERE ip=? ORDER BY count DESC LIMIT 40", ip)
        tot = self.db.execute("SELECT COALESCE(SUM(count),0) AS c, COALESCE(SUM(bytes),0) AS b, COUNT(DISTINCT dport) AS d FROM pkt WHERE ip=?", (ip,)).fetchone()
        return {"ip": row, "by_kind": by_kind, "users": users, "ports": ports, "packets": pk, "packet_total": tot["c"], "packet_bytes": tot["b"], "packet_ports": tot["d"],
                "timeline": q("SELECT ts, kind, user, port, proto, n, detail FROM attempts WHERE ip=? ORDER BY ts DESC LIMIT 60", ip),
                "bans": q("SELECT ts, until, released_at, released_by, reason, backend, manual FROM bans WHERE ip=? ORDER BY ts DESC LIMIT 20", ip)}

    def recent_packets(self, limit: int = 60, ip: str = "") -> list[dict]:
        if ip:
            return [dict(r) for r in self.db.execute("SELECT * FROM pkt_recent WHERE ip=? ORDER BY id DESC LIMIT ?", (ip, limit))]
        return [dict(r) for r in self.db.execute("SELECT * FROM pkt_recent ORDER BY id DESC LIMIT ?", (limit,))]

    def stats(self) -> dict:
        r = self.db.execute("SELECT COUNT(*) AS ips, COALESCE(SUM(attempts),0) AS attempts, SUM(status='bloqueada') AS blocked FROM ips").fetchone()
        pk = self.db.execute("SELECT COALESCE(SUM(count),0) AS c FROM pkt").fetchone()["c"]
        countries = collections.Counter({x["country"] or "Desconocido": x["n"] for x in self.db.execute("SELECT country, COUNT(*) AS n FROM ips GROUP BY country")})
        return {"ips": r["ips"], "attempts": r["attempts"], "blocked": r["blocked"] or 0, "packets": pk, "countries": countries.most_common(8)}
