"""Inteligencia sobre atacantes: une el almacén de expedientes con la ubicación geográfica y la rellena en segundo plano."""
from __future__ import annotations

import queue
import threading

from . import core, geoip, incidents


class Intel:
    def __init__(self, cfg=None, store: incidents.Store | None = None, geo: geoip.GeoIP | None = None):
        self.cfg = cfg or core.load_config()
        self.store = store or incidents.Store()
        self.geo = geo or geoip.GeoIP(self.cfg)
        self.q: queue.Queue = queue.Queue(maxsize=500)
        self._pending: set[str] = set()
        threading.Thread(target=self._worker, daemon=True).start()

    # ---------- registro
    def attempt(self, ip: str, kind: str, user: str | None = None, port: int | None = None, proto: str | None = None, n: int = 1, detail: str = "") -> None:
        try:
            self.store.record_attempt(ip, kind, user, port, proto, n, detail)
            self.ensure_geo(ip)
        except Exception:   # un fallo del registro nunca debe detener la detección
            pass

    def ensure_geo(self, ip: str) -> None:
        row = self.store.get_ip(ip)
        if (row and row.get("geo_source")) or ip in self._pending:
            return
        self._pending.add(ip)
        try:
            self.q.put_nowait(ip)
        except queue.Full:
            self._pending.discard(ip)

    def _worker(self) -> None:
        while True:
            ip = self.q.get()
            try:
                g = self.geo.lookup(ip)
                if g:
                    self.store.set_geo(ip, g)
            except Exception:
                pass
            finally:
                self._pending.discard(ip)

    def geo_text(self, ip: str) -> str:
        """Ubicación breve para los avisos. Usa solo lo que ya se sabe (no espera a internet)."""
        row = self.store.get_ip(ip) or {}
        g = row if row.get("geo_source") else (self.geo.cached(ip) or self.geo.lookup(ip, network=False) or {})
        return geoip.place_text(g) if g else ""

    # ---------- bloqueos
    def ban_started(self, ip: str, until: float, reason: str, backend: str, manual: bool = False) -> None:
        try:
            self.store.ban_started(ip, until, reason, backend, manual)
        except Exception:
            pass

    def ban_released(self, ip: str, by: str, expired: bool = False) -> None:
        try:
            self.store.ban_released(ip, by, expired)
        except Exception:
            pass
