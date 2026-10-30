"""Señuelos: puertos falsos (SSH, Telnet, RDP, VNC y 60009) que no ofrecen ningún servicio real. Quien se conecta queda registrado.

Corre como un usuario sin privilegios y solo escribe su registro (JSONL). El bloqueo lo decide y aplica el monitor principal."""
from __future__ import annotations

import asyncio
import collections
import json
import os
import time

from . import core

BANNERS = {2222: b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10\r\n", 2323: b"\r\nlogin: ", 3390: b"", 5900: b"RFB 003.008\n", 60009: b"220 ready\r\n"}


def log_path() -> str:
    return os.path.join(core.log_dir(), "decoy", "honeypot.jsonl")


def record(ip: str, port: int, data: bytes, path: str | None = None) -> dict:
    rec = {"ts": core.iso(), "epoch": core.now(), "ip": ip, "port": port, "bytes": len(data), "preview": data[:80].decode("latin-1").encode("ascii", "replace").decode()}
    try:
        with open(path or log_path(), "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except OSError:
        pass
    return rec


class Honeypot:
    def __init__(self, cfg, path: str | None = None):
        self.ports = [int(p) for p in core.csv(cfg.get("honeypot", "ports")) if p.isdigit()]
        self.bind = cfg.get("honeypot", "bind", fallback="0.0.0.0")
        self.max_conn = cfg.getint("honeypot", "max_conn_per_ip", fallback=20)
        self.timeout = cfg.getint("honeypot", "read_timeout", fallback=5)
        self.path = path
        self.active: collections.Counter = collections.Counter()
        self.servers: list = []

    async def _handle(self, port: int, reader, writer) -> None:
        ip = (writer.get_extra_info("peername") or ("?", 0))[0]
        if self.active[ip] >= self.max_conn:
            writer.close()
            return
        self.active[ip] += 1
        data = b""
        try:
            if BANNERS.get(port):
                writer.write(BANNERS[port])
                await writer.drain()
            data = await asyncio.wait_for(reader.read(256), timeout=self.timeout)
        except (asyncio.TimeoutError, ConnectionError, OSError):
            pass
        finally:
            record(ip, port, data, self.path)
            self.active[ip] -= 1
            try:
                writer.close()
            except OSError:
                pass

    async def start(self) -> list[int]:
        bound = []
        for port in self.ports:
            try:
                srv = await asyncio.start_server(lambda r, w, p=port: self._handle(p, r, w), self.bind, port)
                self.servers.append(srv)
                bound.append(port)
            except OSError:
                continue  # puerto ocupado por un servicio real: se omite
        return bound

    async def run_forever(self) -> None:
        await self.start()
        await asyncio.gather(*(s.serve_forever() for s in self.servers)) if self.servers else await asyncio.sleep(3600)


def follow_log(callback, path: str | None = None, stop=lambda: False, poll: float = 1.0) -> None:
    """Sigue el registro del señuelo y llama a `callback(registro)` por cada conexión nueva."""
    p = path or log_path()
    pos = os.path.getsize(p) if os.path.exists(p) else 0
    while not stop():
        try:
            size = os.path.getsize(p)
            if size < pos:
                pos = 0
            if size > pos:
                with open(p, encoding="utf-8") as f:
                    f.seek(pos)
                    for ln in f:
                        try:
                            callback(json.loads(ln))
                        except ValueError:
                            pass
                    pos = f.tell()
        except OSError:
            pass
        time.sleep(poll)
