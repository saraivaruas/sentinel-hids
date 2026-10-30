"""Monitor principal (servicio): une todos los detectores. Corre como administrador para poder bloquear y leer archivos protegidos."""
from __future__ import annotations

import fnmatch
import os
import queue
import shutil
import signal
import subprocess
import threading
import time

from . import authwatch, core, fim, honeypot, hostcheck, intel as intel_mod, packets, update


class Monitor:
    def __init__(self, cfg=None):
        self.cfg = cfg or core.load_config()
        self.alerter = core.Alerter(self.cfg)
        self.allow = core.Allow(self.cfg)
        self.intel = intel_mod.Intel(self.cfg)
        self.banner = core.Banner(self.cfg, self.alerter, self.allow, self.intel)
        self.fim = fim.Fim(self.cfg, self.alerter, self.allow)
        self.host = hostcheck.HostCheck(self.cfg, self.alerter, self.allow)
        self.auth = authwatch.AuthWatch(self.cfg, self.alerter, self.allow, self.banner, self.intel)
        self.pkts = packets.PacketWatcher(self.cfg, self.alerter, self.allow, self.banner, self.intel)
        self.stop = threading.Event()
        self.q: queue.Queue = queue.Queue()
        self.threads: list[threading.Thread] = []
        self.procs: list[subprocess.Popen] = []

    # ---------- latido: permite saber si Sentinel sigue vivo
    def heartbeat(self) -> None:
        core.atomic_write_json(os.path.join(core.state_dir(), "heartbeat.json"), {"epoch": core.now(), "pid": os.getpid(), "version": core.VERSION}, 0o644)

    # ---------- señuelos
    def on_decoy(self, rec: dict) -> None:
        ip, port = rec.get("ip", "?"), rec.get("port")
        if self.allow.ip_protected(ip):
            self.alerter.emit("low", "decoy", "toque_red_local", f"Conexión al señuelo {port} desde la red local {ip}", key=f"decoy:{ip}:{port}:{int(core.now() // 3600)}", ip=ip, port=port)
            return
        self.alerter.emit("high", "decoy", "toque", f"{ip} se conectó al puerto señuelo {port} (nadie legítimo lo usa)" + (f"; envió: {rec['preview']!r}" if rec.get("preview") else ""), key=f"decoy:{ip}:{port}:{int(core.now() // 600)}", ip=ip, port=port)
        self.intel.attempt(ip, "senuelo", port=port, proto="tcp", detail=rec.get("preview", ""))
        self.banner.ban(ip, f"tocó el señuelo {port}")

    # ---------- vigilante en vivo
    def _watch(self, args: list[str], keep) -> None:
        cmd = ["inotifywait", "-m", "-q", "-e", "close_write,create,delete,move,attrib", "--format", "%w%f", *args]
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        self.procs.append(p)
        for ln in p.stdout:  # type: ignore[union-attr]
            path = ln.rstrip("\n")
            if keep(path):
                self.q.put(path)

    def live_fim(self) -> bool:
        if not shutil.which("inotifywait"):
            return False
        roots = self.fim.roots()
        dirs = [r for r in roots if os.path.isdir(r) and not os.path.islink(r)]
        files = {r for r in roots if r not in dirs}
        parents = sorted({os.path.dirname(f) for f in files})
        ex = self.fim.excludes

        def ok(path: str) -> bool:
            return not any(fnmatch.fnmatch(path, x) for x in ex) and not self.allow.path_ignored(path) and not path.endswith((".swp", ".swx", "~", ".tmp"))

        if dirs:
            threading.Thread(target=self._watch, args=(["-r", *dirs], ok), daemon=True).start()
        if parents:
            threading.Thread(target=self._watch, args=(parents, lambda p: p in files and ok(p)), daemon=True).start()
        threading.Thread(target=self._consume, daemon=True).start()
        return True

    def _consume(self) -> None:
        while not self.stop.is_set():
            try:
                batch = {self.q.get(timeout=2)}
            except queue.Empty:
                continue
            t0 = time.time()
            while time.time() - t0 < 2.0 and len(batch) < 500:  # junta la ráfaga antes de revisar
                try:
                    batch.add(self.q.get(timeout=0.5))
                except queue.Empty:
                    pass
            try:
                self.fim.scan(paths=sorted(batch))
            except Exception as e:
                self.alerter.emit("low", "monitor", "error", f"Error al revisar cambios: {type(e).__name__}", key="mon:err:fim")

    # ---------- hilos
    def _guard(self, name: str, fn) -> None:
        while not self.stop.is_set():
            try:
                fn()
            except Exception as e:
                self.alerter.emit("low", "monitor", "error", f"El módulo {name} falló ({type(e).__name__}); se reinicia", key=f"mon:err:{name}")
            if not self.stop.wait(5):
                continue

    def run(self) -> None:
        signal.signal(signal.SIGTERM, lambda *a: self.stop.set())
        signal.signal(signal.SIGINT, lambda *a: self.stop.set())
        core.ensure_dir(core.state_dir(), 0o750)
        if self.fim.load() is None:
            self.alerter.emit("info", "monitor", "primera_vez", f"Creando referencias de integridad ({self.fim.init()} elementos)", key="mon:init")
        live = self.live_fim()
        jobs = [("autenticacion", lambda: self.auth.follow(self.stop.is_set)), ("senuelos", lambda: honeypot.follow_log(self.on_decoy, stop=self.stop.is_set))]
        if self.cfg.getboolean("packets", "enabled", fallback=True) and core.is_root():
            jobs.append(("paquetes", lambda: self.pkts.run(self.stop.is_set)))
        for name, fn in jobs:
            t = threading.Thread(target=self._guard, args=(name, fn), daemon=True)
            t.start(); self.threads.append(t)
        self.alerter.emit("info", "monitor", "inicio", f"Sentinel {core.VERSION} iniciado (vigilancia en vivo de archivos: {'sí' if live else 'no, revisión periódica'})", key=f"mon:start:{int(core.now())}")
        every = self.cfg.getint("hostcheck", "interval_seconds", fallback=300)
        last_host = last_fim = 0.0
        last_deep = core.now()
        while not self.stop.is_set():
            t = core.now()
            self.heartbeat()
            self.banner.expire()
            if t - getattr(self, "_upd", 0) > update.TTL:
                self._upd = t
                try:
                    u = update.check(self.cfg, force=True)
                    if u["available"]:
                        self.alerter.emit("low", "update", "disponible", f"Hay una versión nueva de Sentinel: {u['latest']} (tienes la {u['current']}). Ábrela en el panel para actualizar.", key=f"update:{u['latest']}")
                except Exception:
                    pass
            if t - getattr(self, "_pruned", 0) > 86400:
                self._pruned = t
                try:
                    self.intel.store.prune(self.cfg.getint("intel", "retention_days", fallback=90))
                except Exception:
                    pass
            if t - last_host >= every:
                last_host = t
                try:
                    self.host.run(deep=False)
                except Exception as e:
                    self.alerter.emit("low", "monitor", "error", f"Revisión del equipo falló ({type(e).__name__})", key="mon:err:host")
            if t - last_fim >= 900:
                last_fim = t
                try:
                    self.fim.scan()
                except Exception as e:
                    self.alerter.emit("low", "monitor", "error", f"Revisión de integridad falló ({type(e).__name__})", key="mon:err:fimscan")
            if t - last_deep >= 86400:
                last_deep = t
                try:
                    self.fim.scan(deep=True); self.host.run(deep=True)
                except Exception:
                    pass
            self.stop.wait(min(10, every))
        for p in self.procs:
            p.terminate()
        self.alerter.emit("info", "monitor", "detenido", "Sentinel se detuvo", key=f"mon:stop:{int(core.now())}")
