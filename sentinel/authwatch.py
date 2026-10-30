"""Detección de ataques en vivo desde el journal: fuerza bruta (SSH, sudo), accesos sospechosos y escaneo de puertos (bloqueos del cortafuegos)."""
from __future__ import annotations

import collections
import json
import re
import subprocess

from . import core

RE_FAIL = re.compile(r"Failed (?:password|publickey|keyboard-interactive/pam) for (?:invalid user )?(\S+) from (\S+)")
RE_INVALID = re.compile(r"Invalid user (\S*) from (\S+)")
RE_ACCEPT = re.compile(r"Accepted (\S+) for (\S+) from (\S+)")
RE_PREAUTH = re.compile(r"(?:Connection closed by|Disconnected from|Connection reset by) (?:authenticating user \S+ |invalid user \S+ )?(\S+) port \d+ \[preauth\]")
RE_SUDO_FAIL = re.compile(r"(\S+)\s*: (\d+) incorrect password attempts?")
RE_SUDO_ROOT = re.compile(r"(\S+)\s*: .*USER=root ; COMMAND=(.*)")
RE_UFW = re.compile(r"\[UFW BLOCK\].*?SRC=(\S+).*?PROTO=(\S+)(?:.*?DPT=(\d+))?")
RE_SU_FAIL = re.compile(r"FAILED SU \(to (\S+)\) (\S+) on")


class AuthWatch:
    def __init__(self, cfg, alerter: core.Alerter, allow: core.Allow, banner: core.Banner, intel=None):
        self.cfg, self.alerter, self.allow, self.banner, self.intel = cfg, alerter, allow, banner, intel
        self.thr = cfg.getint("auth", "fail_threshold", fallback=5)
        self.win = cfg.getint("auth", "fail_window", fallback=600)
        self.scan_ports = cfg.getint("auth", "scan_ports", fallback=12)
        self.scan_win = cfg.getint("auth", "scan_window", fallback=60)
        self.fails: dict[str, collections.deque] = collections.defaultdict(collections.deque)
        self.ports: dict[str, dict[int, float]] = collections.defaultdict(dict)

    def _fail(self, ip: str, user: str, t: float, kind: str = "ssh_clave", detail: str = "") -> None:
        if self.intel and not self.allow.ip_protected(ip):
            self.intel.attempt(ip, kind, user=user, port=22, proto="tcp", detail=detail)
        q = self.fails[ip]
        q.append(t)
        while q and t - q[0] > self.win:
            q.popleft()
        if len(q) >= self.thr:
            self.alerter.emit("high", "auth", "fuerza_bruta", f"{len(q)} intentos fallidos de acceso desde {ip} en {self.win // 60} min (último usuario probado: {user})", key=f"auth:brute:{ip}:{int(t // self.win)}", ip=ip)
            if self.cfg.getboolean("auth", "ban_on_failures", fallback=True):
                self.banner.ban(ip, f"fuerza bruta ({len(q)} intentos)")

    def handle(self, ident: str, msg: str, t: float | None = None, kernel: bool = False) -> None:
        """Procesa una línea del journal (se puede probar con texto de ejemplo)."""
        t = t if t is not None else core.now()
        if kernel or msg.startswith("[UFW BLOCK]") or "[UFW BLOCK]" in msg:
            m = RE_UFW.search(msg)
            if m and m.group(3):
                self._portscan(m.group(1), int(m.group(3)), t)
            return
        m = RE_FAIL.search(msg) or RE_INVALID.search(msg)
        if m:
            user, ip = m.group(1), m.group(2)
            kind = "ssh_usuario_invalido" if ("invalid user" in msg.lower() or RE_INVALID.search(msg)) else "ssh_llave" if "publickey" in msg else "ssh_clave"
            self._fail(ip, user, t, kind, msg[:120])
            return
        m = RE_ACCEPT.search(msg)
        if m:
            meth, user, ip = m.groups()
            recent = [x for x in self.fails.get(ip, ()) if t - x <= self.win]
            if recent and len(recent) >= 3:
                self.alerter.emit("critical", "auth", "acceso_tras_ataque", f"Acceso exitoso de «{user}» desde {ip} después de {len(recent)} intentos fallidos: posible cuenta comprometida", key=f"auth:cred:{ip}:{user}", ip=ip, user=user)
            elif user == "root" and not self.allow.ip_protected(ip):
                self.alerter.emit("high", "auth", "root_remoto", f"Ingreso remoto como root desde {ip} ({meth})", key=f"auth:root:{ip}", ip=ip)
            elif not self.allow.ip_protected(ip):
                self.alerter.emit("low", "auth", "acceso_externo", f"Ingreso de «{user}» desde una IP pública: {ip} ({meth})", key=f"auth:ext:{user}:{ip}", ip=ip)
            return
        m = RE_SUDO_FAIL.search(msg)
        if m and ident in ("sudo", "su", "pkexec", ""):
            self.alerter.emit("medium", "auth", "sudo_fallido", f"«{m.group(1)}» falló {m.group(2)} veces la clave de sudo", key=f"auth:sudo:{m.group(1)}:{int(t // 3600)}")
            return
        m = RE_SU_FAIL.search(msg)
        if m:
            self.alerter.emit("medium", "auth", "su_fallido", f"Intento fallido de «su» hacia {m.group(1)} por {m.group(2)}", key=f"auth:su:{m.group(2)}:{int(t // 3600)}")

    def _portscan(self, ip: str, port: int, t: float) -> None:
        d = self.ports[ip]
        d[port] = t
        if self.intel and not self.allow.ip_protected(ip):
            self.intel.store.add_packets({(ip, "tcp", port, "SYN"): (t, t, 1, 0)}, []) if self.intel.store.get_ip(ip) else None
        for p, ts in list(d.items()):
            if t - ts > self.scan_win:
                del d[p]
        if len(d) >= self.scan_ports:
            prot = self.allow.ip_protected(ip)
            self.alerter.emit("low" if prot else "high", "auth", "escaneo_de_puertos", f"Escaneo de puertos desde {ip}: {len(d)} puertos distintos en {self.scan_win}s" + (" (red local; no se bloquea)" if prot else ""), key=f"auth:scan:{ip}:{int(t // 600)}", ip=ip, ports=sorted(d)[:30])
            if not prot and self.intel:
                for pt in sorted(d)[:40]:
                    self.intel.attempt(ip, "escaneo_puertos", port=pt, proto="tcp", detail="bloqueado por el cortafuegos")
            if not prot and self.cfg.getboolean("auth", "ban_on_scan", fallback=True):
                self.banner.ban(ip, f"escaneo de {len(d)} puertos")
            d.clear()

    def follow(self, stop=lambda: False) -> None:
        """Lee el journal en vivo. Termina cuando `stop()` es verdadero o se cierra journalctl."""
        cmd = ["journalctl", "-f", "-n", "0", "-o", "json", "--output-fields=MESSAGE,SYSLOG_IDENTIFIER,_TRANSPORT"]
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        try:
            for ln in p.stdout:  # type: ignore[union-attr]
                if stop():
                    break
                try:
                    r = json.loads(ln)
                except ValueError:
                    continue
                msg = r.get("MESSAGE")
                if isinstance(msg, str):
                    self.handle(r.get("SYSLOG_IDENTIFIER", ""), msg, kernel=r.get("_TRANSPORT") == "kernel")
        finally:
            p.terminate()
