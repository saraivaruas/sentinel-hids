"""Núcleo de Sentinel: configuración, eventos, alertas, lista blanca y bloqueo temporal de IPs.

Solo usa la biblioteca estándar de Python. Las rutas se pueden cambiar con variables de entorno para probar sin permisos de administrador:
SENTINEL_CONF, SENTINEL_STATE y SENTINEL_LOG.
"""
from __future__ import annotations

import configparser
import fnmatch
import ipaddress
import json
import os
import pwd
import shutil
import subprocess
import threading
import time
from dataclasses import asdict, dataclass, field

VERSION = "2.0.0"
SEV = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SEV_ES = {"info": "info", "low": "baja", "medium": "media", "high": "alta", "critical": "CRÍTICA"}

DEFAULTS = """
[general]
desktop_user =
notify_min = medium
journal_min = low
email_to =
email_min = high
ntfy_url =
ntfy_min = high
dedupe_seconds = 3600
enable_desktop = yes
enable_journal = yes

[allow]
; IPs o redes que nunca se bloquean (además de la red local, loopback y Tailscale si protect_private = yes)
ips =
; procesos que pueden estar en escucha o leer el teclado sin generar alerta (nombre del ejecutable)
procs =
; puertos locales que se aceptan como normales aunque aparezcan nuevos (por ejemplo 3000,8080)
ports =
; rutas (con comodines) que el vigilante de archivos ignora
paths =

[ban]
backend = auto
ttl_seconds = 86400
protect_private = yes

[fim]
; rutas críticas (archivos o carpetas; admite comodines)
paths = /etc/passwd,/etc/shadow,/etc/group,/etc/gshadow,/etc/sudoers,/etc/sudoers.d,/etc/ssh,/etc/pam.d,/etc/ld.so.preload,/etc/rc.local,/etc/crontab,/etc/cron.d,/etc/cron.daily,/etc/cron.hourly,/etc/systemd/system,/etc/profile.d,/etc/environment,/etc/hosts,/etc/ufw,/etc/crowdsec,/etc/sentinel,/usr/local/bin,/usr/local/sbin,/opt/sentinel,/root/.ssh,/home/*/.ssh,/home/*/.bashrc,/home/*/.profile,/home/*/.config/autostart
; carpetas de aplicaciones web a vigilar (busca además puertas traseras en el contenido)
www = /var/www/html
www_exts = php,phtml,phar,php5,php7,jsp,asp,aspx,cgi,pl,sh,py
excludes = */node_modules/*,*/.git/*,*/cache/*,*/storage/logs/*,*/storage/framework/*,*.log,*/uploads/*,*/vendor/*
hash_max_mb = 64
max_files = 300000

[hostcheck]
interval_seconds = 300
suspicious_ports = 4444,1337,31337,6667,6697,3333,5555,9050,14444
miner_names = xmrig,minerd,cpuminer,kdevtmpfsi,kinsing,ccminer,ethminer,nbminer
exec_dirs = /tmp,/var/tmp,/dev/shm,/run/user
input_ok = Xorg,Xwayland,gnome-shell,gnome-session-b,systemd-logind,systemd,upowerd,libinput,gsd-power,gsd-media-keys,gsd-sharing,mutter,kwin_wayland,kwin_x11,evsieve,xdotool,rustdesk,sunshine
check_usb = yes
check_modules = yes
; revisión de archivos SUID/SGID nuevos (solo en la revisión profunda diaria)
suid_scan = yes
suid_roots =

[auth]
fail_threshold = 5
fail_window = 600
scan_ports = 12
scan_window = 60
ban_on_failures = yes
ban_on_scan = yes

[honeypot]
ports = 2222,2323,3390,5900,60009
bind = 0.0.0.0
max_conn_per_ip = 20
read_timeout = 5
"""


def conf_path() -> str:
    return os.environ.get("SENTINEL_CONF", "/etc/sentinel/sentinel.conf")


def state_dir() -> str:
    return os.environ.get("SENTINEL_STATE", "/var/lib/sentinel")


def log_dir() -> str:
    return os.environ.get("SENTINEL_LOG", "/var/log/sentinel")


def load_config(path: str | None = None) -> configparser.ConfigParser:
    cfg = configparser.ConfigParser(interpolation=None, inline_comment_prefixes=None)
    cfg.read_string(DEFAULTS)
    p = path or conf_path()
    if os.path.exists(p):
        cfg.read(p, encoding="utf-8")
    return cfg


def csv(value: str) -> list[str]:
    return [x.strip() for x in (value or "").split(",") if x.strip()]


def is_root() -> bool:
    return os.geteuid() == 0


def now() -> float:
    return time.time()


def iso(ts: float | None = None) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(ts or now()))


def ensure_dir(path: str, mode: int = 0o750) -> None:
    os.makedirs(path, mode=mode, exist_ok=True)


def share_with_adm(path: str) -> None:
    """Si corre como administrador, deja el archivo legible por el grupo «adm» (así el panel gráfico, que corre con tu usuario, puede leerlo)."""
    if not is_root():
        return
    try:
        import grp
        os.chown(path, -1, grp.getgrnam("adm").gr_gid)
    except (OSError, KeyError, ImportError):
        pass


def atomic_write_json(path: str, obj, mode: int = 0o600, share: bool = False) -> None:
    ensure_dir(os.path.dirname(path), 0o750)
    tmp = f"{path}.{os.getpid()}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False)
    os.chmod(tmp, 0o640 if share and mode == 0o600 else mode)
    if share:
        share_with_adm(tmp)
    os.replace(tmp, path)


def read_json(path: str, default=None):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def run(cmd: list[str], timeout: int = 20) -> tuple[int, str]:
    """Ejecuta un comando sin shell; devuelve (código, salida)."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        return r.returncode, (r.stdout or "") + (r.stderr or "")
    except (OSError, subprocess.SubprocessError) as e:
        return 127, str(e)


@dataclass
class Event:
    sev: str
    source: str
    kind: str
    msg: str
    key: str = ""
    data: dict = field(default_factory=dict)
    ts: str = field(default_factory=iso)
    epoch: float = field(default_factory=now)

    def line(self) -> str:
        return f"[{self.ts[11:19]}] {SEV_ES[self.sev]:>7} · {self.source}/{self.kind} · {self.msg}"


class Allow:
    """Listas blancas: IPs/redes, procesos, puertos y rutas que no deben generar alertas ni bloqueos."""

    PROTECTED = ["127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "fe80::/10", "fc00::/7", "100.64.0.0/10"]

    def __init__(self, cfg: configparser.ConfigParser):
        nets = csv(cfg.get("allow", "ips", fallback=""))
        if cfg.getboolean("ban", "protect_private", fallback=True):
            nets += self.PROTECTED
        self.nets = []
        for n in nets:
            try:
                self.nets.append(ipaddress.ip_network(n, strict=False))
            except ValueError:
                pass
        self.procs = set(csv(cfg.get("allow", "procs", fallback="")))
        self.ports = {int(p) for p in csv(cfg.get("allow", "ports", fallback="")) if p.isdigit()}
        self.paths = csv(cfg.get("allow", "paths", fallback=""))

    def ip_protected(self, ip: str) -> bool:
        try:
            a = ipaddress.ip_address(ip.split("%")[0].strip("[]"))
        except ValueError:
            return True  # algo que no es una IP nunca se bloquea
        return any(a in n for n in self.nets if n.version == a.version)

    def path_ignored(self, path: str) -> bool:
        return any(fnmatch.fnmatch(path, p) for p in self.paths)


class Alerter:
    """Registra cada evento (JSONL), lo manda al journal y, según su gravedad, al escritorio, al correo o a ntfy. Evita repetir el mismo aviso."""

    def __init__(self, cfg: configparser.ConfigParser | None = None, quiet: bool = False):
        self.cfg = cfg or load_config()
        self.quiet = quiet
        self.lock = threading.RLock()
        self.dedupe: dict[str, list] = {}
        self.path = os.path.join(log_dir(), "events.jsonl")
        self._dedupe_path = os.path.join(state_dir(), "dedupe.json")
        self.dedupe = read_json(self._dedupe_path, {}) or {}

    def _min(self, name: str) -> int:
        return SEV.get(self.cfg.get("general", name, fallback="high"), 3)

    def emit(self, sev: str, source: str, kind: str, msg: str, key: str | None = None, **data) -> Event | None:
        with self.lock:
            return self._emit(sev, source, kind, msg, key, data)

    def _emit(self, sev: str, source: str, kind: str, msg: str, key: str | None, data: dict) -> Event | None:
        ev = Event(sev, source, kind, msg, key or f"{source}:{kind}:{msg}", data)
        win = self.cfg.getint("general", "dedupe_seconds", fallback=3600)
        prev = self.dedupe.get(ev.key)
        if prev and ev.epoch - prev[0] < win and SEV[sev] < SEV["critical"]:
            prev[1] += 1
            self._save_dedupe()
            return None
        self.dedupe[ev.key] = [ev.epoch, 1]
        self._prune()
        self._save_dedupe()
        self._write(ev)
        if not self.quiet:
            self._channels(ev)
        return ev

    def _prune(self) -> None:
        if len(self.dedupe) > 5000:
            old = sorted(self.dedupe.items(), key=lambda kv: kv[1][0])[:2500]
            for k, _ in old:
                self.dedupe.pop(k, None)

    def _save_dedupe(self) -> None:
        try:
            atomic_write_json(self._dedupe_path, self.dedupe)
        except OSError:
            pass

    def _write(self, ev: Event) -> None:
        try:
            ensure_dir(os.path.dirname(self.path), 0o750)
            new = not os.path.exists(self.path)
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(asdict(ev), ensure_ascii=False) + "\n")
            if new:
                os.chmod(self.path, 0o640)
                share_with_adm(self.path)
        except OSError:
            pass

    def _channels(self, ev: Event) -> None:
        n = SEV[ev.sev]
        if self.cfg.getboolean("general", "enable_journal", fallback=True) and n >= self._min("journal_min") and shutil.which("logger"):
            prio = {"info": "info", "low": "notice", "medium": "warning", "high": "err", "critical": "crit"}[ev.sev]
            run(["logger", "-t", "sentinel", "-p", f"auth.{prio}", ev.line()], 5)
        if self.cfg.getboolean("general", "enable_desktop", fallback=True) and n >= self._min("notify_min"):
            self.desktop(ev)
        if n >= self._min("email_min") and self.cfg.get("general", "email_to", fallback="") and shutil.which("mail"):
            try:
                subprocess.run(["mail", "-s", f"[Sentinel {SEV_ES[ev.sev]}] {ev.kind}", self.cfg.get("general", "email_to")], input=ev.line() + "\n" + json.dumps(ev.data, ensure_ascii=False, indent=1), text=True, timeout=15, check=False)
            except (OSError, subprocess.SubprocessError):
                pass
        url = self.cfg.get("general", "ntfy_url", fallback="")
        if url and n >= self._min("ntfy_min") and shutil.which("curl"):
            run(["curl", "-s", "-m", "8", "-H", f"Title: Sentinel {SEV_ES[ev.sev]}", "-H", f"Priority: {'urgent' if n >= 4 else 'high'}", "-d", ev.line(), url], 12)

    def desktop_target(self) -> tuple[str, int] | None:
        user = self.cfg.get("general", "desktop_user", fallback="")
        try:
            if user:
                return user, pwd.getpwnam(user).pw_uid
            if not is_root():
                return pwd.getpwuid(os.geteuid()).pw_name, os.geteuid()
            for uid in sorted(int(d) for d in os.listdir("/run/user") if d.isdigit()):
                if uid >= 1000 and os.path.exists(f"/run/user/{uid}/bus"):
                    return pwd.getpwuid(uid).pw_name, uid
        except (OSError, KeyError):
            pass
        return None

    def desktop(self, ev: Event) -> None:
        if not shutil.which("notify-send"):
            return
        tgt = self.desktop_target()
        if not tgt:
            return
        user, uid = tgt
        base = ["notify-send", "-a", "Sentinel", "-u", "critical" if ev.sev in ("high", "critical") else "normal", f"Sentinel · {SEV_ES[ev.sev]}", ev.msg[:300]]
        env = f"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{uid}/bus"
        if is_root():
            run(["runuser", "-u", user, "--", "env", env, *base], 6)
        else:
            e = dict(os.environ, DBUS_SESSION_BUS_ADDRESS=f"unix:path=/run/user/{uid}/bus")
            try:
                subprocess.run(base, env=e, timeout=6, capture_output=True, check=False)
            except (OSError, subprocess.SubprocessError):
                pass


def read_events(since: float = 0, min_sev: str = "info", limit: int = 0, path: str | None = None) -> list[dict]:
    p = path or os.path.join(log_dir(), "events.jsonl")
    out = []
    try:
        with open(p, encoding="utf-8") as f:
            for ln in f:
                try:
                    e = json.loads(ln)
                except ValueError:
                    continue
                if e.get("epoch", 0) >= since and SEV.get(e.get("sev"), 0) >= SEV[min_sev]:
                    out.append(e)
    except OSError:
        return []
    return out[-limit:] if limit else out


class Banner:
    """Bloquea IPs de forma temporal, nunca las protegidas (red local, loopback, Tailscale, lista blanca)."""

    def __init__(self, cfg: configparser.ConfigParser, alerter: Alerter, allow: Allow):
        self.cfg, self.alerter, self.allow = cfg, alerter, allow
        self.path = os.path.join(state_dir(), "bans.json")
        self.bans: dict = read_json(self.path, {}) or {}

    def backend(self) -> str:
        b = self.cfg.get("ban", "backend", fallback="auto")
        if b != "auto":
            return b
        if shutil.which("cscli") and run(["systemctl", "is-active", "crowdsec"], 5)[1].strip() == "active":
            return "crowdsec"
        return "ufw" if shutil.which("ufw") else "none"

    def ban(self, ip: str, reason: str, ttl: int | None = None) -> bool:
        ttl = ttl or self.cfg.getint("ban", "ttl_seconds", fallback=86400)
        if self.allow.ip_protected(ip):
            self.alerter.emit("info", "ban", "protegida", f"{ip} no se bloquea (red protegida o en lista blanca): {reason}", key=f"protegida:{ip}")
            return False
        cur = self.bans.get(ip)
        if cur and cur["until"] > now():
            return False
        be = self.backend()
        if not is_root() or be == "none":
            self.alerter.emit("medium", "ban", "simulado", f"Se habría bloqueado {ip} por {ttl // 3600} h ({reason}); falta permiso de administrador o motor de bloqueo", key=f"sim:{ip}")
            return False
        if be == "crowdsec":
            rc, out = run(["cscli", "decisions", "add", "--ip", ip, "--duration", f"{ttl}s", "--type", "ban", "--reason", f"sentinel: {reason}"[:180]], 20)
        else:
            rc, out = run(["ufw", "insert", "1", "deny", "from", ip, "to", "any", "comment", "sentinel"], 20)
        if rc != 0:
            self.alerter.emit("high", "ban", "fallo", f"No se pudo bloquear {ip}: {out.strip()[:160]}", key=f"banfail:{ip}")
            return False
        self.bans[ip] = {"until": now() + ttl, "reason": reason, "backend": be, "since": iso()}
        atomic_write_json(self.path, self.bans, share=True)
        self.alerter.emit("high", "ban", "bloqueada", f"IP {ip} bloqueada por {ttl // 3600} h con {be}: {reason}", key=f"ban:{ip}:{int(now() // 60)}", ip=ip, ttl=ttl)
        return True

    def expire(self) -> list[str]:
        gone = []
        for ip, b in list(self.bans.items()):
            if b["until"] <= now():
                if b.get("backend") == "ufw" and is_root():
                    run(["ufw", "delete", "deny", "from", ip, "to", "any"], 20)
                gone.append(ip)
                del self.bans[ip]
        if gone:
            atomic_write_json(self.path, self.bans, share=True)
        return gone

    def unban(self, ip: str) -> bool:
        b = self.bans.pop(ip, None)
        if is_root():
            if shutil.which("cscli"):
                run(["cscli", "decisions", "delete", "--ip", ip], 20)
            run(["ufw", "delete", "deny", "from", ip, "to", "any"], 20)
        atomic_write_json(self.path, self.bans, share=True)
        return b is not None
