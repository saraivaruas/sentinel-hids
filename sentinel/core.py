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
import re
import shutil
import subprocess
import threading
import time
from collections import deque
from dataclasses import asdict, dataclass, field

from . import pf, plataforma

VERSION = "2.11.2"
SEV = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SEV_ES = {"info": "info", "low": "baja", "medium": "media", "high": "alta", "critical": "CRÍTICA"}

DEFAULTS = """
[general]
desktop_user =
notify_min = medium
; aviso en la esquina de la pantalla (se cierra solo): segundos visible; las críticas un poco más
notify_seconds = 8
; horas de silencio (HH:MM, hora local): sin avisos en la pantalla salvo las críticas. Vacío = sin silencio. Ejemplo: quiet_from = 22:00, quiet_to = 07:00
quiet_from =
quiet_to =
; corner = aviso propio en la esquina inferior derecha; system = notificación normal del escritorio
notify_style = corner
notify_seconds_critical = 15
; ventana emergente grande (con botón «Abrir panel») desde esta gravedad (never = nunca, solo avisos de esquina); máximo por minuto; segundos abierta
popup_min = never
popup_max_per_min = 3
popup_seconds = 120
journal_min = low
email_to =
email_min = high
; máximo de correos de alerta por hora (las críticas siempre salen)
email_max_per_hour = 20
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

[malware]
; antivirus y reglas YARA para las carpetas web, solo si ya están instalados (clamav / yara). auto = usarlos si existen; no = nunca
clamav = auto
yara = auto
; máximo de archivos que se mandan al antivirus en cada revisión
max_per_scan = 25

[alerts]
; Dirección https del latido externo (por ejemplo la de healthchecks.io): si Sentinel deja de avisar, ese servicio te avisa a ti
heartbeat_url =
heartbeat_seconds = 300

[weblog]
; Registros de acceso de tus sitios web (admite comodines). Si no existen, no se vigila nada.
paths = /var/log/nginx/*access*.log,/var/log/apache2/*access*.log,/var/log/httpd/*access_log
; bloquear 24 h a quien ataca (ejecución de comandos, inyección SQL, escáneres, fuerza bruta)
ban = yes
window = 600
scan_404 = 30
login_fail = 15
attack_hits = 3
probe_hits = 8

[firewall]
backend = auto
allow_tcp = 80,443
allow_udp =
keep_ssh = yes
profile = custom
restrict =
ssh_limit = no
refresh_seconds = 60

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
input_ok = acpid,gdm-x-session,gdm-wayland-ses,Xorg,Xwayland,gnome-shell,gnome-session-b,systemd-logind,systemd,upowerd,libinput,gsd-power,gsd-media-keys,gsd-sharing,mutter,kwin_wayland,kwin_x11,evsieve,xdotool,rustdesk,sunshine
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

[update]
; buscar versiones nuevas en GitHub (solo consulta; instalar siempre lo decides tú). check = no para no consultar nada
check = yes
repo = saraivaruas/sentinel-hids
; auto = exigir la firma (SHA256SUMS.asc) si este equipo trae la clave pública de Sentinel; yes = siempre; no = solo la huella SHA-256
require_signature = auto

[intel]
; de dónde sale la ubicación del atacante: auto (archivo local si existe, si no RIPEstat/RDAP), offline (solo archivo local), online, off
geo_mode = auto
; archivo MMDB local, p. ej. DB-IP City Lite (gratis): https://db-ip.com/db/download/ip-to-city-lite
geoip_db =
retention_days = 90

[packets]
; captura de paquetes (necesita root): detecta escaneos de puertos, escaneos sigilosos, inundaciones y pings masivos
enabled = yes
interface =
ban = yes
syn_scan_ports = 15
window = 60
stealth_count = 3
flood_syn = 300
flood_ping = 100
udp_scan_ports = 20
cooldown = 600
max_pps = 30000

[honeypot]
ports = 2222,2323,3390,5900,60009
bind = 0.0.0.0
max_conn_per_ip = 20
read_timeout = 5

[smtp]
; correo por SMTP (sin necesitar el comando «mail»). La contraseña NO va aquí: sudo sentinel smtp configurar la guarda en /etc/sentinel/smtp.pass (solo root)
enabled = no
host =
port = 587
; starttls (puerto 587), ssl (puerto 465) o none (solo para un servidor local)
security = starttls
user =
sender =
; destinatarios separados por comas (vacío = general.email_to)
to =

[ia]
; asistente de IA que EXPLICA las detecciones (nunca decide ni ejecuta nada). Viene apagado. Se configura en el panel («Asistente de IA») o con: sudo sentinel ia configurar
enabled = no
; local = modelo en este mismo equipo con Ollama (nada sale de aquí) · api = servicio en la nube con tu propia clave (guardada en /etc/sentinel/ia.key)
modo = local
local_url = http://127.0.0.1:11434
local_modelo =
; anthropic u openai (también sirve cualquier servicio compatible con la API de OpenAI poniendo api_url con https://)
proveedor = anthropic
api_url =
api_modelo = claude-haiku-5-5
timeout = 60

[equipo]
; revisión completa del equipo (sentinel equipo): procesos que pueden tener conexiones externas sin generar hallazgo
conexiones_permitidas = chrome,firefox,claude,claude-desktop,cloudflared,syncthing,tailscaled,crowdsec,crowdsec-firewa,apt,apt-get,http,curl,wget,snapd,packagekitd,fwupd,gnome-software,unattended-upgr,node,python3,msmtp,git,ssh,code,dotnet
; puertos de destino típicos de shells inversas o canales de mando y control
puertos_c2 = 4444,4445,1337,31337,6666,6667,5555,9001,9050,2222,8888
; si el informe del equipo se manda por correo cuando lo ejecuta el temporizador (necesita [smtp])
enviar_correo = yes
; horas a las que se genera el informe (HH:MM, hora local, separadas por coma). Se cambia con: sudo sentinel equipo --horario 08:00,16:00,23:00
horas = 08:00,16:00,23:00
; el informe se guarda en /var/lib/sentinel/informes; cuántos se conservan
informes_max = 30

[identidad]
; interfaz cuya MAC e IP se cambian (vacío = la de la salida a internet). Ver: sentinel identidad estado
interfaz =
; cambio programado de MAC e IP, apagado por defecto. Se enciende con: sudo sentinel identidad activar --cada 2 (o desde Ajustes del panel)
activo = no
cada_horas = 2
"""


def conf_path() -> str:
    return os.environ.get("SENTINEL_CONF", "/etc/sentinel/sentinel.conf")


def state_dir() -> str:
    return os.environ.get("SENTINEL_STATE", "/var/lib/sentinel")


def log_dir() -> str:
    return os.environ.get("SENTINEL_LOG", "/var/log/sentinel")


# Valores por defecto que cambian en macOS (/etc, /var y /tmp son enlaces a /private). El resto vale igual.
DEFAULTS_MAC = """
[fim]
paths = /private/etc/passwd,/private/etc/master.passwd,/private/etc/group,/private/etc/sudoers,/private/etc/sudoers.d,/private/etc/ssh,/private/etc/pam.d,/private/etc/hosts,/private/etc/profile,/private/etc/bashrc,/private/etc/zshrc,/private/etc/zprofile,/private/etc/pf.conf,/private/etc/pf.anchors,/private/etc/periodic,/private/etc/crontab,/private/var/at/tabs,/private/etc/sentinel,/Library/LaunchDaemons,/Library/LaunchAgents,/Library/StartupItems,/usr/local/bin,/usr/local/sbin,/opt/sentinel,/private/var/root/.ssh,/Users/*/.ssh,/Users/*/.zshrc,/Users/*/.zprofile,/Users/*/.bashrc,/Users/*/.bash_profile,/Users/*/.profile,/Users/*/Library/LaunchAgents
www = /Library/WebServer/Documents,/opt/homebrew/var/www,/usr/local/var/www
excludes = */node_modules/*,*/.git/*,*/cache/*,*/storage/logs/*,*/storage/framework/*,*.log,*/uploads/*,*/vendor/*,*/.DS_Store

[weblog]
paths = /private/var/log/apache2/*access*log,/opt/homebrew/var/log/nginx/*access*.log,/usr/local/var/log/nginx/*access*.log

[honeypot]
; el 5900 no: en macOS es «Compartir pantalla»
ports = 2222,2323,3390,60009
"""


def load_config(path: str | None = None) -> configparser.ConfigParser:
    cfg = configparser.ConfigParser(interpolation=None, inline_comment_prefixes=None)
    cfg.read_string(DEFAULTS)
    if plataforma.ES_MAC:
        cfg.read_string(DEFAULTS_MAC)
    p = path or conf_path()
    if os.path.exists(p):
        cfg.read(p, encoding="utf-8")
    return cfg


SEVS = ("info", "low", "medium", "high", "critical")
# Ajustes que el panel puede cambiar: (sección, clave) -> validador. Todo lo demás se edita a mano en sentinel.conf.
EDITABLE = {
    ("general", "enable_desktop"): lambda v: v in ("yes", "no"),
    ("general", "notify_min"): lambda v: v in SEVS,
    ("general", "popup_min"): lambda v: v in SEVS or v == "never",
    ("general", "notify_seconds"): lambda v: v.isdigit() and 2 <= int(v) <= 120,
    ("general", "notify_seconds_critical"): lambda v: v.isdigit() and 2 <= int(v) <= 120,
    ("general", "notify_style"): lambda v: v in ("corner", "system"),
    ("general", "quiet_from"): lambda v: v == "" or bool(re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", v)),
    ("general", "quiet_to"): lambda v: v == "" or bool(re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", v)),
    ("general", "email_to"): lambda v: v == "" or bool(re.fullmatch(r"[\w.+-]{1,64}@[\w.-]{1,120}\.[A-Za-z]{2,}", v)),
    ("general", "ntfy_url"): lambda v: v == "" or bool(re.fullmatch(r"https://[\w.-]{1,120}(?::\d{2,5})?/[\w.~%/-]{1,120}", v)),
    ("smtp", "enabled"): lambda v: v in ("yes", "no"),
    ("smtp", "host"): lambda v: v == "" or bool(re.fullmatch(r"[A-Za-z0-9.-]{1,200}", v)),
    ("smtp", "port"): lambda v: v.isdigit() and 1 <= int(v) <= 65535,
    ("smtp", "security"): lambda v: v in ("starttls", "ssl", "none"),
    ("smtp", "user"): lambda v: v == "" or bool(re.fullmatch(r"[^\s\x00-\x1f]{1,120}", v)),
    ("smtp", "sender"): lambda v: v == "" or bool(re.fullmatch(r"[\w.+-]{1,64}@[\w.-]{1,120}\.[A-Za-z]{2,}", v)),
    ("smtp", "to"): lambda v: v == "" or all(re.fullmatch(r"[\w.+-]{1,64}@[\w.-]{1,120}\.[A-Za-z]{2,}", x.strip()) for x in v.split(",")),
    ("ia", "enabled"): lambda v: v in ("yes", "no"),
    ("ia", "modo"): lambda v: v in ("local", "api"),
    ("ia", "local_url"): lambda v: __import__("sentinel.ia", fromlist=["x"]).url_local_valida(v),
    ("ia", "local_modelo"): lambda v: __import__("sentinel.ia", fromlist=["x"]).modelo_valido(v),
    ("ia", "proveedor"): lambda v: v in ("anthropic", "openai"),
    ("ia", "api_url"): lambda v: __import__("sentinel.ia", fromlist=["x"]).url_api_valida(v),
    ("ia", "api_modelo"): lambda v: __import__("sentinel.ia", fromlist=["x"]).modelo_valido(v),
    ("equipo", "conexiones_permitidas"): lambda v: bool(re.fullmatch(r"[\w.@+-]{1,64}(,[\w.@+-]{1,64})*", v.replace(" ", ""))) or v == "",
    ("equipo", "enviar_correo"): lambda v: v in ("yes", "no"),
    ("equipo", "horas"): lambda v: bool(re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d(,([01]\d|2[0-3]):[0-5]\d){0,5}", v)),
    ("identidad", "activo"): lambda v: v in ("yes", "no"),
    ("identidad", "cada_horas"): lambda v: v.isdigit() and 1 <= int(v) <= 168,
    ("alerts", "heartbeat_url"): lambda v: v == "" or __import__("sentinel.heartbeat", fromlist=["valid"]).valid(v),
}


def set_setting(section: str, key: str, value: str, path: str | None = None) -> None:
    """Cambia un valor de sentinel.conf (solo los de EDITABLE, validados) sin tocar el resto del archivo."""
    ok = EDITABLE.get((section, key))
    if ok is None or not ok(value):
        raise ValueError(f"ajuste no permitido: {section}.{key} = {value!r}")
    path = path or conf_path()
    txt = open(path, encoding="utf-8").read() if os.path.exists(path) else ""
    m = re.search(rf"^\[{section}\]\s*$", txt, re.M)
    if not m:
        txt = txt.rstrip("\n") + f"\n\n[{section}]\n{key} = {value}\n"
    else:
        end = re.search(r"^\[", txt[m.end():], re.M)
        stop = m.end() + end.start() if end else len(txt)
        sec = txt[m.end():stop]
        k = re.search(rf"^{key}\s*=.*$", sec, re.M)
        sec = sec[:k.start()] + f"{key} = {value}" + sec[k.end():] if k else sec.rstrip("\n") + f"\n{key} = {value}\n" + ("\n" if end else "")
        txt = txt[:m.end()] + sec + txt[stop:]
    with open(path, "w", encoding="utf-8") as f:
        f.write(txt)


# ---- horas de silencio y eventos resueltos
def in_quiet(cfg, ts: float | None = None) -> bool:
    """¿Estamos dentro de las horas de silencio (hora local)? Aceptan cruzar la medianoche, p. ej. 22:00 → 07:00."""
    a, b = cfg.get("general", "quiet_from", fallback=""), cfg.get("general", "quiet_to", fallback="")
    try:
        ma = int(a[:2]) * 60 + int(a[3:5]); mb = int(b[:2]) * 60 + int(b[3:5])
    except ValueError:
        return False
    if not a or not b or ma == mb:
        return False
    lt = time.localtime(ts if ts is not None else now())
    m = lt.tm_hour * 60 + lt.tm_min
    return ma <= m < mb if ma < mb else (m >= ma or m < mb)


def resolved_path() -> str:
    return os.path.join(state_dir(), "resolved.json")


def resolved_ids() -> set[str]:
    return set((read_json(resolved_path(), {}) or {}).get("ids", []))


def event_id(e: dict) -> str:
    return f"{e.get('key')}@{int(e.get('epoch', 0))}"


def resolve_event(key: str, epoch: float) -> None:
    ids = sorted(resolved_ids() | {f"{key}@{int(epoch)}"})[-5000:]
    atomic_write_json(resolved_path(), {"ids": ids}, 0o640, share=True)


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


def grupo_lector() -> str:
    return "admin" if plataforma.ES_MAC else "adm"


def share_with_adm(path: str) -> None:
    """Si corre como administrador, deja el archivo legible por el grupo de administradores («adm»; «admin» en macOS), así el panel gráfico, que corre con tu usuario, puede leerlo."""
    if not is_root():
        return
    try:
        import grp
        os.chown(path, -1, grp.getgrnam(grupo_lector()).gr_gid)
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
        self._pop: deque = deque()
        self.last_popup: threading.Thread | None = None
        self.dedupe: dict[str, list] = {}
        self.path = os.path.join(log_dir(), "events.jsonl")
        self._dedupe_path = os.path.join(state_dir(), "dedupe.json")
        self.dedupe = read_json(self._dedupe_path, {}) or {}

    def _min(self, name: str) -> int:
        v = self.cfg.get("general", name, fallback="high")
        return 99 if v in ("never", "nunca", "off", "no") else SEV.get(v, 3)

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
            if new or os.stat(self.path).st_gid == 0:
                share_with_adm(self.path)
        except OSError:
            pass

    def _channels(self, ev: Event) -> None:
        n = SEV[ev.sev]
        if self.cfg.getboolean("general", "enable_journal", fallback=True) and n >= self._min("journal_min") and shutil.which("logger"):
            prio = {"info": "info", "low": "notice", "medium": "warning", "high": "err", "critical": "crit"}[ev.sev]
            run(["logger", "-t", "sentinel", "-p", f"auth.{prio}", ev.line()], 5)
        silencio = in_quiet(self.cfg) and ev.sev != "critical"          # de noche solo las críticas suenan en la pantalla (el registro, el correo y el celular siguen igual)
        if self.cfg.getboolean("general", "enable_desktop", fallback=True) and n >= self._min("notify_min") and not silencio:
            self.desktop(ev)
        if self.cfg.getboolean("general", "enable_desktop", fallback=True) and n >= self._min("popup_min") and not silencio:
            self.popup(ev)
        if n >= self._min("email_min"):
            self._email(ev)
        url = self.cfg.get("general", "ntfy_url", fallback="")
        if url and n >= self._min("ntfy_min") and shutil.which("curl"):
            run(["curl", "-s", "-m", "8", "-H", f"Title: Sentinel {SEV_ES[ev.sev]}", "-H", f"Priority: {'urgent' if n >= 4 else 'high'}", "-d", ev.line(), url], 12)

    def _email(self, ev: Event) -> None:
        """Correo de alerta: por SMTP propio si está configurado (en segundo plano y con tope por hora); si no, el comando «mail» como antes."""
        from . import mailer
        body = ev.line() + "\n" + json.dumps(ev.data, ensure_ascii=False, indent=1)
        subject = f"[Sentinel {SEV_ES[ev.sev]}] {ev.kind}"
        if mailer.configured(self.cfg):
            if ev.sev != "critical":
                now_ = now()
                self._mails = [t for t in getattr(self, "_mails", []) if now_ - t < 3600]
                if len(self._mails) >= self.cfg.getint("general", "email_max_per_hour", fallback=20):
                    return
                self._mails.append(now_)
            threading.Thread(target=mailer.send, args=(self.cfg, subject, body), daemon=True).start()
        elif self.cfg.get("general", "email_to", fallback="") and shutil.which("mail"):
            try:
                subprocess.run(["mail", "-s", subject, self.cfg.get("general", "email_to")], input=body, text=True, timeout=15, check=False)
            except (OSError, subprocess.SubprocessError):
                pass

    def desktop_target(self) -> tuple[str, int] | None:
        user = self.cfg.get("general", "desktop_user", fallback="")
        try:
            if user:
                return user, pwd.getpwnam(user).pw_uid
            if not is_root():
                return pwd.getpwuid(os.geteuid()).pw_name, os.geteuid()
            if plataforma.ES_MAC:
                uid = os.stat("/dev/console").st_uid          # quien tiene la pantalla delante (root = nadie ha iniciado sesión)
                return (pwd.getpwuid(uid).pw_name, uid) if uid >= 500 else None
            for uid in sorted(int(d) for d in os.listdir("/run/user") if d.isdigit()):
                if uid >= 1000 and os.path.exists(f"/run/user/{uid}/bus"):
                    return pwd.getpwuid(uid).pw_name, uid
        except (OSError, KeyError):
            pass
        return None

    @staticmethod
    def desktop_env(uid: int) -> dict:
        """Variables que necesita una ventana gráfica lanzada desde un servicio para aparecer en la sesión del usuario (X11 o Wayland)."""
        env = {"XDG_RUNTIME_DIR": f"/run/user/{uid}", "DBUS_SESSION_BUS_ADDRESS": f"unix:path=/run/user/{uid}/bus"}
        try:
            w = sorted(f for f in os.listdir(f"/run/user/{uid}") if f.startswith("wayland-") and not f.endswith(".lock"))
            if w:
                env["WAYLAND_DISPLAY"] = w[0]
        except OSError:
            pass
        try:
            x = sorted((int(f[1:]) for f in os.listdir("/tmp/.X11-unix") if f.startswith("X") and f[1:].isdigit()))
            if x:
                env["DISPLAY"] = f":{x[0]}"
        except OSError:
            pass
        try:
            home = pwd.getpwuid(uid).pw_dir
        except KeyError:
            home = ""
        for xa in (f"/run/user/{uid}/gdm/Xauthority", os.path.join(home, ".Xauthority")):
            if os.path.exists(xa):
                env["XAUTHORITY"] = xa
                break
        return env

    def popup_cmd(self, ev: Event, user: str, uid: int, root: bool) -> list[str]:
        """Comando de la ventana emergente. --no-markup: el texto (que puede venir de un atacante) no se interpreta como formato."""
        crit = ev.sev == "critical"
        secs = self.cfg.getint("general", "popup_seconds", fallback=120)
        text = f"{ev.msg}\n\nMódulo: {ev.source}/{ev.kind}\nHora: {ev.ts[:19].replace('T', ' ')}"
        z = ["zenity", "--question", "--no-markup", "--title", f"Sentinel · ALERTA {SEV_ES[ev.sev]}", "--text", text[:900], "--width=540",
             "--icon-name=" + ("dialog-error" if crit else "dialog-warning"), "--ok-label=Abrir panel", "--cancel-label=Cerrar"]
        if secs > 0 and not crit:
            z.append(f"--timeout={secs}")
        env = [f"{k}={v}" for k, v in self.desktop_env(uid).items()]
        return ["runuser", "-u", user, "--", "env", *env, *z] if root else ["env", *env, *z]

    def popup(self, ev: Event, force: bool = False) -> bool:
        """Muestra una ventana emergente de alerta con botón para abrir el panel. Limita cuántas aparecen por minuto."""
        if not shutil.which("osascript" if plataforma.ES_MAC else "zenity"):
            return False
        tgt = self.desktop_target()
        if not tgt:
            return False
        t = now()
        while self._pop and t - self._pop[0] > 60:
            self._pop.popleft()
        if not force and len(self._pop) >= self.cfg.getint("general", "popup_max_per_min", fallback=3):
            return False
        self._pop.append(t)
        user, uid = tgt
        cmd = (self.popup_mac_cmd if plataforma.ES_MAC else self.popup_cmd)(ev, user, uid, is_root())
        self.last_popup = threading.Thread(target=self._spawn_popup, args=(cmd, user, uid), daemon=True)
        self.last_popup.start()
        return True

    @staticmethod
    def en_sesion_mac(cmd: list[str], user: str, uid: int, root: bool) -> list[str]:
        """Ejecuta un comando en la pantalla del usuario (un servicio de root no la ve)."""
        return ["launchctl", "asuser", str(uid), "sudo", "-u", user, *cmd] if root else cmd

    def popup_mac_cmd(self, ev: Event, user: str, uid: int, root: bool) -> list[str]:
        """Ventana de alerta de macOS con botón «Abrir panel». El texto (que puede venir de un atacante) va como argumento, no dentro del guion."""
        crit = ev.sev == "critical"
        secs = self.cfg.getint("general", "popup_seconds", fallback=120)
        texto = f"{ev.msg}\n\nMódulo: {ev.source}/{ev.kind}\nHora: {ev.ts[:19].replace('T', ' ')}"[:900]
        cierre = f" giving up after {secs}" if secs > 0 and not crit else ""
        guion = ('display dialog (item 2 of argv) with title (item 1 of argv) buttons {"Cerrar", "Abrir panel"} default button "Cerrar" with icon '
                 + ("stop" if crit else "caution") + cierre)
        cmd = ["osascript", "-e", "on run argv", "-e", guion, "-e", "end run", "--", f"Sentinel · ALERTA {SEV_ES[ev.sev]}", texto]
        return self.en_sesion_mac(cmd, user, uid, root)

    def _spawn_popup(self, cmd: list[str], user: str, uid: int) -> None:
        try:
            r = subprocess.run(cmd, capture_output=True, timeout=3600, check=False)
        except (OSError, subprocess.SubprocessError):
            return
        if plataforma.ES_MAC:
            if r.returncode == 0 and b"Abrir panel" in (r.stdout or b""):
                try:
                    subprocess.Popen(self.en_sesion_mac(["open", "-a", "Sentinel"], user, uid, is_root()), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
                except OSError:
                    pass
            return
        if r.returncode == 0:      # pulsó «Abrir panel»
            env = [f"{k}={v}" for k, v in self.desktop_env(uid).items()]
            opener = ["runuser", "-u", user, "--", "env", *env, "sentinel", "ui"] if is_root() else ["env", *env, "sentinel", "ui"]
            try:
                subprocess.Popen(opener, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
            except OSError:
                pass

    def toast_cmd(self, ev: Event, user: str, uid: int, root: bool) -> list[str]:
        secs = self.cfg.getint("general", "notify_seconds_critical" if ev.sev in ("high", "critical") else "notify_seconds", fallback=8)
        t = ["sentinel", "toast", "--sev", ev.sev, "--seg", str(max(2, secs)), "--titulo", f"Sentinel · {SEV_ES[ev.sev]}", ev.msg[:300]]
        env = [f"{k}={v}" for k, v in self.desktop_env(uid).items()]
        return ["runuser", "-u", user, "--", "env", *env, *t] if root else ["env", *env, *t]

    @staticmethod
    def aviso_mac_cmd(titulo: str, texto: str, user: str, uid: int, root: bool) -> list[str]:
        """Notificación de macOS. El título y el texto van como argumentos, nunca dentro del guion: el mensaje puede traer
        texto de un atacante y no debe poder ejecutarse."""
        cmd = ["osascript", "-e", "on run argv", "-e", "display notification (item 2 of argv) with title (item 1 of argv)", "-e", "end run", "--", titulo, texto]
        return ["launchctl", "asuser", str(uid), "sudo", "-u", user, *cmd] if root else cmd

    def desktop(self, ev: Event) -> None:
        tgt = self.desktop_target()
        if not tgt:
            return
        user, uid = tgt
        if plataforma.ES_MAC:
            run(self.aviso_mac_cmd(f"Sentinel · {SEV_ES[ev.sev]}", ev.msg[:300], user, uid, is_root()), 10)
            return
        if self.cfg.get("general", "notify_style", fallback="corner") == "corner" and shutil.which("sentinel"):
            from . import toast                     # aviso propio en la esquina inferior derecha (se cierra solo)
            if toast.available():
                try:
                    subprocess.Popen(self.toast_cmd(ev, user, uid, is_root()), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
                    return
                except OSError:
                    pass
        if not shutil.which("notify-send"):
            return
        secs = self.cfg.getint("general", "notify_seconds_critical" if ev.sev in ("high", "critical") else "notify_seconds", fallback=8)
        # -t: milisegundos visible (el aviso se cierra solo); queda en el historial de notificaciones del escritorio
        base = ["notify-send", "-a", "Sentinel", "-t", str(max(2, secs) * 1000), "-i", "dialog-warning" if ev.sev in ("high", "critical") else "security-medium",
                "-u", "normal", f"Sentinel · {SEV_ES[ev.sev]}", ev.msg[:300]]
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

    def __init__(self, cfg: configparser.ConfigParser, alerter: Alerter, allow: Allow, intel=None):
        self.cfg, self.alerter, self.allow, self.intel = cfg, alerter, allow, intel
        self.path = os.path.join(state_dir(), "bans.json")
        self.bans: dict = read_json(self.path, {}) or {}

    def backend(self) -> str:
        """Motor de bloqueo: en macOS, pf. En Linux, CrowdSec si está activo; si no firewalld, ufw o iptables (en ese orden)."""
        b = self.cfg.get("ban", "backend", fallback="auto")
        if b != "auto":
            return b
        if plataforma.ES_MAC:
            return "pf" if shutil.which("pfctl") else "none"
        active = lambda u: run(["systemctl", "is-active", u], 5)[1].strip().split("\n")[-1] == "active"
        if shutil.which("cscli") and active("crowdsec"):
            return "crowdsec"
        if shutil.which("firewall-cmd") and active("firewalld"):
            return "firewalld"
        try:
            ufw_on = "ENABLED=yes" in open("/etc/ufw/ufw.conf", encoding="utf-8").read()
        except OSError:
            ufw_on = False
        if shutil.which("ufw") and ufw_on:
            return "ufw"
        return "iptables" if shutil.which("iptables") else "none"

    @staticmethod
    def _cmds(be: str, ip: str, ttl: int) -> tuple[list[str], list[str] | None]:
        """(comando para bloquear, comando para desbloquear) de cada motor."""
        v6 = ":" in ip
        if be == "pf":
            return pf.tabla("add", ip), pf.tabla("delete", ip)
        if be == "crowdsec":
            return ["cscli", "decisions", "add", "--ip", ip, "--duration", f"{ttl}s", "--type", "ban"], ["cscli", "decisions", "delete", "--ip", ip]
        if be == "firewalld":
            rule = f'rule family="{"ipv6" if v6 else "ipv4"}" source address="{ip}" drop'
            return ["firewall-cmd", f"--add-rich-rule={rule}", f"--timeout={ttl}"], ["firewall-cmd", f"--remove-rich-rule={rule}"]
        if be == "iptables":
            t = "ip6tables" if v6 else "iptables"
            return [t, "-I", "INPUT", "1", "-s", ip, "-m", "comment", "--comment", "sentinel", "-j", "DROP"], [t, "-D", "INPUT", "-s", ip, "-m", "comment", "--comment", "sentinel", "-j", "DROP"]
        return ["ufw", "insert", "1", "deny", "from", ip, "to", "any", "comment", "sentinel"], ["ufw", "delete", "deny", "from", ip, "to", "any"]

    def ban(self, ip: str, reason: str, ttl: int | None = None, manual: bool = False) -> bool:
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
        cmd, _ = self._cmds(be, ip, ttl)
        if be == "crowdsec":
            cmd += ["--reason", f"sentinel: {reason}"[:180]]
        error = pf.preparar(run, state_dir()) if be == "pf" else ""
        rc, out = (1, error) if error else run(cmd, 20)
        if rc != 0:
            self.alerter.emit("high", "ban", "fallo", f"No se pudo bloquear {ip}: {out.strip()[:160]}", key=f"banfail:{ip}")
            return False
        if be == "pf":
            run(["pfctl", "-k", ip], 20)  # corta también las conexiones que ya tenía abiertas
        self.bans[ip] = {"until": now() + ttl, "reason": reason, "backend": be, "since": iso()}
        atomic_write_json(self.path, self.bans, share=True)
        where = self.intel.geo_text(ip) if self.intel else ""
        if self.intel:
            self.intel.ban_started(ip, now() + ttl, reason, be, manual)
        self.alerter.emit("high", "ban", "bloqueada", f"IP {ip}{f' ({where})' if where else ''} bloqueada por {ttl // 3600} h con {be}: {reason}", key=f"ban:{ip}:{int(now() // 60)}", ip=ip, ttl=ttl)
        return True

    def reafirmar(self) -> list[str]:
        """Vuelve a poner en pf los bloqueos vigentes: macOS los olvida al reiniciar. En Linux no hace nada."""
        guardados = read_json(self.path, {}) or {}  # del disco: «sentinel» pudo bloquear o liberar desde la terminal
        activos = [ip for ip, b in guardados.items() if b.get("backend") == "pf" and b["until"] > now()]
        if not activos or not is_root():
            return []
        self.bans = guardados
        error = pf.preparar(run, state_dir())
        if error:
            self.alerter.emit("high", "ban", "fallo", f"No pude reponer los bloqueos: {error}", key="banfail:pf")
            return []
        return [ip for ip in activos if run(pf.tabla("add", ip), 20)[0] == 0]

    def _release(self, ip: str, be: str) -> None:
        if not is_root() or be in ("crowdsec", "firewalld", "none"):
            return  # CrowdSec y firewalld caducan solos (--duration / --timeout)
        _, undo = self._cmds(be, ip, 0)
        if undo:
            run(undo, 20)

    def expire(self) -> list[str]:
        gone = []
        for ip, b in list(self.bans.items()):
            if b["until"] <= now():
                self._release(ip, b.get("backend", ""))
                if self.intel:
                    self.intel.ban_released(ip, "caducó", expired=True)
                gone.append(ip)
                del self.bans[ip]
        if gone:
            atomic_write_json(self.path, self.bans, share=True)
        return gone

    def unban(self, ip: str, by: str = "usuario") -> bool:
        b = self.bans.pop(ip, None)
        if self.intel:
            self.intel.ban_released(ip, by)
        if is_root():
            for be in ("pf", "crowdsec", "firewalld", "ufw", "iptables"):
                if be == "crowdsec" and not shutil.which("cscli"):
                    continue
                _, undo = self._cmds(be, ip, 0)
                if undo and shutil.which(undo[0]):
                    run(undo, 20)
        atomic_write_json(self.path, self.bans, share=True)
        return b is not None
