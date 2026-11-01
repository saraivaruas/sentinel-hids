"""Vigilancia de los registros de acceso de tus sitios web (nginx, apache): detecta inyección SQL, rutas prohibidas, archivos secretos, ejecución de comandos,
escáneres, ráfagas de errores 404 y fuerza bruta de inicio de sesión, y bloquea a quien insiste. Solo lee los registros; no toca el servidor web."""
from __future__ import annotations

import collections
import glob
import os
import re
import time
import urllib.parse

from . import core

LINE = re.compile(r'^(\S+) \S+ \S+ \[[^\]]+\] "(\S+) (\S+)[^"]*" (\d{3}) \S+(?: "[^"]*" "([^"]*)")?')

SQLI = re.compile(r"union\s+(?:all\s+)?select|\bor\s+1\s*=\s*1|'\s*or\s*'|information_schema|sleep\s*\(\s*\d|benchmark\s*\(|load_file\s*\(|into\s+outfile|;\s*drop\s+table|extractvalue\s*\(|updatexml\s*\(")
TRAVERSAL = re.compile(r"\.\./|\.\.\\|/etc/passwd|/etc/shadow|/proc/self|boot\.ini|win\.ini|%00")
SECRETOS = re.compile(r"/\.env(?:\.|$|\?)|/\.git(?:/|$)|/\.svn/|wp-config(?:\.php)?(?:\.|~|$|\?)|/\.aws/|/id_rsa|/\.ssh/|phpinfo\.php|/\.ds_store|\.sql(?:\.gz)?(?:$|\?)|\.(?:bak|old|swp|orig)(?:$|\?)|/backup\.(?:zip|tar|gz)|/\.htpasswd|/composer\.(?:json|lock)$|/config\.(?:php|yml|json)\.(?:bak|old)")
RCE = re.compile(r"\$\{jndi:|\$%7bjndi|\$\{\$\{|;\s*(?:wget|curl)\s|\|\s*(?:sh|bash)\b|`[^`]{1,40}`|\bbase64_decode\s*\(|\beval\s*\(|<\?php|\bsystem\s*\(|\bexec\s*\(|\bpassthru\s*\(|cmd=|/bin/(?:ba)?sh|%24%7bjndi|\(\)\s*\{\s*:;\s*\}")
XSS = re.compile(r"<script|%3cscript|javascript:|onerror\s*=|onload\s*=|<svg[^>]*on\w+=")
SONDEO = re.compile(r"/wp-login\.php|/xmlrpc\.php|/wp-admin|/phpmyadmin|/pma/|/adminer|/manager/html|/cgi-bin/|/vendor/phpunit|/actuator|/solr/|/jenkins|/console|/boaform|/hnap1|/remote/login|/owa/|/ecp/")
LOGIN = re.compile(r"login|signin|sign-in|wp-login|xmlrpc|/auth|/session|/token|password")
ESCANERES = re.compile(r"sqlmap|nikto|nmap|masscan|zgrab|dirbuster|gobuster|wpscan|nuclei|acunetix|nessus|openvas|havij|hydra|fuzz faster|ffuf|feroxbuster|burp|w3af|netsparker|metasploit|jaeles", re.I)


def parse(line: str) -> dict | None:
    m = LINE.match(line)
    if not m:
        return None
    ip, method, raw, status, ua = m.groups()
    path = urllib.parse.unquote_plus(urllib.parse.unquote(raw)).lower()[:600]
    return {"ip": ip, "method": method.upper(), "raw": raw[:300], "path": path, "status": int(status), "ua": (ua or "")[:200]}


def classify(r: dict) -> list[str]:
    """Qué intentos hay en una petición (puede ser más de uno)."""
    out, p, st = [], r["path"], r["status"]
    if RCE.search(p):
        out.append("web_rce")
    if SQLI.search(p):
        out.append("web_sqli")
    if TRAVERSAL.search(p):
        out.append("web_traversal")
    if XSS.search(p):
        out.append("web_xss")
    if SECRETOS.search(p) and (st != 200 or "/.env" in p):        # pedirlos es sospechoso; que respondan 200 con un .env es además una fuga
        out.append("web_secretos")
    if r["ua"] and ESCANERES.search(r["ua"]):
        out.append("web_escaner")
    if SONDEO.search(p) and st in (401, 403, 404, 405, 301, 302) and r["method"] == "GET":
        out.append("web_sondeo")
    if r["method"] == "POST" and LOGIN.search(p):
        out.append("web_login")
    if st == 404 and not out:
        out.append("web_404")
    return out


class WebWatch:
    def __init__(self, cfg, alerter: core.Alerter, allow: core.Allow, banner: core.Banner, intel=None):
        self.cfg, self.alerter, self.allow, self.banner, self.intel = cfg, alerter, allow, banner, intel
        g = lambda k, d: cfg.getint("weblog", k, fallback=d)
        self.win, self.n404, self.nlogin, self.nattack, self.nsondeo = g("window", 600), g("scan_404", 30), g("login_fail", 15), g("attack_hits", 3), g("probe_hits", 8)
        self.ban_on = cfg.getboolean("weblog", "ban", fallback=True)
        self.hits: dict[tuple, collections.deque] = collections.defaultdict(collections.deque)
        self.fired: dict[tuple, float] = {}
        self.pos: dict[str, tuple[int, int]] = {}

    def paths(self) -> list[str]:
        out = []
        for pat in core.csv(self.cfg.get("weblog", "paths", fallback="")):
            out += glob.glob(pat)
        return sorted({p for p in out if os.path.isfile(p)})

    def _count(self, ip: str, kind: str, t: float) -> int:
        q = self.hits[(ip, kind)]
        q.append(t)
        window = 60 if kind == "web_404" else self.win
        while q and t - q[0] > window:
            q.popleft()
        return len(q)

    def feed(self, line: str, t: float | None = None) -> list[str]:
        """Analiza una línea del registro; devuelve los tipos de ataque que disparó una alerta."""
        r = parse(line)
        if not r or self.allow.ip_protected(r["ip"]):
            return []
        t = t if t is not None else core.now()
        fired = []
        for kind in classify(r):
            n = self._count(r["ip"], kind, t)
            limit = {"web_rce": 1, "web_escaner": 1, "web_404": self.n404, "web_login": self.nlogin, "web_sondeo": self.nsondeo}.get(kind, self.nattack)
            if self.intel and kind != "web_404":
                self.intel.attempt(r["ip"], kind, port=80, proto="tcp", detail=f"{r['method']} {r['raw'][:120]} → {r['status']}")
            if n >= limit and t - self.fired.get((r["ip"], kind), 0) > self.win:
                self.fired[(r["ip"], kind)] = t
                fired.append(kind)
                self._alert(r, kind, n)
        return fired

    LABEL = {"web_rce": "intento de ejecutar comandos", "web_sqli": "inyección SQL", "web_traversal": "salir de la carpeta del sitio (../)", "web_xss": "inyección de scripts (XSS)",
             "web_secretos": "búsqueda de archivos secretos (.env, .git, copias de seguridad)", "web_escaner": "escáner de vulnerabilidades", "web_sondeo": "búsqueda de paneles de administración",
             "web_login": "fuerza bruta de inicio de sesión", "web_404": "ráfaga de páginas inexistentes (escaneo)"}

    def _alert(self, r: dict, kind: str, n: int) -> None:
        graves = kind in ("web_rce", "web_sqli", "web_traversal", "web_escaner", "web_login")
        self.alerter.emit("high" if graves else "medium", "web", kind, f"{self.LABEL[kind].capitalize()} desde {r['ip']} ({n} vez/veces): {r['method']} {r['raw'][:100]} → {r['status']}",
                          key=f"web:{kind}:{r['ip']}:{int(core.now() // 3600)}", ip=r["ip"], path=r["raw"][:160], status=r["status"])
        if self.ban_on:
            self.banner.ban(r["ip"], f"ataque web: {self.LABEL[kind]}")

    def follow(self, stop=lambda: False, poll: float = 1.0) -> None:
        """Sigue los registros como `tail -F` (aguanta la rotación) y analiza solo lo nuevo."""
        for p in self.paths():
            try:
                st = os.stat(p); self.pos[p] = (st.st_ino, st.st_size)
            except OSError:
                pass
        while not stop():
            for p in self.paths():
                try:
                    st = os.stat(p)
                    ino, off = self.pos.get(p, (st.st_ino, 0))
                    if ino != st.st_ino or st.st_size < off:
                        off = 0                                    # el registro rotó
                    if st.st_size > off:
                        with open(p, "r", encoding="utf-8", errors="replace") as f:
                            f.seek(off)
                            for ln in f.read(5_000_000).splitlines():
                                self.feed(ln)
                            off = f.tell()
                    self.pos[p] = (st.st_ino, off)
                except OSError:
                    pass
            time.sleep(poll)
