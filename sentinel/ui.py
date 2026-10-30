"""Panel gráfico de Sentinel: aplicación web local (solo 127.0.0.1) con llave de acceso. Sin internet ni dependencias externas.

Seguridad: escucha solo en loopback; exige la llave (cookie SameSite=Strict); valida Host y Origin (anti DNS-rebinding y CSRF); CSP estricta;
los textos de los eventos (que pueden venir de un atacante) se muestran siempre como texto, nunca como HTML. Las acciones son una lista cerrada
y las que necesitan permisos de administrador pasan por pkexec (la ventana de clave del sistema)."""
from __future__ import annotations

import collections
import hmac
import http.server
import ipaddress
import json
import os
import re
import secrets
import shutil
import socketserver
import subprocess
import threading
import time
import urllib.parse
import webbrowser

from . import audit, core, explain, geoip, incidents

STATIC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ui")
TYPES = {".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8", ".svg": "image/svg+xml"}
UNITS = ("sentinel-monitor", "sentinel-honeypot", "sentinel-scan.timer", "sentinel-report.timer")
DEFAULT_PORT = 8737


def token_path() -> str:
    return os.path.join(os.environ.get("XDG_CONFIG_HOME", os.path.expanduser("~/.config")), "sentinel", "ui_token")


def load_token() -> str:
    p = token_path()
    try:
        t = open(p, encoding="utf-8").read().strip()
        if len(t) >= 32:
            return t
    except OSError:
        pass
    os.makedirs(os.path.dirname(p), mode=0o700, exist_ok=True)
    t = secrets.token_urlsafe(32)
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(t)
    return t


class Data:
    """Reúne los datos que muestra el panel (todo de solo lectura) y guarda en caché lo que tarda."""

    def __init__(self, cfg=None):
        self.cfg = cfg or core.load_config()
        self._audit: dict | None = None
        self._audit_at = 0.0
        self._audit_running = False
        self._svc: tuple[float, dict] = (0, {})
        self.lock = threading.Lock()

    def services(self) -> dict:
        if time.time() - self._svc[0] < 4:
            return self._svc[1]
        res = {}
        for u in UNITS:
            res[u] = core.run(["systemctl", "is-active", u], 4)[1].strip().split("\n")[-1] or "desconocido"
        self._svc = (time.time(), res)
        return res

    def audit(self, force: bool = False) -> dict:
        with self.lock:
            stale = time.time() - self._audit_at > 900
            if (force or stale or self._audit is None) and not self._audit_running:
                self._audit_running = True
                threading.Thread(target=self._run_audit, daemon=True).start()
            return {**(self._audit or {"score": None, "checks": []}), "running": self._audit_running, "at": self._audit_at}

    def _run_audit(self) -> None:
        try:
            r = audit.run_audit(self.cfg)
            with self.lock:
                self._audit, self._audit_at = r, time.time()
        finally:
            self._audit_running = False

    def overview(self) -> dict:
        now = core.now()
        ev7 = core.read_events(now - 7 * 86400)
        ev24 = [e for e in ev7 if e["epoch"] >= now - 86400]
        count = lambda lst: {s: sum(1 for e in lst if e["sev"] == s) for s in core.SEV}
        h0 = int(now // 3600) * 3600
        hours = [{"t": h0 - (23 - i) * 3600, "c": {s: 0 for s in core.SEV}} for i in range(24)]
        for e in ev24:
            i = 23 - int((h0 - int(e["epoch"] // 3600) * 3600) // 3600)
            if 0 <= i < 24:
                hours[i]["c"][e["sev"]] += 1
        ips = collections.Counter(e["data"].get("ip") for e in ev7 if (e.get("data") or {}).get("ip") and core.SEV[e["sev"]] >= 2)
        bans = core.read_json(os.path.join(core.state_dir(), "bans.json"), {}) or {}
        active = {ip: b for ip, b in bans.items() if b["until"] > now}
        svc = self.services()
        hb = core.read_json(os.path.join(core.state_dir(), "heartbeat.json"))
        age = int(now - hb["epoch"]) if hb else None
        meta = core.read_json(os.path.join(core.state_dir(), "fim_meta.json"))
        c24 = count(ev24)
        alive = svc.get("sentinel-monitor") == "active" and age is not None and age < 120
        if c24["critical"]:
            level, why = "peligro", f"{c24['critical']} evento(s) crítico(s) en las últimas 24 horas"
        elif c24["high"] or not alive:
            level, why = "atencion", (f"{c24['high']} evento(s) de gravedad alta en las últimas 24 horas" if c24["high"] else "El monitor de Sentinel no está respondiendo")
        elif c24["medium"]:
            level, why = "revision", f"{c24['medium']} evento(s) para revisar en las últimas 24 horas"
        else:
            level, why = "protegido", "Sin eventos graves en las últimas 24 horas"
        return {"version": core.VERSION, "now": now, "level": level, "why": why, "alive": alive, "heartbeat_age": age, "services": svc,
                "baseline": meta, "counts24": c24, "counts7": count(ev7), "hours": hours, "top_ips": [{"ip": ip, "n": n, "banned": ip in active} for ip, n in ips.most_common(8)],
                "bans": [{"ip": ip, "reason": b["reason"], "backend": b["backend"], "left": int(b["until"] - now)} for ip, b in sorted(active.items(), key=lambda kv: kv[1]["until"])],
                "events": ev7[-60:][::-1], "root": core.is_root(), "installed": sentinel_bin() is not None}

    def _store(self):
        try:
            return incidents.Store(readonly=True)
        except Exception:
            return None

    def attackers(self, q: str = "", status: str = "") -> dict:
        st = self._store()
        if not st:
            return {"items": [], "stats": None}
        try:
            kinds = st.kinds_by_ip()
            items = []
            for r in st.list_ips(200, q, status):
                pts, nivel = explain.puntaje(kinds.get(r["ip"], {}), 0, 0)
                items.append({"ip": r["ip"], "riesgo": pts, "nivel": nivel, "lugar": geoip.place_text(r), "pais": r.get("country"), "codigo": r.get("country_code"), "intentos": r["attempts"], "estado": r["status"],
                              "primera": r["first_seen"], "ultima": r["last_seen"], "bloqueo_hasta": r.get("ban_until"), "paquetes": r.get("pkt_total", 0)})
            return {"items": items, "stats": st.stats()}
        finally:
            st.close()

    def attacker(self, ip: str) -> dict | None:
        st = self._store()
        if not st:
            return None
        try:
            d = st.dossier(ip)
            return {"dossier": d, "explicacion": explain.explicar(d), "paquetes_recientes": st.recent_packets(30, ip)} if d else None
        finally:
            st.close()

    def packets(self) -> dict:
        st = self._store()
        rec = []
        if st:
            try:
                rec = st.recent_packets(60)
            finally:
                st.close()
        for r in rec:
            r["clave"] = explain.clasificar_paquete(r["proto"], r["flags"], r["dport"])
            r["info"] = {k: explain.PAQUETES[r["clave"]][k] for k in ("nombre", "nivel", "nino")}
        stats = core.read_json(os.path.join(core.state_dir(), "packets_stats.json"))
        return {"recientes": rec, "captura": stats, "captura_viva": bool(stats and core.now() - stats.get("ts", 0) < 120 and stats.get("activo"))}

    @staticmethod
    def glossary() -> dict:
        return {"paquetes": explain.PAQUETES, "tipos": explain.TIPOS, "glosario": explain.GLOSARIO, "niveles": {k: v[1] for k, v in explain.NIVELES.items()}}

    def events(self, hours: int, min_sev: str, q: str, limit: int) -> list[dict]:
        ev = core.read_events(core.now() - hours * 3600, min_sev)
        if q:
            ql = q.lower()
            ev = [e for e in ev if ql in (e["msg"] + e["kind"] + e["source"] + json.dumps(e.get("data") or {}, ensure_ascii=False)).lower()]
        return ev[-limit:][::-1]


def sentinel_bin() -> str | None:
    for p in ("/usr/bin/sentinel", "/usr/local/bin/sentinel"):
        if os.path.exists(p):
            return p
    return shutil.which("sentinel")


def build_action(body: dict) -> list[str]:
    """Convierte una acción pedida por el panel en los argumentos de `sentinel`. Lista cerrada y con valores validados."""
    name = body.get("name")
    if name == "scan":
        return ["scan", "--quiet"]
    if name == "scan_deep":
        return ["scan", "--deep", "--quiet"]
    if name == "report":
        return ["report"]
    if name == "unban":
        ip = str(body.get("ip", ""))
        ipaddress.ip_address(ip)
        return ["bans", "unban", ip]
    if name == "ban":
        ip = str(body.get("ip", ""))
        ipaddress.ip_address(ip)
        horas = int(body.get("horas", 24))
        if not 1 <= horas <= 720:
            raise ValueError("horas entre 1 y 720")
        motivo = re.sub(r"[^\w .,:()/-]", "", str(body.get("motivo", "bloqueo manual")))[:80] or "bloqueo manual"
        return ["bans", "ban", ip, "--horas", str(horas), "--motivo", motivo]
    if name == "baseline_accept":
        paths = body.get("paths") or []
        if not isinstance(paths, list) or len(paths) > 50 or not all(isinstance(p, str) and p.startswith("/") and re.fullmatch(r"[\w./@+=:,~-]+", p) for p in paths):
            raise ValueError("rutas inválidas")
        return ["baseline", "accept", *paths]
    if name == "allow":
        tipo, val = str(body.get("tipo", "")), str(body.get("valor", ""))
        if tipo == "ip":
            ipaddress.ip_network(val, strict=False)
        elif tipo == "port":
            if not (val.isdigit() and 0 < int(val) < 65536):
                raise ValueError("puerto inválido")
        elif tipo == "proc":
            if not re.fullmatch(r"[\w.-]{1,40}", val):
                raise ValueError("nombre de proceso inválido")
        elif tipo == "path":
            if not (val.startswith("/") and re.fullmatch(r"[\w./*?@+=:,~-]+", val)):
                raise ValueError("ruta inválida")
        else:
            raise ValueError("tipo inválido")
        return ["allow", tipo, val]
    raise ValueError("acción desconocida")


def run_action(body: dict) -> dict:
    try:
        args = build_action(body)
    except (ValueError, TypeError) as e:
        return {"ok": False, "out": f"Acción rechazada: {e}"}
    binp = sentinel_bin()
    if not binp:
        return {"ok": False, "out": "Sentinel no está instalado en el sistema: ejecuta «sudo ./install.sh»."}
    cmd = [binp, *args] if core.is_root() else ["pkexec", binp, *args]
    if not core.is_root() and not shutil.which("pkexec"):
        return {"ok": False, "out": "Falta pkexec para pedir permisos de administrador."}
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=300, check=False)
    except (OSError, subprocess.SubprocessError) as e:
        return {"ok": False, "out": str(e)}
    out = ((r.stdout or "") + (r.stderr or "")).strip()
    if r.returncode == 126:
        out = "No se autorizó la acción (clave cancelada o incorrecta)."
    return {"ok": r.returncode in (0, 1, 2) if args[0] == "scan" else r.returncode == 0, "out": out[-3000:], "code": r.returncode}


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "Sentinel"
    sys_version = ""

    def log_message(self, *a):
        pass

    # ---- seguridad
    def _host_ok(self) -> bool:
        port = self.server.server_address[1]
        return (self.headers.get("Host") or "") in (f"127.0.0.1:{port}", f"localhost:{port}")

    def _token(self) -> str:
        c = self.headers.get("Cookie") or ""
        m = re.search(r"(?:^|;\s*)sentinel_t=([\w-]+)", c)
        return m.group(1) if m else ""

    def _authed(self) -> bool:
        return hmac.compare_digest(self._token(), self.server.token)

    def _send(self, code: int, body: bytes, ctype: str, extra: dict | None = None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code: int = 200) -> None:
        self._send(code, json.dumps(obj, ensure_ascii=False).encode(), "application/json; charset=utf-8")

    def _deny(self, msg: str = "Acceso denegado. Abre el panel con el comando «sentinel ui».") -> None:
        self._send(403, f"<meta charset=utf-8><body style='font:16px system-ui;padding:3rem'><h1>🛡️ Sentinel</h1><p>{msg}</p>".encode(), TYPES[".html"])

    # ---- rutas
    def do_GET(self) -> None:
        if not self._host_ok():
            return self._deny("Host no permitido.")
        u = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(u.query)
        t = (q.get("t") or [""])[0]
        if t and hmac.compare_digest(t, self.server.token):      # primera visita desde el lanzador: guarda la llave en una cookie y limpia la URL
            return self._send(302, b"", "text/plain", {"Location": "/", "Set-Cookie": f"sentinel_t={t}; HttpOnly; SameSite=Strict; Path=/; Max-Age=2592000"})
        if not self._authed():
            return self._deny()
        d: Data = self.server.data
        if u.path in ("/", "/index.html"):
            return self._static("index.html")
        if u.path.startswith("/static/"):
            return self._static(u.path[len("/static/"):])
        if u.path == "/api/overview":
            return self._json(d.overview())
        if u.path == "/api/events":
            hours = max(1, min(720, int((q.get("hours") or ["24"])[0] or 24)))
            sev = (q.get("min") or ["info"])[0]
            return self._json(d.events(hours, sev if sev in core.SEV else "info", (q.get("q") or [""])[0][:100], max(1, min(500, int((q.get("limit") or ["200"])[0] or 200)))))
        if u.path == "/api/audit":
            return self._json(d.audit())
        if u.path == "/api/attackers":
            return self._json(d.attackers((q.get("q") or [""])[0][:60], (q.get("estado") or [""])[0][:20]))
        if u.path == "/api/attacker":
            ip = (q.get("ip") or [""])[0]
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                return self._json({"error": "IP inválida"}, 400)
            r = d.attacker(ip)
            return self._json(r) if r else self._json({"error": "sin expediente"}, 404)
        if u.path == "/api/packets":
            return self._json(d.packets())
        if u.path == "/api/glossary":
            return self._json(d.glossary())
        self._send(404, b"no encontrado", "text/plain; charset=utf-8")

    def do_POST(self) -> None:
        if not self._host_ok() or not self._authed():
            return self._deny()
        port = self.server.server_address[1]
        origin = self.headers.get("Origin")
        if origin and origin not in (f"http://127.0.0.1:{port}", f"http://localhost:{port}"):
            return self._deny("Origen no permitido.")
        if "application/json" not in (self.headers.get("Content-Type") or ""):
            return self._deny("Tipo no permitido.")
        try:
            n = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(min(n, 20000)) or b"{}")
        except (ValueError, OSError):
            return self._json({"ok": False, "out": "Solicitud inválida"}, 400)
        if self.path == "/api/audit/refresh":
            return self._json(self.server.data.audit(force=True))
        if self.path == "/api/action":
            return self._json(run_action(body))
        self._send(404, b"no encontrado", "text/plain; charset=utf-8")

    def _static(self, name: str) -> None:
        if not re.fullmatch(r"[\w-]+\.(html|js|css|svg)", name):
            return self._send(404, b"no encontrado", "text/plain; charset=utf-8")
        try:
            with open(os.path.join(STATIC, name), "rb") as f:
                body = f.read()
        except OSError:
            return self._send(404, b"no encontrado", "text/plain; charset=utf-8")
        self._send(200, body, TYPES[os.path.splitext(name)[1]])


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, port: int, token: str, data: Data):
        super().__init__(("127.0.0.1", port), Handler)
        self.token, self.data = token, data


def open_window(url: str) -> None:
    """Abre el panel como una ventana de aplicación (sin barra de direcciones) si hay Chrome/Chromium; si no, en el navegador."""
    for b in ("google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "brave-browser", "microsoft-edge"):
        exe = shutil.which(b)
        if exe:
            try:
                subprocess.Popen([exe, f"--app={url}", "--window-size=1320,900", "--class=Sentinel"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
                return
            except OSError:
                continue
    webbrowser.open(url)


def run_ui(port: int = DEFAULT_PORT, open_browser: bool = True, cfg=None) -> int:
    token = load_token()
    url = f"http://127.0.0.1:{port}/?t={token}"
    try:
        srv = Server(port, token, Data(cfg))
    except OSError:
        print(f"El panel ya está abierto en el puerto {port}.")
        if open_browser:
            open_window(url)
        return 0
    print(f"Panel de Sentinel en http://127.0.0.1:{port}/  (solo este equipo). Ctrl+C para cerrar.")
    if open_browser:
        threading.Timer(0.6, open_window, args=(url,)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0
