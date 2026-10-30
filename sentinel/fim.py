"""Vigilante de integridad: compara el estado de archivos críticos contra una referencia (SHA-256, permisos, dueño) y busca puertas traseras web."""
from __future__ import annotations

import fnmatch
import glob
import hashlib
import os
import re
import stat
import time

from . import core

CRITICAL = [r"^/etc/(passwd|shadow|gshadow|group|sudoers)(\.|$)", r"^/etc/sudoers\.d/", r"/\.ssh/authorized_keys2?$", r"^/etc/ld\.so\.preload$", r"^/etc/pam\.d/", r"^/root/\.ssh/"]
HIGH = [r"^/etc/ssh/", r"^/usr/local/(s)?bin/", r"^/etc/systemd/system/", r"^/etc/cron", r"^/etc/rc\.local$", r"^/opt/sentinel", r"^/etc/profile", r"^/etc/environment$",
        r"/\.(bashrc|profile|bash_profile|zshrc)$", r"/\.config/autostart/", r"^/etc/crowdsec/", r"^/etc/ufw/", r"^/etc/hosts$", r"^/etc/sentinel/", r"/\.ssh/"]

# Firmas de puertas traseras y shells inversas (patrones comunes, no exhaustivos).
SIGNATURES = {
    "php: eval de datos codificados": re.compile(rb"eval\s*\(\s*(?:base64_decode|gzinflate|str_rot13|gzuncompress)\s*\(", re.I),
    "php: ejecución de comandos desde la petición": re.compile(rb"(?:system|shell_exec|passthru|exec|popen|proc_open)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)", re.I),
    "php: eval de la petición": re.compile(rb"eval\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)", re.I),
    "php: asserts con la petición": re.compile(rb"assert\s*\(\s*\$_(?:GET|POST|REQUEST)", re.I),
    "shell inversa (/dev/tcp)": re.compile(rb"/dev/tcp/\d{1,3}(?:\.\d{1,3}){3}/\d+"),
    "shell inversa (bash -i)": re.compile(rb"bash\s+-i\s+>&\s*/dev/tcp/"),
    "shell inversa (nc -e)": re.compile(rb"\bn(?:c|cat)\b[^\n]{0,40}\s-e\s+/bin/(?:ba)?sh"),
    "python: shell inversa": re.compile(rb"socket\.socket\([^)]*\)[\s\S]{0,200}(?:pty\.spawn|os\.dup2)"),
    "descarga y ejecución (curl|sh)": re.compile(rb"(?:curl|wget)\s+[^\n|;]{4,200}\|\s*(?:ba)?sh"),
}


def classify(path: str, www: list[str]) -> str:
    if any(re.search(p, path) for p in CRITICAL):
        return "critical"
    if any(re.search(p, path) for p in HIGH):
        return "high"
    if any(path.startswith(w.rstrip("/") + "/") for w in www):
        return "medium"
    return "medium"


def expand(paths: list[str]) -> list[str]:
    out: list[str] = []
    for p in paths:
        hit = glob.glob(p) if any(c in p for c in "*?[") else [p]
        out += [h for h in hit if os.path.lexists(h)]
    return sorted(set(out))


def _entry(path: str, st: os.stat_result, hash_max: int, old: dict | None, rehash: bool) -> dict:
    e = {"mode": stat.S_IMODE(st.st_mode), "uid": st.st_uid, "gid": st.st_gid, "size": st.st_size, "mtime": st.st_mtime_ns, "ino": st.st_ino, "type": "d" if stat.S_ISDIR(st.st_mode) else "l" if stat.S_ISLNK(st.st_mode) else "f"}
    if e["type"] == "l":
        try:
            e["link"] = os.readlink(path)
        except OSError:
            pass
    elif e["type"] == "f":
        if st.st_size > hash_max:
            e["sha"] = "(grande)"
        elif old and not rehash and old.get("sha") and (old.get("size"), old.get("mtime"), old.get("ino")) == (e["size"], e["mtime"], e["ino"]):
            e["sha"] = old["sha"]
        else:
            h = hashlib.sha256()
            try:
                with open(path, "rb") as f:
                    for blk in iter(lambda: f.read(1 << 20), b""):
                        h.update(blk)
                e["sha"] = h.hexdigest()
            except OSError:
                e["sha"] = "(ilegible)"
    return e


def snapshot(roots: list[str], excludes: list[str], hash_max: int, old: dict | None = None, rehash: bool = False, max_files: int = 300000) -> dict:
    """Recorre las rutas sin seguir enlaces simbólicos y devuelve {ruta: atributos}."""
    snap: dict[str, dict] = {}
    old = old or {}

    def skip(p: str) -> bool:
        # «*/.git/*» debe excluir también la carpeta .git en sí (y no recorrerla)
        return any(fnmatch.fnmatch(p, x) or fnmatch.fnmatch(p + "/", x) for x in excludes)

    def add(p: str) -> None:
        if len(snap) >= max_files or skip(p):
            return
        try:
            st = os.lstat(p)
        except OSError:
            return
        snap[p] = _entry(p, st, hash_max, old.get(p), rehash)

    def walk(d: str) -> None:
        add(d)
        try:
            with os.scandir(d) as it:
                for de in it:
                    p = de.path
                    if skip(p):
                        continue
                    try:
                        if de.is_dir(follow_symlinks=False):
                            walk(p)
                        else:
                            add(p)
                    except OSError:
                        continue
        except OSError:
            return

    for r in roots:
        if os.path.isdir(r) and not os.path.islink(r):
            walk(r)
        else:
            add(r)
    return snap


def diff(old: dict, new: dict, www: list[str] | None = None) -> list[dict]:
    """Diferencias entre dos fotos. Cada una: {kind, path, sev, detail}."""
    www = www or []
    out = []
    for p in sorted(set(old) | set(new)):
        o, n = old.get(p), new.get(p)
        sev = classify(p, www)
        if o is None:
            d = "archivo nuevo" if n["type"] == "f" else "carpeta nueva" if n["type"] == "d" else "enlace nuevo"
            if n["mode"] & 0o6000 and n["type"] == "f":
                out.append({"kind": "setuid", "path": p, "sev": "critical", "detail": f"archivo nuevo con permiso SUID/SGID ({oct(n['mode'])})"})
            elif n["type"] != "d":
                out.append({"kind": "added", "path": p, "sev": sev, "detail": d})
            else:
                out.append({"kind": "added", "path": p, "sev": "low" if sev == "medium" else sev, "detail": d})
        elif n is None:
            out.append({"kind": "removed", "path": p, "sev": sev if sev in ("critical", "high") else "medium", "detail": "eliminado"})
        else:
            if o.get("type") != n.get("type"):
                out.append({"kind": "type", "path": p, "sev": "high" if sev == "medium" else sev, "detail": f"cambió de tipo ({o.get('type')} → {n.get('type')})"})
                continue
            if n["type"] == "f" and o.get("sha") != n.get("sha") and "(grande)" not in (o.get("sha"), n.get("sha")):
                out.append({"kind": "modified", "path": p, "sev": sev, "detail": "contenido modificado", "sha": n.get("sha")})
            elif n["type"] == "f" and n["size"] != o["size"] and n.get("sha") == "(grande)":
                out.append({"kind": "modified", "path": p, "sev": sev, "detail": f"tamaño cambió ({o['size']} → {n['size']})"})
            if n["type"] == "l" and o.get("link") != n.get("link"):
                out.append({"kind": "link", "path": p, "sev": "high" if sev == "medium" else sev, "detail": f"enlace redirigido ({o.get('link')} → {n.get('link')})"})
            if (o["mode"] & 0o6000) != (n["mode"] & 0o6000) and n["mode"] & 0o6000:
                out.append({"kind": "setuid", "path": p, "sev": "critical", "detail": f"se activó SUID/SGID ({oct(o['mode'])} → {oct(n['mode'])})"})
            elif o["mode"] != n["mode"]:
                worse = bool(n["mode"] & 0o002) and not (o["mode"] & 0o002)
                out.append({"kind": "perm", "path": p, "sev": "high" if worse else "low" if sev == "medium" else sev, "detail": f"permisos {oct(o['mode'])} → {oct(n['mode'])}" + (" (ahora escribible por todos)" if worse else "")})
            if (o["uid"], o["gid"]) != (n["uid"], n["gid"]):
                out.append({"kind": "owner", "path": p, "sev": "high" if sev != "medium" else "medium", "detail": f"dueño {o['uid']}:{o['gid']} → {n['uid']}:{n['gid']}"})
    return out


def scan_content(path: str, exts: list[str], limit: int = 2_000_000) -> list[str]:
    """Busca firmas de puertas traseras en un archivo de aplicación web."""
    if os.path.splitext(path)[1].lstrip(".").lower() not in exts:
        return []
    try:
        if os.path.getsize(path) > limit:
            return []
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        return []
    return [name for name, rx in SIGNATURES.items() if rx.search(data)]


def package_activity(window: int = 300, log: str = "/var/log/dpkg.log") -> bool:
    """¿Se instaló o actualizó algún paquete hace poco? (para no alarmar por cambios normales de apt)"""
    try:
        return time.time() - os.path.getmtime(log) < window
    except OSError:
        return False


class Fim:
    def __init__(self, cfg, alerter: core.Alerter, allow: core.Allow):
        self.cfg, self.alerter, self.allow = cfg, alerter, allow
        self.path = os.path.join(core.state_dir(), "fim_baseline.json")
        self.www = core.csv(cfg.get("fim", "www", fallback=""))
        self.exts = [e.lower() for e in core.csv(cfg.get("fim", "www_exts", fallback="php"))]
        self.excludes = core.csv(cfg.get("fim", "excludes", fallback=""))
        self.hash_max = cfg.getint("fim", "hash_max_mb", fallback=64) * 1024 * 1024
        self.max_files = cfg.getint("fim", "max_files", fallback=300000)

    def roots(self) -> list[str]:
        return expand(core.csv(self.cfg.get("fim", "paths", fallback="")) + self.www)

    def load(self) -> dict | None:
        return core.read_json(self.path)

    def init(self) -> int:
        snap = snapshot(self.roots(), self.excludes, self.hash_max, max_files=self.max_files, rehash=True)
        core.atomic_write_json(self.path, {"created": core.iso(), "epoch": core.now(), "files": snap})
        self._meta(core.iso(), len(snap))
        return len(snap)

    def _meta(self, created: str, count: int) -> None:
        """Resumen público de la referencia (la referencia completa es solo de root): lo lee el panel gráfico."""
        core.atomic_write_json(os.path.join(core.state_dir(), "fim_meta.json"), {"created": created, "count": count, "updated": core.iso()}, 0o644)

    def scan(self, paths: list[str] | None = None, deep: bool = False) -> list[dict]:
        """Compara con la referencia y registra los hallazgos. Con `paths` solo mira esas rutas (para el modo en vivo)."""
        base = self.load()
        if base is None:
            self.alerter.emit("medium", "fim", "sin_referencia", "No hay referencia de integridad: ejecuta «sentinel baseline init»", key="fim:sinref")
            return []
        old = base["files"]
        if paths:
            roots = [p for p in paths if os.path.lexists(p)]
            sub_old = {p: v for p, v in old.items() if any(p == r or p.startswith(r.rstrip("/") + "/") for r in paths)}
            new = snapshot(roots, self.excludes, self.hash_max, old=sub_old, rehash=True, max_files=self.max_files)
            old_view = sub_old
        else:
            roots = self.roots()
            new = snapshot(roots, self.excludes, self.hash_max, old=old, rehash=deep, max_files=self.max_files)
            scope = tuple(r.rstrip("/") for r in roots)
            old_view = {p: v for p, v in old.items() if p in new or any(p == r or p.startswith(r + "/") for r in scope)}
        found = diff(old_view, new, self.www)
        pkg = package_activity()
        results = []
        for f in found:
            if self.allow.path_ignored(f["path"]):
                continue
            sev, detail = f["sev"], f["detail"]
            sigs = []
            if f["kind"] in ("added", "modified") and any(f["path"].startswith(w.rstrip("/") + "/") for w in self.www):
                sigs = scan_content(f["path"], self.exts)
                if sigs:
                    sev, detail = "critical", f"posible puerta trasera: {', '.join(sigs)}"
                elif f["kind"] == "added" and os.path.splitext(f["path"])[1].lstrip(".").lower() in self.exts:
                    sev = "high"; detail = "archivo ejecutable nuevo en carpeta web"
            if pkg and not sigs and f["path"].startswith(("/usr/", "/etc/", "/opt/", "/lib")) and f["kind"] in ("modified", "added", "perm") and sev in ("medium", "high"):
                sev = "low"; detail += " (durante una actualización de paquetes)"
            f2 = dict(f, sev=sev, detail=detail)
            results.append(f2)
            self.alerter.emit(sev, "fim", f["kind"], f"{f['path']}: {detail}", key=f"fim:{f['kind']}:{f['path']}:{f.get('sha', '')}", path=f["path"], detail=detail, signatures=sigs)
        return results

    def accept(self, paths: list[str] | None = None) -> int:
        """Acepta el estado actual como nueva referencia (todo o solo algunas rutas)."""
        base = self.load() or {"files": {}}
        if not paths:
            return self.init()
        files = base["files"]
        for p in list(files):
            if any(p == r or p.startswith(r.rstrip("/") + "/") for r in paths):
                del files[p]
        files.update(snapshot([p for p in paths if os.path.lexists(p)], self.excludes, self.hash_max, rehash=True, max_files=self.max_files))
        core.atomic_write_json(self.path, {"created": base.get("created", core.iso()), "epoch": core.now(), "files": files, "updated": core.iso()})
        self._meta(base.get("created", core.iso()), len(files))
        return len(files)
