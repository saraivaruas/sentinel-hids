"""Actualizaciones: detecta si hay una versión nueva publicada en GitHub y la instala de forma verificada.

Seguridad: solo se descarga desde las publicaciones (Releases) del repositorio configurado, por HTTPS; la huella SHA-256 del archivo debe coincidir
con la de SHA256SUMS; el paquete debe llamarse «sentinel» y traer exactamente la versión anunciada; y nunca se instala una versión menor o igual
a la actual. Instalar necesita administrador. Para no consultar nada: [update] check = no."""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
import urllib.error
import urllib.request

from . import core

TTL = 6 * 3600
MAX_BYTES = 30 * 1024 * 1024
HOSTS_OK = ("github.com", "githubusercontent.com")


def vtuple(v: str) -> tuple:
    n = [int(x) for x in re.findall(r"\d+", (v or "").split("-")[0])][:3]
    return tuple(n + [0] * (3 - len(n)))


def repo_of(cfg) -> str:
    r = cfg.get("update", "repo", fallback="saraivaruas/sentinel-hids")
    if not re.fullmatch(r"[\w.-]+/[\w.-]+", r):
        raise ValueError("repositorio inválido")
    return r


def parse_release(js: dict, repo: str) -> dict | None:
    """Del JSON de la API de GitHub a lo que necesitamos. None si es borrador o prerelease."""
    if not js or js.get("draft") or js.get("prerelease") or not js.get("tag_name"):
        return None
    prefix = f"https://github.com/{repo}/releases/download/"
    assets = {a["name"]: a["browser_download_url"] for a in js.get("assets", []) if str(a.get("browser_download_url", "")).startswith(prefix)}
    return {"version": js["tag_name"].lstrip("v"), "tag": js["tag_name"], "notes": (js.get("body") or "")[:2500], "url": js.get("html_url", ""), "published": js.get("published_at", ""), "assets": assets}


def _get(url: str, timeout: float = 8, limit: int = 2_000_000) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "sentinel-hids-update", "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        host = (r.geturl().split("/")[2] if "//" in r.geturl() else "")
        if not any(host == h or host.endswith("." + h) for h in HOSTS_OK):
            raise ValueError("redirección a un servidor no permitido")
        data = r.read(limit + 1)
    if len(data) > limit:
        raise ValueError("archivo demasiado grande")
    return data


def cache_path() -> str:
    return os.path.join(core.state_dir(), "update_check.json")


def check(cfg=None, force: bool = False, current: str | None = None) -> dict:
    cfg = cfg or core.load_config()
    current = current or core.VERSION
    base = {"current": current, "latest": current, "available": False, "checked_at": 0, "error": None, "enabled": cfg.getboolean("update", "check", fallback=True)}
    if not base["enabled"]:
        return base
    c = core.read_json(cache_path())
    if c and not force and core.now() - c.get("checked_at", 0) < TTL and c.get("current") == current:
        return c
    try:
        repo = repo_of(cfg)
        rel = parse_release(json.loads(_get(f"https://api.github.com/repos/{repo}/releases/latest")), repo)
    except Exception as e:   # sin internet o GitHub caído: no es un error grave, se reintenta más tarde
        code = "sin_publicaciones" if isinstance(e, urllib.error.HTTPError) and e.code == 404 else "sin_conexion" if isinstance(e, (urllib.error.URLError, OSError)) else type(e).__name__
        out = dict(c or base, error=code, checked_at=core.now(), current=current)
        out["available"] = bool(out.get("available")) and vtuple(out.get("latest", current)) > vtuple(current)
        core.atomic_write_json(cache_path(), out, 0o644) if core.is_root() else None
        return out
    out = dict(base, checked_at=core.now())
    if rel:
        out.update(latest=rel["version"], available=vtuple(rel["version"]) > vtuple(current), notes=rel["notes"], release_url=rel["url"], published=rel["published"], assets=sorted(rel["assets"]), asset_urls=rel["assets"])
    try:
        core.atomic_write_json(cache_path(), out, 0o644)
    except OSError:
        pass
    return out


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for blk in iter(lambda: f.read(1 << 20), b""):
            h.update(blk)
    return h.hexdigest()


def expected_hash(sums_text: str, name: str) -> str | None:
    for ln in sums_text.splitlines():
        parts = ln.split()
        if len(parts) == 2 and parts[1].lstrip("*") == name and re.fullmatch(r"[0-9a-f]{64}", parts[0]):
            return parts[0]
    return None


def install(cfg=None, log=print) -> tuple[bool, str]:
    """Descarga, verifica e instala la versión nueva. Devuelve (éxito, mensaje)."""
    cfg = cfg or core.load_config()
    if not core.is_root():
        return False, "Instalar una actualización necesita permisos de administrador (usa sudo o el botón del panel)."
    info = check(cfg, force=True)
    if info.get("error") and not info.get("asset_urls"):
        return False, f"No se pudo consultar GitHub: {error_text(info['error'])}."
    if not info.get("available"):
        return True, f"Ya tienes la última versión ({info['current']})."
    ver, urls = info["latest"], info.get("asset_urls", {})
    prefix = f"https://github.com/{repo_of(cfg)}/releases/download/"
    deb_name, sums_name, tgz_name = f"sentinel_{ver}_all.deb", "SHA256SUMS", f"sentinel-{ver}.tar.gz"
    use_deb = bool(shutil.which("dpkg-deb") and shutil.which("apt-get") and deb_name in urls)
    name = deb_name if use_deb else tgz_name
    if name not in urls or sums_name not in urls or not all(urls[n].startswith(prefix) for n in (name, sums_name)):
        return False, f"La publicación {ver} no trae los archivos esperados ({name} y {sums_name})."
    tmp = tempfile.mkdtemp(prefix="sentinel-update-")
    os.chmod(tmp, 0o700)
    try:
        log(f"Descargando {name}…")
        path = os.path.join(tmp, name)
        with open(path, "wb") as f:
            f.write(_get(urls[name], 60, MAX_BYTES))
        sums = _get(urls[sums_name]).decode("utf-8", "replace")
        want, got = expected_hash(sums, name), _sha256(path)
        if not want or want != got:
            return False, "La huella SHA-256 NO coincide: el archivo descargado no es el publicado. No se instaló nada."
        log("Huella verificada ✔")
        if use_deb:
            rc, out = core.run(["dpkg-deb", "--field", path, "Package", "Version"], 20)
            f = dict(ln.split(": ", 1) for ln in out.splitlines() if ": " in ln)
            if f.get("Package") != "sentinel" or f.get("Version") != ver:
                return False, "El paquete descargado no es Sentinel " + ver + ". No se instaló nada."
            log("Instalando el paquete…")
            env = dict(os.environ, DEBIAN_FRONTEND="noninteractive")
            import subprocess
            r = subprocess.run(["apt-get", "install", "-y", "-o", "Dpkg::Options::=--force-confold", path], capture_output=True, text=True, env=env, timeout=600, check=False)
            if r.returncode != 0:
                return False, "La instalación falló:\n" + (r.stdout + r.stderr)[-600:]
        else:
            import subprocess, tarfile
            with tarfile.open(path) as t:
                t.extractall(tmp, filter="data") if hasattr(tarfile, "data_filter") else t.extractall(tmp)
            d = next(os.path.join(tmp, x) for x in os.listdir(tmp) if x.startswith("sentinel-") and os.path.isdir(os.path.join(tmp, x)))
            r = subprocess.run([os.path.join(d, "install.sh"), "--sin-limpiar"], capture_output=True, text=True, timeout=900, check=False)
            if r.returncode != 0:
                return False, "La instalación falló:\n" + (r.stdout + r.stderr)[-600:]
        core.atomic_write_json(cache_path(), dict(info, current=ver, available=False), 0o644)
        return True, f"Sentinel actualizado a la versión {ver}."
    except Exception as e:
        return False, f"No se pudo actualizar: {type(e).__name__}: {e}"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


ERRORES = {"sin_publicaciones": "todavía no hay versiones publicadas", "sin_conexion": "no hay conexión con GitHub"}


def error_text(code: str | None) -> str:
    return ERRORES.get(code or "", code or "")
