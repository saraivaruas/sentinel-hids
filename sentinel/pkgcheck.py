"""¿Este archivo es exactamente el que trae su paquete? (equivalente a `debsums`, sin instalar nada).

Cuando un archivo del sistema cambia y su contenido coincide con el que publica el paquete oficial (apt lo actualizó, lo reinstaló o lo restauró), no hay nada
raro que reportar. Si el contenido NO coincide, el aviso se mantiene tal cual."""
from __future__ import annotations

import glob
import hashlib
import os

INFO_DIR = "/var/lib/dpkg/info"
ROOTS = ("/usr/", "/lib/", "/lib64/", "/bin/", "/sbin/")
_cache: dict = {"stamp": None, "idx": {}}


def _stamp(info_dir: str):
    try:
        return os.stat(os.path.join(info_dir, "..", "status")).st_mtime_ns
    except OSError:
        return None


def index(info_dir: str = INFO_DIR) -> dict[str, str]:
    """ruta → md5 oficial. Se arma una vez (≈1 s) y se rehace solo si apt cambió algo."""
    st = _stamp(info_dir)
    if _cache["idx"] and _cache["stamp"] == st and _cache.get("dir") == info_dir:
        return _cache["idx"]
    idx: dict[str, str] = {}
    for f in glob.glob(os.path.join(info_dir, "*.md5sums")):
        try:
            with open(f, encoding="utf-8", errors="replace") as fh:
                for ln in fh:
                    md5, _, rel = ln.rstrip("\n").partition("  ")
                    if rel:
                        idx["/" + rel] = md5
        except OSError:
            pass
    _cache.update(stamp=st, idx=idx, dir=info_dir)
    return idx


def _md5():
    try:
        return hashlib.md5(usedforsecurity=False)          # Python 3.9+
    except TypeError:
        return hashlib.md5()                               # Python 3.8


def candidates(path: str) -> list[str]:
    """Rutas con que puede aparecer el archivo en la lista del paquete (con /usr unificado: /bin → /usr/bin, /lib → /usr/lib…)."""
    out = [path]
    for a, b in (("/usr/bin/", "/bin/"), ("/usr/sbin/", "/sbin/"), ("/usr/lib/", "/lib/"), ("/usr/lib64/", "/lib64/")):
        if path.startswith(a):
            out.append(b + path[len(a):])
        elif path.startswith(b):
            out.append(a + path[len(b):])
    return out


def is_pristine(path: str, info_dir: str = INFO_DIR) -> bool:
    if not path.startswith(ROOTS):
        return False
    idx = index(info_dir)
    want = next((idx[c] for c in candidates(path) if c in idx), None)
    if not want:
        return False
    try:
        h = _md5()                                         # md5 solo porque es lo que publica dpkg; la comparación es con su lista oficial
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
    except OSError:
        return False
    return h.hexdigest() == want
