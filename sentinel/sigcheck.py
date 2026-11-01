"""Verificación de la firma de las publicaciones: además de la huella SHA-256, `SHA256SUMS` puede venir firmado (SHA256SUMS.asc) con la clave del autor.

La clave pública que se acepta viene EN el paquete que ya tienes instalado (/opt/sentinel/release-key.asc), no de la descarga: así, aunque alguien
tomara la cuenta de GitHub, no podría publicar una actualización que se instale. Usa `gpg`, que ya trae Ubuntu/Debian/Fedora."""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile

from . import core

KEY_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(core.__file__))), "release-key.asc")


def key_path() -> str:
    return os.environ.get("SENTINEL_RELEASE_KEY", KEY_PATH)


def _gpg(home: str, *args: str, data: bytes | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(["gpg", "--batch", "--no-tty", "--homedir", home, *args], input=data, capture_output=True, timeout=30, check=False)


def fingerprints(key_file: str) -> set[str]:
    """Huellas de las claves que trae el archivo (solo lectura, sin instalarlas)."""
    with tempfile.TemporaryDirectory() as home:
        os.chmod(home, 0o700)
        r = _gpg(home, "--with-colons", "--import-options", "show-only", "--import", key_file)
    return {ln.split(":")[9] for ln in r.stdout.decode("utf-8", "replace").splitlines() if ln.startswith("fpr:")}


def verify(sums: bytes, sig: bytes, key_file: str | None = None) -> tuple[bool, str]:
    """(válida, motivo). Válida solo si la firma es correcta y la hizo una de las claves de `key_file`."""
    key_file = key_file or key_path()
    if not shutil.which("gpg"):
        return False, "falta gpg para verificar la firma"
    if not os.path.exists(key_file):
        return False, "este equipo no tiene la clave pública de las publicaciones"
    ok_fprs = fingerprints(key_file)
    if not ok_fprs:
        return False, "la clave pública instalada no es válida"
    with tempfile.TemporaryDirectory() as home:
        os.chmod(home, 0o700)
        imp = _gpg(home, "--import", key_file)
        if imp.returncode != 0:
            return False, "no se pudo cargar la clave pública"
        sf = os.path.join(home, "SHA256SUMS"); sg = sf + ".asc"
        open(sf, "wb").write(sums); open(sg, "wb").write(sig)
        r = _gpg(home, "--status-fd", "1", "--verify", sg, sf)
    out = r.stdout.decode("utf-8", "replace")
    m = re.search(r"\[GNUPG:\] VALIDSIG \S+ \S+ \S+ \S+ \S+ \S+ \S+ \S+ \S+ ([0-9A-F]{40})", out)
    if r.returncode == 0 and m and m.group(1) in ok_fprs and "[GNUPG:] GOODSIG" in out:
        return True, "firma verificada"
    return False, "la firma NO es válida o no es de la clave de Sentinel"


def policy(cfg) -> str:
    """auto = exigir la firma si el equipo tiene la clave pública; yes = siempre; no = nunca (solo huella SHA-256)."""
    return cfg.get("update", "require_signature", fallback="auto")
