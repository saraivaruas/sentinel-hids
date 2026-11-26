"""PIN de protección: sin él no se puede detener Sentinel, desinstalarlo, cambiar su configuración, ampliar la lista blanca ni aceptar cambios.

Se guarda como hash PBKDF2-SHA256 con sal (nunca el PIN) en un archivo que solo lee root. Cinco errores seguidos bloquean los intentos por 10 minutos.
Límite honesto: quien ya es root puede saltarse cualquier protección de software (por ejemplo con `kill -9`); el PIN cierra las vías normales
(panel, comandos, systemctl stop, apt remove) y cada intento sin PIN deja una alerta crítica."""
from __future__ import annotations

import getpass
import hashlib
import hmac
import json
import os
import secrets
import shutil
import subprocess
import sys

from . import core, plataforma

ITERS = 300_000
MIN_LEN = 6
MAX_FAILS = 5
LOCK_SECONDS = 600
TOKEN_SECONDS = 300
_stdin_lines: list[str] | None = None


def pin_path() -> str:
    return os.environ.get("SENTINEL_PIN", "/etc/sentinel/pin")


def _state(name: str) -> str:
    return os.path.join(core.state_dir(), name)


def required() -> bool:
    return os.path.exists(pin_path())


def _hash(pin: str, salt: bytes, iters: int) -> str:
    return hashlib.pbkdf2_hmac("sha256", pin.encode("utf-8"), salt, iters).hex()


def _publish_state() -> None:
    """Marca legible por el panel (sin secretos) de si hay PIN."""
    try:
        core.atomic_write_json(_state("pin_state.json"), {"enabled": required(), "at": core.iso()}, 0o640, share=True)
    except OSError:
        pass


def locked_for() -> int:
    f = core.read_json(_state("pin_fail.json"), {}) or {}
    return max(0, int(f.get("until", 0) - core.now()))


def _fail(alerter=None) -> None:
    f = core.read_json(_state("pin_fail.json"), {}) or {}
    n = f.get("n", 0) + 1
    until = core.now() + LOCK_SECONDS if n >= MAX_FAILS else f.get("until", 0)
    try:
        core.atomic_write_json(_state("pin_fail.json"), {"n": 0 if n >= MAX_FAILS else n, "until": until}, 0o600)
    except OSError:
        pass
    if alerter is not None:
        alerter.emit("high", "pin", "pin_incorrecto", f"PIN de Sentinel incorrecto ({n} de {MAX_FAILS})" + ("; intentos bloqueados 10 minutos" if n >= MAX_FAILS else ""), key=f"pin:fail:{int(core.now())}")


def verify(pin: str, alerter=None) -> tuple[bool, str]:
    """(correcto, mensaje). Sin PIN configurado todo se permite."""
    if not required():
        return True, ""
    wait = locked_for()
    if wait:
        return False, f"Demasiados intentos: espera {wait // 60 + 1} minuto(s)."
    d = core.read_json(pin_path(), None)
    if not d or "hash" not in d:
        return False, "El archivo del PIN está dañado."
    if hmac.compare_digest(_hash(pin or "", bytes.fromhex(d["salt"]), d.get("iters", ITERS)), d["hash"]):
        try:
            os.remove(_state("pin_fail.json"))
        except OSError:
            pass
        return True, ""
    _fail(alerter)
    return False, "PIN incorrecto."


def set_pin(new: str, old: str = "", alerter=None) -> tuple[bool, str]:
    if not core.is_root():
        return False, "Necesita administrador."
    ok, msg = verify(old, alerter)
    if not ok:
        return False, msg
    if len(new) < MIN_LEN:
        return False, f"El PIN debe tener al menos {MIN_LEN} caracteres."
    salt = secrets.token_bytes(16)
    p = pin_path()
    os.makedirs(os.path.dirname(p), exist_ok=True)
    tmp = p + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump({"algo": "pbkdf2_sha256", "iters": ITERS, "salt": salt.hex(), "hash": _hash(new, salt, ITERS), "set_at": core.iso()}, f)
    os.replace(tmp, p)
    os.chmod(p, 0o600)
    _publish_state()
    return True, "PIN guardado."


def clear(pin: str, alerter=None) -> tuple[bool, str]:
    ok, msg = verify(pin, alerter)
    if not ok:
        return False, msg
    try:
        os.remove(pin_path())
    except OSError:
        pass
    _publish_state()
    return True, "PIN quitado: Sentinel ya no pide PIN."


# ---- permiso temporal para detener el servicio (lo concede quien demostró el PIN)
def authorize_stop(seconds: int = TOKEN_SECONDS) -> None:
    core.atomic_write_json(_state("stop_ok.json"), {"until": core.now() + seconds}, 0o600)


def stop_authorized() -> bool:
    t = core.read_json(_state("stop_ok.json"), {}) or {}
    return t.get("until", 0) > core.now()


def revoke_stop() -> None:
    try:
        os.remove(_state("stop_ok.json"))
    except OSError:
        pass


PKG_PROCS = ("apt", "apt-get", "aptitude", "dpkg", "needrestart")


def package_update_running() -> bool:
    """¿Hay una instalación o actualización de paquetes en curso? Entonces apt/needrestart reinician los servicios y Sentinel se detiene solo: es normal.
    (El servicio «unattended-upgrade-shutdown» está siempre encendido en Ubuntu: no cuenta; sí cuenta la actualización automática en marcha.)"""
    try:
        for d in os.listdir("/proc"):
            if not d.isdigit():
                continue
            try:
                comm = open(f"/proc/{d}/comm", encoding="utf-8", errors="replace").read().strip()
                if comm in PKG_PROCS:
                    return True
                if comm.startswith("unattended-upgr"):
                    cmd = open(f"/proc/{d}/cmdline", "rb").read().replace(b"\x00", b" ").decode("utf-8", "replace")
                    if "unattended-upgrade" in cmd and "-shutdown" not in cmd:
                        return True
            except OSError:
                continue
    except OSError:
        pass
    return False


def shutting_down() -> bool:
    """¿El sistema se está apagando o reiniciando? (entonces detener Sentinel es normal)."""
    rc, out = core.run(["systemctl", "is-system-running"], 4)
    if out.strip() == "stopping":
        return True
    rc, jobs = core.run(["systemctl", "list-jobs", "--no-legend"], 4)
    return any(x in jobs for x in ("shutdown.target", "reboot.target", "poweroff.target", "halt.target", "kexec.target"))


# ---- cómo se pregunta el PIN
def read_stdin_lines() -> list[str]:
    global _stdin_lines
    if _stdin_lines is None:
        _stdin_lines = sys.stdin.read().split("\n") if not sys.stdin.isatty() else []
    return _stdin_lines


def next_stdin_line() -> str:
    lines = read_stdin_lines()
    return lines.pop(0).rstrip("\r") if lines else ""


def _ventana_mac(prompt: str) -> str | None:
    """Sin terminal, en macOS: una ventana con el campo oculto en la pantalla del usuario."""
    from .core import Alerter
    tgt = Alerter().desktop_target()
    if not tgt or not shutil.which("osascript"):
        return None
    user, uid = tgt
    cmd = ["osascript", "-e", "on run argv", "-e", 'text returned of (display dialog (item 1 of argv) with title "Sentinel" default answer "" with hidden answer)', "-e", "end run", "--", prompt.strip()]
    try:
        r = subprocess.run(Alerter.en_sesion_mac(cmd, user, uid, core.is_root()), capture_output=True, text=True, timeout=120, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    return r.stdout.rstrip("\n") if r.returncode == 0 else None


def ask(prompt: str = "PIN de Sentinel: ") -> str | None:
    """Pregunta el PIN en la terminal; si no hay terminal, con una ventana (zenity). None = no se pudo preguntar."""
    if sys.stdin.isatty():
        try:
            return getpass.getpass(prompt)
        except (EOFError, KeyboardInterrupt):
            return None
    try:
        with open("/dev/tty", "r+") as tty:
            return getpass.getpass(prompt, stream=tty)
    except (OSError, EOFError, KeyboardInterrupt):
        pass
    if plataforma.ES_MAC:
        return _ventana_mac(prompt)
    if shutil.which("zenity"):
        from .core import Alerter
        tgt = Alerter().desktop_target()
        if tgt:
            user, uid = tgt
            env = [f"{k}={v}" for k, v in Alerter.desktop_env(uid).items()]
            cmd = ["zenity", "--password", "--title=Sentinel", "--text=" + prompt]
            cmd = ["runuser", "-u", user, "--", "env", *env, *cmd] if core.is_root() else ["env", *env, *cmd]
            try:
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=120, check=False)
                return r.stdout.rstrip("\n") if r.returncode == 0 else None
            except (OSError, subprocess.SubprocessError):
                return None
    return None
