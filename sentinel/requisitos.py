"""Requisitos de Sentinel: detecta solo qué tiene el equipo, lo marca con ✔ / ✖ y, si aceptas, instala lo que falta.

`sentinel requisitos` muestra la lista (y pregunta); el panel tiene la misma lista en «Requisitos». Instalar pide la contraseña de administrador
(sudo en la terminal, la ventana de clave del sistema en el panel). Sentinel nunca instala nada sin que lo aceptes.
Los nombres de paquete son los de Debian/Ubuntu (apt), Fedora (dnf), Arch (pacman) y openSUSE (zypper).
"""
from __future__ import annotations

import importlib.util
import os
import shutil
import sys
from dataclasses import dataclass, field

from . import plataforma

OBLIGATORIO, RECOMENDADO, OPCIONAL = "obligatorio", "recomendado", "opcional"
GESTORES = ("apt", "dnf", "pacman", "zypper")


def _bin(*nombres: str):
    return lambda: any(shutil.which(n) for n in nombres)


def _modulo(nombre: str):
    def f() -> bool:
        try:
            return importlib.util.find_spec(nombre) is not None
        except (ImportError, ValueError):
            return False
    return f


@dataclass
class Requisito:
    id: str
    nombre: str
    para_que: str                 # en lenguaje claro
    nivel: str                    # obligatorio | recomendado | opcional
    esta: object                  # () -> bool
    paquetes: dict = field(default_factory=dict)       # gestor -> [paquetes]
    manual: str = ""              # si no se instala con el gestor (p. ej. CrowdSec): cómo conseguirlo


def _py() -> bool:
    return sys.version_info >= (3, 8)


REQUISITOS = [
    Requisito("python3", "Python 3.8 o superior", "Sentinel está escrito en Python.", OBLIGATORIO, _py, {"apt": ["python3"], "dnf": ["python3"], "pacman": ["python"], "zypper": ["python3"]}),
    Requisito("systemd", "systemd (systemctl y journalctl)", "Arranca Sentinel, programa los informes y lee los registros del sistema.", OBLIGATORIO, _bin("systemctl", "journalctl"), {"apt": ["systemd"], "dnf": ["systemd"], "pacman": ["systemd"], "zypper": ["systemd"]}),
    Requisito("iproute2", "iproute2 (comandos ss e ip)", "Ve qué puertos escuchan y qué conexiones hay abiertas.", OBLIGATORIO, _bin("ss", "ip"), {"apt": ["iproute2"], "dnf": ["iproute"], "pacman": ["iproute2"], "zypper": ["iproute2"]}),
    Requisito("procps", "procps (ps, sysctl)", "Lista los procesos y lee los parámetros del kernel.", OBLIGATORIO, _bin("ps", "sysctl"), {"apt": ["procps"], "dnf": ["procps-ng"], "pacman": ["procps-ng"], "zypper": ["procps"]}),
    Requisito("inotify", "inotify-tools", "Vigila tus archivos en vivo: avisa al instante en lugar de cada 30 minutos.", RECOMENDADO, _bin("inotifywait"), {"apt": ["inotify-tools"], "dnf": ["inotify-tools"], "pacman": ["inotify-tools"], "zypper": ["inotify-tools"]}),
    Requisito("firewall", "Un cortafuegos (ufw, firewalld o iptables)", "Cierra los puertos y bloquea a quien ataca.", RECOMENDADO, _bin("ufw", "firewall-cmd", "iptables", "nft"), {"apt": ["ufw"], "dnf": ["firewalld"], "pacman": ["iptables-nft"], "zypper": ["firewalld"]}),
    Requisito("notify", "libnotify (avisos en la pantalla)", "Muestra los avisos de seguridad en una esquina del escritorio.", RECOMENDADO, _bin("notify-send"), {"apt": ["libnotify-bin"], "dnf": ["libnotify"], "pacman": ["libnotify"], "zypper": ["libnotify-tools"]}),
    Requisito("polkit", "polkit (pkexec)", "Pide tu contraseña de administrador desde el panel cuando hace falta.", RECOMENDADO, _bin("pkexec"), {"apt": ["policykit-1"], "dnf": ["polkit"], "pacman": ["polkit"], "zypper": ["polkit"]}),
    Requisito("ssh-keygen", "openssh-client (ssh-keygen)", "Revisa las llaves SSH autorizadas en el informe del equipo.", RECOMENDADO, _bin("ssh-keygen"), {"apt": ["openssh-client"], "dnf": ["openssh-clients"], "pacman": ["openssh"], "zypper": ["openssh-clients"]}),
    Requisito("logrotate", "logrotate", "Evita que los registros de Sentinel crezcan sin límite.", RECOMENDADO, _bin("logrotate"), {"apt": ["logrotate"], "dnf": ["logrotate"], "pacman": ["logrotate"], "zypper": ["logrotate"]}),
    Requisito("bandeja", "Ícono en la barra del sistema (python3-gi)", "Muestra el estado de Sentinel junto al reloj.", OPCIONAL, _modulo("gi"), {"apt": ["python3-gi", "gir1.2-ayatanaappindicator3-0.1"], "dnf": ["python3-gobject"], "pacman": ["python-gobject"], "zypper": ["python3-gobject"]}),
    Requisito("zenity", "zenity", "Ventana para escribir el PIN cuando no hay terminal.", OPCIONAL, _bin("zenity"), {"apt": ["zenity"], "dnf": ["zenity"], "pacman": ["zenity"], "zypper": ["zenity"]}),
    Requisito("auditd", "auditd", "Registro detallado de cambios en cuentas, sudo y SSH (lo usa el endurecimiento).", OPCIONAL, _bin("auditd", "auditctl"), {"apt": ["auditd"], "dnf": ["audit"], "pacman": ["audit"], "zypper": ["audit"]}),
    Requisito("unattended", "unattended-upgrades", "Instala solas las actualizaciones de seguridad (lo usa el endurecimiento).", OPCIONAL, _bin("unattended-upgrade"), {"apt": ["unattended-upgrades"]}),
    Requisito("pdf", "wkhtmltopdf", "Adjunta el informe del equipo también en PDF.", OPCIONAL, _bin("wkhtmltopdf"), {"apt": ["wkhtmltopdf"], "dnf": ["wkhtmltopdf"], "zypper": ["wkhtmltopdf"]}),
    Requisito("lynis", "Lynis", "Auditoría de endurecimiento complementaria (índice de Lynis en el informe semanal).", OPCIONAL, _bin("lynis"), {"apt": ["lynis"], "pacman": ["lynis"], "zypper": ["lynis"]}),
    Requisito("crowdsec", "CrowdSec y su bloqueador", "Bloquea en el firewall a los atacantes que ya conoce la comunidad.", OPCIONAL, _bin("cscli"), {},
              manual="No viene en los repositorios de la distribución: se instala desde https://docs.crowdsec.net/docs/getting_started/install_crowdsec"),
    Requisito("clamav", "ClamAV", "Antivirus para las carpetas web.", OPCIONAL, _bin("clamscan"), {"apt": ["clamav"], "dnf": ["clamav"], "pacman": ["clamav"], "zypper": ["clamav"]}),
]


# macOS trae casi todo: no hay nada que instalar con un gestor de paquetes.
REQUISITOS_MAC = [
    Requisito("python3", "Python 3.8 o superior", "Sentinel está escrito en Python.", OBLIGATORIO, _py, manual="Instálalo con las herramientas de Apple:  xcode-select --install"),
    Requisito("launchd", "launchd (launchctl)", "Arranca Sentinel y programa las revisiones y los informes.", OBLIGATORIO, _bin("launchctl")),
    Requisito("registro", "Registro del sistema (log)", "Detecta los ataques por SSH, sudo y su.", OBLIGATORIO, _bin("log")),
    Requisito("lsof", "lsof y ps", "Ve los procesos, los puertos que escuchan y las conexiones abiertas.", OBLIGATORIO, lambda: bool(shutil.which("lsof") and shutil.which("ps"))),
    Requisito("firewall", "pf (pfctl)", "Bloquea a quien ataca.", RECOMENDADO, _bin("pfctl")),
    Requisito("ssh-keygen", "ssh-keygen", "Revisa las llaves SSH autorizadas en el informe del equipo.", RECOMENDADO, _bin("ssh-keygen")),
]


def gestor(os_release: str = "/etc/os-release", id_falso: str = "", like_falso: str = "") -> str:
    """Familia de la distribución: apt (Debian/Ubuntu), dnf (Fedora/RHEL), pacman (Arch), zypper (openSUSE) o «» si no se reconoce."""
    ident, like = id_falso, like_falso
    if not ident:
        try:
            datos = dict(ln.rstrip().split("=", 1) for ln in open(os_release, encoding="utf-8") if "=" in ln)
            ident, like = datos.get("ID", "").strip('"'), datos.get("ID_LIKE", "").strip('"')
        except OSError:
            return ""
    fam = f" {ident} {like} "
    for palabras, g in ((("debian", "ubuntu"), "apt"), (("fedora", "rhel", "centos"), "dnf"), (("arch",), "pacman"), (("suse", "opensuse"), "zypper")):
        if any(f" {p} " in fam or f" {p}" in fam for p in palabras):
            return g
    return ""


def estado() -> list[tuple[Requisito, bool]]:
    """Qué tiene el equipo. SENTINEL_FAKE_MISSING=id,id fuerza que falten esos requisitos (para pruebas y para ver cómo se ve la lista)."""
    falsos = {x.strip() for x in os.environ.get("SENTINEL_FAKE_MISSING", "").split(",") if x.strip()}
    return [(r, bool(r.esta()) and r.id not in falsos) for r in (REQUISITOS_MAC if plataforma.ES_MAC else REQUISITOS)]


def faltan(niveles=(OBLIGATORIO, RECOMENDADO), lista=None) -> list[Requisito]:
    return [r for r, ok in (lista if lista is not None else estado()) if not ok and r.nivel in niveles]


def paquetes_para(faltantes: list[Requisito], g: str) -> tuple[list[str], list[Requisito]]:
    """(paquetes a instalar con el gestor g, requisitos que no se pueden instalar con él)"""
    paquetes, sin = [], []
    for r in faltantes:
        p = r.paquetes.get(g)
        if p:
            paquetes += [x for x in p if x not in paquetes]
        else:
            sin.append(r)
    return paquetes, sin


def comando_instalar(g: str, paquetes: list[str], con_sudo: bool) -> list[str]:
    base = {"apt": ["apt-get", "install", "-y", "--no-install-recommends", *paquetes], "dnf": ["dnf", "install", "-y", *paquetes],
            "pacman": ["pacman", "-S", "--noconfirm", "--needed", *paquetes], "zypper": ["zypper", "--non-interactive", "install", *paquetes]}[g]
    cmd = (["sudo"] if con_sudo else []) + (["env", "DEBIAN_FRONTEND=noninteractive"] if g == "apt" else []) + base
    return cmd


def resumen(lista=None) -> dict:
    lista = lista if lista is not None else estado()
    cuenta = {n: [sum(1 for r, ok in lista if r.nivel == n and ok), sum(1 for r, _ in lista if r.nivel == n)] for n in (OBLIGATORIO, RECOMENDADO, OPCIONAL)}
    return {"obligatorios_ok": cuenta[OBLIGATORIO][0] == cuenta[OBLIGATORIO][1], "cuenta": cuenta, "faltan": [r.id for r in faltan(lista=lista)]}


def como_dict(lista=None, g: str | None = None) -> dict:
    """Para el panel: la lista con su estado y lo que se instalaría."""
    lista = lista if lista is not None else estado()
    g = g if g is not None else gestor()
    pend = faltan(lista=lista)
    paquetes, sin = paquetes_para(pend, g) if g else ([], pend)
    return {"gestor": g, "requisitos": [{"id": r.id, "nombre": r.nombre, "para_que": r.para_que, "nivel": r.nivel, "ok": ok, "manual": r.manual} for r, ok in lista],
            "paquetes": paquetes, "sin_paquete": [r.nombre for r in sin], "resumen": resumen(lista)}
