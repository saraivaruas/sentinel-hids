"""Auditoría de postura de seguridad en macOS: las protecciones que trae Apple y lo que expone el equipo. Solo lee.

Si una herramienta responde algo que no se reconoce, la revisión queda como «no se pudo determinar»: no se da por buena.
"""
from __future__ import annotations

import glob
import re

from . import audit, core, servicio
from .audit import FAIL, INFO, OK, WARN

AJUSTES = "Ajustes del Sistema"


def _salida(cmd: list[str]) -> str:
    return core.run(cmd, 20)[1].strip()


def _interruptor(cmd, activo: str, inactivo: str, bien: str, mal: str, arreglo: str, gravedad: str = FAIL):
    """Revisión de un «encendido/apagado» según el texto que responde un programa del sistema."""
    txt = _salida(cmd)
    if re.search(inactivo, txt, re.I):
        return gravedad, mal, arreglo
    if re.search(activo, txt, re.I):
        return OK, bien, ""
    return INFO, f"no se pudo determinar ({txt[:80] or 'sin respuesta'})", ""


def c_firewall(cfg):
    return _interruptor(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"], r"Firewall is enabled", r"Firewall is disabled",
                        "El cortafuegos de macOS está encendido", "El cortafuegos de macOS está apagado", f"{AJUSTES} > Red > Cortafuegos")


def c_sip(cfg):
    return _interruptor(["csrutil", "status"], r"status: enabled", r"status: disabled", "La protección de integridad del sistema (SIP) está activa",
                        "La protección de integridad del sistema (SIP) está desactivada", "Reinicia en modo de recuperación y ejecuta: csrutil enable")


def c_filevault(cfg):
    return _interruptor(["fdesetup", "status"], r"FileVault is On", r"FileVault is Off", "El disco está cifrado (FileVault)",
                        "El disco no está cifrado: quien tenga el equipo puede leer tus archivos", f"{AJUSTES} > Privacidad y seguridad > FileVault")


def c_gatekeeper(cfg):
    return _interruptor(["spctl", "--status"], r"assessments enabled", r"assessments disabled", "Gatekeeper comprueba las aplicaciones antes de abrirlas",
                        "Gatekeeper está apagado: se abre cualquier aplicación sin comprobarla", "sudo spctl --master-enable")


def c_actualizaciones(cfg):
    rc, out = core.run(["defaults", "read", "/Library/Preferences/com.apple.SoftwareUpdate"], 20)
    if rc != 0:
        return INFO, "no se pudo determinar (macOS no guarda un ajuste propio: usa el de fábrica)", ""
    apagadas = [n for c, n in (("AutomaticCheckEnabled", "la búsqueda"), ("CriticalUpdateInstall", "las respuestas de seguridad"), ("ConfigDataInstall", "las listas de protección"))
                if re.search(rf"\b{c}\s*=\s*0\s*;", out)]
    if apagadas:
        return WARN, "Actualizaciones automáticas apagadas para " + ", ".join(apagadas), f"{AJUSTES} > General > Actualización de software > Actualizaciones automáticas"
    return OK, "Las actualizaciones de seguridad automáticas no están apagadas", ""


def c_ssh(cfg):
    if core.run(["launchctl", "print", "system/com.openssh.sshd"], 20)[0] != 0:
        return OK, "El acceso remoto por SSH está apagado", ""
    txt = ""
    for f in ["/etc/ssh/sshd_config"] + sorted(glob.glob("/etc/ssh/sshd_config.d/*.conf")):
        txt += "\n" + audit._read(f)
    claves = (re.findall(r"^\s*PasswordAuthentication\s+(\S+)", txt, re.I | re.M) or ["yes"])[0].lower()
    if claves != "no":
        return WARN, "El acceso remoto por SSH está encendido y acepta contraseñas", f"Apágalo en {AJUSTES} > General > Compartir si no lo usas, o exige llave (PasswordAuthentication no)"
    return OK, "SSH encendido y solo con llave", ""


def c_sentinel(cfg):
    st = servicio.estado("sentinel-monitor")
    return (OK, "Sentinel activo (monitor)", "") if st == "active" else (FAIL, f"El monitor de Sentinel no está activo ({st})", "sudo sentinel iniciar")


CHECKS = [("firewall", "Cortafuegos", c_firewall), ("sip", "Integridad del sistema", c_sip), ("filevault", "Cifrado del disco", c_filevault),
          ("gatekeeper", "Aplicaciones", c_gatekeeper), ("autoupdates", "Actualización automática", c_actualizaciones), ("ssh", "SSH", c_ssh),
          ("home", "Credenciales del usuario", audit.c_home_secrets), ("sentinel", "Sentinel", c_sentinel)]
