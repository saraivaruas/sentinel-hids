"""Medidas de endurecimiento de macOS. Las aplica el mismo motor que en Linux (plan, copia, comprobación y reversión).

Casi todas son interruptores del sistema: cada una sabe cómo dejarlo encendido y cómo volver a como estaba.
"""
from __future__ import annotations

import re

from . import endurecer as en
from .endurecer import APLICADA, BLOQUEADA, NO_APLICA, PENDIENTE, Contexto, Medida

FIREWALL = "/usr/libexec/ApplicationFirewall/socketfilterfw"
ACTUALIZACIONES = "/Library/Preferences/com.apple.SoftwareUpdate"
INICIO = "/Library/Preferences/com.apple.loginwindow"
CLAVES_ACTUALIZACION = ("AutomaticCheckEnabled", "AutomaticDownload", "CriticalUpdateInstall", "ConfigDataInstall")


def _interruptor(consulta: list[str], encendido: str, apagado: str, bien: str, mal: str):
    def estado(ctx: Contexto):
        txt = ctx.run(consulta, 20)[1]
        if re.search(apagado, txt, re.I):
            return PENDIENTE, mal
        if re.search(encendido, txt, re.I):
            return APLICADA, bien
        return NO_APLICA, "no se pudo determinar en este equipo"
    return estado


def _nada(ctx: Contexto) -> list:
    return []


def _fijo(*comandos: list[str]):
    return lambda ctx: [list(c) for c in comandos]


def _apagadas(ctx: Contexto) -> list[str]:
    """Ajustes de actualización automática que alguien apagó expresamente (si no existen, macOS usa los de fábrica)."""
    rc, txt = ctx.run(["defaults", "read", ACTUALIZACIONES], 20)
    return [c for c in CLAVES_ACTUALIZACION if rc == 0 and re.search(rf"\b{c}\s*=\s*0\s*;", txt)]


def _actualizaciones_estado(ctx: Contexto):
    off = _apagadas(ctx)
    return (PENDIENTE, "apagado: " + ", ".join(off)) if off else (APLICADA, "no hay nada apagado")


def _actualizaciones(valor: str):
    return lambda ctx: [["defaults", "write", ACTUALIZACIONES, c, "-bool", valor] for c in _apagadas(ctx)]


def _invitado_estado(ctx: Contexto):
    rc, txt = ctx.run(["defaults", "read", INICIO, "GuestEnabled"], 20)
    return (PENDIENTE, "cualquiera puede usar el equipo con la cuenta de invitado") if rc == 0 and txt.strip() == "1" else (APLICADA, "la cuenta de invitado está desactivada")


def _filevault_estado(ctx: Contexto):
    txt = ctx.run(["fdesetup", "status"], 20)[1]
    if "FileVault is On" in txt:
        return APLICADA, "el disco ya está cifrado"
    if "FileVault is Off" in txt:
        return BLOQUEADA, "actívalo tú en Ajustes del Sistema > Privacidad y seguridad > FileVault: genera una clave de recuperación que solo tú debes guardar"
    return NO_APLICA, "no se pudo determinar en este equipo"


MEDIDAS = [
    Medida("mac-cortafuegos", "Encender el cortafuegos de macOS", "Activa el cortafuegos de aplicaciones del sistema.",
           "Impide que programas que no lo piden reciban conexiones de otros equipos.", "bajo", "basico",
           _interruptor([FIREWALL, "--getglobalstate"], r"Firewall is enabled", r"Firewall is disabled", "ya está encendido", "el cortafuegos de macOS está apagado"),
           _nada, _fijo([FIREWALL, "--setglobalstate", "on"]), deshacer=_fijo([FIREWALL, "--setglobalstate", "off"]),
           nota="macOS puede preguntarte si dejas que una aplicación reciba conexiones."),
    Medida("mac-gatekeeper", "Comprobar las aplicaciones antes de abrirlas (Gatekeeper)", "Vuelve a activar Gatekeeper.",
           "Frena programas sin firmar o ya identificados como maliciosos.", "bajo", "basico",
           _interruptor(["spctl", "--status"], r"assessments enabled", r"assessments disabled", "ya está activo", "Gatekeeper está apagado"),
           _nada, _fijo(["spctl", "--master-enable"]), deshacer=_fijo(["spctl", "--master-disable"]),
           nota="En macOS recientes, volver a apagarlo se confirma a mano en Ajustes."),
    Medida("mac-actualizaciones", "Actualizaciones automáticas", "Vuelve a encender la búsqueda, descarga e instalación de respuestas de seguridad que estuvieran apagadas.",
           "La mayoría de los equipos comprometidos lo fueron por un fallo ya corregido que nadie instaló.", "bajo", "basico",
           _actualizaciones_estado, _nada, _actualizaciones("true"), deshacer=_actualizaciones("false")),
    Medida("mac-invitado", "Desactivar la cuenta de invitado", "Quita el acceso sin contraseña como invitado.",
           "Cualquiera con el equipo delante podría usarlo.", "ninguno", "basico",
           _invitado_estado, _nada, _fijo(["defaults", "write", INICIO, "GuestEnabled", "-bool", "false"]), deshacer=_fijo(["defaults", "write", INICIO, "GuestEnabled", "-bool", "true"])),
    Medida("ssh-basico", "SSH: sin root, sin X11 y con menos intentos", "Crea un archivo propio de SSH que prohíbe entrar como root y contraseñas vacías, y limita los intentos.",
           "Reduce lo que un atacante puede probar contra tu SSH.", "bajo", "basico", en._ssh_basico_estado, en._ssh_basico_cambios,
           comprobar=en._sshd_comprobar, nota="Se comprueba con `sshd -t`; si falla se deshace solo."),
    Medida("mac-sigiloso", "Modo sigiloso del cortafuegos", "El equipo no contesta a sondeos como el ping a puertos cerrados.",
           "Dificulta que te encuentren en una red ajena.", "bajo", "recomendado",
           _interruptor([FIREWALL, "--getstealthmode"], r"\b(on|enabled)\b", r"\b(off|disabled)\b", "ya está activo", "el equipo contesta a los sondeos"),
           _nada, _fijo([FIREWALL, "--setstealthmode", "on"]), deshacer=_fijo([FIREWALL, "--setstealthmode", "off"])),
    Medida("mac-filevault", "Cifrar el disco (FileVault)", "Sentinel solo lo revisa: se activa a mano.",
           "Sin cifrado, quien tenga el equipo puede leer tus archivos.", "medio", "recomendado", _filevault_estado, _nada),
    Medida("ssh-solo-llaves", "SSH: entrar solo con llave, sin contraseña", "Desactiva el ingreso por contraseña en SSH.",
           "Las contraseñas se prueban a la fuerza todo el día; una llave no.", "medio", "estricto", en._ssh_llaves_estado, en._ssh_llaves_cambios,
           comprobar=en._sshd_comprobar, nota="Solo se aplica si ya hay una llave autorizada; así no te quedas sin acceso."),
]
