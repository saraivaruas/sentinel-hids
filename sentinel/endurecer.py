"""Endurecimiento (hardening) guiado: `sentinel endurecer plan | aplicar | revertir | estado`.

Principios (pensado para equipos de otras personas, donde un error hace daño real):
  - NADA se aplica solo: primero un plan (solo lectura) que explica cada medida en lenguaje claro y su riesgo.
  - Cada medida escribe archivos propios (drop-ins en /etc/sysctl.d, /etc/modprobe.d, /etc/ssh/sshd_config.d…); nunca edita los del sistema,
    así que revertir es borrar lo nuestro. Antes de tocar algo se guarda una copia y un manifiesto en /var/lib/sentinel/endurecer/.
  - Una medida con comprobación (p. ej. `sshd -t`) que falla se revierte sola; las que podrían dejarte fuera (SSH sin contraseña) solo se aplican si es seguro.
  - Tres perfiles acumulativos: básico (sin efectos visibles), recomendado (CIS nivel 1) y estricto (para servidores: puede cambiar hábitos).
Fuentes de las medidas: CIS Benchmarks (Ubuntu/Debian), Lynis y el Kernel Self Protection Project. No es una certificación.
"""
from __future__ import annotations

import glob
import json
import os
import re
import shutil
import time
from dataclasses import dataclass, field

from . import core, plataforma

PERFILES = ("basico", "recomendado", "estricto")
PERFIL_ES = {"basico": "básico", "recomendado": "recomendado", "estricto": "estricto"}
APLICADA, PENDIENTE, NO_APLICA, BLOQUEADA = "aplicada", "pendiente", "no_aplica", "bloqueada"


def base_dir() -> str:
    return os.path.join(core.state_dir(), "endurecer")


class Contexto:
    """Acceso al sistema con un prefijo de raíz (así las pruebas usan una carpeta temporal y nunca tocan el sistema real)."""

    def __init__(self, raiz: str = "/", ejecutar=None) -> None:
        self.raiz = raiz
        self.ejecutar = ejecutar or core.run

    def ruta(self, p: str) -> str:
        return os.path.join(self.raiz, p.lstrip("/")) if self.raiz != "/" else p

    def leer(self, p: str) -> str:
        try:
            with open(self.ruta(p), encoding="utf-8", errors="replace") as f:
                return f.read()
        except OSError:
            return ""

    def existe(self, p: str) -> bool:
        return os.path.exists(self.ruta(p))

    def sysctl(self, clave: str) -> str:
        return self.leer("/proc/sys/" + clave.replace(".", "/")).strip()

    def run(self, cmd: list[str], timeout: int = 30) -> tuple[int, str]:
        return self.ejecutar(cmd, timeout)


@dataclass
class Cambio:
    ruta: str
    contenido: str
    modo: int = 0o644


@dataclass
class Medida:
    id: str
    titulo: str
    que_hace: str                 # en lenguaje claro: qué cambia
    por_que: str                  # qué ataque o problema evita
    riesgo: str                   # ninguno | bajo | medio
    perfil: str                   # basico | recomendado | estricto
    estado: object                # (ctx) -> (código, detalle)
    cambios: object               # (ctx) -> list[Cambio]
    despues: object = None        # (ctx) -> list[list[str]]  comandos tras escribir (recargar sysctl, sshd…)
    comprobar: object = None      # (ctx) -> (ok, mensaje)    se ejecuta tras aplicar; si falla se revierte
    nota: str = ""                # aviso de impacto en el uso diario
    revertir_despues: object = None
    deshacer: object = None       # (ctx) -> list[list[str]]  para medidas que son comandos: se calcula ANTES de aplicar y devuelve el sistema a como estaba


# ---------------------------------------------------------------------------- sysctl
def _sysctl_estado(valores: dict, tolerar: dict | None = None):
    tolerar = tolerar or {}

    def estado(ctx: Contexto):
        mal = []
        for k, v in valores.items():
            actual = ctx.sysctl(k)
            if not actual:
                continue                                  # el kernel no lo tiene: no aplica
            if actual != v and actual not in tolerar.get(k, ()):
                mal.append(f"{k}={actual} (recomendado {v})")
        if not any(ctx.sysctl(k) for k in valores):
            return NO_APLICA, "este kernel no tiene esos parámetros"
        return (PENDIENTE, "; ".join(mal[:4]) + (" …" if len(mal) > 4 else "")) if mal else (APLICADA, "ya está así")
    return estado


def _sysctl_cambios(archivo: str, valores: dict, cabecera: str):
    def cambios(ctx: Contexto):
        txt = f"# Sentinel · endurecimiento: {cabecera}\n# Para quitarlo: sudo sentinel endurecer revertir\n" + "".join(f"{k} = {v}\n" for k, v in valores.items() if ctx.sysctl(k))
        return [Cambio(f"/etc/sysctl.d/{archivo}", txt)]
    return cambios


SYSCTL_RED = {"net.ipv4.tcp_syncookies": "1", "net.ipv4.conf.all.accept_redirects": "0", "net.ipv4.conf.default.accept_redirects": "0", "net.ipv6.conf.all.accept_redirects": "0",
              "net.ipv4.conf.all.send_redirects": "0", "net.ipv4.conf.all.accept_source_route": "0", "net.ipv4.conf.default.accept_source_route": "0",
              "net.ipv4.conf.all.log_martians": "1", "net.ipv4.icmp_echo_ignore_broadcasts": "1", "net.ipv4.icmp_ignore_bogus_error_responses": "1",
              "net.ipv4.conf.all.rp_filter": "2", "net.ipv4.conf.default.rp_filter": "2"}      # 2 = estricto «flexible»: no rompe VPN (Tailscale/WireGuard) ni equipos con dos redes
SYSCTL_KERNEL = {"kernel.randomize_va_space": "2", "kernel.kptr_restrict": "2", "kernel.dmesg_restrict": "1", "fs.protected_hardlinks": "1", "fs.protected_symlinks": "1",
                 "fs.protected_fifos": "2", "fs.protected_regular": "2", "fs.suid_dumpable": "0", "kernel.unprivileged_bpf_disabled": "1", "net.core.bpf_jit_harden": "2"}
TOLERAR_KERNEL = {"kernel.kptr_restrict": ("1",), "kernel.unprivileged_bpf_disabled": ("1", "2")}


# ---------------------------------------------------------------------------- módulos del kernel poco usados
MODULOS = ["cramfs", "freevxfs", "jffs2", "hfs", "hfsplus", "dccp", "sctp", "rds", "tipc"]


def _modulos_estado(ctx: Contexto):
    txt = "".join(ctx.leer(f) for f in ["/etc/modprobe.d/sentinel-endurecer.conf"])
    falta = [m for m in MODULOS if not re.search(rf"^install\s+{m}\s+/bin/(true|false)", txt, re.M)]
    return (PENDIENTE, f"{len(falta)} de {len(MODULOS)} sin bloquear") if falta else (APLICADA, "ya están bloqueados")


def _modulos_cambios(ctx: Contexto):
    cuerpo = "".join(f"install {m} /bin/true\nblacklist {m}\n" for m in MODULOS)
    return [Cambio("/etc/modprobe.d/sentinel-endurecer.conf", "# Sentinel · endurecimiento: módulos que casi nadie usa y que han tenido fallos graves\n# Para quitarlo: sudo sentinel endurecer revertir\n" + cuerpo)]


# ---------------------------------------------------------------------------- volcados de memoria
def _core_estado(ctx: Contexto):
    ok = "hard core 0" in ctx.leer("/etc/security/limits.d/99-sentinel-endurecer.conf") and ctx.sysctl("fs.suid_dumpable") in ("0", "")
    return (APLICADA, "ya están desactivados") if ok else (PENDIENTE, "los programas pueden volcar su memoria a disco (puede incluir contraseñas)")


def _core_cambios(ctx: Contexto):
    return [Cambio("/etc/security/limits.d/99-sentinel-endurecer.conf", "# Sentinel · endurecimiento: sin volcados de memoria\n* hard core 0\n"),
            Cambio("/etc/sysctl.d/99-sentinel-coredump.conf", "# Sentinel · endurecimiento\nfs.suid_dumpable = 0\n")]


# ---------------------------------------------------------------------------- actualizaciones automáticas de seguridad
def _auto_estado(ctx: Contexto):
    if not ctx.existe("/usr/bin/unattended-upgrade") and not ctx.existe("/usr/share/unattended-upgrades"):
        return BLOQUEADA, "falta instalar «unattended-upgrades» (sudo apt install unattended-upgrades); Sentinel no instala programas por su cuenta"
    t = ctx.leer("/etc/apt/apt.conf.d/20auto-upgrades") + ctx.leer("/etc/apt/apt.conf.d/52sentinel-autoupdates")
    ok = re.search(r'APT::Periodic::Update-Package-Lists\s+"1"', t) and re.search(r'APT::Periodic::Unattended-Upgrade\s+"1"', t)
    return (APLICADA, "ya se instalan solas") if ok else (PENDIENTE, "las actualizaciones de seguridad esperan a que las instales a mano")


def _auto_cambios(ctx: Contexto):
    return [Cambio("/etc/apt/apt.conf.d/52sentinel-autoupdates", '// Sentinel · endurecimiento: parches de seguridad automáticos\nAPT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n')]


# ---------------------------------------------------------------------------- SSH (solo si hay servidor SSH; nunca te deja fuera)
def _sshd_hay(ctx: Contexto) -> bool:
    """¿Hay un servidor SSH instalado? (puede quedar un sshd_config suelto de uno desinstalado: eso no cuenta)"""
    return ctx.existe("/etc/ssh/sshd_config") and (ctx.existe("/usr/sbin/sshd") or ctx.existe("/sbin/sshd"))


def _ssh_llaves(ctx: Contexto) -> bool:
    """¿Hay al menos una llave autorizada para entrar por SSH? Sin ella, desactivar las contraseñas dejaría a todos fuera."""
    for home in glob.glob(ctx.ruta("/home/*")) + [ctx.ruta("/root")] + glob.glob(ctx.ruta("/Users/*")) + [ctx.ruta("/var/root")]:      # las dos últimas, macOS
        try:
            if os.path.getsize(os.path.join(home, ".ssh", "authorized_keys")) > 20:
                return True
        except OSError:
            continue
    return False


def _ssh_texto(ctx: Contexto) -> str:
    return ctx.leer("/etc/ssh/sshd_config") + "\n" + "".join(ctx.leer(f[len(ctx.raiz):] if ctx.raiz != "/" else f) for f in sorted(glob.glob(ctx.ruta("/etc/ssh/sshd_config.d/*.conf"))))


def _ssh_valor(txt: str, clave: str) -> str:
    v = re.findall(rf"^\s*{clave}\s+(\S+)", txt, re.I | re.M)
    return v[0].lower() if v else ""


def _ssh_basico_estado(ctx: Contexto):
    if not _sshd_hay(ctx):
        return NO_APLICA, "no hay servidor SSH instalado"
    t = _ssh_texto(ctx)
    falta = [k for k, v in (("PermitRootLogin", "no"), ("X11Forwarding", "no"), ("PermitEmptyPasswords", "no")) if _ssh_valor(t, k) != v]
    return (PENDIENTE, "falta definir: " + ", ".join(falta)) if falta else (APLICADA, "SSH ya endurecido")


def _ssh_basico_cambios(ctx: Contexto):
    return [Cambio("/etc/ssh/sshd_config.d/90-sentinel-endurecer.conf", "# Sentinel · endurecimiento de SSH (se puede borrar este archivo para deshacerlo)\nPermitRootLogin no\nX11Forwarding no\nPermitEmptyPasswords no\nMaxAuthTries 4\nLoginGraceTime 30\n")]


def _sshd_comprobar(ctx: Contexto):
    rc, out = ctx.run(["sshd", "-t"], 15)
    return (True, "sshd acepta la configuración") if rc == 0 else (False, "sshd rechaza la configuración: " + out.strip()[:160])


def _ssh_llaves_estado(ctx: Contexto):
    if not _sshd_hay(ctx):
        return NO_APLICA, "no hay servidor SSH instalado"
    if _ssh_valor(_ssh_texto(ctx), "PasswordAuthentication") == "no":
        return APLICADA, "SSH ya exige llave"
    if not _ssh_llaves(ctx):
        return BLOQUEADA, "NO se aplica: ningún usuario tiene una llave SSH autorizada y te quedarías sin poder entrar. Crea una con «ssh-copy-id» primero"
    return PENDIENTE, "SSH todavía acepta contraseñas (las prueban a la fuerza todo el día)"


def _ssh_llaves_cambios(ctx: Contexto):
    return [Cambio("/etc/ssh/sshd_config.d/91-sentinel-solo-llaves.conf", "# Sentinel · SSH solo con llave (se puede borrar este archivo para deshacerlo)\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n")]


# ---------------------------------------------------------------------------- reglas de auditoría
AUDIT_REGLAS = """# Sentinel · endurecimiento: reglas de auditoría básicas (CIS)
-w /etc/passwd -p wa -k identidad
-w /etc/shadow -p wa -k identidad
-w /etc/group -p wa -k identidad
-w /etc/gshadow -p wa -k identidad
-w /etc/sudoers -p wa -k privilegios
-w /etc/sudoers.d/ -p wa -k privilegios
-w /etc/ssh/sshd_config -p wa -k ssh
-w /etc/ssh/sshd_config.d/ -p wa -k ssh
-w /var/log/sudo.log -p wa -k privilegios
-w /sbin/insmod -p x -k modulos
-w /sbin/rmmod -p x -k modulos
-w /sbin/modprobe -p x -k modulos
-a always,exit -F arch=b64 -S init_module,delete_module,finit_module -k modulos
-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k hora
"""


def _audit_estado(ctx: Contexto):
    if not ctx.existe("/sbin/auditd") and not ctx.existe("/usr/sbin/auditd"):
        return BLOQUEADA, "falta instalar «auditd» (sudo apt install auditd); Sentinel no instala programas por su cuenta"
    return (APLICADA, "ya están") if "-k identidad" in ctx.leer("/etc/audit/rules.d/90-sentinel-endurecer.rules") else (PENDIENTE, "auditd no vigila cambios en cuentas, sudo ni SSH")


def _audit_cambios(ctx: Contexto):
    return [Cambio("/etc/audit/rules.d/90-sentinel-endurecer.rules", AUDIT_REGLAS, 0o640)]


MEDIDAS = [
    Medida("kernel-red", "Red: ignorar redirecciones y rutas falsas", "Ajusta 12 parámetros de la red del sistema: no aceptar redirecciones ICMP ni rutas de origen, activar las «syncookies» y anotar paquetes imposibles.",
           "Evita que alguien en tu red te desvíe el tráfico (man-in-the-middle) o te tumbe con una inundación de conexiones.", "ninguno", "basico",
           _sysctl_estado(SYSCTL_RED), _sysctl_cambios("99-sentinel-red.conf", SYSCTL_RED, "red"), lambda ctx: [["sysctl", "--system"]],
           nota="El filtro de ruta inversa queda en modo flexible (2) para no romper VPN como Tailscale."),
    Medida("kernel-proteccion", "Kernel: ocultar direcciones internas y proteger archivos temporales", "Esconde direcciones de memoria del kernel, restringe `dmesg`, protege enlaces y archivos en carpetas compartidas y desactiva BPF para usuarios sin privilegios.",
           "Dificulta que un programa malicioso ya dentro de tu cuenta escale a administrador.", "ninguno", "basico",
           _sysctl_estado(SYSCTL_KERNEL, TOLERAR_KERNEL), _sysctl_cambios("99-sentinel-kernel.conf", SYSCTL_KERNEL, "kernel"), lambda ctx: [["sysctl", "--system"]]),
    Medida("modulos-raros", "Bloquear módulos del kernel que casi nadie usa", "Impide cargar 9 módulos antiguos o raros (cramfs, jffs2, dccp, sctp…).",
           "Han tenido fallos graves de seguridad y un atacante los carga a propósito para aprovecharlos.", "ninguno", "basico",
           _modulos_estado, _modulos_cambios),
    Medida("ssh-basico", "SSH: sin root, sin X11 y con menos intentos", "Crea un archivo propio de SSH que prohíbe entrar como root y contraseñas vacías, y limita los intentos.",
           "Reduce lo que un atacante puede probar contra tu SSH.", "bajo", "basico", _ssh_basico_estado, _ssh_basico_cambios,
           lambda ctx: [["systemctl", "reload", "ssh"]], _sshd_comprobar, "Se comprueba con `sshd -t` antes de recargar; si falla se deshace solo."),
    Medida("actualizaciones-auto", "Instalar solas las actualizaciones de seguridad", "Activa los parches de seguridad automáticos (unattended-upgrades).",
           "La mayoría de los equipos comprometidos lo fueron por un fallo ya corregido que nadie instaló.", "bajo", "recomendado", _auto_estado, _auto_cambios,
           nota="Pueden reiniciar servicios al actualizar; no reinician el equipo."),
    Medida("sin-volcados", "No guardar la memoria de los programas que fallan", "Desactiva los volcados de memoria (core dumps).",
           "Un volcado puede contener contraseñas o llaves en texto plano.", "bajo", "recomendado", _core_estado, _core_cambios, lambda ctx: [["sysctl", "--system"]],
           nota="Si programas y depuras, dejarás de tener volcados para analizar."),
    Medida("auditoria-basica", "Auditoría: vigilar cuentas, sudo y SSH", "Agrega reglas a auditd para registrar cambios en usuarios, sudo, SSH y carga de módulos.",
           "Permite saber quién cambió qué si algo sale mal.", "bajo", "recomendado", _audit_estado, _audit_cambios, lambda ctx: [["augenrules", "--load"]]),
    Medida("ssh-solo-llaves", "SSH: entrar solo con llave, sin contraseña", "Desactiva el ingreso por contraseña en SSH.",
           "Las contraseñas se prueban a la fuerza todo el día; una llave no.", "medio", "estricto", _ssh_llaves_estado, _ssh_llaves_cambios,
           lambda ctx: [["systemctl", "reload", "ssh"]], _sshd_comprobar, "Solo se aplica si ya hay una llave autorizada; así no te quedas sin acceso."),
]


# ---------------------------------------------------------------------------- motor
@dataclass
class Item:
    medida: Medida
    codigo: str
    detalle: str
    cambios: list = field(default_factory=list)


def indice_perfil(p: str) -> int:
    return PERFILES.index(p)


def medidas() -> list:
    """Las medidas de este sistema (en macOS son otras; el motor es el mismo)."""
    if plataforma.ES_MAC:
        from . import endurecer_mac          # importa este módulo: por eso va aquí
        return endurecer_mac.MEDIDAS
    return MEDIDAS


def plan(perfil: str = "recomendado", solo: list[str] | None = None, ctx: Contexto | None = None) -> list[Item]:
    if perfil not in PERFILES:
        raise ValueError(f"perfil desconocido: {perfil}")
    ctx = ctx or Contexto()
    out = []
    for m in medidas():
        if solo and m.id not in solo:
            continue
        if not solo and indice_perfil(m.perfil) > indice_perfil(perfil):
            continue
        codigo, detalle = m.estado(ctx)
        out.append(Item(m, codigo, detalle, m.cambios(ctx) if codigo == PENDIENTE else []))
    return out


def _guardar_json(path: str, obj) -> None:
    core.atomic_write_json(path, obj, 0o600)


def _marcar_cambio_propio(rutas: list[str]) -> None:
    """Avisa al vigilante de archivos de que estos cambios los hizo Sentinel (para que no los reporte como un ataque)."""
    rutas = sorted(set(rutas) | {os.path.realpath(r) for r in rutas})      # en macOS /etc es un enlace a /private/etc, que es lo que se vigila
    try:
        core.atomic_write_json(os.path.join(core.state_dir(), "self_changes.json"), {"at": core.now(), "paths": rutas}, 0o640, share=True)
    except OSError:
        pass


def aplicar(items: list[Item], ctx: Contexto | None = None, alerter=None) -> dict:
    """Aplica las medidas pendientes con copia de seguridad. Devuelve {«aplicadas»: [...], «revertidas»: [...], «omitidas»: [...], «carpeta»: ...}."""
    ctx = ctx or Contexto()
    pend = [i for i in items if i.codigo == PENDIENTE]
    res = {"aplicadas": [], "revertidas": [], "omitidas": [(i.medida.id, i.detalle) for i in items if i.codigo != PENDIENTE and i.codigo != APLICADA], "carpeta": ""}
    if not pend:
        return res
    ts = time.strftime("%Y%m%d-%H%M%S")
    carpeta = os.path.join(base_dir(), ts)
    core.ensure_dir(os.path.join(carpeta, "copias"), 0o700)
    res["carpeta"] = carpeta
    manifiesto = {"fecha": core.iso(), "medidas": []}
    rutas_todas = []
    for it in pend:
        m = it.medida
        previo = []
        for c in it.cambios:
            destino = ctx.ruta(c.ruta)
            existia = os.path.exists(destino)
            copia = ""
            if existia:
                copia = os.path.join(carpeta, "copias", re.sub(r"[^\w.-]", "_", c.ruta))
                shutil.copy2(destino, copia)
            previo.append({"ruta": c.ruta, "existia": existia, "copia": copia})
        entrada = {"id": m.id, "archivos": previo}
        if m.deshacer:
            entrada["deshacer"] = m.deshacer(ctx)        # antes de cambiar nada: depende de cómo está ahora
        manifiesto["medidas"].append(entrada)
        _guardar_json(os.path.join(carpeta, "manifiesto.json"), manifiesto)          # el manifiesto se guarda ANTES de tocar nada
        for c in it.cambios:
            destino = ctx.ruta(c.ruta)
            core.ensure_dir(os.path.dirname(destino), 0o755)
            tmp = destino + ".sentinel-tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                f.write(c.contenido)
            os.chmod(tmp, c.modo)
            os.replace(tmp, destino)
            rutas_todas.append(c.ruta)
        _marcar_cambio_propio(rutas_todas)
        for cmd in (m.despues(ctx) if m.despues else []):
            ctx.run(cmd, 60)
        ok, msg = (m.comprobar(ctx) if m.comprobar else (True, ""))
        if ok and m.deshacer and m.estado(ctx)[0] != APLICADA:
            ok, msg = False, "el sistema no aceptó el cambio"
        if not ok:
            _restaurar_medida(manifiesto["medidas"][-1], ctx)
            for cmd in (entrada["deshacer"] if m.deshacer else (m.despues(ctx) if m.despues else [])):
                ctx.run(cmd, 60)
            res["revertidas"].append((m.id, msg))
            manifiesto["medidas"].pop()
            _guardar_json(os.path.join(carpeta, "manifiesto.json"), manifiesto)
            continue
        res["aplicadas"].append(m.id)
        if alerter:
            alerter.emit("info", "endurecer", "aplicada", f"Endurecimiento aplicado: {m.titulo}", key=f"hard:{m.id}:{ts}", medida=m.id)
    _marcar_cambio_propio(rutas_todas)
    if not res["aplicadas"]:
        shutil.rmtree(carpeta, ignore_errors=True)
        res["carpeta"] = ""
    return res


def _restaurar_medida(entrada: dict, ctx: Contexto) -> None:
    for a in entrada["archivos"]:
        destino = ctx.ruta(a["ruta"])
        if a["existia"] and a["copia"] and os.path.exists(a["copia"]):
            shutil.copy2(a["copia"], destino)
        else:
            try:
                os.remove(destino)
            except OSError:
                pass


def historial() -> list[str]:
    return sorted(d for d in os.listdir(base_dir()) if os.path.isfile(os.path.join(base_dir(), d, "manifiesto.json"))) if os.path.isdir(base_dir()) else []


def revertir(carpeta: str | None = None, ctx: Contexto | None = None, alerter=None) -> dict:
    """Deshace una tanda de endurecimiento (por defecto la última): restaura las copias o borra los archivos que creamos."""
    ctx = ctx or Contexto()
    hist = historial()
    nombre = carpeta or (hist[-1] if hist else "")
    if not nombre or nombre not in hist:
        return {"revertidas": [], "error": "No hay nada que revertir." if not hist else f"No existe la tanda «{carpeta}». Disponibles: {', '.join(hist)}"}
    man = core.read_json(os.path.join(base_dir(), nombre, "manifiesto.json"))
    ids, rutas = [], []
    for ent in man["medidas"]:
        _restaurar_medida(ent, ctx)
        ids.append(ent["id"]); rutas += [a["ruta"] for a in ent["archivos"]]
    _marcar_cambio_propio(rutas)
    por_id = {m.id: m for m in medidas()}
    visto = set()
    for ent in reversed(man["medidas"]):                 # las que son comandos: lo guardado al aplicar
        for cmd in ent.get("deshacer", []):
            ctx.run(cmd, 60)
    for i in ids:
        m = por_id.get(i)
        for cmd in (m.despues(ctx) if m and m.despues and not m.deshacer else []):
            if tuple(cmd) not in visto:
                visto.add(tuple(cmd)); ctx.run(cmd, 60)
    # un interruptor puede negarse a volver atrás (macOS reciente no deja apagar Gatekeeper por comando): se mira, no se supone
    siguen = [(m.id, m.titulo) for m in (por_id.get(e["id"]) for e in man["medidas"] if e.get("deshacer")) if m and m.estado(ctx)[0] == APLICADA]
    ids = [i for i in ids if i not in {x for x, _ in siguen}]
    os.rename(os.path.join(base_dir(), nombre, "manifiesto.json"), os.path.join(base_dir(), nombre, "manifiesto.revertido.json"))
    if alerter:
        alerter.emit("info", "endurecer", "revertida", f"Endurecimiento revertido ({nombre}): {', '.join(ids)}", key=f"hard:rev:{nombre}")
    return {"revertidas": ids, "sin_deshacer": siguen, "error": ""}
