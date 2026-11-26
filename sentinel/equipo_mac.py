"""El informe del equipo en macOS: las mismas secciones, leídas con las herramientas de Apple.

Lo que todavía no se revisa en Mac lo dice con esas palabras: nunca da algo por bueno sin haberlo mirado.
"""
from __future__ import annotations

import collections
import glob
import hashlib
import os
import platform
import re
import time

from . import authwatch, core, equipo, hostcheck, servicio

NO_REVISADO = "No se revisa en macOS todavía."
DUENOS_ROOT = ("/", "/private/etc", "/usr", "/usr/bin", "/usr/sbin", "/bin", "/sbin", "/Library", "/Library/LaunchDaemons", "/Library/LaunchAgents",
               "/private/etc/sudoers", "/private/etc/sudoers.d", "/private/etc/passwd", "/private/etc/group", "/private/etc/ssh", "/private/etc/pam.d")
DE_HOMEBREW = ("/usr/local/bin", "/usr/local/sbin")
PERSISTENCIA = ("/Library/LaunchDaemons", "/Library/LaunchAgents", "/Library/StartupItems", "/private/var/at/tabs", "/private/etc/periodic")
PERFILES_SHELL = (".zshrc", ".zprofile", ".zshenv", ".bashrc", ".bash_profile", ".profile")


class RevisionMac(equipo.Revision):
    def _casas(self) -> list[str]:
        return ["/private/var/root"] + sorted(h for h in glob.glob("/Users/*") if os.path.basename(h) != "Shared")

    def _ss_escucha(self) -> str:
        salida = ""
        for filtro in (["-iTCP", "-sTCP:LISTEN"], ["-iUDP"]):
            rc, out = core.run(["lsof", "-nP", *filtro, "-F", "pcPn"], 30)
            salida += hostcheck.lsof_a_ss(out if rc in (0, 1) else "")          # lsof sale con 1 cuando no encuentra nada
        return salida

    def _ss_establecidas(self) -> str:
        rc, out = core.run(["lsof", "-nP", "-iTCP", "-sTCP:ESTABLISHED", "-F", "pcPn"], 30)
        return hostcheck.lsof_a_ss(out if rc in (0, 1) else "", conectados=True)

    def _procesos(self):
        """(pid, programa, línea de comandos) de los procesos que no son esta revisión."""
        rc, out = core.run(["ps", "-axww", "-o", "pid=,command="], 15)
        if rc != 0:
            raise OSError("no pude listar los procesos con ps")
        for ln in out.splitlines():
            p = ln.strip().split(None, 1)
            if len(p) == 2 and p[0].isdigit() and int(p[0]) != os.getpid():
                yield p[0], os.path.basename(p[1].split()[0]).lstrip("-"), p[1][:300]

    def _sin_revisar(self, titulo: str) -> None:
        self.inf.sec(titulo)
        self.inf.linea(NO_REVISADO)

    # ------------------------------------------------------------------ comprobaciones
    def contexto(self) -> None:
        i = self.inf
        i.sec("Contexto del sistema")
        i.linea(f"Equipo: {i.host} · macOS {platform.mac_ver()[0]} · kernel {os.uname().release}")
        m = re.search(r"sec = (\d+)", core.run(["sysctl", "-n", "kern.boottime"], 5)[1])
        up = max(0, time.time() - int(m.group(1))) if m else 0
        quienes = core.run(["who"], 5)[1].strip()
        i.linea(f"Encendido hace {int(up // 3600)} h {int(up % 3600 // 60)} min · sesiones abiertas: {len(quienes.splitlines()) if quienes else 0}")

    def autenticacion(self) -> None:
        i = self.inf
        i.sec("Autenticación fallida y accesos (registro del sistema, 24 h)")
        rc, out = core.run(["log", "show", "--last", "24h", "--info", "--style", "ndjson", "--predicate", authwatch.FILTRO_MAC], 180)
        if rc != 0:
            i.linea("No pude leer el registro del sistema (hace falta administrador)."); return
        mensajes = [m for m in map(authwatch.mensaje_mac, out.splitlines()) if m]
        fallos_r = [msg for ident, msg in mensajes if ident == "sshd" and (authwatch.RE_FAIL.search(msg) or authwatch.RE_INVALID.search(msg))]
        fallos_l = [msg for ident, msg in mensajes if (ident == "sudo" and authwatch.RE_SUDO_FAIL.search(msg)) or (ident == "su" and authwatch.RE_SU_FAIL_MAC.search(msg))]
        aceptados = [msg for ident, msg in mensajes if ident == "sshd" and authwatch.RE_ACCEPT.search(msg)]
        i.linea(f"Fallos remotos (SSH): {len(fallos_r)} · fallos locales (sudo y su): {len(fallos_l)}")
        i.linea("(macOS conserva poco tiempo parte de estos mensajes: el recuento puede quedarse corto. Las alertas en vivo de Sentinel están más abajo.)")
        if fallos_r:
            ips = collections.Counter(m for x in fallos_r for m in re.findall(r"from ([0-9a-fA-F:.]{3,})", x))
            i.linea("IPs de origen: " + ", ".join(f"{ip} ({n})" for ip, n in ips.most_common(8)))
            if len(fallos_r) >= 10:
                i.hall("ALTO", "autenticación", f"Posible fuerza bruta: {len(fallos_r)} fallos de acceso remoto en 24 h")
            else:
                i.hall("MEDIO", "autenticación", f"{len(fallos_r)} fallo(s) de autenticación remota en 24 h")
        if len(fallos_l) >= 8:
            i.hall("BAJO", "autenticación", f"{len(fallos_l)} contraseñas locales fallidas en 24 h (sudo o su de este equipo)")
        if aceptados:
            i.hall("MEDIO", "autenticación", f"{len(aceptados)} acceso(s) SSH aceptado(s) en 24 h")

    def firewall(self) -> None:
        self.inf.sec("Firewall y puertos abiertos a cualquier origen")
        self.inf.linea("Sentinel todavía no revisa las reglas del cortafuegos de macOS (sí bloquea atacantes con pf).")

    def shell_reversa(self) -> None:
        i = self.inf
        i.sec("Indicadores de shell reversa")
        n = 0
        for pid, comm, cmd in self._procesos():
            if "sentinel" in cmd or " grep " in f" {cmd} ":
                continue
            if comm in equipo.TOOLS:
                i.hall("ALTO", "shell reversa", f"Herramienta de túnel o shell en ejecución: PID {pid} ({comm})"); n += 1
            elif equipo.RSH_RE.search(cmd) and not equipo.solo_destinos_locales(cmd):
                i.hall("ALTO", "shell reversa", f"Línea de comandos con patrón de shell reversa: PID {pid} ({comm}); comando: {' '.join(cmd.split())[:140]}"); n += 1
        if not n:
            i.linea("Sin indicadores en las líneas de comandos. En macOS no se revisa si una consola tiene la red como entrada o salida.")

    def tuneles(self) -> None:
        i = self.inf
        i.sec("Túneles públicos")
        n = 0
        for pid, comm, cmd in self._procesos():
            if comm in ("cloudflared", "ngrok", "localtunnel", "bore", "frpc"):
                dest = re.search(r"--url \S+|http \d+|tcp \d+", cmd)
                i.hall("MEDIO", "túneles", f"Túnel público activo: {comm} (PID {pid}) {dest.group(0) if dest else ''}".strip()); n += 1
            elif comm == "ssh" and re.search(r" -R ", cmd) and "sentinel" not in cmd:
                i.hall("MEDIO", "túneles", f"Túnel SSH inverso (-R) activo (PID {pid})"); n += 1
        if not n:
            i.linea("Ninguno.")

    def paquetes(self) -> None:
        self._sin_revisar("Integridad de los programas instalados")

    def cuentas(self) -> None:
        import grp
        i = self.inf
        i.sec("Cuentas, privilegios y llaves SSH")
        a = hostcheck.accounts()
        for u in a.get("uid0", []):
            i.hall("ALTO", "cuentas", f"La cuenta «{u}» tiene UID 0 (equivale a root)")
        lineas = [f"shell:{u}" for u in a.get("users", [])]
        for g in ("admin", "wheel"):
            try:
                lineas.append(f"grupo:{g}:{','.join(sorted(grp.getgrnam(g).gr_mem))}")
            except KeyError:
                pass
        for f in ["/private/etc/sudoers"] + sorted(glob.glob("/private/etc/sudoers.d/*")):
            try:
                with open(f, encoding="utf-8") as fh:
                    lineas += [f"sudoers:{os.path.basename(f)}:{ln.strip()}" for ln in fh if ln.strip() and not ln.lstrip().startswith(("#", "@includedir", "Defaults"))]
            except OSError:
                pass
        for casa in self._casas():
            ak = os.path.join(casa, ".ssh", "authorized_keys")
            if os.path.isfile(ak):
                lineas += [f"llave:{casa}:{ln.strip()}" for ln in core.run(["ssh-keygen", "-lf", ak], 10)[1].splitlines()]
        self.comparar("cuentas", lineas, "MEDIO", "Cambiaron cuentas con shell, grupos de administradores, sudoers o llaves SSH autorizadas")

    def duenos(self) -> None:
        i = self.inf
        i.sec("Dueños de carpetas y archivos críticos del sistema")
        malos = equipo.duenos_inseguros(DUENOS_ROOT)
        if malos:
            i.hall("ALTO", "dueños", f"{len(malos)} carpeta(s)/archivo(s) críticos del sistema NO son de root: " + ", ".join(malos[:6]) + (" …" if len(malos) > 6 else "")
                   + ". Quien los posea puede reemplazar lo que root ejecuta")
        else:
            i.linea("Las carpetas del sistema son de root, como debe ser.")
        brew = equipo.duenos_inseguros(DE_HOMEBREW)
        if brew:
            i.hall("BAJO", "dueños", "Un usuario puede cambiar programas en " + ", ".join(brew) + " (habitual si usas Homebrew): no ejecutes desde ahí nada como administrador sin revisarlo")

    def persistencia(self) -> None:
        i = self.inf
        i.sec("Persistencia (programas de arranque, tareas programadas, perfiles de shell)")
        rutas = []
        for d in list(PERSISTENCIA) + [os.path.join(c, "Library", "LaunchAgents") for c in self._casas()]:
            for raiz, dirs, files in os.walk(d):
                if raiz.count(os.sep) - d.count(os.sep) > 2:
                    dirs[:] = []
                rutas += [os.path.join(raiz, f) for f in files if f != ".DS_Store"]
        rutas += [os.path.join(c, f) for c in self._casas() for f in PERFILES_SHELL]
        lineas = []
        for p in sorted(set(rutas)):
            try:
                if os.path.isfile(p):
                    with open(p, "rb") as fh:
                        lineas.append(hashlib.sha256(fh.read()).hexdigest()[:12] + " " + p)
            except OSError:
                continue
        self.comparar("persistencia", lineas, "BAJO" if self.sentinel_activo else "MEDIO", "Cambió la persistencia (programas de arranque, tareas programadas o perfiles de shell)")

    def herramientas(self) -> None:
        i = self.inf
        i.sec("Tareas de Sentinel")
        for n in servicio.TAREAS:
            est = servicio.estado(f"sentinel-{n}")
            i.linea(f"  sentinel-{n:<19} {est}")
            if est == "inactive":
                i.hall("MEDIO", "herramientas", f"La tarea «sentinel-{n}» está instalada pero no está activa (sudo sentinel iniciar)")

    def integridad_extra(self) -> None:
        self._sin_revisar("Protección de integridad del sistema (SIP) y antivirus")

    def actualizaciones(self) -> None:
        self._sin_revisar("Actualizaciones y reinicio pendiente")
