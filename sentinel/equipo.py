"""Revisión completa del equipo («sentinel equipo»): una foto de seguridad con informe HTML/texto que se puede mandar por correo.

Reúne lo que antes hacían dos scripts sueltos (auditoria_red.sh y auditoria_extra.sh) y reutiliza lo que Sentinel ya sabe:
el firewall (qué puertos están abiertos a cualquiera), los procesos sospechosos, las cuentas y los eventos de las últimas 24 horas.
No lee el historial de comandos ni muestra los argumentos de los procesos (el informe viaja por correo y podrían llevar secretos).
Los resultados se clasifican en ALTO / MEDIO / BAJO; solo ALTO y MEDIO suben el nivel global.
"""
from __future__ import annotations

import collections
import glob
import hashlib
import html
import json
import os
import re
import shutil
import socket
import stat
import sys
import time
from dataclasses import dataclass

from . import core, firewall, hostcheck, mailer, plataforma, report, servicio
from .firewall import exposure

NIVELES = ("ALTO", "MEDIO", "BAJO")
SHELLS = {"bash", "sh", "dash", "zsh", "ash", "ksh", "fish", "python", "python3", "perl", "ruby", "php", "lua", "node", "busybox"}
TOOLS = {"nc", "ncat", "netcat", "socat", "chisel", "msfconsole"}
RSH_RE = re.compile(r"/dev/(tcp|udp)/|bash -i >|sh -i >|mkfifo \S+ .*(nc|ncat) |(nc|ncat) .* -e |socat .*(exec|EXEC)|python[0-9.]* -c .*socket.*connect|perl -e .*socket")
DPKG_EXCLUIR = re.compile(r"^/var/lib/(rkhunter|aide|dpkg|mysql|docker|containerd|postgresql|wazuh|sentinel)|^/var/cache|^/var/ossec/|^/usr/share/wazuh-|^/etc/wazuh")
DPKG_CRITICO = re.compile(r"^/(bin|sbin|usr/bin|usr/sbin|lib|usr/lib|boot)/")
TMP_DIRS = ("/tmp", "/dev/shm", "/var/tmp")
TMP_RUIDO = re.compile(r"systemd-private|snap-private-tmp|opensearch-|\.X11|\.ICE-unix|\.font-unix|\.XIM-unix|\.Test-unix|hsperfdata|\.com\.google|/claude-|scratchpad")
RKH_BENIGNO = re.compile(r"/etc/\.java|lwp-request|SSH and rkhunter configuration|large\) shared memory|xdg-desktop-portal|Possible rootkits|Suspect files|Process:")
# Carpetas y archivos del sistema que SOLO puede poseer root: si los posee un usuario normal, ese usuario puede reemplazar lo que root ejecuta o instala
# (ejemplo real: un «chown -R usuario /var» dejó a dpkg y apt en manos de un usuario, que así llegaba a root en la próxima actualización).
DUENOS_ROOT = ("/", "/etc", "/usr", "/usr/bin", "/usr/sbin", "/usr/lib", "/usr/local", "/usr/local/bin", "/usr/local/sbin", "/bin", "/sbin", "/lib", "/boot", "/opt",
               "/var", "/var/lib", "/var/lib/dpkg", "/var/lib/dpkg/status", "/var/lib/apt", "/var/cache", "/var/cache/apt", "/var/backups", "/var/spool",
               "/etc/sudoers", "/etc/sudoers.d", "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/cron.d", "/etc/systemd/system", "/etc/ssh", "/etc/pam.d", "/etc/ld.so.preload")


def duenos_inseguros(rutas=DUENOS_ROOT, estat=os.stat) -> list[str]:
    """Rutas del sistema cuyo dueño no es root (o que cualquiera puede escribir sin «sticky»). Devuelve «ruta (motivo)»; las que no existen se ignoran."""
    malos = []
    for p in rutas:
        try:
            st = estat(p)
        except OSError:
            continue
        if st.st_uid != 0:
            try:
                import pwd
                quien = pwd.getpwuid(st.st_uid).pw_name
            except (ImportError, KeyError):
                quien = f"uid {st.st_uid}"
            malos.append(f"{p} (dueño: {quien})")
        elif stat.S_ISDIR(st.st_mode) and st.st_mode & 0o002 and not st.st_mode & 0o1000:
            malos.append(f"{p} (cualquiera puede escribir)")
        elif not stat.S_ISDIR(st.st_mode) and st.st_mode & 0o002:
            malos.append(f"{p} (cualquiera puede modificarlo)")
    return malos


_DEV_RE = re.compile(r"/dev/(?:tcp|udp)/([^/\s]+)/")
_RSH_OTROS = re.compile(r"bash -i >|sh -i >|mkfifo \S+ .*(nc|ncat) |(nc|ncat) .* -e |socat .*(exec|EXEC)|python[0-9.]* -c .*socket.*connect|perl -e .*socket")


def solo_destinos_locales(cmd: str) -> bool:
    """True si el único indicio es /dev/tcp o /dev/udp hacia esta misma máquina
    (p. ej. un script que espera a que un servicio local responda): no es una shell reversa."""
    if _RSH_OTROS.search(cmd):
        return False
    destinos = _DEV_RE.findall(cmd)
    return bool(destinos) and all(x in ("127.0.0.1", "localhost", "::1", "[::1]") for x in destinos)


@dataclass
class Hallazgo:
    nivel: str
    area: str
    texto: str


class Informe:
    def __init__(self) -> None:
        self.host = socket.gethostname()
        self.fecha = core.iso()
        self.secciones: list[tuple[str, list[str]]] = []
        self.hallazgos: list[Hallazgo] = []
        self._cur: list[str] = []

    def sec(self, titulo: str) -> None:
        self._cur = []
        self.secciones.append((titulo, self._cur))

    def linea(self, texto: str) -> None:
        self._cur.append(texto)

    def hall(self, nivel: str, area: str, texto: str) -> None:
        self.hallazgos.append(Hallazgo(nivel, area, texto))
        self._cur.append(f"[{nivel}] {texto}")

    def unicos(self) -> list[Hallazgo]:
        visto, out = set(), []
        for h in sorted(self.hallazgos, key=lambda h: NIVELES.index(h.nivel)):
            if (h.nivel, h.texto) not in visto:
                visto.add((h.nivel, h.texto))
                out.append(h)
        return out

    def cuenta(self) -> dict:
        c = collections.Counter(h.nivel for h in self.unicos())
        return {n: c.get(n, 0) for n in NIVELES}

    def nivel(self) -> str:
        c = self.cuenta()
        return "ALTO" if c["ALTO"] else "MEDIO" if c["MEDIO"] else "BAJO"

    def asunto(self) -> str:
        c = self.cuenta()
        return f"[Sentinel] Informe del equipo {self.host}: riesgo {self.nivel()} (alto {c['ALTO']}, medio {c['MEDIO']}, bajo {c['BAJO']})"


class Revision:
    """Ejecuta cada comprobación sobre un Informe. Una que falle no detiene a las demás."""

    def __init__(self, cfg, aceptar: bool = False, rapido: bool = False) -> None:
        self.cfg, self.aceptar, self.rapido = cfg, aceptar, rapido
        self.inf = Informe()
        self.allow = core.Allow(cfg)
        self.root = core.is_root()
        self.sentinel_activo = servicio.estado("sentinel-monitor") == "active"

    # ---- referencias (líneas base) propias de esta revisión
    def _ref(self, nombre: str) -> str:
        return os.path.join(core.state_dir(), "equipo", nombre + ".json")

    def comparar(self, nombre: str, lineas: list[str], nivel: str, texto: str) -> None:
        p = self._ref(nombre)
        old = core.read_json(p)
        guardar = lambda: (core.ensure_dir(os.path.dirname(p), 0o750), core.atomic_write_json(p, {"lineas": sorted(lineas), "fecha": core.iso()}))
        try:
            if old is None:
                guardar(); self.inf.linea(f"(referencia de «{nombre}» creada en esta revisión)"); return
            antes, ahora = set(old.get("lineas", [])), set(lineas)
            if antes == ahora:
                self.inf.linea("Sin cambios respecto a la referencia."); return
            self.inf.hall(nivel, nombre, texto)
            for x in sorted(antes - ahora)[:15]:
                self.inf.linea(f"   (antes) {x}")
            for x in sorted(ahora - antes)[:15]:
                self.inf.linea(f"   (ahora) {x}")
            if self.aceptar:
                guardar()
        except OSError:
            self.inf.linea("(no pude guardar la referencia: se necesita administrador)")

    def run(self) -> Informe:
        pasos = [self.contexto, self.autenticacion, self.firewall, self.puertos, self.conexiones, self.shell_reversa, self.procesos_riesgo,
                 self.tmp_ejecutables, self.cuentas, self.duenos, self.persistencia, self.herramientas, self.crowdsec, self.tuneles, self.integridad_extra, self.sentinel, self.correo]
        if not self.rapido:
            pasos[8:8] = [self.paquetes]
            pasos.append(self.actualizaciones)
        for paso in pasos:
            try:
                paso()
            except Exception as e:                                   # una comprobación rota no debe tirar el informe entero
                self.inf.sec(f"{paso.__name__} (falló)")
                self.inf.linea(f"La comprobación falló: {type(e).__name__}: {str(e)[:150]}")
        return self.inf

    # ------------------------------------------------------------------ comprobaciones
    def contexto(self) -> None:
        i = self.inf
        i.sec("Contexto del sistema")
        try:
            up = float(open("/proc/uptime", encoding="utf-8").read().split()[0])
        except (OSError, ValueError):
            up = 0
        so = ""
        try:
            so = next((ln.split("=", 1)[1].strip().strip('"') for ln in open("/etc/os-release", encoding="utf-8") if ln.startswith("PRETTY_NAME=")), "")
        except OSError:
            pass
        i.linea(f"Equipo: {i.host} · {so} · kernel {os.uname().release}")
        quienes = core.run(["who"], 5)[1].strip()
        i.linea(f"Encendido hace {int(up // 3600)} h {int(up % 3600 // 60)} min · sesiones abiertas: {len(quienes.splitlines()) if quienes else 0}")
        for ln in core.run(["ip", "-brief", "addr"], 5)[1].splitlines():
            if ln.split()[:2] and ln.split()[1] == "UP":
                i.linea("  " + " ".join(ln.split())[:150])

    def autenticacion(self) -> None:
        i = self.inf
        i.sec("Autenticación fallida y accesos (últimas 24 h)")
        rc, out = core.run(["journalctl", "--since", "24 hours ago", "-q", "--no-pager", "-g", "Failed|Invalid user|authentication failure|Accepted"], 90)
        lineas = out.splitlines() if rc == 0 else []
        remoto = re.compile(r"sshd.*(Failed|Invalid user)|(pam_unix|pam_sss)\(.*authentication failure.*rhost=[0-9a-fA-F:.]{3,}")
        local = re.compile(r"(gdm-password|sudo|su|login)\b.*authentication failure")
        fallos_r = [x for x in lineas if remoto.search(x)]
        fallos_l = [x for x in lineas if local.search(x) and not re.search(r"rhost=[0-9a-fA-F:.]{3,}", x)]
        aceptados = [x for x in lineas if re.search(r"sshd.*Accepted (password|publickey)", x)]
        rc2, lb = core.run(["lastb", "-s", "-1days"], 10)
        btmp = [x for x in lb.splitlines() if x.strip() and "btmp begins" not in x] if rc2 == 0 else []
        i.linea(f"Fallos remotos (SSH/PAM con IP de origen): {len(fallos_r)} · fallos locales (login/sudo, sin IP): {len(fallos_l)} · registros en btmp: {len(btmp)}")
        if fallos_r:
            ips = collections.Counter(m for x in fallos_r for m in re.findall(r"(?:from |rhost=)([0-9a-fA-F:.]{3,})", x))
            i.linea("IPs de origen: " + ", ".join(f"{ip} ({n})" for ip, n in ips.most_common(8)))
            if len(fallos_r) >= 10:
                i.hall("ALTO", "autenticación", f"Posible fuerza bruta: {len(fallos_r)} fallos de acceso remoto en 24 h")
            else:
                i.hall("MEDIO", "autenticación", f"{len(fallos_r)} fallo(s) de autenticación remota en 24 h")
        if btmp:
            i.hall("MEDIO", "autenticación", f"btmp registra {len(btmp)} intento(s) de login fallido en 24 h")
        if len(fallos_l) >= 8:
            i.hall("BAJO", "autenticación", f"{len(fallos_l)} contraseñas locales fallidas en 24 h (login o sudo de este equipo)")
        if aceptados:
            i.hall("MEDIO", "autenticación", f"{len(aceptados)} acceso(s) SSH aceptado(s) en 24 h (el servidor SSH no debería estar en uso)")

    def firewall(self) -> None:
        i = self.inf
        i.sec("Firewall y puertos abiertos a cualquier origen")
        snap = core.read_json(firewall.snapshot_path(), None)
        if (not snap or core.now() - os.path.getmtime(firewall.snapshot_path()) > 600) and self.root:
            try:
                snap = firewall.save_snapshot(self.cfg)
            except Exception:
                snap = snap or None
        if not snap or not snap.get("ok"):
            i.linea("No pude leer el firewall (ejecuta con sudo o espera a que el monitor tome la foto)."); return
        i.linea(f"Cortafuegos: {snap.get('backend', '?')}")
        if self.root and snap.get("backend") == "ufw":
            txt = core.run(["ufw", "status", "verbose"], 10)[1]
            if re.search(r"inactiv|inactive", txt, re.I):
                i.hall("ALTO", "firewall", "UFW está INACTIVO: nada filtra la entrada")
            elif not re.search(r"deny \((incoming|entrantes)\)|reject \((incoming|entrantes)\)", txt, re.I):
                i.hall("ALTO", "firewall", "UFW no deniega el tráfico entrante por defecto")
        abiertas = []
        for r in snap.get("rules", []):
            etiqueta = re.sub(r"^\[\s*\d+\]\s*", "", r.get("label", ""))
            i.linea(f"  {etiqueta:<28} {r['action']:<6} desde {r['from']}" + (f"  # {r['comment']}" if r.get("comment") else ""))
            if r["action"] == "ALLOW" and r["from"].lower().startswith("anywhere") and not etiqueta.lower().startswith(("anywhere on lo", "anywhere (v6) on lo")):
                abiertas.append(etiqueta.replace(" (v6)", ""))
        for puerto in sorted(set(abiertas)):
            i.hall("MEDIO", "firewall", f"El firewall deja entrar a cualquiera por {puerto}. Cerrarlo: sudo ufw delete allow {puerto}")
        for e in snap.get("listening", []):
            if e.get("status") in ("abierto", "docker"):
                i.hall("MEDIO", "firewall", f"{e['proto']}/{e['port']} ({e.get('proc') or '?'}) es alcanzable desde cualquier origen" + (" (Docker salta el firewall)" if e.get("status") == "docker" else ""))

    def puertos(self) -> None:
        i = self.inf
        i.sec("Puertos en escucha")
        filas = set()
        for e in exposure.parse_ss(core.run(["ss", "-tulnpH"], 10)[1]):
            ambito = "local" if e["addr"].startswith(exposure.LOOP) else "TODAS LAS INTERFACES" if e["addr"] in ("0.0.0.0", "*", "[::]", "::") else e["addr"]
            filas.add((e["proto"], ambito, "efímero" if e["port"] >= 32768 and e["proto"] == "udp" else str(e["port"]), e["proc"] or "?"))
        for f in sorted(filas):
            i.linea("  {:<4} {:<22} {:<8} {}".format(*f))
        i.linea("(Quién puede alcanzarlos desde afuera lo decide el firewall: ver la sección anterior; los cambios los vigila Sentinel en vivo.)")

    def conexiones(self) -> None:
        i = self.inf
        i.sec("Conexiones salientes por proceso")
        permitidos = set(core.csv(self.cfg.get("equipo", "conexiones_permitidas", fallback=""))) | self.allow.procs
        c2 = {int(p) for p in core.csv(self.cfg.get("equipo", "puertos_c2", fallback="")) if p.isdigit()}
        por_proc: dict = collections.defaultdict(set)
        for ln in core.run(["ss", "-tnpH", "state", "established"], 10)[1].splitlines():
            f = ln.split()
            if len(f) < 4:
                continue
            peer = f[3]
            if re.match(r"^(127\.|\[::1\]|\[::ffff:127\.)", peer):
                continue
            m = re.search(r'users:\(\("([^"]+)"', ln)
            por_proc[m.group(1) if m else "?"].add(peer)
        i.linea(f"Conexiones externas establecidas: {sum(len(v) for v in por_proc.values())}")
        for proc, peers in sorted(por_proc.items()):
            i.linea(f"  {proc}: " + ", ".join(sorted(peers)[:6]) + (" …" if len(peers) > 6 else ""))
            for p in sorted(peers):
                if p.rsplit(":", 1)[-1].isdigit() and int(p.rsplit(":", 1)[-1]) in c2:
                    i.hall("ALTO", "conexiones", f"Conexión saliente de '{proc}' a {p} (puerto típico de shell reversa o de mando y control)")
            if proc == "?" and not self.root:
                i.linea("    (sin permisos de administrador no se ve qué proceso es: ejecuta con sudo)")
            elif proc == "?":
                i.hall("MEDIO", "conexiones", f"Conexión externa sin proceso identificable hacia {', '.join(sorted(peers)[:3])}")
            elif proc not in permitidos:
                i.hall("MEDIO", "conexiones", f"El proceso '{proc}' tiene conexión externa a {', '.join(sorted(peers)[:3])} y no está en la lista permitida (sentinel config equipo.conexiones_permitidas=…)")

    def shell_reversa(self) -> None:
        i = self.inf
        i.sec("Indicadores de shell reversa")
        tcp: set = set()
        for f in ("/proc/net/tcp", "/proc/net/tcp6"):
            try:
                tcp |= {ln.split()[9] for ln in open(f, encoding="utf-8").read().splitlines()[1:] if len(ln.split()) > 9}
            except OSError:
                pass
        yo, n = os.getpid(), 0
        for d in os.listdir("/proc"):
            if not d.isdigit() or int(d) == yo:
                continue
            try:
                comm = open(f"/proc/{d}/comm", encoding="utf-8", errors="replace").read().strip()
                cmd = open(f"/proc/{d}/cmdline", "rb").read().replace(b"\x00", b" ").decode("utf-8", "replace")[:300]
            except OSError:
                continue
            if "sentinel" in cmd or " grep " in f" {cmd} " or "journalctl" in cmd:
                continue
            if comm in TOOLS:
                i.hall("ALTO", "shell reversa", f"Herramienta de túnel o shell en ejecución: PID {d} ({comm})"); n += 1
                continue
            if comm in SHELLS:
                for fd in (0, 1, 2):
                    try:
                        link = os.readlink(f"/proc/{d}/fd/{fd}")
                    except OSError:
                        continue
                    if link.startswith("socket:[") and link[8:-1] in tcp:
                        i.hall("ALTO", "shell reversa", f"PID {d} ({comm}) tiene un socket TCP como entrada o salida estándar (fd{fd})"); n += 1
                        break
            if RSH_RE.search(cmd) and not solo_destinos_locales(cmd):
                i.hall("ALTO", "shell reversa", f"Línea de comandos con patrón de shell reversa: PID {d} ({comm}); comando: {' '.join(cmd.split())[:140]}"); n += 1
        if not n:
            i.linea("Sin indicadores de shell reversa.")

    def procesos_riesgo(self) -> None:
        i = self.inf
        i.sec("Procesos desde carpetas temporales, mineros y programas reemplazados")
        c = self.cfg
        found = hostcheck.proc_scan(core.csv(c.get("hostcheck", "exec_dirs", fallback="")), [m.lower() for m in core.csv(c.get("hostcheck", "miner_names", fallback=""))], self.allow.procs)
        pend = [f for f in found if f["kind"] == "reinicio_pendiente"]
        for f in found:
            if f["kind"] != "reinicio_pendiente":
                i.hall("ALTO", "procesos", f["msg"])
        if pend:
            nombres = ", ".join(sorted({f["comm"] for f in pend})[:8])
            i.hall("BAJO", "procesos", f"{len(pend)} proceso(s) usan un programa que se actualizó mientras corría ({nombres}): reinícialos para cargar la versión nueva")
        if not found:
            i.linea("Ninguno.")

    def tmp_ejecutables(self) -> None:
        i = self.inf
        i.sec("Ejecutables recientes en carpetas temporales (2 días)")
        limite, hallados = time.time() - 2 * 86400, []
        for base in TMP_DIRS:
            for raiz, dirs, files in os.walk(base):
                dirs[:] = [d for d in dirs if not TMP_RUIDO.search(os.path.join(raiz, d))]
                if raiz.count(os.sep) - base.count(os.sep) > 4:
                    dirs[:] = []
                for f in files:
                    p = os.path.join(raiz, f)
                    try:
                        st = os.lstat(p)
                    except OSError:
                        continue
                    if stat.S_ISREG(st.st_mode) and st.st_mode & 0o111 and st.st_mtime > limite and not f.endswith(".so") and not TMP_RUIDO.search(p):
                        hallados.append(p)
        if hallados:
            i.hall("MEDIO", "temporales", f"{len(hallados)} ejecutable(s) reciente(s) en carpetas temporales: " + ", ".join(sorted(hallados)[:5]))
        else:
            i.linea("Ninguno.")

    def paquetes(self) -> None:
        i = self.inf
        i.sec("Integridad de los paquetes instalados (dpkg -V)")
        rc, out = core.run(["dpkg", "-V"], 400)
        malos = []
        for ln in out.splitlines():
            m = re.match(r"^(.{9}) (.) (/.*)$", ln)
            if m and m.group(1)[2] == "5" and m.group(2) != "c" and not DPKG_EXCLUIR.search(m.group(3)):
                malos.append(m.group(3))
        if not malos:
            i.linea("Todos los archivos de paquetes coinciden con su hash original."); return
        criticos = [p for p in malos if DPKG_CRITICO.match(p)]
        i.linea(f"Archivos con hash distinto (tras excluir carpetas que sus programas reescriben): {len(malos)}")
        for d, n in collections.Counter("/".join(p.split("/")[:4]) for p in malos).most_common(6):
            i.linea(f"   {n:>4}  {d}")
        if criticos:
            i.hall("ALTO", "integridad", f"{len(criticos)} binario(s) o librería(s) con hash distinto al de su paquete: " + ", ".join(criticos[:4]))
        if len(malos) - len(criticos):
            i.hall("BAJO", "integridad", f"{len(malos) - len(criticos)} archivo(s) de otras carpetas con hash distinto (detalle por carpeta arriba)")

    def cuentas(self) -> None:
        i = self.inf
        i.sec("Cuentas, privilegios y llaves SSH")
        a = hostcheck.accounts()
        for u in a.get("uid0", []):
            i.hall("ALTO", "cuentas", f"La cuenta «{u}» tiene UID 0 (equivale a root)")
        for u in a.get("empty", []):
            i.hall("ALTO", "cuentas", f"La cuenta «{u}» no tiene contraseña")
        lineas = [f"shell:{u}" for u in a.get("users", [])]
        try:
            lineas += [f"grupo:{ln.strip()}" for ln in open("/etc/group", encoding="utf-8") if ln.split(":")[0] in ("sudo", "adm", "docker", "lxd", "libvirt", "root", "disk", "shadow", "wheel")]
        except OSError:
            pass
        for f in ["/etc/sudoers"] + sorted(glob.glob("/etc/sudoers.d/*")):
            try:
                lineas += [f"sudoers:{os.path.basename(f)}:{ln.strip()}" for ln in open(f, encoding="utf-8") if ln.strip() and not ln.lstrip().startswith(("#", "@includedir", "Defaults"))]
            except OSError:
                pass
        for home in ["/root"] + sorted(glob.glob("/home/*")):
            ak = os.path.join(home, ".ssh", "authorized_keys")
            if os.path.isfile(ak):
                for ln in core.run(["ssh-keygen", "-lf", ak], 10)[1].splitlines():
                    lineas.append(f"llave:{home}:{ln.strip()}")
        self.comparar("cuentas", lineas, "MEDIO", "Cambiaron cuentas con shell, grupos privilegiados, sudoers o llaves SSH autorizadas")

    def duenos(self) -> None:
        i = self.inf
        i.sec("Dueños de carpetas y archivos críticos del sistema")
        malos = duenos_inseguros()
        if malos:
            i.hall("ALTO", "dueños", f"{len(malos)} carpeta(s)/archivo(s) críticos del sistema NO son de root: " + ", ".join(malos[:6]) + (" …" if len(malos) > 6 else "")
                   + ". Quien los posea puede reemplazar lo que root instala o ejecuta. No uses «chown -R» a ciegas: restaura por zonas (dpkg y apt primero)")
        else:
            i.linea("Todo es de root, como debe ser.")

    def persistencia(self) -> None:
        i = self.inf
        i.sec("Persistencia (cron, systemd, perfiles de shell, preload)")
        try:
            if os.path.getsize("/etc/ld.so.preload") > 0:
                i.hall("ALTO", "persistencia", "/etc/ld.so.preload existe y tiene contenido (carga librerías en todos los programas)")
        except OSError:
            pass
        rutas = []
        for d in ("/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.weekly", "/etc/cron.monthly", "/var/spool/cron/crontabs", "/etc/profile.d", "/etc/xdg/autostart", "/etc/systemd/system"):
            for raiz, dirs, files in os.walk(d):
                if raiz.count(os.sep) - d.count(os.sep) > 2:
                    dirs[:] = []
                rutas += [os.path.join(raiz, f) for f in files if not re.match(r"snap[.-]|.*\.mount$|.*\.wants$", f)]
        rutas.append("/etc/rc.local")
        for home in ["/root"] + sorted(glob.glob("/home/*")):
            for sub in (".config/autostart", ".config/systemd/user"):
                rutas += glob.glob(os.path.join(home, sub, "*"))
            rutas += [os.path.join(home, f) for f in (".bashrc", ".profile", ".bash_profile", ".bash_login", ".zshrc")]
        lineas = []
        for p in sorted(set(rutas)):
            try:
                if os.path.isfile(p):
                    lineas.append(hashlib.sha256(open(p, "rb").read()).hexdigest()[:12] + " " + p)
            except OSError:
                continue
        # con Sentinel encendido estos archivos ya los vigila su monitor de integridad: aquí es solo informativo
        self.comparar("persistencia", lineas, "BAJO" if self.sentinel_activo else "MEDIO", "Cambió la persistencia (cron, systemd, autostart o perfiles de shell)")

    def herramientas(self) -> None:
        i = self.inf
        i.sec("Salud de las herramientas de seguridad")
        for s in ("sentinel-monitor", "crowdsec", "crowdsec-firewall-bouncer", "auditd", "apparmor", "ufw"):
            est = core.run(["systemctl", "is-active", s], 5)[1].strip().split("\n")[-1]
            i.linea(f"  {s:<28} {est}")
            if est != "active" and core.run(["systemctl", "is-enabled", s], 5)[1].strip().split("\n")[-1] == "enabled":
                i.hall("MEDIO" if s != "ufw" else "ALTO", "herramientas", f"El servicio de seguridad '{s}' no está activo ({est})")
        for s in ("wazuh-manager", "wazuh-indexer", "wazuh-dashboard"):
            est = core.run(["systemctl", "is-active", s], 5)[1].strip().split("\n")[-1]
            en = core.run(["systemctl", "is-enabled", s], 5)[1].strip().split("\n")[-1]
            if en == "enabled" and est != "active":
                i.hall("MEDIO", "herramientas", f"El servicio '{s}' está habilitado pero no está activo ({est})")
            elif en not in ("enabled", "not-found", ""):
                i.linea(f"  {s:<28} desactivado a propósito")
        rc, out = core.run(["journalctl", "-b", "-u", "crowdsec-firewall-bouncer", "-q", "--no-pager", "-g", "connection refused"], 20)
        fallos = len(out.splitlines()) if rc == 0 and out.strip() else 0
        if fallos:
            i.hall("BAJO", "herramientas", f"El bouncer de CrowdSec falló {fallos} vez/veces en este arranque (su API aún no estaba lista)")

    def crowdsec(self) -> None:
        i = self.inf
        i.sec("CrowdSec (24 h)")
        if not shutil.which("cscli"):
            i.linea("cscli no está instalado."); return
        rc, out = core.run(["cscli", "alerts", "list", "--since", "24h", "-o", "json"], 30)
        try:
            alertas = json.loads(out) if rc == 0 and out.strip().startswith("[") else []
        except ValueError:
            alertas = []
        rc, out = core.run(["cscli", "decisions", "list", "-o", "json"], 30)
        try:
            bloqueos = json.loads(out) if rc == 0 and out.strip().startswith("[") else []
        except ValueError:
            bloqueos = []
        i.linea(f"Alertas: {len(alertas)} · bloqueos activos: {len(bloqueos)}")
        if alertas:
            det = sorted({f"{a.get('scenario', '?')} desde {(a.get('source') or {}).get('ip') or (a.get('source') or {}).get('value') or '?'}" for a in alertas})
            i.hall("MEDIO", "crowdsec", f"CrowdSec generó {len(alertas)} alerta(s) en 24 h: " + "; ".join(det)[:300])

    def tuneles(self) -> None:
        i = self.inf
        i.sec("Túneles públicos")
        n = 0
        for d in os.listdir("/proc"):
            if not d.isdigit():
                continue
            try:
                comm = open(f"/proc/{d}/comm", encoding="utf-8", errors="replace").read().strip()
                cmd = open(f"/proc/{d}/cmdline", "rb").read().replace(b"\x00", b" ").decode("utf-8", "replace")
            except OSError:
                continue
            if comm in ("cloudflared", "ngrok", "localtunnel", "bore", "frpc"):
                dest = re.search(r"--url \S+|http \d+|tcp \d+", cmd)
                i.hall("MEDIO", "túneles", f"Túnel público activo: {comm} (PID {d}) {dest.group(0) if dest else ''}".strip()); n += 1
            elif comm == "ssh" and re.search(r" -R ", cmd) and "sentinel" not in cmd:
                i.hall("MEDIO", "túneles", f"Túnel SSH inverso (-R) activo (PID {d})"); n += 1
        if not n:
            i.linea("Ninguno.")

    def integridad_extra(self) -> None:
        i = self.inf
        i.sec("AIDE y rkhunter")
        try:
            dias = int((time.time() - os.path.getmtime("/var/lib/aide/aide.db")) / 86400)
            i.linea(f"Base de AIDE: {dias} días de antigüedad")
            if dias > 30:
                i.hall("BAJO", "AIDE", f"Recomendación: la base de AIDE tiene {dias} días y sus diferencias ya son ruido (sudo aideinit -y -f)")
        except OSError:
            i.linea("AIDE no está instalado o sin base.")
        try:
            txt = open("/var/log/rkhunter.log", encoding="utf-8", errors="replace").read()
            ultima = txt[txt.rfind("Start date"):] if "Start date" in txt else txt[-60000:]
            avisos = [re.sub(r"^\[[0-9:]+\] ", "", x) for x in ultima.splitlines() if re.match(r"^\[[0-9:]+\] Warning:", x)]
            nuevos = [x for x in avisos if not RKH_BENIGNO.search(x)]
            i.linea(f"rkhunter (última ejecución): {len(avisos)} advertencia(s), {len(nuevos)} fuera de los falsos positivos conocidos")
            if nuevos:
                i.hall("MEDIO", "rkhunter", f"rkhunter reporta {len(nuevos)} advertencia(s) nueva(s): " + "; ".join(nuevos[:2])[:250])
        except OSError:
            pass

    def actualizaciones(self) -> None:
        i = self.inf
        i.sec("Actualizaciones y reinicio pendiente")
        rc, out = core.run(["apt-get", "-s", "dist-upgrade"], 90)
        n = len(re.findall(r"^Inst .*-security", out, re.M))
        i.linea(f"Actualizaciones de seguridad pendientes: {n}")
        if n:
            i.hall("BAJO", "actualizaciones", f"{n} actualización(es) de seguridad pendiente(s) (sudo apt upgrade)")
        if os.path.exists("/var/run/reboot-required"):
            i.hall("BAJO", "actualizaciones", "El sistema necesita reiniciarse (kernel o librerías actualizadas)")

    def sentinel(self) -> None:
        i = self.inf
        i.sec("Sentinel (eventos de las últimas 24 h)")
        hb = core.read_json(os.path.join(core.state_dir(), "heartbeat.json"), {}) or {}
        meta = core.read_json(os.path.join(core.state_dir(), "fim_meta.json"), {}) or {}
        if hb.get("epoch"):
            edad = core.now() - hb["epoch"]
            i.linea(f"Versión {hb.get('version', core.VERSION)} · latido hace {edad:.0f} s · referencia de integridad: {meta.get('count', 0)} elementos")
            if self.sentinel_activo and edad > 180:
                i.hall("ALTO", "sentinel", f"Sentinel no da señales de vida hace {edad:.0f} s (¿detenido o bloqueado?)")
        else:
            i.linea(f"Versión {core.VERSION} · sin latido registrado")
            if self.sentinel_activo:
                i.hall("MEDIO", "sentinel", "El monitor de Sentinel está activo pero no encuentro su latido")
        if not meta.get("count"):
            i.hall("MEDIO", "sentinel", "Sentinel no tiene referencia de integridad (sudo sentinel baseline init)")
        eventos = [e for e in report.relevant(core.read_events(core.now() - 86400, "high"))]
        i.linea(f"Eventos de gravedad alta o crítica sin resolver: {len(eventos)}")
        grupos: dict = collections.OrderedDict()
        for e in sorted(eventos, key=lambda e: -core.SEV[e["sev"]]):
            grupos.setdefault((e["sev"], e["source"], e["kind"]), []).append(e)
        for (sev, src, kind), lst in grupos.items():
            i.hall("ALTO" if sev == "critical" else "MEDIO", "sentinel", f"Sentinel ×{len(lst)} [{src}/{kind}]: {lst[0]['msg'][:150]}")

    def correo(self) -> None:
        i = self.inf
        i.sec("Correo de Sentinel")
        if mailer.configured(self.cfg):
            i.linea("SMTP configurado: " + ", ".join(mailer.settings(self.cfg)["to"]))
        else:
            i.hall("BAJO", "correo", "Sentinel no tiene correo SMTP configurado: no puede avisarte por email (sudo sentinel smtp configurar)")


# ---------------------------------------------------------------------- informe
def revisar(cfg=None, aceptar: bool = False, rapido: bool = False) -> Informe:
    return Revision(cfg or core.load_config(), aceptar, rapido).run()


def a_texto(inf: Informe) -> str:
    c = inf.cuenta()
    out = [f"INFORME DEL EQUIPO {inf.host} — {inf.fecha}", f"Riesgo: {inf.nivel()}  (alto {c['ALTO']}, medio {c['MEDIO']}, bajo {c['BAJO']})", ""]
    out += ["HALLAZGOS"] + ([f"  [{h.nivel}] {h.texto}" for h in inf.unicos()] or ["  Ninguno."]) + [""]
    for titulo, lineas in inf.secciones:
        out += [f"== {titulo} =="] + (lineas or ["(sin datos)"]) + [""]
    return "\n".join(out)


def a_html(inf: Informe) -> str:
    e = html.escape
    c = inf.cuenta()
    color = {"ALTO": ("#f8d7da", "#721c24"), "MEDIO": ("#fff3cd", "#856404"), "BAJO": ("#d4edda", "#155724")}[inf.nivel()]
    marca = {"ALTO": "#b00020", "MEDIO": "#b26a00", "BAJO": "#555"}
    hall = "".join(f"<li><b style='color:{marca[h.nivel]}'>[{h.nivel}]</b> {e(h.texto)}</li>" for h in inf.unicos()) or "<li>Sin hallazgos.</li>"
    secs = ""
    for titulo, lineas in inf.secciones:
        cuerpo = "\n".join(re.sub(r"^\[(ALTO|MEDIO|BAJO)\]", lambda m: f"<b style='color:{marca[m.group(1)]}'>[{m.group(1)}]</b>", e(x)) for x in lineas)
        secs += f"<h3>{e(titulo)}</h3>" + (f"<pre>{cuerpo}</pre>" if lineas else "<p class='vacio'>(sin datos)</p>")
    return f"""<!DOCTYPE html><html lang="es"><head><meta charset="utf-8"><title>Informe del equipo {e(inf.host)}</title>
<style>body{{font-family:Arial,sans-serif;margin:20px;background:#f9f9f9;color:#333}}h1{{margin:0 0 6px 0;color:#fff}}h3{{color:#0056b3;margin:22px 0 6px 0}}
pre{{background:#fff;padding:10px;border:1px solid #ddd;border-radius:5px;white-space:pre-wrap;word-wrap:break-word;font-size:12px}}
.header{{background:#0056b3;color:#fff;padding:15px;border-radius:5px}}.riesgo{{background:{color[0]};color:{color[1]};padding:14px;border-radius:8px;margin:16px 0}}
.vacio{{color:#777;font-style:italic}}li{{margin:4px 0}}.pie{{font-size:12px;color:#666;text-align:center;margin-top:30px}}</style></head><body>
<div class="header"><h1>Informe del equipo</h1><div>{e(inf.host)} — {e(inf.fecha)}</div></div>
<div class="riesgo"><b>Riesgo global: {inf.nivel()}</b> — alto {c['ALTO']}, medio {c['MEDIO']}, bajo {c['BAJO']}.<br>Un hallazgo ALTO sube el nivel a ALTO y uno MEDIO a MEDIO; los BAJO son informativos.</div>
<h3>Hallazgos</h3><ul>{hall}</ul>{secs}
<div class="pie">Generado por Sentinel {core.VERSION} (sentinel equipo). Este informe no incluye el historial de comandos ni los argumentos de los procesos.</div></body></html>"""


HORAS_POR_DEFECTO = "08:00,16:00,23:00"


def horas_validas(txt: str) -> list[str] | None:
    """«08:00, 16:00,23:00» → ['08:00', '16:00', '23:00'] (ordenadas, sin repetir, de 1 a 6); None si algo no es una hora válida."""
    partes = [p.strip() for p in str(txt).split(",") if p.strip()]
    if not 1 <= len(partes) <= 6 or not all(re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", p) for p in partes):
        return None
    return sorted(set(partes))


def carpeta_systemd() -> str:
    return os.environ.get("SENTINEL_SYSTEMD_DIR", "/etc/systemd/system")


def aplicar_horario(txt: str, ejecutar=None) -> tuple[bool, str]:
    """Cambia las horas del informe: guarda [equipo] horas y escribe un drop-in del temporizador (el archivo del paquete no se toca, así que una actualización no lo pisa)."""
    ejecutar = ejecutar or core.run
    horas = horas_validas(txt)
    if horas is None:
        return False, "Horario no válido: usa de 1 a 6 horas HH:MM separadas por coma, por ejemplo 08:00,16:00,23:00."
    try:
        core.set_setting("equipo", "horas", ",".join(horas))
        if plataforma.ES_MAC:
            if os.path.exists(servicio.ruta("equipo")):             # instalado: se reescribe la tarea y launchd la relee
                servicio.detener(ejecutar, ["equipo"])
                servicio.escribir("equipo", sys.executable, horas=horas)
                errores = servicio.iniciar(ejecutar, ["equipo"])
                if errores:
                    return False, "No se pudo guardar el horario: " + "; ".join(errores)
            return True, "Horario guardado: el informe se generará a las " + ", ".join(horas) + "."
        d = os.path.join(carpeta_systemd(), "sentinel-equipo.timer.d")
        arch = os.path.join(d, "horario.conf")
        if ",".join(horas) == HORAS_POR_DEFECTO:
            if os.path.exists(arch):
                os.remove(arch)
        else:
            core.ensure_dir(d, 0o755)
            with open(arch, "w", encoding="utf-8") as f:
                f.write("# Sentinel · horario del informe del equipo (sentinel equipo --horario)\n[Timer]\nOnCalendar=\n" + "".join(f"OnCalendar=*-*-* {h}:00\n" for h in horas))
    except (ValueError, OSError) as e:
        return False, f"No se pudo guardar el horario: {e}"
    ejecutar(["systemctl", "daemon-reload"], 30)
    ejecutar(["systemctl", "restart", "sentinel-equipo.timer"], 30)
    return True, "Horario guardado: el informe se generará a las " + ", ".join(horas) + "."


def guardar(inf: Informe, cfg=None) -> tuple[str, str]:
    cfg = cfg or core.load_config()
    d = os.path.join(core.state_dir(), "informes")
    core.ensure_dir(d, 0o750)
    core.share_with_adm(d)                       # el panel (que corre con tu usuario) puede ver cuándo fue el último
    base = os.path.join(d, "equipo-" + time.strftime("%Y%m%d-%H%M"))
    for ext, txt in ((".html", a_html(inf)), (".txt", a_texto(inf))):
        with open(base + ext, "w", encoding="utf-8") as f:
            f.write(txt)
        os.chmod(base + ext, 0o640)
        core.share_with_adm(base + ext)
    viejos = sorted(glob.glob(os.path.join(d, "equipo-*.html")))[:-max(1, cfg.getint("equipo", "informes_max", fallback=30))]
    for v in viejos:
        for ext in (".html", ".txt", ".pdf"):
            try:
                os.remove(v[:-5] + ext)
            except OSError:
                pass
    return base + ".html", base + ".txt"


def enviar(cfg, inf: Informe, ruta_html: str, ruta_txt: str) -> tuple[bool, str]:
    """Manda el informe por SMTP: cuerpo con el resumen, HTML completo, texto y, si hay wkhtmltopdf, un PDF."""
    c = inf.cuenta()
    cuerpo = f"Riesgo {inf.nivel()} (alto {c['ALTO']}, medio {c['MEDIO']}, bajo {c['BAJO']}) en {inf.host}.\n\n" + "\n".join(f"[{h.nivel}] {h.texto}" for h in inf.unicos()) + "\n\nEl informe completo va adjunto.\n"
    adj = [(os.path.basename(ruta_html), open(ruta_html, "rb").read(), "text/html"), (os.path.basename(ruta_txt), open(ruta_txt, "rb").read(), "text/plain")]
    if shutil.which("wkhtmltopdf"):
        pdf = ruta_html[:-5] + ".pdf"
        core.run(["wkhtmltopdf", "--quiet", "--enable-local-file-access", ruta_html, pdf], 120)
        if os.path.exists(pdf) and os.path.getsize(pdf) > 0:
            adj.append((os.path.basename(pdf), open(pdf, "rb").read(), "application/pdf"))
    return mailer.send(cfg, inf.asunto(), cuerpo, html=open(ruta_html, encoding="utf-8").read(), attachments=adj, timeout=60)
