"""Detectores del equipo: puertos en escucha, procesos sospechosos, lectores de teclado, USB, módulos del kernel, cuentas y archivos SUID."""
from __future__ import annotations

import glob
import os
import re
import time

from . import core

LISTEN_RE = re.compile(r'users:\(\("([^"]+)",pid=(\d+)')


def split_addr(local: str) -> tuple[str, int]:
    local = re.sub(r"%[^:\]]*", "", local)  # quita la interfaz («127.0.0.53%lo:53» -> «127.0.0.53:53»)
    host, _, port = local.rpartition(":")
    host = host.strip("[]").split("%")[0]
    return host, int(port) if port.isdigit() else 0


def parse_listeners(text: str) -> dict[str, dict]:
    """Salida de `ss -H -ltnup` -> {«tcp/80»: {proc, addr, scope}}."""
    out: dict[str, dict] = {}
    for ln in text.splitlines():
        f = ln.split()
        if len(f) < 5 or f[0] not in ("tcp", "udp"):
            continue
        host, port = split_addr(f[4])
        if not port:
            continue
        m = LISTEN_RE.search(ln)
        wild = host in ("0.0.0.0", "::", "*", "")
        scope = "todas las interfaces" if wild else "solo local" if host.startswith("127.") or host == "::1" else host
        key = f"{f[0]}/{port}"
        cur = out.get(key)
        if cur and cur["scope"] == "todas las interfaces":
            continue
        out[key] = {"proc": m.group(1) if m else "?", "addr": host, "scope": scope, "port": port}
    return out


def listeners() -> dict[str, dict]:
    rc, out = core.run(["ss", "-H", "-ltnup"], 10)
    return parse_listeners(out) if rc == 0 else {}


def usb_devices() -> list[str]:
    res = []
    for d in glob.glob("/sys/bus/usb/devices/*"):
        try:
            rd = lambda n: open(os.path.join(d, n), encoding="utf-8", errors="ignore").read().strip()
            if os.path.exists(os.path.join(d, "idVendor")):
                res.append(f"{rd('idVendor')}:{rd('idProduct')} {rd('product') if os.path.exists(os.path.join(d, 'product')) else ''}".strip())
        except OSError:
            continue
    return sorted(set(res))


def kernel_modules() -> list[str]:
    try:
        return sorted({ln.split()[0] for ln in open("/proc/modules", encoding="utf-8") if ln.strip()})
    except OSError:
        return []


def accounts() -> dict:
    users, uid0, empty = [], [], []
    try:
        for ln in open("/etc/passwd", encoding="utf-8"):
            p = ln.strip().split(":")
            if len(p) >= 7:
                shell = p[6]
                if not shell.endswith(("nologin", "false")):
                    users.append(p[0])
                if p[2] == "0" and p[0] != "root":
                    uid0.append(p[0])
    except OSError:
        pass
    try:
        for ln in open("/etc/shadow", encoding="utf-8"):
            p = ln.strip().split(":")
            if len(p) >= 2 and p[1] == "":
                empty.append(p[0])
    except OSError:
        pass
    return {"users": sorted(users), "uid0": uid0, "empty": empty}


def suid_files(roots: list[str] | None = None) -> list[str]:
    """Archivos SUID/SGID en las carpetas indicadas (sin recorrer node_modules, .git, cachés ni contenedores)."""
    roots = [r for r in (roots or ["/usr", "/bin", "/sbin", "/lib", "/lib64", "/opt", "/etc", "/var/tmp", "/tmp", "/dev/shm", "/root", "/home"]) if os.path.isdir(r)]
    if not roots:
        return []
    cmd = ["find", *roots, "-xdev", "(", "-name", "node_modules", "-o", "-name", ".git", "-o", "-name", ".cache", "-o", "-path", "*/docker/*", "-o", "-path", "/snap/*", ")", "-prune", "-o", "-type", "f", "-perm", "/6000", "-print"]
    rc, out = core.run(cmd, 120)
    return sorted(x for x in out.splitlines() if x.startswith("/"))


def proc_scan(exec_dirs: list[str], miners: list[str], skip: set[str]) -> list[dict]:
    """Procesos que corren desde carpetas temporales, con el ejecutable borrado o con nombre de minero."""
    found = []
    me = os.getpid()
    for d in os.listdir("/proc"):
        if not d.isdigit() or int(d) == me:
            continue
        base = f"/proc/{d}"
        try:
            exe = os.readlink(f"{base}/exe")
        except OSError:
            continue  # hilo del kernel o sin permiso
        try:
            comm = open(f"{base}/comm", encoding="utf-8").read().strip()
        except OSError:
            comm = os.path.basename(exe)
        name = os.path.basename(exe.replace(" (deleted)", ""))
        if comm in skip or name in skip:
            continue
        sev = kind = msg = None
        if any(m == name.lower() or m == comm.lower() for m in miners):
            sev, kind, msg = "critical", "minero", f"proceso con nombre de minero de criptomonedas: {comm} (PID {d}, {exe})"
        elif any(exe.startswith(x.rstrip("/") + "/") for x in exec_dirs):
            sev, kind, msg = "high", "ejecuta_desde_temporal", f"{comm} (PID {d}) ejecuta un programa desde una carpeta temporal: {exe}"
        elif exe.endswith(" (deleted)"):
            if exe.startswith(("/tmp", "/var/tmp", "/dev/shm", "/run/user", "/home")):
                sev, kind, msg = "high", "binario_borrado", f"{comm} (PID {d}) corre con su ejecutable borrado desde {exe}"
            else:
                sev, kind, msg = "low", "reinicio_pendiente", f"{comm} (PID {d}) usa un programa actualizado: conviene reiniciarlo ({exe})"
        if sev:
            found.append({"sev": sev, "kind": kind, "msg": msg, "pid": int(d), "comm": comm, "exe": exe})
    return found


def input_readers(skip: set[str]) -> list[dict]:
    """Procesos con un dispositivo de teclado/ratón abierto que no son del sistema gráfico (posible keylogger). Solo informa; nunca detiene procesos."""
    found = []
    for d in os.listdir("/proc"):
        if not d.isdigit():
            continue
        try:
            for fd in os.listdir(f"/proc/{d}/fd"):
                try:
                    tgt = os.readlink(f"/proc/{d}/fd/{fd}")
                except OSError:
                    continue
                if tgt.startswith("/dev/input/event") or tgt == "/dev/uinput":
                    comm = open(f"/proc/{d}/comm", encoding="utf-8").read().strip()
                    if comm not in skip:
                        found.append({"pid": int(d), "comm": comm, "dev": tgt})
                    break
        except OSError:
            continue
    return found


def hidden_pids() -> list[int]:
    """PIDs visibles en /proc pero ausentes de `ps` en dos muestras seguidas (posible rootkit)."""
    def sample():
        proc = {int(d) for d in os.listdir("/proc") if d.isdigit()}
        rc, out = core.run(["ps", "-e", "-o", "pid="], 10)
        return proc, {int(x) for x in out.split() if x.isdigit()}
    a_proc, a_ps = sample()
    time.sleep(1)
    b_proc, b_ps = sample()
    return sorted((a_proc - a_ps) & (b_proc - b_ps) & b_proc & {p for p in b_proc if os.path.exists(f"/proc/{p}/stat")})


def suspicious_connections(ports: set[int], skip: set[str]) -> list[dict]:
    rc, out = core.run(["ss", "-H", "-tnp", "state", "established"], 10)
    res = []
    for ln in out.splitlines():
        f = ln.split()
        if len(f) < 4:
            continue
        host, port = split_addr(f[3])
        m = LISTEN_RE.search(ln)
        proc = m.group(1) if m else "?"
        if port in ports and proc not in skip:
            res.append({"remote": f"{host}:{port}", "proc": proc})
    return res


class HostCheck:
    def __init__(self, cfg, alerter: core.Alerter, allow: core.Allow):
        self.cfg, self.alerter, self.allow = cfg, alerter, allow
        self.path = os.path.join(core.state_dir(), "host_baseline.json")

    def snapshot(self, deep: bool = False) -> dict:
        s = {"listeners": listeners(), "usb": usb_devices() if self.cfg.getboolean("hostcheck", "check_usb", fallback=True) else [],
             "modules": kernel_modules() if self.cfg.getboolean("hostcheck", "check_modules", fallback=True) else [], "accounts": accounts()}
        if deep and self.cfg.getboolean("hostcheck", "suid_scan", fallback=True):
            s["suid"] = suid_files(core.csv(self.cfg.get("hostcheck", "suid_roots", fallback="")) or None)
        return s

    def init(self) -> dict:
        s = self.snapshot(deep=True)
        core.atomic_write_json(self.path, {"created": core.iso(), **s})
        return s

    def run(self, deep: bool = False) -> list[core.Event]:
        out: list[core.Event] = []
        emit = lambda *a, **k: out.append(e) if (e := self.alerter.emit(*a, **k)) else None
        base = core.read_json(self.path)
        cur = self.snapshot(deep=deep)
        if base is None:
            core.atomic_write_json(self.path, {"created": core.iso(), **self.snapshot(deep=True)})
            emit("info", "host", "referencia", "Referencia del equipo creada (puertos, USB, módulos, cuentas, SUID)", key="host:ref")
            base = core.read_json(self.path)
        # puertos
        for k, v in cur["listeners"].items():
            if v["port"] in self.allow.ports or v["proc"] in self.allow.procs:
                continue
            b = base["listeners"].get(k)
            if b is None:
                sev = "high" if v["scope"] == "todas las interfaces" else "medium"
                emit(sev, "host", "puerto_nuevo", f"Nuevo puerto en escucha {k} ({v['proc']}, {v['scope']})", key=f"host:port:{k}:{v['proc']}")
            elif b["scope"] != "todas las interfaces" and v["scope"] == "todas las interfaces":
                emit("high", "host", "puerto_expuesto", f"El puerto {k} ({v['proc']}) pasó de local a todas las interfaces", key=f"host:expo:{k}")
        # cuentas
        a, b = cur["accounts"], base["accounts"]
        for u in a["uid0"]:
            emit("critical", "host", "uid0", f"La cuenta «{u}» tiene privilegios de administrador (UID 0)", key=f"host:uid0:{u}")
        for u in a["empty"]:
            emit("critical", "host", "sin_clave", f"La cuenta «{u}» no tiene contraseña", key=f"host:empty:{u}")
        for u in sorted(set(a["users"]) - set(b["users"])):
            emit("high", "host", "usuario_nuevo", f"Nueva cuenta con acceso al sistema: {u}", key=f"host:user:{u}")
        # USB y módulos
        for d in sorted(set(cur["usb"]) - set(base.get("usb", []))):
            emit("low", "host", "usb_nuevo", f"Nuevo dispositivo USB: {d}", key=f"host:usb:{d}")
        for m in sorted(set(cur["modules"]) - set(base.get("modules", []))):
            emit("medium", "host", "modulo_nuevo", f"Nuevo módulo del kernel cargado: {m}", key=f"host:mod:{m}")
        # SUID (solo en revisión profunda)
        if deep and "suid" in cur:
            for p in sorted(set(cur["suid"]) - set(base.get("suid", []))):
                if not self.allow.path_ignored(p):
                    emit("high", "host", "suid_nuevo", f"Nuevo archivo con permiso SUID/SGID: {p}", key=f"host:suid:{p}")
        # procesos y conexiones
        c = self.cfg
        skip = set(core.csv(c.get("hostcheck", "input_ok", fallback=""))) | self.allow.procs
        for p in proc_scan(core.csv(c.get("hostcheck", "exec_dirs")), [m.lower() for m in core.csv(c.get("hostcheck", "miner_names"))], self.allow.procs):
            emit(p["sev"], "host", p["kind"], p["msg"], key=f"host:{p['kind']}:{p['comm']}:{p['exe']}")
        for r in input_readers(skip):
            emit("medium", "host", "lector_de_teclado", f"{r['comm']} (PID {r['pid']}) lee directamente el teclado/ratón ({r['dev']}); revisa que sea legítimo", key=f"host:kbd:{r['comm']}")
        ports = {int(x) for x in core.csv(c.get("hostcheck", "suspicious_ports")) if x.isdigit()}
        for s in suspicious_connections(ports, self.allow.procs):
            emit("high", "host", "conexion_sospechosa", f"{s['proc']} está conectado a {s['remote']}, puerto usado por troyanos, mineros o canales de control", key=f"host:conn:{s['proc']}:{s['remote']}")
        if deep:
            for pid in hidden_pids():
                emit("high", "host", "pid_oculto", f"El proceso {pid} existe en /proc pero no aparece en `ps` (posible rootkit)", key=f"host:hidden:{pid}")
        return out
