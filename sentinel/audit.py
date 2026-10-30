"""Auditoría de postura de seguridad: revisa configuraciones débiles del equipo y propone cómo arreglarlas. Casi todo funciona sin permisos de administrador."""
from __future__ import annotations

import glob
import os
import re
import stat

from . import core, hostcheck

OK, WARN, FAIL, INFO = "ok", "aviso", "fallo", "info"
DB_PORTS = {3306, 3307, 5432, 5433, 6379, 27017, 9200, 9300, 33060, 11211, 1433}


def _svc(name: str) -> str:
    return core.run(["systemctl", "is-active", name], 5)[1].strip().split("\n")[-1]


def _read(path: str) -> str:
    try:
        return open(path, encoding="utf-8", errors="ignore").read()
    except OSError:
        return ""


def c_firewall(cfg):
    on = re.search(r"^ENABLED=yes", _read("/etc/ufw/ufw.conf"), re.M) is not None or _svc("ufw") == "active"
    pol = re.search(r'DEFAULT_INPUT_POLICY="(\w+)"', _read("/etc/default/ufw"))
    if not on:
        return FAIL, "El cortafuegos ufw está apagado", "sudo ufw default deny incoming && sudo ufw enable"
    if pol and pol.group(1) != "DROP":
        return WARN, f"ufw activo pero la política de entrada es {pol.group(1)}", "sudo ufw default deny incoming"
    return OK, "ufw activo, entrada denegada por defecto", ""


def c_ids(cfg):
    act = [n for n in ("crowdsec", "crowdsec-firewall-bouncer", "fail2ban", "firewalld") if _svc(n) == "active"]
    if "crowdsec" in act and "crowdsec-firewall-bouncer" not in act:
        return WARN, "CrowdSec detecta pero su bouncer no bloquea (inactivo)", "sudo systemctl enable --now crowdsec-firewall-bouncer"
    if not act:
        return FAIL, "No hay ningún sistema que bloquee atacantes (CrowdSec o fail2ban)", "sudo apt install crowdsec crowdsec-firewall-bouncer-iptables"
    return OK, "Bloqueo de atacantes activo: " + ", ".join(act), ""


def c_auditd(cfg):
    return (OK, "auditd activo", "") if _svc("auditd") == "active" else (WARN, "auditd inactivo: no hay registro detallado de llamadas al sistema", "sudo apt install auditd && sudo systemctl enable --now auditd")


def c_ssh(cfg):
    txt = _read("/etc/ssh/sshd_config")
    for f in sorted(glob.glob("/etc/ssh/sshd_config.d/*.conf")):
        txt += "\n" + _read(f)
    if not txt:
        return INFO, "No hay servidor SSH instalado", ""
    g = lambda k: (re.findall(rf"^\s*{k}\s+(\S+)", txt, re.I | re.M) or [""])[0].lower()
    active = _svc("ssh") == "active" or _svc("sshd") == "active"
    bad = []
    if g("PermitRootLogin") in ("yes", ""):
        bad.append("permite entrar como root" if g("PermitRootLogin") == "yes" else "PermitRootLogin sin definir")
    if g("PasswordAuthentication") in ("yes", ""):
        bad.append("acepta contraseñas (mejor solo llaves)")
    if not bad:
        return OK, "SSH endurecido" + ("" if active else " (servicio inactivo)"), ""
    return (WARN if not active else FAIL), "SSH: " + "; ".join(bad) + ("" if active else " (el servicio está inactivo ahora)"), "Crea /etc/ssh/sshd_config.d/99-endurecer.conf con «PermitRootLogin no» y «PasswordAuthentication no» (solo después de comprobar que tienes tu llave) y valida con `sudo sshd -t`"


def c_www(cfg):
    bad = []
    for w in core.csv(cfg.get("fim", "www", fallback="")):
        if not os.path.isdir(w):
            continue
        for r, ds, fs in os.walk(w):
            ds[:] = [d for d in ds if d not in ("node_modules", ".git", "vendor")]
            for n in ds + fs:
                p = os.path.join(r, n)
                try:
                    m = os.lstat(p).st_mode
                except OSError:
                    continue
                if stat.S_ISLNK(m):
                    continue
                if m & 0o002:
                    bad.append(p)
            if len(bad) > 200:
                break
        top = os.stat(w).st_mode & 0o777
        if top & 0o002:
            bad.insert(0, f"{w} ({oct(top)})")
    if bad:
        return FAIL, f"{len(bad)} archivos o carpetas web escribibles por cualquier usuario (por ejemplo {bad[0]})", "sudo chown -R www-data:www-data /var/www/html && sudo chmod -R o-w /var/www/html  (o dale a tu usuario el grupo www-data y usa 775)"
    return OK, "Sin archivos web escribibles por todos", ""


def _ww(bases):
    hits = []
    for base in bases:
        for r, ds, fs in os.walk(base):
            for n in fs:
                p = os.path.join(r, n)
                try:
                    st = os.lstat(p)
                except OSError:
                    continue
                if stat.S_ISREG(st.st_mode) and st.st_mode & 0o002:
                    hits.append(p)
    return hits


def c_worldwritable(cfg):
    sysw = _ww(["/etc", "/usr/local/bin", "/usr/local/sbin"])
    if sysw:
        return FAIL, f"{len(sysw)} archivos del sistema escribibles por todos: {', '.join(sysw[:3])}", "sudo chmod o-w <archivo>"
    opt = _ww(["/opt"])
    if opt:
        top = sorted({"/".join(p.split("/")[:3]) for p in opt})
        return WARN, f"{len(opt)} archivos en /opt escribibles por todos (en {', '.join(top[:3])}): cualquier usuario podría alterar esos programas", "sudo chmod -R o-w <carpeta>"
    return OK, "Sin archivos de sistema escribibles por todos", ""


def c_listeners(cfg):
    ls = hostcheck.listeners()
    wild = [(k, v) for k, v in ls.items() if v["scope"] == "todas las interfaces"]
    db = [f"{k} ({v['proc']})" for k, v in wild if v["port"] in DB_PORTS]
    if db:
        return WARN, "Bases de datos escuchando en todas las interfaces: " + ", ".join(db) + ". El cortafuegos las cubre hoy, pero si falla quedan expuestas", "Configura bind-address = 127.0.0.1 en cada servicio"
    return INFO, f"{len(wild)} servicios escuchan en todas las interfaces (protegidos por el cortafuegos)", ""


SYSCTL = [("kernel.randomize_va_space", "2"), ("net.ipv4.tcp_syncookies", "1"), ("net.ipv4.conf.all.accept_redirects", "0"), ("net.ipv4.conf.all.rp_filter", "1"),
          ("fs.protected_hardlinks", "1"), ("fs.protected_symlinks", "1"), ("kernel.kptr_restrict", "2"), ("kernel.dmesg_restrict", "1"), ("kernel.yama.ptrace_scope", "1")]


def c_sysctl(cfg):
    weak = []
    for k, want in SYSCTL:
        v = _read("/proc/sys/" + k.replace(".", "/")).strip()
        if v and v != want and not (k == "kernel.kptr_restrict" and v == "1") and not (k == "kernel.yama.ptrace_scope" and v in ("1", "2", "3")):
            weak.append(f"{k}={v} (recomendado {want})")
    return (WARN, f"{len(weak)} parámetros del kernel débiles: " + "; ".join(weak[:3]), "Crea /etc/sysctl.d/99-sentinel.conf con los valores recomendados y aplica `sudo sysctl --system`") if weak else (OK, "Parámetros del kernel endurecidos", "")


def c_updates(cfg):
    rc, out = core.run(["apt-get", "-s", "-o", "Debug::NoLocking=1", "upgrade"], 60)
    n = len([x for x in out.splitlines() if x.startswith("Inst ")])
    sec = len([x for x in out.splitlines() if x.startswith("Inst ") and "-security" in x])
    if sec:
        return FAIL, f"{sec} actualizaciones de seguridad pendientes ({n} en total)", "sudo apt update && sudo apt upgrade"
    return (WARN, f"{n} actualizaciones pendientes (ninguna marcada de seguridad)", "sudo apt upgrade") if n > 20 else (OK, f"{n} actualizaciones pendientes", "")


def c_autoupdates(cfg):
    on = "enabled" in core.run(["systemctl", "is-enabled", "unattended-upgrades"], 5)[1]
    return (OK, "Actualizaciones de seguridad automáticas activas", "") if on else (WARN, "Las actualizaciones de seguridad no son automáticas", "sudo apt install unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades")


def c_login_defs(cfg):
    t = _read("/etc/login.defs")
    um = re.search(r"^UMASK\s+(\d+)", t, re.M)
    issues = []
    if um and um.group(1) not in ("027", "077"):
        issues.append(f"UMASK {um.group(1)} (recomendado 027)")
    mx = re.search(r"^PASS_MAX_DAYS\s+(\d+)", t, re.M)
    if mx and int(mx.group(1)) > 365:
        issues.append(f"las contraseñas no caducan (PASS_MAX_DAYS {mx.group(1)})")
    return (WARN, "Política de contraseñas/permisos: " + "; ".join(issues), "Edita /etc/login.defs") if issues else (OK, "Política de contraseñas y permisos razonable", "")


def c_home_secrets(cfg):
    home = os.path.expanduser("~")
    bad = []
    ssh = os.path.join(home, ".ssh")
    if os.path.isdir(ssh):
        if os.stat(ssh).st_mode & 0o077:
            bad.append("~/.ssh accesible por otros")
        for f in glob.glob(os.path.join(ssh, "id_*")):
            if not f.endswith(".pub") and os.stat(f).st_mode & 0o077:
                bad.append(f"{f} legible por otros")
    for d in (".gnupg", ".aws", ".config/gcloud", ".kube"):
        p = os.path.join(home, d)
        if os.path.isdir(p) and os.stat(p).st_mode & 0o007:
            bad.append(f"~/{d} accesible por cualquier usuario")
    skip = {"node_modules", ".git", ".cache", "venv", ".venv", "__pycache__", "vendor", "snap", ".local", ".npm"}
    for r, ds, fs in os.walk(home):
        ds[:] = [d for d in ds if d not in skip and r.count(os.sep) - home.count(os.sep) < 7]
        for n in fs:
            if n == ".env" or n.startswith(".env."):
                f = os.path.join(r, n)
                try:
                    if os.stat(f).st_mode & 0o004:
                        bad.append(f"{f.replace(home, '~')} legible por cualquier usuario")
                except OSError:
                    pass
    return (FAIL, f"{len(bad)} credenciales con permisos abiertos: {'; '.join(bad[:3])}", "chmod 600 <archivo>; chmod 700 <carpeta>") if bad else (OK, "Llaves y archivos .env con permisos cerrados", "")


def c_docker(cfg):
    for ln in _read("/etc/group").splitlines():
        if ln.startswith("docker:") and ln.split(":")[3]:
            return INFO, f"Los usuarios del grupo docker ({ln.split(':')[3]}) equivalen a administradores del sistema", "Úsalo solo con usuarios de confianza (o docker rootless)"
    return OK, "Sin usuarios en el grupo docker", ""


def c_legacy(cfg):
    legacy = [p for p in ("/usr/local/bin/sentinel-honeypot", "/usr/local/bin/sentinel-fim", "/usr/local/bin/sentinel-app") if os.path.exists(p)]
    rc = "sentinel-core.sh" in _read("/etc/rc.local")
    if legacy or rc:
        return WARN, "Quedan restos de la versión 1 de Sentinel (scripts antiguos y arranque por rc.local)", "sudo ./install.sh los retira (guarda una copia de rc.local)"
    return OK, "Sin restos de versiones anteriores", ""


def c_authlog(cfg):
    p = "/var/log/auth.log"
    if os.path.exists(p) and os.path.getsize(p) == 0:
        return INFO, "/var/log/auth.log está vacío: este sistema registra los accesos en el journal (Sentinel v2 lee el journal)", ""
    return OK, "Registro de accesos disponible", ""


def c_sentinel(cfg):
    st = {n: _svc(n) for n in ("sentinel-monitor", "sentinel-honeypot")}
    if all(v == "active" for v in st.values()):
        return OK, "Sentinel v2 activo (monitor y señuelos)", ""
    return FAIL, "Sentinel v2 no está activo: " + ", ".join(f"{k}={v}" for k, v in st.items()), "sudo ./install.sh"


CHECKS = [("firewall", "Cortafuegos", c_firewall), ("ids", "Bloqueo de atacantes", c_ids), ("auditd", "Registro de auditoría", c_auditd), ("ssh", "SSH", c_ssh),
          ("www", "Carpetas web", c_www), ("worldwritable", "Archivos de sistema", c_worldwritable), ("listeners", "Servicios expuestos", c_listeners), ("sysctl", "Kernel", c_sysctl),
          ("updates", "Actualizaciones", c_updates), ("autoupdates", "Actualización automática", c_autoupdates), ("login_defs", "Contraseñas y permisos", c_login_defs),
          ("home", "Credenciales del usuario", c_home_secrets), ("docker", "Docker", c_docker), ("legacy", "Versión anterior", c_legacy), ("authlog", "Registro de accesos", c_authlog),
          ("sentinel", "Sentinel", c_sentinel)]


def run_audit(cfg=None) -> dict:
    cfg = cfg or core.load_config()
    res = []
    for cid, title, fn in CHECKS:
        try:
            st, detail, fix = fn(cfg)
        except Exception as e:  # una revisión que falla no debe detener a las demás
            st, detail, fix = INFO, f"no se pudo revisar ({type(e).__name__})", ""
        res.append({"id": cid, "title": title, "status": st, "detail": detail, "fix": fix})
    scored = [r for r in res if r["status"] != INFO]
    pts = sum(1 if r["status"] == OK else 0.5 if r["status"] == WARN else 0 for r in scored)
    return {"score": round(100 * pts / len(scored)) if scored else 100, "checks": res}
