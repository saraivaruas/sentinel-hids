"""Línea de comandos de Sentinel: `sentinel status | scan | baseline | events | bans | audit | report | allow | test | monitor | honeypot`."""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import shutil
import sys
import time

from . import audit, core, explain, fim, geoip, honeypot, hostcheck, incidents, report
from .monitor import Monitor

C = {"critical": "\033[1;41;97m", "high": "\033[1;31m", "medium": "\033[33m", "low": "\033[36m", "info": "\033[2m", "ok": "\033[32m", "aviso": "\033[33m", "fallo": "\033[1;31m"}
R = "\033[0m"


def col(txt: str, k: str) -> str:
    return f"{C.get(k, '')}{txt}{R}" if sys.stdout.isatty() else txt


def build():
    cfg = core.load_config()
    al = core.Alerter(cfg)
    allow = core.Allow(cfg)
    return cfg, al, allow, core.Banner(cfg, al, allow)


def cmd_status(a) -> int:
    cfg, al, allow, banner = build()
    print(f"Sentinel {core.VERSION}")
    for n in ("sentinel-monitor", "sentinel-honeypot", "sentinel-scan.timer", "sentinel-report.timer"):
        st = core.run(["systemctl", "is-active", n], 5)[1].strip().split("\n")[-1]
        print(f"  {n:<24} {col(st, 'ok' if st == 'active' else 'fallo')}")
    hb = core.read_json(os.path.join(core.state_dir(), "heartbeat.json"))
    if hb:
        age = int(core.now() - hb["epoch"])
        print(f"  último latido           hace {age} s " + col("(vivo)", "ok") if age < 120 else f"  último latido           hace {age} s " + col("(DETENIDO)", "fallo"))
    base = core.read_json(os.path.join(core.state_dir(), "fim_baseline.json"))
    print(f"  referencia de integridad {len(base['files']) if base else 0} elementos" + (f", creada {base['created'][:16]}" if base else col(" · falta: sentinel baseline init", "aviso")))
    bans = {k: v for k, v in banner.bans.items() if v["until"] > core.now()}
    print(f"  bloqueos activos        {len(bans)}")
    ev = core.read_events(core.now() - 86400)
    cnt = {s: sum(1 for e in ev if e["sev"] == s) for s in core.SEV}
    print("  últimas 24 h            " + ", ".join(f"{cnt[s]} {core.SEV_ES[s]}" for s in ("critical", "high", "medium", "low")))
    for e in [e for e in ev if core.SEV[e["sev"]] >= 2][-5:]:
        print("   ·", col(f"{e['ts'][5:16]} {core.SEV_ES[e['sev']]}", e["sev"]), e["msg"][:110])
    return 0


def cmd_scan(a) -> int:
    cfg, al, allow, banner = build()
    f = fim.Fim(cfg, al, allow)
    if a.quiet:
        al.quiet = True
    res = f.scan(deep=a.deep)
    hc = hostcheck.HostCheck(cfg, al, allow).run(deep=a.deep)
    worst = max([core.SEV[r["sev"]] for r in res] + [e.sev and core.SEV[e.sev] for e in hc] + [0])
    if a.json:
        print(json.dumps({"fim": res, "host": [e.__dict__ for e in hc]}, ensure_ascii=False, indent=1))
    else:
        for r in res:
            print(col(f"[{core.SEV_ES[r['sev']]}]", r["sev"]), r["path"], "·", r["detail"])
        for e in hc:
            print(col(f"[{core.SEV_ES[e.sev]}]", e.sev), e.msg)
        if not res and not hc:
            print(col("Sin novedades: todo coincide con la referencia.", "ok"))
    hb = core.read_json(os.path.join(core.state_dir(), "heartbeat.json"))
    if a.watchdog and hb and core.now() - hb["epoch"] > 300:
        al.emit("high", "monitor", "sin_latido", "El monitor de Sentinel dejó de latir hace más de 5 minutos", key="mon:silent")
        worst = max(worst, 3)
    return 2 if worst >= 3 else 1 if worst == 2 else 0


def cmd_baseline(a) -> int:
    cfg, al, allow, _ = build()
    f = fim.Fim(cfg, al, allow)
    if a.action == "init":
        n = f.init()
        hostcheck.HostCheck(cfg, al, allow).init()
        print(f"Referencia creada: {n} elementos de integridad + estado del equipo")
    else:
        n = f.accept(a.paths or None)
        print(f"Referencia actualizada ({n} elementos)")
        if not a.paths:
            hostcheck.HostCheck(cfg, al, allow).init()
    return 0


def cmd_events(a) -> int:
    since = core.now() - a.horas * 3600
    for e in core.read_events(since, a.min, a.n):
        print(col(f"{e['ts'][:16]} {core.SEV_ES[e['sev']]:>7}", e["sev"]), f"{e['source']}/{e['kind']}", "·", e["msg"])
    return 0


def cmd_bans(a) -> int:
    cfg, al, allow, banner = build()
    if core.is_root():
        from . import intel as intel_mod
        banner.intel = intel_mod.Intel(cfg)
    if a.action == "unban":
        print("Liberada" if banner.unban(a.ip, "usuario") else "No estaba en la lista de Sentinel (se intentó quitar igual)")
        return 0
    if a.action == "ban":
        if not a.ip:
            print("Indica la IP: sentinel bans ban 203.0.113.9 --horas 24", file=sys.stderr); return 1
        ok = banner.ban(a.ip, a.motivo or "bloqueo manual", a.horas * 3600, manual=True)
        print("Bloqueada por %d h" % a.horas if ok else "No se bloqueó (IP protegida, ya bloqueada, o falta permiso de administrador)")
        return 0 if ok else 1
    for ip, b in banner.bans.items():
        left = int(b["until"] - core.now())
        print(f"{ip:<40} {b['backend']:<9} {'caducado' if left <= 0 else f'{left // 3600} h {left % 3600 // 60} min'}  {b['reason']}")
    if not banner.bans:
        print("Sin bloqueos activos")
    return 0


def _ro_store():
    try:
        return incidents.Store(readonly=True)
    except Exception:
        print("Todavía no hay expedientes (el monitor los crea al detectar algo) o no tienes permiso para leerlos.", file=sys.stderr)
        return None


def cmd_attackers(a) -> int:
    st = _ro_store()
    if not st:
        return 1
    kinds = st.kinds_by_ip()
    rows = st.list_ips(a.n, a.q)
    if not rows:
        print("Sin atacantes registrados.")
    for r in rows:
        pts, nivel = explain.puntaje(kinds.get(r["ip"], {}), 0, 0)
        e = explain.NIVELES[nivel][0]
        print(f"{e} {r['ip']:<40} riesgo {pts:>3}  {r['attempts']:>5} intentos  {r['status']:<10} {geoip.place_text(r)[:60]}")
    return 0


def cmd_attacker(a) -> int:
    st = _ro_store()
    if not st:
        return 1
    d = st.dossier(a.ip)
    if not d:
        print("No hay expediente de esa IP."); return 1
    info = explain.explicar(d)
    print(f"\n{info['resumen']}\n" + "=" * 70)
    for b in info["bloques"]:
        print(f"\n▸ {b['titulo']}")
        if b.get("texto"):
            print("  " + b["texto"])
        for i in b.get("items", []):
            print(f"   • {i['nombre']} ×{i['veces']}  [{explain.nivel_str(i['nivel'])}]")
            if not a.tecnico:
                print(f"       Qué es: {i['nino']}\n       Para qué sirve: {i['sirve']}\n       ¿Es peligroso?: {i['peligro']}")
    print("\n▸ Qué puedes hacer")
    for r in info["recomendaciones"]:
        print("   - " + r)
    return 0


def cmd_packets(a) -> int:
    print("¿QUÉ ES UN PAQUETE?\n" + explain.GLOSARIO[0][1] + "\n")
    for k, t in explain.PAQUETES.items():
        if k != "otro":
            print(f"{explain.NIVELES[t['nivel']][0]} {t['nombre']}\n   {t['nino']}\n   Sirve para: {t['sirve']}\n   Peligro: {t['peligro']}\n")
    st = _ro_store()
    if st:
        rec = st.recent_packets(15)
        print("ÚLTIMOS PAQUETES SOSPECHOSOS" + ("" if rec else ": ninguno todavía"))
        for r in rec:
            print(f"  {time.strftime('%H:%M:%S', time.localtime(r['ts']))}  {r['ip']:<40} → puerto {r['dport']}  {r['label']}")
    return 0


def cmd_audit(a) -> int:
    r = audit.run_audit()
    if a.json:
        print(json.dumps(r, ensure_ascii=False, indent=1))
        return 0
    for c in r["checks"]:
        print(col(f"{c['status'].upper():>6}", c["status"]), f"{c['title']:<26}", c["detail"])
        if c["fix"] and c["status"] in ("aviso", "fallo"):
            print(" " * 8, "→", c["fix"])
    print(f"\nPostura de seguridad: {r['score']}/100")
    return 0


def cmd_report(a) -> int:
    print(report.save(a.dias, a.lynis))
    return 0


def cmd_allow(a) -> int:
    path = core.conf_path()
    if not os.path.exists(path):
        print(f"No existe {path}; copia etc/sentinel.conf.example", file=sys.stderr)
        return 1
    key = {"ip": "ips", "proc": "procs", "port": "ports", "path": "paths"}[a.tipo]
    txt = open(path, encoding="utf-8").read()
    m = re.search(rf"^({key}\s*=)(.*)$", txt, re.M)
    if not m:
        print(f"No encontré «{key} =» en [allow] de {path}", file=sys.stderr)
        return 1
    vals = core.csv(m.group(2))
    if a.valor not in vals:
        vals.append(a.valor)
    open(path, "w", encoding="utf-8").write(txt[:m.start()] + f"{m.group(1)} " + ",".join(vals) + txt[m.end():])
    print(f"Agregado a la lista blanca ({key}): {a.valor}")
    return 0


def cmd_test(a) -> int:
    cfg, al, allow, _ = build()
    ev = al.emit("medium", "test", "prueba", f"Prueba de Sentinel {core.iso()}", key=f"test:{time.time()}")
    ok = lambda b: col("sí", "ok") if b else col("no", "fallo")
    print("Evento registrado en", al.path, ":", ok(ev is not None and os.path.exists(al.path)))
    if shutil.which("journalctl") and cfg.getboolean("general", "enable_journal", fallback=True):
        time.sleep(1)
        print("Llegó al journal:", ok("Prueba de Sentinel" in core.run(["journalctl", "-t", "sentinel", "-n", "5", "--no-pager"], 8)[1]))
    print("Escritorio disponible:", ok(al.desktop_target() is not None and shutil.which("notify-send") is not None), "(deberías ver una notificación)")
    if ev is not None:
        ev.msg = "Esta es una alerta de PRUEBA: Sentinel puede avisarte con una ventana. No requiere ninguna acción."
        shown = al.popup(ev, force=True)
        print("Ventana de alerta:", ok(shown), "(debería aparecer una ventana con el botón «Abrir panel»; ciérrala o púlsalo)")
        if shown and al.last_popup:
            al.last_popup.join(timeout=cfg.getint("general", "popup_seconds", fallback=120) + 5)     # espera para poder abrir el panel desde la ventana
    print("Motor de bloqueo:", core.Banner(cfg, al, allow).backend())
    print("Vigilancia en vivo (inotifywait):", ok(shutil.which("inotifywait")))
    return 0


def cmd_ui(a) -> int:
    from . import ui
    return ui.run_ui(a.port, not a.sin_abrir)


def cmd_monitor(a) -> int:
    Monitor().run()
    return 0


def cmd_honeypot(a) -> int:
    cfg = core.load_config()
    hp = honeypot.Honeypot(cfg)

    async def main():
        bound = await hp.start()
        print("Señuelos escuchando en:", bound or "ninguno (puertos ocupados)", flush=True)
        if hp.servers:
            await asyncio.gather(*(s.serve_forever() for s in hp.servers))
        else:
            await asyncio.sleep(3600)

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="sentinel", description=f"Sentinel {core.VERSION}: detector de intrusiones y cambios")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("status", help="estado de los servicios y últimos eventos").set_defaults(fn=cmd_status)
    s = sub.add_parser("scan", help="revisa ahora integridad y estado del equipo"); s.add_argument("--deep", action="store_true", help="revisión profunda (recalcula todas las huellas, SUID, procesos ocultos)")
    s.add_argument("--json", action="store_true"); s.add_argument("--quiet", action="store_true", help="sin notificaciones"); s.add_argument("--watchdog", action="store_true", help="avisa si el monitor dejó de latir"); s.set_defaults(fn=cmd_scan)
    s = sub.add_parser("baseline", help="crea o actualiza la referencia de integridad"); s.add_argument("action", choices=["init", "accept"]); s.add_argument("paths", nargs="*"); s.set_defaults(fn=cmd_baseline)
    s = sub.add_parser("events", help="muestra eventos"); s.add_argument("-n", type=int, default=30); s.add_argument("--horas", type=int, default=24); s.add_argument("--min", default="info", choices=list(core.SEV)); s.set_defaults(fn=cmd_events)
    s = sub.add_parser("bans", help="lista, agrega o quita bloqueos"); s.add_argument("action", nargs="?", default="list", choices=["list", "ban", "unban"]); s.add_argument("ip", nargs="?"); s.add_argument("--horas", type=int, default=24); s.add_argument("--motivo", default=""); s.set_defaults(fn=cmd_bans)
    s = sub.add_parser("attackers", help="lista los atacantes registrados con su riesgo"); s.add_argument("--q", default=""); s.add_argument("-n", type=int, default=30); s.set_defaults(fn=cmd_attackers)
    s = sub.add_parser("attacker", help="expediente de una IP, explicado de forma sencilla"); s.add_argument("ip"); s.add_argument("--tecnico", action="store_true", help="datos sin explicaciones"); s.set_defaults(fn=cmd_attacker)
    sub.add_parser("packets", help="qué es un paquete y los últimos paquetes sospechosos").set_defaults(fn=cmd_packets)
    s = sub.add_parser("audit", help="revisa la postura de seguridad del equipo"); s.add_argument("--json", action="store_true"); s.set_defaults(fn=cmd_audit)
    s = sub.add_parser("report", help="genera el informe HTML"); s.add_argument("--dias", type=int, default=7); s.add_argument("--lynis", action="store_true"); s.set_defaults(fn=cmd_report)
    s = sub.add_parser("allow", help="agrega algo a la lista blanca"); s.add_argument("tipo", choices=["ip", "proc", "port", "path"]); s.add_argument("valor"); s.set_defaults(fn=cmd_allow)
    sub.add_parser("test", help="prueba que las alertas lleguen").set_defaults(fn=cmd_test)
    s = sub.add_parser("ui", help="abre el panel gráfico"); s.add_argument("--port", type=int, default=8737); s.add_argument("--sin-abrir", action="store_true", help="no abrir la ventana"); s.set_defaults(fn=cmd_ui)
    sub.add_parser("monitor", help="servicio principal (lo lanza systemd)").set_defaults(fn=cmd_monitor)
    sub.add_parser("honeypot", help="servicio de señuelos (lo lanza systemd)").set_defaults(fn=cmd_honeypot)
    a = p.parse_args(argv)
    return a.fn(a)
