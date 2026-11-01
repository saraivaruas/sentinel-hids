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

from . import audit, core, explain, fim, geoip, honeypot, hostcheck, incidents, pin, report, update
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
    if a.action == "host":
        hostcheck.HostCheck(cfg, al, allow).init()
        print("Referencia del equipo actualizada (puertos, USB y módulos actuales aceptados como normales)")
        return 0
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


def cmd_update(a) -> int:
    if a.instalar and pin.required() and core.is_root():
        pin.authorize_stop()                      # ya demostró el PIN: el reinicio del servicio durante la actualización es legítimo
    cfg = core.load_config()
    if a.instalar:
        ok, msg = update.install(cfg)
        print(("✔ " if ok else "✖ ") + msg)
        return 0 if ok else 1
    i = update.check(cfg, force=True)
    if not i["enabled"]:
        print("La búsqueda de actualizaciones está desactivada ([update] check = no)."); return 0
    if i.get("error") and not i["available"]:
        print(f"No se pudo buscar actualizaciones: {update.error_text(i['error'])}. Estás en la versión {i['current']}."); return 1
    if i["available"]:
        print(f"Hay una versión nueva: {i['latest']} (tienes la {i['current']}).\n")
        if i.get("notes"):
            print(i["notes"][:900] + "\n")
        print("Para instalarla:  sudo sentinel update --instalar   (o el botón «Actualizar» del panel)")
        return 2
    print(f"Estás al día: versión {i['current']}.")
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
    if ev is not None and cfg.get("general", "popup_min", fallback="never") not in ("never", "nunca", "off", "no"):
        ev.msg = "Esta es una alerta de PRUEBA: Sentinel puede avisarte con una ventana. No requiere ninguna acción."
        shown = al.popup(ev, force=True)
        print("Ventana de alerta:", ok(shown), "(debería aparecer una ventana con el botón «Abrir panel»; ciérrala o púlsalo)")
        if shown and al.last_popup:
            al.last_popup.join(timeout=cfg.getint("general", "popup_seconds", fallback=120) + 5)     # espera para poder abrir el panel desde la ventana
    print("Motor de bloqueo:", core.Banner(cfg, al, allow).backend())
    print("Vigilancia en vivo (inotifywait):", ok(shutil.which("inotifywait")))
    return 0


def cmd_firewall(a) -> int:
    from . import firewall
    cfg = core.load_config()
    if a.accion == "config" and a.pares:           # varios ajustes en una sola autorización
        try:
            for par in a.pares:
                k, _, v = par.partition("=")
                firewall.set_config(k, v)
        except (ValueError, TypeError, OSError) as e:
            print("No se cambió:", e); return 1
        if core.is_root():
            firewall.save_snapshot(core.load_config())        # el panel ve el plan nuevo de inmediato, sin pedir otra clave
        print(f"Listo: {len(a.pares)} ajuste(s) del firewall guardados"); return 0
    if a.accion == "config":
        try:
            firewall.set_config(a.clave, a.valor)
        except (ValueError, TypeError, OSError) as e:
            print("No se cambió:", e); return 1
        if core.is_root():
            firewall.save_snapshot(core.load_config())
        print(f"Listo: [firewall] {a.clave} = {a.valor}"); return 0
    if a.accion in ("estado", "plan"):
        s = firewall.state(cfg)
        if a.guardar and core.is_root():
            firewall.save_snapshot(cfg)
        if a.json:
            print(json.dumps(s, ensure_ascii=False, indent=1)); return 0 if s.get("ok") else 1
        if not s.get("ok"):
            print("No pude leer el cortafuegos:", s.get("error"), "(¿falta sudo?)"); return 1
        print("\n".join(s["text"]))
        if s["needs_harden"]:
            print("  ! iptables acepta todo por defecto: usa  sudo sentinel firewall aplicar --endurecer  para cerrar de verdad.")
        if a.accion == "plan":
            print("\nSolo es el plan. Para aplicarlo:  sudo sentinel firewall aplicar")
        return 0
    if a.accion == "confirmar":
        print("\n".join(firewall.confirm())); firewall.save_snapshot(cfg) if core.is_root() else None; return 0
    if a.accion == "restaurar":
        print("\n".join(firewall.restore(a.clave or None, use_pending=a.pendiente, cfg=cfg)))
        if core.is_root():
            firewall.save_snapshot(cfg)
        return 0
    print("\n".join(firewall.apply(cfg, harden=a.endurecer, probar=a.probar)))
    if core.is_root():
        firewall.save_snapshot(cfg)
    return 0


def cmd_config(a) -> int:
    changed = 0
    for pair in a.pares:
        key, _, value = pair.partition("=")
        sec, _, k = key.partition(".")
        try:
            core.set_setting(sec, k, value.strip())
        except (ValueError, OSError) as e:
            print("No se cambió:", e); return 1
        changed += 1
    print(f"Guardado ({changed} ajuste{'s' if changed != 1 else ''}). Los avisos nuevos usan los valores de inmediato; el monitor los lee al reiniciar: sudo systemctl restart sentinel-monitor")
    if core.is_root() and shutil.which("systemctl") and core.conf_path() == "/etc/sentinel/sentinel.conf":      # solo con la configuración real del sistema
        core.run(["systemctl", "try-restart", "sentinel-monitor.service"], 20)
    return 0


def cmd_senuelos(a) -> int:
    if a.accion == "estado":
        on = core.run(["systemctl", "is-active", "sentinel-honeypot"], 5)[1].strip() == "active"
        print("Señuelos:", "activos" if on else "apagados"); return 0
    if not core.is_root():
        print("Necesita administrador: ejecuta  sudo sentinel senuelos " + a.accion); return 1
    cmd = ["systemctl", "enable", "--now", "sentinel-honeypot.service"] if a.accion == "activar" else ["systemctl", "disable", "--now", "sentinel-honeypot.service"]
    rc, out = core.run(cmd, 30)
    print(("Señuelos activados: abren los puertos " + ", ".join(core.csv(core.load_config().get("honeypot", "ports", fallback=""))) + " en este equipo (el firewall los mantiene cerrados hacia afuera salvo que los abras tú)." if a.accion == "activar" else "Señuelos apagados: sus puertos se cerraron.") if rc == 0 else out.strip())
    return 0 if rc == 0 else 1


def _protected(a) -> bool:
    """¿Este comando debilita o cambia la protección? Entonces exige el PIN (si hay uno)."""
    n = a.fn.__name__
    if n in ("cmd_allow", "cmd_config", "cmd_baseline", "cmd_detener", "cmd_aprender", "cmd_resolver"):
        return True
    return ((n == "cmd_bans" and a.action == "unban") or (n == "cmd_senuelos" and a.accion == "desactivar") or (n == "cmd_update" and a.instalar)
            or (n == "cmd_firewall" and (a.accion in ("aplicar", "config") or (a.accion == "restaurar" and not a.pendiente)))
            or (n == "cmd_pin" and a.accion in ("establecer", "quitar")))


def gate(a) -> int | None:
    """None = puede seguir. Si hay PIN y no se demuestra, devuelve el código de salida."""
    if not core.is_root() or not pin.required() or not _protected(a):
        return None
    if a.fn.__name__ == "cmd_baseline" and a.action == "accept" and pin.stop_authorized():
        return None                          # la actualización del paquete ya verificó el PIN hace un momento: no se pregunta dos veces
    given = pin.next_stdin_line() if a.pin_stdin else pin.ask()
    _last_given[0] = given or ""
    if given is None:
        print("Este comando necesita el PIN de Sentinel y no hay forma de preguntarlo (usa una terminal).", file=sys.stderr); return 2
    ok, msg = pin.verify(given, core.Alerter(core.load_config()))
    if not ok:
        print(msg, file=sys.stderr); return 2
    return None


def cmd_pin(a) -> int:
    was = pin.required()
    cfg = core.load_config()
    if a.accion == "estado":
        print("PIN:", "activo" if was else "no configurado"); return 0
    if a.accion == "verificar":                # lo usa el desinstalador: sin PIN correcto no sigue
        if not was:
            return 0
        given = pin.next_stdin_line() if a.pin_stdin else pin.ask()
        ok, msg = pin.verify(given or "", core.Alerter(cfg)) if given is not None else (False, "No pude preguntar el PIN.")
        if not ok:
            print(msg, file=sys.stderr)
        else:
            pin.authorize_stop()                # demostró el PIN: ya puede detener los servicios para desinstalar
        return 0 if ok else 1
    if a.accion == "autorizar":                # la actualización del paquete pide permiso para reiniciar el servicio
        if not was or pin.stop_authorized():
            return 0
        given = pin.ask("\nSentinel está protegido con PIN. Escríbelo para actualizar y pulsa Enter (o solo Enter para omitir): ")
        if not given:
            print("Sin PIN: la actualización sigue, pero el monitor tardará unos 20 segundos en reiniciarse y se registrará una alerta.", file=sys.stderr); return 1
        ok, msg = pin.verify(given, core.Alerter(cfg))
        if ok:
            pin.authorize_stop()
        else:
            print(msg, file=sys.stderr)
        return 0 if ok else 1
    if a.accion == "quitar":
        ok, msg = pin.clear(_last_given[0], core.Alerter(cfg))
        print(msg); return 0 if ok else 1
    # establecer / cambiar
    if a.pin_stdin:
        if not was:
            pin.next_stdin_line()              # la línea del PIN actual viene vacía
        new = pin.next_stdin_line()
    else:
        new = pin.ask("PIN nuevo (mínimo 6 caracteres): ")
        if new is None or new != pin.ask("Repite el PIN nuevo: "):
            print("No coinciden o no pude preguntarlo.", file=sys.stderr); return 1
    ok, msg = pin.set_pin(new, _last_given[0], core.Alerter(cfg))
    print(msg); return 0 if ok else 1


_last_given: list[str] = [""]


def cmd_detener(a) -> int:
    if not core.is_root():
        print("Necesita administrador: ejecuta  sudo sentinel detener", file=sys.stderr); return 1
    pin.authorize_stop()
    units = ["sentinel-monitor.service", "sentinel-honeypot.service", "sentinel-scan.timer", "sentinel-report.timer"]
    rc, out = core.run(["systemctl", "stop", *units], 60)
    core.Alerter(core.load_config()).emit("high", "pin", "detenido", "Sentinel fue detenido de forma autorizada", key=f"stop:{int(core.now())}")
    pin.revoke_stop()
    print("Sentinel detenido. Para volver a encenderlo:  sudo sentinel iniciar" if rc == 0 else out.strip()); return 0 if rc == 0 else 1


def cmd_iniciar(a) -> int:
    rc, out = core.run(["systemctl", "start", "sentinel-monitor.service", "sentinel-scan.timer", "sentinel-report.timer"], 60)
    print("Sentinel iniciado." if rc == 0 else out.strip()); return 0 if rc == 0 else 1


def cmd_resolver(a) -> int:
    if not core.is_root():
        print("Necesita administrador: ejecuta  sudo sentinel resolver CLAVE EPOCH", file=sys.stderr); return 1
    core.resolve_event(a.clave, a.epoch)
    print("Evento marcado como resuelto: ya no cuenta en el resumen ni en los informes (sigue en el historial)."); return 0


def cmd_aprender(a) -> int:
    if not core.is_root():
        print("Necesita administrador: ejecuta  sudo sentinel aprender", file=sys.stderr); return 1
    p = hostcheck.learn_path()
    if a.dias == 0:
        try:
            os.remove(p)
        except OSError:
            pass
        print("Modo aprendizaje terminado: desde ahora lo nuevo vuelve a avisar."); return 0
    core.atomic_write_json(p, {"until": core.now() + a.dias * 86400, "since": core.iso()}, 0o640, share=True)
    print(f"Modo aprendizaje por {a.dias} día(s): los puertos, USB y módulos nuevos se aceptan como normales sin avisar. Los ataques, los archivos y las cuentas siguen avisando igual.")
    return 0


def cmd_tray(a) -> int:
    from . import tray
    return tray.run()


def cmd_toast(a) -> int:
    from . import toast
    return toast.show(a.titulo[:120], a.mensaje[:400], a.sev, a.seg)


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
    p.add_argument("--pin-stdin", action="store_true", help="lee el PIN de la entrada estándar (lo usa el panel)")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("status", help="estado de los servicios y últimos eventos").set_defaults(fn=cmd_status)
    s = sub.add_parser("scan", help="revisa ahora integridad y estado del equipo"); s.add_argument("--deep", action="store_true", help="revisión profunda (recalcula todas las huellas, SUID, procesos ocultos)")
    s.add_argument("--json", action="store_true"); s.add_argument("--quiet", action="store_true", help="sin notificaciones"); s.add_argument("--watchdog", action="store_true", help="avisa si el monitor dejó de latir"); s.set_defaults(fn=cmd_scan)
    s = sub.add_parser("baseline", help="crea o actualiza la referencia de integridad"); s.add_argument("action", choices=["init", "accept", "host"]); s.add_argument("paths", nargs="*"); s.set_defaults(fn=cmd_baseline)
    s = sub.add_parser("events", help="muestra eventos"); s.add_argument("-n", type=int, default=30); s.add_argument("--horas", type=int, default=24); s.add_argument("--min", default="info", choices=list(core.SEV)); s.set_defaults(fn=cmd_events)
    s = sub.add_parser("bans", help="lista, agrega o quita bloqueos"); s.add_argument("action", nargs="?", default="list", choices=["list", "ban", "unban"]); s.add_argument("ip", nargs="?"); s.add_argument("--horas", type=int, default=24); s.add_argument("--motivo", default=""); s.set_defaults(fn=cmd_bans)
    s = sub.add_parser("attackers", help="lista los atacantes registrados con su riesgo"); s.add_argument("--q", default=""); s.add_argument("-n", type=int, default=30); s.set_defaults(fn=cmd_attackers)
    s = sub.add_parser("attacker", help="expediente de una IP, explicado de forma sencilla"); s.add_argument("ip"); s.add_argument("--tecnico", action="store_true", help="datos sin explicaciones"); s.set_defaults(fn=cmd_attacker)
    s = sub.add_parser("update", help="busca una versión nueva y, si quieres, la instala"); s.add_argument("--instalar", action="store_true", help="descargar, verificar e instalar (necesita sudo)"); s.set_defaults(fn=cmd_update)
    sub.add_parser("packets", help="qué es un paquete y los últimos paquetes sospechosos").set_defaults(fn=cmd_packets)
    s = sub.add_parser("audit", help="revisa la postura de seguridad del equipo"); s.add_argument("--json", action="store_true"); s.set_defaults(fn=cmd_audit)
    s = sub.add_parser("report", help="genera el informe HTML"); s.add_argument("--dias", type=int, default=7); s.add_argument("--lynis", action="store_true"); s.set_defaults(fn=cmd_report)
    s = sub.add_parser("allow", help="agrega algo a la lista blanca"); s.add_argument("tipo", choices=["ip", "proc", "port", "path"]); s.add_argument("valor"); s.set_defaults(fn=cmd_allow)
    sub.add_parser("test", help="prueba que las alertas lleguen").set_defaults(fn=cmd_test)
    s = sub.add_parser("firewall", help="módulo de cortafuegos (ufw/iptables): estado, plan, aplicar, config"); s.add_argument("accion", nargs="?", default="estado", choices=["estado", "plan", "aplicar", "config", "confirmar", "restaurar"]); s.add_argument("clave", nargs="?", default=""); s.add_argument("valor", nargs="?", default="")
    s.add_argument("--pares", nargs="+", metavar="clave=valor", help="config: varios ajustes a la vez"); s.add_argument("--json", action="store_true"); s.add_argument("--guardar", action="store_true", help="guarda la foto para el panel"); s.add_argument("--endurecer", action="store_true", help="iptables: política de entrada DROP")
    s.add_argument("--probar", type=int, default=0, metavar="SEG", help="aplica a prueba: si no confirmas en SEG segundos, vuelve atrás solo"); s.add_argument("--pendiente", action="store_true", help="restaurar: la copia de los cambios a prueba"); s.set_defaults(fn=cmd_firewall)
    s = sub.add_parser("config", help="cambia ajustes de avisos (usado por el panel): sentinel config general.notify_min=high ..."); s.add_argument("pares", nargs="+", metavar="seccion.clave=valor"); s.set_defaults(fn=cmd_config)
    s = sub.add_parser("senuelos", help="activa o apaga los señuelos (puertos falsos)"); s.add_argument("accion", choices=["activar", "desactivar", "estado"]); s.set_defaults(fn=cmd_senuelos)
    s = sub.add_parser("pin", help="PIN de protección: estado, establecer, quitar, verificar"); s.add_argument("accion", choices=["estado", "establecer", "quitar", "verificar", "autorizar"]); s.set_defaults(fn=cmd_pin)
    sub.add_parser("detener", help="detiene Sentinel (pide el PIN si hay uno)").set_defaults(fn=cmd_detener)
    sub.add_parser("iniciar", help="vuelve a encender Sentinel").set_defaults(fn=cmd_iniciar)
    s = sub.add_parser("aprender", help="modo aprendizaje: acepta como normales los puertos, USB y módulos nuevos durante N días (0 = terminar)"); s.add_argument("dias", type=int, nargs="?", default=3); s.set_defaults(fn=cmd_aprender)
    s = sub.add_parser("resolver", help="marca un evento como resuelto (deja de contar en el resumen y los informes)"); s.add_argument("clave"); s.add_argument("epoch", type=float); s.set_defaults(fn=cmd_resolver)
    sub.add_parser("tray", help="ícono de estado en la barra del sistema (se inicia solo al abrir la sesión)").set_defaults(fn=cmd_tray)
    s = sub.add_parser("toast", help="muestra un aviso en la esquina de la pantalla (lo usa Sentinel)"); s.add_argument("mensaje"); s.add_argument("--sev", default="medium", choices=list(core.SEV)); s.add_argument("--seg", type=int, default=8); s.add_argument("--titulo", default="Sentinel"); s.set_defaults(fn=cmd_toast)
    s = sub.add_parser("ui", help="abre el panel gráfico"); s.add_argument("--port", type=int, default=8737); s.add_argument("--sin-abrir", action="store_true", help="no abrir la ventana"); s.set_defaults(fn=cmd_ui)
    sub.add_parser("monitor", help="servicio principal (lo lanza systemd)").set_defaults(fn=cmd_monitor)
    sub.add_parser("honeypot", help="servicio de señuelos (lo lanza systemd)").set_defaults(fn=cmd_honeypot)
    a = p.parse_args(argv)
    code = gate(a)
    if code is not None:
        return code
    return a.fn(a)
