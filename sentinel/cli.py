"""Línea de comandos de Sentinel: `sentinel status | scan | baseline | events | bans | audit | report | allow | test | monitor | honeypot`."""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import shutil
import subprocess
import sys
import time

from . import audit, core, endurecer, equipo, explain, fim, geoip, honeypot, hostcheck, ia, identidad, incidents, mailer, pin, plataforma, report, requisitos, servicio, update
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
    from . import ui
    ov = ui.Data().overview()                          # el mismo veredicto que el panel (los avisos ya revisados no cuentan)
    veredicto = {"protegido": col("PROTEGIDO", "ok"), "atencion": col("REQUIERE ATENCIÓN", "high")}.get(ov["level"], col(str(ov["level"]).upper(), "aviso"))
    print(f"Sentinel {core.VERSION} — {veredicto}: {ov['why']}")
    for n in ("sentinel-monitor", "sentinel-honeypot", "sentinel-scan.timer", "sentinel-report.timer", "sentinel-equipo.timer"):
        if plataforma.ES_MAC and n == "sentinel-honeypot":
            continue                                   # los señuelos todavía no existen en macOS
        st = servicio.estado(n)
        print(f"  {n:<24} {col(st, 'ok' if st == 'active' else 'fallo')}")
    hb = core.read_json(os.path.join(core.state_dir(), "heartbeat.json"))
    if hb:
        age = int(core.now() - hb["epoch"])
        print(f"  último latido           hace {age} s " + col("(vivo)", "ok") if age < 120 else f"  último latido           hace {age} s " + col("(DETENIDO)", "fallo"))
    # La referencia completa es solo de root; el resumen público (fim_meta.json) permite mostrarla sin sudo
    meta = core.read_json(os.path.join(core.state_dir(), "fim_meta.json"))
    if meta and meta.get("count"):
        print(f"  referencia de integridad {meta['count']:,} elementos, creada {str(meta.get('created', ''))[:16]}")
    else:
        print("  referencia de integridad " + col("falta: ejecuta  sudo sentinel baseline init", "aviso"))
    bans = {k: v for k, v in banner.bans.items() if v["until"] > core.now()}
    print(f"  bloqueos activos        {len(bans)}")
    done = core.resolved_ids()
    ev = [e for e in core.read_events(core.now() - 86400) if core.event_id(e) not in done]
    cnt = {s: sum(1 for e in ev if e["sev"] == s) for s in core.SEV}
    print("  últimas 24 h            " + ", ".join(f"{cnt[s]} {core.SEV_ES[s]}" for s in ("critical", "high", "medium", "low")) + "  (sin contar los avisos ya revisados)")
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


def estado_captura() -> str:
    """Una línea que dice si la captura de paquetes está funcionando y qué ha visto (lo mismo que muestra el panel)."""
    s = core.read_json(os.path.join(core.state_dir(), "packets_stats.json"))
    if not s:
        return "CAPTURA DE PAQUETES: sin datos todavía (el monitor aún no la inició, o está apagada)"
    edad = core.now() - s.get("ts", 0)
    if s.get("activo") and edad < 120:
        d = s.get("detectados", 0)
        return (f"CAPTURA DE PAQUETES: ACTIVA · {s.get('vistos', 0):,} paquetes vistos desde {str(s.get('desde', ''))[:16].replace('T', ' ')} · "
                f"{s.get('interesantes', 0):,} sin conversación previa · {d} escaneo(s) detectado(s)" + (" (sin novedades: es lo normal)" if not d else ""))
    if s.get("activo"):
        return f"CAPTURA DE PAQUETES: SIN SEÑAL desde hace {int(edad // 60)} min (¿el monitor está detenido?)"
    return f"CAPTURA DE PAQUETES: APAGADA ({s.get('motivo') or 'detenida'}): se usan los registros del cortafuegos"


def cmd_packets(a) -> int:
    print(estado_captura() + "\n")
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


def cmd_equipo(a) -> int:
    """Revisión completa del equipo: la muestra, la guarda como informe y, si se pide, la manda por correo SMTP."""
    cfg = core.load_config()
    if a.horario:
        if not core.is_root():
            print("Necesita administrador: ejecuta  sudo sentinel equipo --horario " + a.horario, file=sys.stderr); return 1
        ok, msg = equipo.aplicar_horario(a.horario)
        print(msg)
        return 0 if ok else 1
    inf = equipo.revisar(cfg, aceptar=a.aceptar, rapido=a.rapido)
    c = inf.cuenta()
    if a.json:
        print(json.dumps({"host": inf.host, "fecha": inf.fecha, "riesgo": inf.nivel(), "cuenta": c, "hallazgos": [vars(h) for h in inf.unicos()]}, ensure_ascii=False, indent=1))
    elif not a.programado:
        print(equipo.a_texto(inf))
    try:
        ruta_html, ruta_txt = equipo.guardar(inf, cfg)
    except OSError as e:
        print("No pude guardar el informe:", e, file=sys.stderr)
        return 1
    print(f"Riesgo {inf.nivel()} (alto {c['ALTO']}, medio {c['MEDIO']}, bajo {c['BAJO']}). Informe guardado: {ruta_html}")
    if a.aceptar:
        print("Las referencias de esta revisión (cuentas, persistencia) quedaron actualizadas.")
    if a.enviar or (a.programado and cfg.getboolean("equipo", "enviar_correo", fallback=True)):
        if not mailer.configured(cfg):
            print("Correo no enviado: SMTP sin configurar (sudo sentinel smtp configurar)."); return 0 if a.programado else 1
        ok, msg = equipo.enviar(cfg, inf, ruta_html, ruta_txt)
        print(("Correo: " if ok else "No se pudo enviar el correo: ") + msg)
        return 0 if ok else 1
    return 0


def _mostrar_requisitos(lista) -> None:
    for nivel, titulo in ((requisitos.OBLIGATORIO, "Obligatorios (sin esto Sentinel no funciona)"), (requisitos.RECOMENDADO, "Recomendados (mejoran la protección)"), (requisitos.OPCIONAL, "Opcionales (funciones extra)")):
        print(f" {titulo}")
        for r, ok in lista:
            if r.nivel != nivel:
                continue
            marca = col("✔", "ok") if ok else col("✖", "fallo") if nivel != requisitos.OPCIONAL else col("○", "aviso")
            print(f"   {marca} {r.nombre}" + ("" if ok else f"\n       {r.para_que}"))
        print()


def cmd_requisitos(a) -> int:
    """Muestra qué necesita Sentinel y qué tiene este equipo (✔ / ✖) y, si aceptas, instala lo que falta pidiendo tu contraseña de administrador."""
    lista, g = requisitos.estado(), requisitos.gestor()
    if a.json:
        print(json.dumps(requisitos.como_dict(lista, g), ensure_ascii=False, indent=1))
        return 0
    print("REQUISITOS DE SENTINEL\n")
    _mostrar_requisitos(lista)
    pend = requisitos.faltan(lista=lista)
    if not pend:
        print(col("Todo lo necesario ya está instalado ✔", "ok"))
        return 0
    paquetes, sin = requisitos.paquetes_para(pend, g) if g else ([], pend)
    faltan_obl = [r for r in pend if r.nivel == requisitos.OBLIGATORIO]
    print(f"Faltan {len(pend)}: " + ", ".join(r.nombre for r in pend))
    for r in sin:
        print(f"   · {r.nombre}: " + (r.manual or "instálalo con el gestor de paquetes de tu distribución"))
    if not g:
        print("No reconozco el gestor de paquetes de esta distribución: instala a mano lo que falta.")
        return 1 if faltan_obl else 0
    if not paquetes:
        return 1 if faltan_obl else 0
    print(f"\nSe instalaría con {g}: {' '.join(paquetes)}")
    tty = sys.stdin.isatty() and sys.stdout.isatty()
    if not a.si:
        if not tty:
            print("Para instalarlo:  sentinel requisitos --instalar"); return 1 if faltan_obl else 0
        if input("¿Instalar ahora lo que falta? Te pedirá tu contraseña de administrador. [S/n]: ").strip().lower() in ("n", "no"):
            print("No se instaló nada." + (" Sin lo obligatorio Sentinel no podrá funcionar." if faltan_obl else ""))
            return 1 if faltan_obl else 0
    root = core.is_root()
    if not root and not shutil.which("sudo"):
        print("Falta sudo: ejecuta este comando como administrador.", file=sys.stderr); return 1
    if g == "apt":
        subprocess.run((["sudo"] if not root else []) + ["apt-get", "update", "-qq"], check=False)
    rc = subprocess.run(requisitos.comando_instalar(g, paquetes, con_sudo=not root), check=False).returncode
    print()
    nuevo = requisitos.estado()
    _mostrar_requisitos(nuevo)
    quedan = requisitos.faltan(lista=nuevo)
    print(col("Listo: todo instalado ✔", "ok") if not quedan else "Todavía falta: " + ", ".join(r.nombre for r in quedan))
    return 0 if rc == 0 and not [r for r in quedan if r.nivel == requisitos.OBLIGATORIO] else 1


def cmd_endurecer(a) -> int:
    """Endurecimiento guiado: `plan` (solo lectura), `aplicar` (con copia y comprobación), `revertir` y `estado`."""
    solo = core.csv(a.solo) if a.solo else None
    items = endurecer.plan(a.perfil, solo)
    cuenta = {c: sum(1 for i in items if i.codigo == c) for c in (endurecer.APLICADA, endurecer.PENDIENTE, endurecer.BLOQUEADA, endurecer.NO_APLICA)}
    if a.accion == "revertir":
        if not core.is_root():
            print("Necesita administrador: ejecuta  sudo sentinel endurecer revertir", file=sys.stderr); return 1
        r = endurecer.revertir(a.tanda, alerter=core.Alerter(core.load_config()))
        print(r["error"] or "Revertido: " + ", ".join(r["revertidas"]) + ". Todo quedó como estaba antes.")
        return 1 if r["error"] else 0
    if a.json:
        print(json.dumps([{"id": i.medida.id, "titulo": i.medida.titulo, "estado": i.codigo, "detalle": i.detalle, "riesgo": i.medida.riesgo, "perfil": i.medida.perfil} for i in items], ensure_ascii=False, indent=1))
        return 0
    icono = {endurecer.APLICADA: col("✔", "ok"), endurecer.PENDIENTE: col("○", "aviso"), endurecer.BLOQUEADA: col("✖", "fallo"), endurecer.NO_APLICA: col("–", "info")}
    print(f"ENDURECIMIENTO · perfil {endurecer.PERFIL_ES[a.perfil]}\n")
    for i in items:
        m = i.medida
        print(f" {icono[i.codigo]} {m.titulo}" + (f"  [{i.codigo.upper().replace('_', ' ')}]" if i.codigo != endurecer.APLICADA else col("  (ya aplicada)", "ok")))
        if i.codigo in (endurecer.PENDIENTE, endurecer.BLOQUEADA):
            print(f"     Qué hace: {m.que_hace}\n     Para qué:  {m.por_que}\n     Riesgo:    {m.riesgo}" + (f"  ·  {m.nota}" if m.nota else ""))
        if i.codigo != endurecer.APLICADA:
            print(f"     Ahora:     {i.detalle}")
    total = len(items) - cuenta[endurecer.NO_APLICA]
    print(f"\nEndurecimiento: {cuenta[endurecer.APLICADA]} de {total} medidas aplicadas · {cuenta[endurecer.PENDIENTE]} pendientes · {cuenta[endurecer.BLOQUEADA]} bloqueadas por seguridad")
    if a.accion in ("plan", "estado"):
        if cuenta[endurecer.PENDIENTE]:
            print(f"Nada se ha cambiado. Para aplicar lo pendiente (con copia de seguridad y reversión):  sudo sentinel endurecer aplicar --perfil {a.perfil}")
        return 0
    if not core.is_root():
        print("Necesita administrador: ejecuta  sudo sentinel endurecer aplicar", file=sys.stderr); return 1
    if not cuenta[endurecer.PENDIENTE]:
        print("No hay nada pendiente en este perfil."); return 0
    if not a.si and sys.stdin.isatty() and input(f"\n¿Aplicar las {cuenta[endurecer.PENDIENTE]} medidas pendientes? Se guarda una copia y se puede deshacer. [s/N]: ").strip().lower() not in ("s", "si", "sí", "y"):
        print("No se cambió nada."); return 0
    r = endurecer.aplicar(items, alerter=core.Alerter(core.load_config()))
    for x in r["aplicadas"]:
        print(col(f" ✔ aplicada: {x}", "ok"))
    for x, motivo in r["revertidas"]:
        print(col(f" ✖ se deshizo sola: {x} — {motivo}", "fallo"))
    for x, motivo in r["omitidas"]:
        print(f" – omitida: {x} — {motivo}")
    if r["carpeta"]:
        print(f"\nCopia de seguridad: {r['carpeta']}\nPara deshacerlo todo:  sudo sentinel endurecer revertir")
    return 0 if not r["revertidas"] else 1


def cmd_identidad(a) -> int:
    """MAC e IP del equipo en la red: `estado` (solo lectura), `rotar`, `restaurar`, `activar` y `desactivar`."""
    cfg = core.load_config()
    if a.accion == "rotar" and a.programado:                  # lo lanza el temporizador: sin preguntas
        if not core.is_root():
            print("Necesita administrador.", file=sys.stderr); return 1
        r = identidad.programada(cfg, core.Alerter(cfg))
        if r is not None:
            print(r["mensaje"])
        return 0 if r is None or r["ok"] else 1
    if a.accion in ("activar", "desactivar"):
        if not core.is_root():
            print(f"Necesita administrador: ejecuta  sudo sentinel identidad {a.accion}", file=sys.stderr); return 1
        al = core.Alerter(cfg)
        r = identidad.activar(cfg, a.cada or identidad.cada_horas(cfg), al) if a.accion == "activar" else identidad.desactivar(cfg, al)
        print(r["mensaje"], file=sys.stdout if r["ok"] else sys.stderr)
        return 0 if r["ok"] else 1
    if a.accion in ("rotar", "restaurar"):
        if not core.is_root():
            print(f"Necesita administrador: ejecuta  sudo sentinel identidad {a.accion}", file=sys.stderr); return 1
        if not a.si and sys.stdin.isatty() and input("La red se cortará unos segundos (y se cierran las conexiones abiertas, también SSH). ¿Seguir? [s/N]: ").strip().lower() not in ("s", "si", "sí", "y"):
            print("No se cambió nada."); return 0
        r = getattr(identidad, a.accion)(cfg, core.Alerter(cfg))
        print(r["mensaje"], file=sys.stdout if r["ok"] else sys.stderr)
        return 0 if r["ok"] else 1
    e = identidad.estado(cfg)
    if a.json:
        print(json.dumps(e, ensure_ascii=False, indent=1)); return 1 if e["error"] else 0
    if e["error"]:
        print(e["error"], file=sys.stderr); return 1
    print(f"IDENTIDAD EN LA RED · {e['interfaz']}\n")
    print(f" MAC en uso:      {e['mac']}  ({'cambiada' if e['aleatoria'] else 'la de fábrica'})")
    print(f" MAC de fábrica:  {e['mac_fabrica']}")
    print(f" IP:              {e['ip'] or 'sin dirección'}  ({'automática por DHCP' if e['metodo'] == 'auto' else 'fija: no cambia al rotar'})")
    print(f" Puerta de salida: {e['puerta'] or 'ninguna'}")
    print(f" Nombre del equipo: {col('se envía a la red', 'aviso') if e['envia_nombre'] else col('no se envía', 'ok')}")
    print(f" Cambio programado: {'cada ' + str(e['cada_horas']) + ' h' if e['activo'] else 'apagado'}")
    if e["otros"]:
        print(col("\n Otros programas que también cambian la MAC o la IP:", "aviso"))
        for x in e["otros"]:
            print(f"   - {x}")
    if not e["cron_revisado"]:
        print("\n No pude revisar las tareas programadas de root: ejecuta  sudo sentinel identidad estado")
    return 0


def _hay_servicios() -> bool:
    return plataforma.ES_MAC or bool(shutil.which("systemctl"))


def _smtp_reiniciar_monitor() -> None:
    """El monitor lee la configuración al arrancar: lo reinicia (ya se demostró el PIN, así que no es un «intento de detener»)."""
    if core.is_root() and _hay_servicios() and core.conf_path() == "/etc/sentinel/sentinel.conf":
        pin.authorize_stop()
        servicio.reiniciar_monitor()


def cmd_smtp(a) -> int:
    """Correo por SMTP: estado, configurar, importar de un ~/.msmtprc, probar y quitar. La contraseña va a /etc/sentinel/smtp.pass (solo root), no a sentinel.conf."""
    cfg = core.load_config()
    if a.accion == "estado":
        e = mailer.estado(cfg)
        print(f"SMTP: {'activo' if e['enabled'] else 'apagado'} · servidor {e['host'] or '—'}:{e['port']} ({e['security']}) · usuario {e['user'] or '—'} · remitente {e['sender'] or '—'}")
        print(f"Destinatarios: {', '.join(e['to']) or '—'} · contraseña: {e['password']} ({e['secret']})")
        print("Listo para enviar." if e["ok"] else "Falta configurarlo: sudo sentinel smtp configurar")
        return 0 if e["ok"] else 1
    if a.accion == "probar":
        ok, msg = mailer.test(cfg)
        print(msg)
        return 0 if ok else 1
    if not core.is_root():
        print("Necesita administrador: ejecuta  sudo sentinel smtp " + a.accion, file=sys.stderr)
        return 1
    if a.accion == "quitar":
        core.set_setting("smtp", "enabled", "no")
        mailer.clear_password()
        print("SMTP desactivado y contraseña borrada.")
        _smtp_reiniciar_monitor()
        return 0
    s = mailer.settings(cfg)
    if a.accion == "importar":
        try:
            v = mailer.from_msmtp(a.desde)
        except OSError as e:
            print(f"No pude leer {a.desde}: {e.strerror or e}", file=sys.stderr); return 1
        clave = v.pop("password")
        if not v["host"]:
            print("En ese archivo no encontré «host»: nada que importar.", file=sys.stderr); return 1
    else:
        ask = lambda texto, actual: (input(f"{texto} [{actual}]: ").strip() or str(actual)) if sys.stdin.isatty() else str(actual)
        v = {"host": a.host or ask("Servidor SMTP", s["host"]), "port": str(a.puerto or ask("Puerto (587 starttls, 465 ssl)", s["port"])),
             "security": a.seguridad or ask("Seguridad (starttls, ssl, none)", s["security"]), "user": a.usuario if a.usuario is not None else ask("Usuario", s["user"]),
             "sender": a.de or ask("Remitente (vacío = el usuario)", s["sender"])}
        if a.password_stdin:
            clave = pin.next_stdin_line() if a.pin_stdin else sys.stdin.readline().strip("\r\n")        # desde el panel llega tras el PIN, por la misma entrada
        elif sys.stdin.isatty() and v["user"]:
            import getpass
            clave = getpass.getpass("Contraseña (con Gmail, una «contraseña de aplicación»; no se muestra): ")
        else:
            clave = ""
    para = a.para if a.para is not None else (",".join(s["to"]) or (input("Destinatarios, separados por coma: ").strip() if sys.stdin.isatty() else ""))
    if any(h in v["host"] for h in ("gmail.com", "googlemail.com")):
        clave = clave.replace(" ", "")                           # Google las muestra en grupos de 4 con espacios: no son parte de la contraseña
    try:
        for k in ("host", "port", "security", "user", "sender"):
            core.set_setting("smtp", k, str(v[k]))
        core.set_setting("smtp", "to", para)
        core.set_setting("smtp", "enabled", "yes")
        if clave:
            mailer.set_password(clave)
    except (ValueError, OSError) as e:
        print("No se guardó:", e, file=sys.stderr); return 1
    print("Guardado. Probando el envío…")
    _smtp_reiniciar_monitor()
    ok, msg = mailer.test(core.load_config())
    print(msg)
    return 0 if ok else 1


def cmd_ia(a) -> int:
    """Asistente de IA: estado, configurar, probar, quitar. La clave de la API va a /etc/sentinel/ia.key (no a sentinel.conf)."""
    cfg = core.load_config()
    if a.accion == "estado":
        e = ia.estado(cfg)
        print(f"IA: {'activa' if e['enabled'] else 'apagada'} · modo {e['modo']}" + (f" · modelo local {e['local_modelo'] or '(el primero instalado)'} en {e['local_url']}" if e["modo"] == "local" else f" · {e['proveedor']} · modelo {e['api_modelo']} · clave: {e['clave']}"))
        print("Solo explica las detecciones; nunca ejecuta nada. " + ia.AVISO)
        return 0 if e["ok"] else 1
    if a.accion == "probar":
        ok, msg = ia.probar(cfg)
        print(msg)
        return 0 if ok else 1
    if not core.is_root():
        print("Necesita administrador: ejecuta  sudo sentinel ia " + a.accion, file=sys.stderr)
        return 1
    if a.accion == "quitar":
        core.set_setting("ia", "enabled", "no"); ia.quitar_clave()
        print("Asistente de IA apagado y clave borrada.")
        return 0
    pares = {"modo": a.modo, "local_url": a.local_url, "local_modelo": a.local_modelo, "proveedor": a.proveedor, "api_url": a.api_url, "api_modelo": a.api_modelo}
    try:
        for k, v in pares.items():
            if v is not None:
                core.set_setting("ia", k, v)
        if a.key_stdin:
            k = pin.next_stdin_line() if a.pin_stdin else sys.stdin.readline().strip("\r\n")
            if k:
                ia.set_clave(k)
        core.set_setting("ia", "enabled", "yes")
    except (ValueError, OSError) as e:
        print("No se guardó:", e, file=sys.stderr); return 1
    cfg = core.load_config()
    if cfg.get("ia", "modo") == "api" and not ia.clave_presente():
        print("Guardado, pero falta la clave de la API: sin ella la IA usará la explicación fija.")
        return 1
    print("Guardado. Probando…")
    ok, msg = ia.probar(cfg)
    print(msg)
    return 0 if ok else 1


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
    avisador = "osascript" if plataforma.ES_MAC else "notify-send"
    print("Escritorio disponible:", ok(al.desktop_target() is not None and shutil.which(avisador) is not None), "(deberías ver una notificación)")
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
    print(f"Guardado ({changed} ajuste{'s' if changed != 1 else ''}). Los avisos nuevos usan los valores de inmediato; el monitor los lee al reiniciar: " + ("sudo sentinel detener && sudo sentinel iniciar" if plataforma.ES_MAC else "sudo systemctl restart sentinel-monitor"))
    if core.is_root() and _hay_servicios() and core.conf_path() == "/etc/sentinel/sentinel.conf":      # solo con la configuración real del sistema
        servicio.reiniciar_monitor()
    return 0


def cmd_senuelos(a) -> int:
    if plataforma.ES_MAC:
        print("Los señuelos todavía no están disponibles en macOS: están apagados."); return 0 if a.accion == "estado" else 1
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
    return ((n == "cmd_endurecer" and a.accion in ("aplicar", "revertir")) or (n == "cmd_identidad" and (a.accion in ("restaurar", "activar", "desactivar") or (a.accion == "rotar" and not a.programado))) or (n == "cmd_smtp" and a.accion in ("configurar", "importar", "quitar")) or (n == "cmd_ia" and a.accion in ("configurar", "quitar")) or (n == "cmd_equipo" and (a.aceptar or a.horario)) or (n == "cmd_bans" and a.action == "unban") or (n == "cmd_senuelos" and a.accion == "desactivar") or (n == "cmd_update" and a.instalar)
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
    units = ["sentinel-monitor.service", "sentinel-honeypot.service", "sentinel-scan.timer", "sentinel-report.timer", "sentinel-equipo.timer"]
    if plataforma.ES_MAC:
        errores = servicio.detener()
        rc, out = (1 if errores else 0), "\n".join(errores)
    else:
        rc, out = core.run(["systemctl", "stop", *units], 60)
    core.Alerter(core.load_config()).emit("low", "pin", "detenido", "Sentinel fue detenido de forma autorizada (con el PIN)", key=f"stop:{int(core.now())}")
    pin.revoke_stop()
    print("Sentinel detenido. Para volver a encenderlo:  sudo sentinel iniciar" if rc == 0 else out.strip()); return 0 if rc == 0 else 1


def cmd_iniciar(a) -> int:
    if plataforma.ES_MAC:
        if not core.is_root():
            print("Necesita administrador: ejecuta  sudo sentinel iniciar", file=sys.stderr); return 1
        errores = servicio.iniciar()
        rc, out = (1 if errores else 0), "\n".join(errores)
    else:
        rc, out = core.run(["systemctl", "start", "sentinel-monitor.service", "sentinel-scan.timer", "sentinel-report.timer", "sentinel-equipo.timer"], 60)
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


def cmd_resumen(a) -> int:
    """Resumen corto y de solo lectura del estado de este equipo (lo consulta el panel de otro servidor por SSH)."""
    import socket
    from . import ui
    o = ui.Data().overview()
    fw = core.read_json(os.path.join(core.state_dir(), "firewall.json"), {}) or {}
    out = {"hostname": socket.gethostname(), "version": core.VERSION, "level": o["level"], "why": o["why"], "alive": o["alive"], "heartbeat_age": o["heartbeat_age"],
           "counts24": o["counts24"], "bans": len(o["bans"]), "firewall": {"backend": fw.get("backend"), "pendientes": len((fw.get("plan") or {}).get("remove", [])) + len((fw.get("plan") or {}).get("missing", [])), "docker_expuestos": fw.get("exposed_count")}}
    print(json.dumps(out, ensure_ascii=False))
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
    s = sub.add_parser("equipo", help="revisión completa del equipo con informe (y correo por SMTP)"); s.add_argument("--enviar", action="store_true", help="manda el informe por correo"); s.add_argument("--programado", action="store_true", help="modo del temporizador: guarda y manda solo si [equipo] enviar_correo = yes")
    s.add_argument("--aceptar", action="store_true", help="acepta los cambios de cuentas y persistencia de esta revisión como nueva referencia (pide el PIN)"); s.add_argument("--rapido", action="store_true", help="sin dpkg -V ni actualizaciones pendientes"); s.add_argument("--json", action="store_true")
    s.add_argument("--horario", metavar="HH:MM,HH:MM", help="cambia las horas a las que se genera y envía el informe (pide el PIN), por ejemplo 08:00,16:00,23:00"); s.set_defaults(fn=cmd_equipo)
    s = sub.add_parser("endurecer", help="endurecimiento guiado del equipo: plan (solo lectura), aplicar (con copia y comprobación), revertir"); s.add_argument("accion", nargs="?", default="plan", choices=["plan", "estado", "aplicar", "revertir"])
    s.add_argument("--perfil", default="recomendado", choices=list(endurecer.PERFILES), help="basico (sin efectos visibles), recomendado (CIS nivel 1) o estricto (servidores)"); s.add_argument("--solo", help="solo estas medidas, separadas por coma")
    s.add_argument("--si", action="store_true", help="no preguntar antes de aplicar"); s.add_argument("--tanda", help="revertir: carpeta de la tanda (por defecto la última)"); s.add_argument("--json", action="store_true"); s.set_defaults(fn=cmd_endurecer)
    s = sub.add_parser("identidad", help="MAC e IP del equipo en la red: estado, rotar (MAC e IP nuevas), restaurar, activar o desactivar el cambio programado"); s.add_argument("accion", nargs="?", default="estado", choices=["estado", "rotar", "restaurar", "activar", "desactivar"]); s.add_argument("--cada", type=int, help="activar: cada cuántas horas (1 a 168)"); s.add_argument("--programado", action="store_true", help="rotar: modo del temporizador (solo si está activado y toca)"); s.add_argument("--json", action="store_true"); s.add_argument("--si", action="store_true", help="no preguntar antes de cortar la red"); s.set_defaults(fn=cmd_identidad)
    s = sub.add_parser("requisitos", help="qué necesita Sentinel y qué tiene tu equipo (✔/✖); ofrece instalar lo que falta"); s.add_argument("--instalar", action="store_true", help="instala lo que falta (pregunta antes y pide tu contraseña de administrador)")
    s.add_argument("--si", action="store_true", help="instala sin preguntar (lo usa el panel)"); s.add_argument("--json", action="store_true"); s.set_defaults(fn=cmd_requisitos)
    s = sub.add_parser("smtp", help="correo por SMTP: estado, configurar, importar, probar, quitar"); s.add_argument("accion", choices=["estado", "configurar", "importar", "probar", "quitar"])
    s.add_argument("--host"); s.add_argument("--puerto", type=int); s.add_argument("--seguridad", choices=["starttls", "ssl", "none"]); s.add_argument("--usuario"); s.add_argument("--de", help="remitente"); s.add_argument("--para", help="destinatarios separados por coma")
    s.add_argument("--password-stdin", dest="password_stdin", action="store_true", help="lee la contraseña de la entrada estándar (no queda en el historial)"); s.add_argument("--desde", default="", metavar="RUTA", help="importar: ruta de un ~/.msmtprc"); s.set_defaults(fn=cmd_smtp)
    s = sub.add_parser("ia", help="asistente de IA que explica las detecciones: estado, configurar, probar, quitar"); s.add_argument("accion", choices=["estado", "configurar", "probar", "quitar"])
    s.add_argument("--modo", choices=["local", "api"]); s.add_argument("--local-url", dest="local_url"); s.add_argument("--local-modelo", dest="local_modelo"); s.add_argument("--proveedor", choices=["anthropic", "openai"])
    s.add_argument("--api-url", dest="api_url"); s.add_argument("--api-modelo", dest="api_modelo"); s.add_argument("--key-stdin", dest="key_stdin", action="store_true", help="lee la clave de la API de la entrada estándar"); s.set_defaults(fn=cmd_ia)
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
    s = sub.add_parser("resumen", help="resumen de solo lectura de este equipo (para el panel de otro servidor)"); s.add_argument("--json", action="store_true"); s.set_defaults(fn=cmd_resumen)
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
