"""Informe de actividad: resumen en HTML de los eventos de los últimos días y de la auditoría."""
from __future__ import annotations

import collections
import html
import os
import re
import time

from . import audit, core


def lynis_index(run_lynis: bool = False) -> int | None:
    """Índice de endurecimiento de Lynis (si hay permisos y la herramienta, la ejecuta; si no, lee la última corrida)."""
    p = os.path.join(core.state_dir(), "lynis.json")
    hist = core.read_json(p, []) or []
    if run_lynis and core.is_root():
        rc, out = core.run(["lynis", "audit", "system", "--quick", "--no-colors"], 900)
        m = re.search(r"Hardening index\s*:\s*(\d+)", out)
        if m:
            hist.append({"date": core.iso(), "index": int(m.group(1))})
            core.atomic_write_json(p, hist[-60:])
    return hist[-1]["index"] if hist else None


def build(days: int = 7, run_lynis: bool = False, cfg=None) -> str:
    cfg = cfg or core.load_config()
    since = core.now() - days * 86400
    ev = core.read_events(since)
    au = audit.run_audit(cfg)
    by_sev = collections.Counter(e["sev"] for e in ev)
    by_kind = collections.Counter(f"{e['source']}/{e['kind']}" for e in ev)
    ips = collections.Counter(e["data"].get("ip") for e in ev if e.get("data", {}).get("ip"))
    day = collections.Counter(e["ts"][:10] for e in ev)
    li = lynis_index(run_lynis)
    esc = html.escape
    rows = lambda c, n=10: "".join(f"<tr><td>{esc(str(k))}</td><td>{v}</td></tr>" for k, v in c.most_common(n)) or "<tr><td colspan=2>sin datos</td></tr>"
    audit_rows = "".join(f"<tr class='{r['status']}'><td>{esc(r['title'])}</td><td>{r['status']}</td><td>{esc(r['detail'])}<br><small>{esc(r['fix'])}</small></td></tr>" for r in au["checks"])
    top = [e for e in ev if core.SEV[e["sev"]] >= 3][-15:]
    top_rows = "".join(f"<tr class='{e['sev']}'><td>{e['ts'][:16]}</td><td>{core.SEV_ES[e['sev']]}</td><td>{esc(e['msg'])}</td></tr>" for e in reversed(top)) or "<tr><td colspan=3>Sin eventos de gravedad alta en el período</td></tr>"
    return f"""<!doctype html><meta charset=utf-8><title>Informe Sentinel</title><style>
body{{font:15px system-ui,sans-serif;max-width:980px;margin:2rem auto;padding:0 1rem;color:#1d1d1b}}h1{{color:#00629b}}table{{border-collapse:collapse;width:100%;margin:.5rem 0 1.5rem}}
td,th{{border-bottom:1px solid #e8eaed;padding:.4rem .6rem;text-align:left;vertical-align:top}}.k{{display:flex;gap:1rem;flex-wrap:wrap}}.k div{{flex:1;min-width:130px;background:#f0f8fd;border-radius:12px;padding:.8rem}}
.k b{{display:block;font-size:1.8rem;color:#00629b}}tr.fallo td,tr.critical td{{background:#fdecea}}tr.aviso td,tr.high td{{background:#fff6e8}}small{{color:#4a5568}}</style>
<h1>Informe de Sentinel · últimos {days} días</h1><p>Generado el {core.iso()} · versión {core.VERSION}</p>
<div class=k><div><b>{len(ev)}</b>eventos</div><div><b>{by_sev.get('critical', 0) + by_sev.get('high', 0)}</b>alta o crítica</div><div><b>{au['score']}/100</b>postura de seguridad</div><div><b>{li if li is not None else '—'}</b>índice Lynis</div></div>
<h2>Eventos graves recientes</h2><table>{top_rows}</table>
<h2>Por tipo</h2><table>{rows(by_kind)}</table><h2>IPs más activas</h2><table>{rows(ips)}</table><h2>Por día</h2><table>{rows(day, 14)}</table>
<h2>Postura de seguridad</h2><table>{audit_rows}</table>"""


def save(days: int = 7, run_lynis: bool = False) -> str:
    d = os.path.join(core.state_dir(), "reports")
    core.ensure_dir(d, 0o750)
    p = os.path.join(d, f"informe-{time.strftime('%Y%m%d-%H%M')}.html")
    with open(p, "w", encoding="utf-8") as f:
        f.write(build(days, run_lynis))
    return p
