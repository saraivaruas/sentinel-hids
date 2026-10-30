"use strict";
// Panel de Sentinel. Todo texto que viene de los eventos se inserta con textContent (nunca como HTML): puede contener datos de un atacante.
(() => {
  const $ = (s, r = document) => r.querySelector(s);
  const SEV = ["info", "low", "medium", "high", "critical"];
  const SEV_ES = { info: "info", low: "baja", medium: "media", high: "alta", critical: "crítica" };
  const SEV_COL = { info: "var(--s-info)", low: "var(--s-low)", medium: "var(--s-medium)", high: "var(--s-high)", critical: "var(--s-critical)" };
  const NS = "http://www.w3.org/2000/svg";
  const st = { view: "resumen", ov: null, seen: new Set(), first: true, minSev: "info", auditFilter: "todo", installed: true };

  function el(tag, cls, text, attrs) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    if (attrs) for (const k in attrs) e.setAttribute(k, attrs[k]);
    return e;
  }
  function svg(tag, attrs, text) {
    const e = document.createElementNS(NS, tag);
    for (const k in attrs) e.setAttribute(k, attrs[k]);
    if (text != null) e.textContent = text;
    return e;
  }
  const clear = (n) => { while (n.firstChild) n.removeChild(n.firstChild); };
  const nf = new Intl.NumberFormat("es-CL");
  const hhmmss = (t) => new Date(t * 1000).toLocaleTimeString("es-CL", { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
  const when = (t) => new Date(t * 1000).toLocaleString("es-CL", { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit", hour12: false });
  function ago(sec) {
    if (sec < 60) return "hace " + Math.max(0, Math.round(sec)) + " s";
    if (sec < 3600) return "hace " + Math.round(sec / 60) + " min";
    if (sec < 86400) return "hace " + Math.round(sec / 3600) + " h";
    return "hace " + Math.round(sec / 86400) + " d";
  }
  function left(sec) { return sec <= 0 ? "caducado" : sec >= 3600 ? Math.floor(sec / 3600) + " h " + Math.round((sec % 3600) / 60) + " min" : Math.round(sec / 60) + " min"; }

  async function api(path, body) {
    const r = await fetch(path, body ? { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) } : undefined);
    if (r.status === 403) { document.body.textContent = "Sesión no válida: abre el panel con el comando «sentinel ui»."; throw new Error("403"); }
    return r.json();
  }
  function toast(msg, err) {
    const t = el("div", "toast" + (err ? " err" : ""), msg);
    $("#toasts").appendChild(t);
    setTimeout(() => t.remove(), err ? 9000 : 6000);
  }
  function confirmDlg(title, text, okLabel) {
    return new Promise((res) => {
      const d = $("#dlg");
      $("#dlg-t").textContent = title; $("#dlg-p").textContent = text; $("#dlg-ok").textContent = okLabel || "Confirmar";
      d.onclose = () => res(d.returnValue === "si");
      d.showModal();
    });
  }
  async function runAction(name, extra, btn) {
    if (!st.installed) { toast("Sentinel aún no está instalado en el sistema. Ejecuta «sudo ./install.sh».", true); return null; }
    if (btn) { btn.disabled = true; btn.dataset.l = btn.textContent; btn.textContent = "Trabajando…"; }
    try {
      const r = await api("/api/action", Object.assign({ name }, extra || {}));
      toast((r.ok ? "✔ " : "✖ ") + (r.out || (r.ok ? "Listo" : "Falló")).slice(0, 700), !r.ok);
      refresh();
      return r;
    } catch (e) { toast("No se pudo completar la acción", true); return null; }
    finally { if (btn) { btn.disabled = false; btn.textContent = btn.dataset.l; } }
  }

  // ---------- navegación
  const TITLES = { resumen: ["Resumen", "Estado de la protección de este equipo"], eventos: ["Eventos", "Todo lo que Sentinel ha detectado"], bloqueos: ["Bloqueos", "Atacantes bloqueados y lista blanca"], postura: ["Postura de seguridad", "Qué tan bien configurado está el equipo"],
    atacantes: ["Atacantes", "Quién intentó entrar, de dónde viene y qué hizo"], paquetes: ["Paquetes", "Qué son y cuáles son peligrosos, explicado fácil"] };
  function go(v) {
    if (!TITLES[v]) v = "resumen";
    st.view = v;
    document.querySelectorAll(".view").forEach((s) => (s.hidden = s.id !== "view-" + v));
    document.querySelectorAll(".nav").forEach((b) => b.setAttribute("aria-current", b.dataset.view === v ? "page" : "false"));
    $("#title").textContent = TITLES[v][0]; $("#subtitle").textContent = TITLES[v][1];
    if (location.hash !== "#" + v) history.replaceState(null, "", "#" + v);
    if (v === "eventos") loadEvents();
    if (v === "postura") loadAudit();
    if (v === "atacantes") loadAttackers();
    if (v === "paquetes") loadPackets();
    window.scrollTo(0, 0);
  }

  // ---------- icono del estado y anillo
  const ICONS = {
    protegido: "M12 3 4 6v6c0 5 3.4 8 8 9 4.6-1 8-4 8-9V6z M9 12l2 2 4-4",
    revision: "M12 3 4 6v6c0 5 3.4 8 8 9 4.6-1 8-4 8-9V6z M12 8v5 M12 16.5v.01",
    atencion: "M12 3 4 6v6c0 5 3.4 8 8 9 4.6-1 8-4 8-9V6z M12 8v5 M12 16.5v.01",
    peligro: "M12 3 4 6v6c0 5 3.4 8 8 9 4.6-1 8-4 8-9V6z M9 9l6 6 M15 9l-6 6",
  };
  const TXT = { protegido: "Protegido", revision: "Para revisar", atencion: "Requiere atención", peligro: "Posible intrusión" };
  function ring(target, pct, color, size) {
    clear(target);
    const r = 52, c = 2 * Math.PI * r;
    target.setAttribute("viewBox", "0 0 120 120");
    target.appendChild(svg("circle", { cx: 60, cy: 60, r, fill: "none", stroke: "currentColor", "stroke-opacity": ".13", "stroke-width": 9 }));
    const arc = svg("circle", { cx: 60, cy: 60, r, fill: "none", stroke: color, "stroke-width": 9, "stroke-linecap": "round", "stroke-dasharray": (c * pct) / 100 + " " + c, transform: "rotate(-90 60 60)" });
    target.appendChild(arc);
  }

  // ---------- Resumen
  function renderHero(o) {
    const h = $("#hero");
    h.className = "hero " + o.level;
    $("#hero-eyebrow").textContent = o.alive ? "SENTINEL ACTIVO" : "SENTINEL SIN RESPUESTA";
    $("#hero-h").textContent = TXT[o.level];
    $("#hero-p").textContent = o.why + (o.heartbeat_age != null ? " · último latido " + ago(o.heartbeat_age) : "");
    ring($("#hero-ring"), o.level === "protegido" ? 100 : o.level === "revision" ? 75 : o.level === "atencion" ? 50 : 30, "var(--lv)");
    const ic = $("#hero-icon"); clear(ic); ic.appendChild(svg("path", { d: ICONS[o.level] }));
    const mini = $("#mini"); mini.className = "mini " + (o.alive ? "ok" : "bad");
    $("#mini-t").textContent = o.alive ? "Monitor activo" : "Monitor detenido";
    const lv = $("#live"); lv.classList.toggle("off", !o.alive);
  }
  function renderKpis(o) {
    $("#k-crit").textContent = nf.format(o.counts24.critical);
    $("#k-high").textContent = nf.format(o.counts24.high);
    $("#k-med").textContent = nf.format(o.counts24.medium);
    $("#k-ban").textContent = nf.format(o.bans.length);
    $("#k-fim").textContent = o.baseline ? nf.format(o.baseline.count) : "—";
    $("#k-fim-s").textContent = o.baseline ? "referencia del " + o.baseline.created.slice(0, 10) : "referencia sin crear";
    const nb = $("#nav-bans"); nb.hidden = !o.bans.length; nb.textContent = o.bans.length;
    const hi = o.counts24.high + o.counts24.critical, ne = $("#nav-ev"); ne.hidden = !hi; ne.textContent = hi;
  }
  function renderLegend() {
    const lg = $("#legend"); if (lg.firstChild) return;
    ["critical", "high", "medium", "low", "info"].forEach((s) => { const sp = el("span", null, SEV_ES[s]); const i = el("i"); i.style.setProperty("--c", SEV_COL[s]); sp.prepend(i); lg.appendChild(sp); });
  }
  function renderChart(o) {
    const box = $("#chart"); clear(box);
    const W = 720, H = 300, L = 34, B = 26, T = 8, bw = (W - L) / 24;
    const tot = o.hours.map((h) => SEV.reduce((s, k) => s + h.c[k], 0));
    const max = Math.max(4, ...tot), top = Math.ceil(max / 4) * 4;
    const s = svg("svg", { viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": "Eventos por hora en las últimas 24 horas" });
    for (let i = 0; i <= 4; i++) {
      const y = T + ((H - B - T) * i) / 4;
      s.appendChild(svg("line", { x1: L, x2: W, y1: y, y2: y, stroke: "currentColor", "stroke-opacity": ".1" }));
      s.appendChild(svg("text", { x: L - 6, y: y + 4, "text-anchor": "end" }, String(Math.round(top - (top * i) / 4))));
    }
    o.hours.forEach((h, i) => {
      const g = svg("g", { class: "col" });
      let y = H - B;
      ["info", "low", "medium", "high", "critical"].forEach((k) => {
        const n = h.c[k]; if (!n) return;
        const ht = (n / top) * (H - B - T);
        g.appendChild(svg("rect", { class: "bar", x: L + i * bw + 3, y: y - ht, width: bw - 6, height: ht, rx: 3, fill: SEV_COL[k] }));
        y -= ht + 1;
      });
      const hit = svg("rect", { x: L + i * bw, y: T, width: bw, height: H - B - T, fill: "transparent" });
      hit.addEventListener("mousemove", (e) => tip(e, h, tot[i]));
      hit.addEventListener("mouseleave", () => ($("#tip").hidden = true));
      g.appendChild(hit);
      if (i % 4 === 0 || i === 23) s.appendChild(svg("text", { x: L + i * bw + bw / 2, y: H - 8, "text-anchor": "middle" }, new Date(h.t * 1000).toLocaleTimeString("es-CL", { hour: "2-digit", minute: "2-digit", hour12: false })));
      s.appendChild(g);
    });
    if (!tot.some(Boolean)) s.appendChild(svg("text", { x: W / 2, y: H / 2, "text-anchor": "middle", "font-size": 14 }, "Sin eventos en las últimas 24 horas"));
    box.appendChild(s);
  }
  function tip(e, h, total) {
    const t = $("#tip"); clear(t); t.hidden = false;
    t.appendChild(el("b", null, new Date(h.t * 1000).toLocaleString("es-CL", { weekday: "short", hour: "2-digit", minute: "2-digit", hour12: false }) + " · " + total + " evento(s)"));
    ["critical", "high", "medium", "low", "info"].forEach((k) => { if (h.c[k]) { const d = el("div"); d.appendChild(el("span", null, SEV_ES[k])); d.appendChild(el("b", null, String(h.c[k]))); t.appendChild(d); } });
    t.style.left = Math.min(e.clientX + 14, innerWidth - 200) + "px"; t.style.top = e.clientY + 14 + "px";
  }
  const SVC = { "sentinel-monitor": "Monitor principal", "sentinel-honeypot": "Señuelos", "sentinel-scan.timer": "Revisión cada 30 min", "sentinel-report.timer": "Informe semanal" };
  function renderServices(o) {
    const ul = $("#svc"); clear(ul);
    Object.keys(SVC).forEach((k) => {
      const v = o.services[k] || "desconocido", ok = v === "active";
      const li = el("li"); li.appendChild(el("span", "n", SVC[k])); li.appendChild(el("em", ok ? "ok-b" : "bad-b", ok ? "activo" : v === "inactive" ? "inactivo" : v));
      ul.appendChild(li);
    });
  }
  function renderIps(o) {
    const ul = $("#ips"); clear(ul);
    if (!o.top_ips.length) { ul.appendChild(el("li", "empty", "Ninguna IP hostil en los últimos 7 días.")); return; }
    const m = o.top_ips[0].n;
    o.top_ips.forEach((x) => {
      const li = el("li"); li.appendChild(el("code", null, x.ip)); li.appendChild(el("span", null, x.n + " ev.")); li.appendChild(x.banned ? el("span", "badge sev-high", "bloqueada") : el("span"));
      const b = el("div", "bar-i"); const i = el("i"); i.style.width = (x.n / m) * 100 + "%"; b.appendChild(i); li.appendChild(b);
      ul.appendChild(li);
    });
  }
  function feedItem(e, now, isNew) {
    const li = el("li", isNew ? "new" : "");
    li.appendChild(el("time", null, hhmmss(e.epoch)));
    li.appendChild(el("span", "badge sev-" + e.sev, SEV_ES[e.sev]));
    const m = el("div", "m"); m.appendChild(el("span", null, e.msg)); m.appendChild(el("small", null, e.source + " · " + e.kind + " · " + ago(now - e.epoch)));
    li.appendChild(m);
    return li;
  }
  function renderFeed(o) {
    const ul = $("#feed"); clear(ul);
    const list = o.events.filter((e) => SEV.indexOf(e.sev) >= 1).slice(0, 12);
    if (!list.length) { ul.appendChild(el("li", "empty", "Sin eventos recientes. Todo tranquilo.")); }
    list.forEach((e) => { const k = e.epoch + e.key; const isNew = !st.first && !st.seen.has(k); ul.appendChild(feedItem(e, o.now, isNew)); });
    o.events.forEach((e) => st.seen.add(e.epoch + e.key));
    st.first = false;
  }
  function renderBans(o) {
    const body = $("#ban-body"); clear(body);
    $("#ban-empty").hidden = o.bans.length > 0;
    o.bans.forEach((b) => {
      const tr = el("tr"); tr.appendChild(el("td", "mono", b.ip)); tr.appendChild(el("td", "msg", b.reason)); tr.appendChild(el("td", null, b.backend)); tr.appendChild(el("td", null, left(b.left)));
      const td = el("td"); const bt = el("button", "btn sm", "Desbloquear");
      bt.addEventListener("click", async () => { if (await confirmDlg("Desbloquear IP", "¿Quitar el bloqueo a " + b.ip + "? Pedirá tu clave de administrador.", "Desbloquear")) runAction("unban", { ip: b.ip }, bt); });
      td.appendChild(bt); tr.appendChild(td); body.appendChild(tr);
    });
  }
  function render(o) {
    st.ov = o; st.installed = o.installed;
    $("#ver").textContent = "v" + o.version;
    renderHero(o); renderKpis(o); renderLegend(); renderChart(o); renderServices(o); renderIps(o); renderFeed(o); renderBans(o);
    $("#clock").textContent = new Date().toLocaleTimeString("es-CL", { hour: "2-digit", minute: "2-digit", hour12: false });
  }

  // ---------- Eventos
  function chips() {
    const c = $("#sev-chips"); clear(c);
    [["info", "Todo"], ["low", "Baja+"], ["medium", "Media+"], ["high", "Alta+"], ["critical", "Crítica"]].forEach(([k, l]) => {
      const b = el("button", "chip", l, { "aria-pressed": String(st.minSev === k) });
      b.addEventListener("click", () => { st.minSev = k; chips(); loadEvents(); });
      c.appendChild(b);
    });
  }
  let evTimer = 0;
  async function loadEvents() {
    const q = new URLSearchParams({ hours: $("#f-hours").value, min: st.minSev, q: $("#f-q").value, limit: 300 });
    const list = await api("/api/events?" + q);
    const body = $("#ev-body"); clear(body);
    $("#ev-empty").hidden = list.length > 0;
    list.forEach((e) => {
      const tr = el("tr", "row");
      tr.appendChild(el("td", "mono", when(e.epoch)));
      const t = el("td"); t.appendChild(el("span", "badge sev-" + e.sev, SEV_ES[e.sev])); tr.appendChild(t);
      tr.appendChild(el("td", null, e.source + "/" + e.kind));
      const d = el("td", "msg"); d.appendChild(el("div", null, e.msg)); tr.appendChild(d);
      let pre = null;
      tr.addEventListener("click", () => { if (pre) { pre.remove(); pre = null; } else { pre = el("pre", null, JSON.stringify(e.data || {}, null, 2) + "\nclave: " + e.key); d.appendChild(pre); } });
      body.appendChild(tr);
    });
  }

  // ---------- Postura
  async function loadAudit() {
    const a = await api("/api/audit");
    const sc = $("#score"); clear(sc);
    const s = svg("svg", {}); sc.appendChild(s);
    const v = a.score;
    ring(s, v == null ? 0 : v, v == null ? "var(--mu)" : v >= 80 ? "var(--ok)" : v >= 60 ? "var(--s-medium)" : "var(--s-high)");
    sc.appendChild(el("b", null, v == null ? "…" : String(v))); sc.appendChild(el("small", null, "de 100"));
    $("#score-p").textContent = a.running ? "Revisando el equipo… (puede tardar un minuto)" : a.checks.length + " revisiones · " + a.checks.filter((c) => c.status === "ok").length + " en orden";
    const f = $("#au-filter"); clear(f);
    [["todo", "Todo"], ["problemas", "Pendientes"]].forEach(([k, l]) => { const b = el("button", "chip", l, { "aria-pressed": String(st.auditFilter === k) }); b.addEventListener("click", () => { st.auditFilter = k; loadAudit(); }); f.appendChild(b); });
    const ul = $("#audit"); clear(ul);
    const order = { fallo: 0, aviso: 1, info: 2, ok: 3 };
    a.checks.slice().sort((x, y) => order[x.status] - order[y.status]).filter((c) => st.auditFilter === "todo" || c.status === "fallo" || c.status === "aviso").forEach((c) => {
      const li = el("li"); li.appendChild(el("div", "ic " + c.status, c.status === "ok" ? "✓" : c.status === "fallo" ? "!" : c.status === "aviso" ? "!" : "i"));
      const m = el("div"); m.appendChild(el("h4", null, c.title)); m.appendChild(el("p", null, c.detail));
      if (c.fix && (c.status === "fallo" || c.status === "aviso")) {
        const fx = el("div", "fix"); fx.appendChild(el("code", null, c.fix)); const cp = el("button", "btn sm", "Copiar");
        cp.addEventListener("click", () => { navigator.clipboard.writeText(c.fix).then(() => toast("Comando copiado")).catch(() => toast("No se pudo copiar", true)); });
        fx.appendChild(cp); m.appendChild(fx);
      }
      li.appendChild(m); li.appendChild(el("span", "badge sev-" + (c.status === "fallo" ? "critical" : c.status === "aviso" ? "medium" : c.status === "ok" ? "low" : "info"), c.status));
      ul.appendChild(li);
    });
    if (!ul.firstChild) ul.appendChild(el("li", "empty", a.running ? "Revisando…" : "Nada pendiente."));
    if (a.running) setTimeout(() => st.view === "postura" && loadAudit(), 3500);
  }


  // ---------- Atacantes
  const NIV = { bajo: ["🟢", "Poco peligroso", "low"], medio: ["🟡", "Para vigilar", "medium"], alto: ["🔴", "Peligroso", "critical"] };
  const KIND_ES = { ssh_clave: "Adivinar contraseñas", ssh_usuario_invalido: "Probar usuarios", ssh_llave: "Probar llaves", escaneo_puertos: "Revisar puertas", escaneo_syn: "Escaneo de puertos", escaneo_sigiloso: "Escaneo sigiloso", escaneo_udp: "Escaneo UDP", inundacion_syn: "Inundación de timbres", ping_masivo: "Ping masivo", senuelo: "Cayó en el señuelo" };
  const flag = (cc) => (cc && cc.length === 2 && /^[A-Za-z]+$/.test(cc)) ? String.fromCodePoint(...cc.toUpperCase().split("").map((c) => 127397 + c.charCodeAt(0))) : "🌐";
  let attSel = null, attTimer = 0, glossCache = null;
  async function glossary() { if (!glossCache) glossCache = await api("/api/glossary"); return glossCache; }

  function nivelBadge(n) { const x = NIV[n] || NIV.medio; return el("span", "badge sev-" + x[2], x[0] + " " + x[1]); }
  async function loadAttackers() {
    const q = new URLSearchParams({ q: $("#att-q").value, estado: $("#att-estado").value });
    const r = await api("/api/attackers?" + q);
    const st = $("#att-stats"); clear(st);
    if (r.stats) [["IPs registradas", r.stats.ips], ["Intentos", r.stats.attempts], ["Bloqueadas ahora", r.stats.blocked], ["Paquetes sospechosos", r.stats.packets]].forEach(([l, v]) => { const c = el("div", "chip-stat"); c.appendChild(el("b", null, nf.format(v || 0))); c.appendChild(el("span", null, l)); st.appendChild(c); });
    const ul = $("#att-list"); clear(ul);
    $("#att-empty").hidden = r.items.length > 0;
    const nb = $("#nav-att"); const bl = r.items.filter((x) => x.estado === "bloqueada").length; nb.hidden = !bl; nb.textContent = bl;
    r.items.forEach((x) => {
      const li = el("li", "att" + (x.ip === attSel ? " sel" : ""), null, { tabindex: "0", role: "button" });
      li.appendChild(el("span", "att-flag", flag(x.codigo)));
      const m = el("div", "att-m"); m.appendChild(el("b", "mono", x.ip)); m.appendChild(el("small", null, x.lugar));
      m.appendChild(el("small", null, nf.format(x.intentos) + " intentos · " + ago(r.stats ? core_now() - x.ultima : 0)));
      li.appendChild(m);
      const rt = el("div", "att-r"); rt.appendChild(nivelBadge(x.nivel)); rt.appendChild(el("small", x.estado === "bloqueada" ? "bl" : "", x.estado === "bloqueada" ? "bloqueada" : x.estado));
      li.appendChild(rt);
      const open = () => { attSel = x.ip; loadAttackers(); showAttacker(x.ip); };
      li.addEventListener("click", open); li.addEventListener("keydown", (e) => { if (e.key === "Enter") open(); });
      ul.appendChild(li);
    });
    if (attSel) showAttacker(attSel, true);
  }
  const core_now = () => Date.now() / 1000;

  function infoBox(items) {
    const box = el("div", "info");
    items.forEach(([k, v]) => { const r = el("p"); r.appendChild(el("b", null, k.endsWith("?") ? k + " " : k + ": ")); r.appendChild(document.createTextNode(v)); box.appendChild(r); });
    return box;
  }
  async function showAttacker(ip, silent) {
    const r = await api("/api/attacker?ip=" + encodeURIComponent(ip)).catch(() => null);
    const box = $("#att-det");
    if (!r || r.error) { if (!silent) { clear(box); box.appendChild(el("p", "empty", "Sin expediente para esa IP.")); } return; }
    const d = r.dossier, e = r.explicacion, g = d.ip;
    clear(box);
    const head = el("div", "det-h");
    head.appendChild(el("span", "det-flag", flag(g.country_code)));
    const t = el("div", "det-t"); t.appendChild(el("h2", "mono", g.ip)); t.appendChild(el("p", null, e.donde)); head.appendChild(t);
    const sc = el("div", "det-score"); const sv = svg("svg", {}); ring(sv, e.puntaje, e.nivel === "alto" ? "var(--s-critical)" : e.nivel === "medio" ? "var(--s-medium)" : "var(--ok)"); sc.appendChild(sv); sc.appendChild(el("b", null, String(e.puntaje))); head.appendChild(sc);
    box.appendChild(head);
    const acts = el("div", "det-a"); acts.appendChild(nivelBadge(e.nivel));
    const blocked = d.bans.some((b) => !b.released_at && b.until > core_now());
    if (blocked) { const b = el("button", "btn sm", "Liberar esta IP"); b.addEventListener("click", async () => { if (await confirmDlg("Liberar IP", "¿Quitar el bloqueo a " + g.ip + "? Podrá volver a conectarse. Pedirá tu clave de administrador.", "Liberar")) runAction("unban", { ip: g.ip }, b).then(() => setTimeout(() => showAttacker(g.ip), 800)); }); acts.appendChild(b); }
    else { const b = el("button", "btn sm primary", "Bloquear 24 horas"); b.addEventListener("click", async () => { if (await confirmDlg("Bloquear IP", "¿Bloquear " + g.ip + " durante 24 horas? Pedirá tu clave de administrador.", "Bloquear")) runAction("ban", { ip: g.ip, horas: 24, motivo: "bloqueo manual desde el panel" }, b).then(() => setTimeout(() => showAttacker(g.ip), 800)); }); acts.appendChild(b); }
    const cp = el("button", "btn sm", "Copiar IP"); cp.addEventListener("click", () => navigator.clipboard.writeText(g.ip).then(() => toast("IP copiada")).catch(() => toast("No se pudo copiar", true))); acts.appendChild(cp);
    box.appendChild(acts);
    e.bloques.forEach((b) => {
      const sec = el("section", "blk"); sec.appendChild(el("h3", null, b.titulo));
      if (b.texto) sec.appendChild(el("p", null, b.texto));
      (b.items || []).forEach((i) => {
        const c = el("div", "kid"); const h = el("div", "kid-h"); h.appendChild(el("b", null, i.nombre)); h.appendChild(el("em", null, "×" + nf.format(i.veces))); h.appendChild(nivelBadge(i.nivel)); c.appendChild(h);
        c.appendChild(infoBox([["Qué es", i.nino], ["Para qué sirve", i.sirve], ["¿Es peligroso?", i.peligro]] ));
        if (i.puertos && i.puertos.length) c.appendChild(el("small", "mu", "Puertas: " + i.puertos.join(", ")));
        sec.appendChild(c);
      });
      box.appendChild(sec);
    });
    const rec = el("section", "blk rec"); rec.appendChild(el("h3", null, "¿Qué puedes hacer?")); const ul = el("ul"); e.recomendaciones.forEach((x) => ul.appendChild(el("li", null, x))); rec.appendChild(ul); box.appendChild(rec);
    const det = el("details", "tech"); det.appendChild(el("summary", null, "Ver los datos técnicos (para quien sabe del tema)"));
    const tl = el("table", "tbl"); const th = el("thead"); const tr = el("tr"); ["Hora", "Tipo", "Usuario", "Puerto", "Veces", "Detalle"].forEach((x) => tr.appendChild(el("th", null, x))); th.appendChild(tr); tl.appendChild(th);
    const tb = el("tbody"); d.timeline.forEach((x) => { const r2 = el("tr"); [when(x.ts), KIND_ES[x.kind] || x.kind, x.user || "—", x.port ? x.port + "/" + (x.proto || "tcp") : "—", x.n, x.detail || ""].forEach((v, i) => r2.appendChild(el("td", i === 5 ? "msg" : i === 0 ? "mono" : "", String(v)))); tb.appendChild(r2); }); tl.appendChild(tb);
    det.appendChild(el("h4", null, "Línea de tiempo")); det.appendChild(tl);
    if (d.bans.length) { det.appendChild(el("h4", null, "Historial de bloqueos")); const bt = el("table", "tbl"); const bh = el("thead"); const br = el("tr"); ["Desde", "Hasta", "Liberada", "Por", "Motivo", "Motor"].forEach((x) => br.appendChild(el("th", null, x))); bh.appendChild(br); bt.appendChild(bh); const bb = el("tbody"); d.bans.forEach((x) => { const r3 = el("tr"); [when(x.ts), when(x.until), x.released_at ? when(x.released_at) : "—", x.released_by || (x.manual ? "manual" : "automático"), x.reason || "", x.backend || ""].forEach((v) => r3.appendChild(el("td", null, v))); bb.appendChild(r3); }); bt.appendChild(bb); det.appendChild(bt); }
    box.appendChild(det);
  }

  // ---------- Paquetes
  async function loadPackets() {
    const gl = await glossary();
    const cards = $("#pk-cards"); if (!cards.firstChild) {
      Object.keys(gl.paquetes).filter((k) => k !== "otro").forEach((k) => { const t = gl.paquetes[k]; const c = el("div", "kid"); const h = el("div", "kid-h"); h.appendChild(el("b", null, t.nombre)); h.appendChild(nivelBadge(t.nivel)); c.appendChild(h); c.appendChild(infoBox([["Qué es", t.nino], ["Para qué sirve", t.sirve], ["¿Es peligroso?", t.peligro]])); cards.appendChild(c); });
      const tp = $("#pk-tipos"); Object.keys(gl.tipos).forEach((k) => { const t = gl.tipos[k]; const c = el("div", "kid"); const h = el("div", "kid-h"); h.appendChild(el("b", null, t.nombre)); h.appendChild(nivelBadge(t.nivel)); c.appendChild(h); c.appendChild(infoBox([["Qué es", t.nino], ["Para qué sirve", t.sirve], ["¿Es peligroso?", t.peligro]])); tp.appendChild(c); });
      const dl = $("#gloss"); gl.glosario.forEach(([k, v]) => { dl.appendChild(el("dt", null, k)); dl.appendChild(el("dd", null, v)); });
    }
    const r = await api("/api/packets");
    const lv = $("#pk-live"); lv.classList.toggle("off", !r.captura_viva);
    $("#pk-live-t").textContent = r.captura_viva ? "capturando · " + nf.format(r.captura.vistos) + " paquetes vistos" : "captura apagada (se usan los registros del cortafuegos)";
    const body = $("#pk-body"); clear(body); $("#pk-empty").hidden = r.recientes.length > 0;
    r.recientes.forEach((p) => { const tr = el("tr"); tr.appendChild(el("td", "mono", hhmmss(p.ts))); tr.appendChild(el("td", "mono", p.ip)); tr.appendChild(el("td", null, p.dport ? String(p.dport) : "—"));
      const td = el("td"); td.appendChild(nivelBadge(p.info.nivel)); td.appendChild(document.createTextNode(" " + p.info.nombre)); td.setAttribute("title", p.info.nino); tr.appendChild(td); body.appendChild(tr); });
  }

  // ---------- ciclo
  async function refresh() {
    try { render(await api("/api/overview")); } catch (e) { $("#mini").className = "mini bad"; $("#mini-t").textContent = "Sin conexión con el panel"; $("#live").classList.add("off"); }
  }
  document.querySelectorAll(".nav").forEach((b) => b.addEventListener("click", () => go(b.dataset.view)));
  document.querySelectorAll("[data-goto]").forEach((b) => b.addEventListener("click", () => go(b.dataset.goto)));
  document.querySelectorAll("[data-action]").forEach((b) => b.addEventListener("click", () => runAction(b.dataset.action, null, b)));
  $("#f-hours").addEventListener("change", loadEvents);
  $("#att-q").addEventListener("input", () => { clearTimeout(attTimer); attTimer = setTimeout(loadAttackers, 300); });
  $("#att-estado").addEventListener("change", loadAttackers);
  $("#f-q").addEventListener("input", () => { clearTimeout(evTimer); evTimer = setTimeout(loadEvents, 300); });
  $("#re-audit").addEventListener("click", async () => { await api("/api/audit/refresh", {}); loadAudit(); });
  $("#allow-form").addEventListener("submit", async (e) => { e.preventDefault(); const r = await runAction("allow", { tipo: $("#al-tipo").value, valor: $("#al-valor").value.trim() }); if (r && r.ok) $("#al-valor").value = ""; });
  $("#theme").addEventListener("click", () => { const t = document.documentElement.dataset.theme === "dark" ? "light" : "dark"; document.documentElement.dataset.theme = t; try { localStorage.setItem("sentinel-theme", t); } catch (e) { /* sin almacenamiento */ } });
  try { const t = localStorage.getItem("sentinel-theme"); if (t) document.documentElement.dataset.theme = t; else if (matchMedia("(prefers-color-scheme: light)").matches) document.documentElement.dataset.theme = "light"; } catch (e) { /* sin almacenamiento */ }
  chips();
  go(location.hash.slice(1) || "resumen");
  refresh();
  setInterval(() => { if (!document.hidden) { refresh(); if (st.view === "eventos" && !$("#f-q").value) loadEvents(); if (st.view === "atacantes" && !$("#att-q").value) loadAttackers(); if (st.view === "paquetes") loadPackets(); } }, 3000);
  setInterval(() => ($("#clock").textContent = new Date().toLocaleTimeString("es-CL", { hour: "2-digit", minute: "2-digit", hour12: false })), 15000);
})();
