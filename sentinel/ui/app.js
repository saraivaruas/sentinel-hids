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
  const NEEDS_PIN = new Set(["resolver", "normal", "aprender", "ajustes", "allow", "unban", "update", "baseline_accept", "fw_aplicar", "fw_config", "fw_config_varios", "pin_establecer", "pin_quitar"]);
  let pinCache = { v: "", until: 0 };
  function askPin() {
    return new Promise((res) => {
      const d = $("#pin-dlg"), i = $("#pin-dlg-in"); i.value = "";
      d.onclose = () => res(d.returnValue === "si" ? i.value : null);
      d.showModal(); setTimeout(() => i.focus(), 50);
    });
  }
  async function runAction(name, extra, btn) {
    const needs = st.pinSet && (NEEDS_PIN.has(name) || (name === "senuelos" && !(extra && extra.on)));
    if (needs && name !== "pin_establecer" && name !== "pin_quitar") {
      let p = Date.now() < pinCache.until ? pinCache.v : await askPin();
      if (p == null) return null;
      pinCache = { v: p, until: Date.now() + 90000 };
      extra = Object.assign({}, extra, { pin: p });
    } else if (st.pinSet && (name === "pin_establecer" || name === "pin_quitar")) {
      if (!extra || extra.pin == null) return null;
    } else if (name === "pin_establecer") { extra = Object.assign({ pin: "" }, extra); }
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

  // ---------- menú lateral (hamburguesa): se recoge a solo íconos; en pantallas angostas es un cajón
  const narrow = () => matchMedia("(max-width: 900px)").matches;
  function setSidebar(open, save) {
    const b = document.body;
    if (narrow()) b.classList.toggle("sb-open", open); else b.classList.toggle("sb-collapsed", !open);
    $("#burger").setAttribute("aria-expanded", String(open));
    if (save && !narrow()) { try { localStorage.setItem("sentinel-sb", open ? "1" : "0"); } catch (e) { /* sin almacenamiento: no pasa nada */ } }
  }
  $("#burger").addEventListener("click", () => setSidebar(narrow() ? !document.body.classList.contains("sb-open") : document.body.classList.contains("sb-collapsed"), true));
  $("#scrim").addEventListener("click", () => setSidebar(false));
  document.querySelectorAll(".nav").forEach((b) => { const t = b.querySelector("span"); if (t) b.setAttribute("title", t.textContent); });
  try { if (!narrow() && localStorage.getItem("sentinel-sb") === "0") setSidebar(false); } catch (e) { /* idem */ }
  // ---------- navegación
  const TITLES = { resumen: ["Resumen", "Estado de la protección de este equipo"], eventos: ["Eventos", "Todo lo que Sentinel ha detectado"], bloqueos: ["Bloqueos", "Atacantes bloqueados y lista blanca"], postura: ["Postura de seguridad", "Qué tan bien configurado está el equipo"],
    atacantes: ["Atacantes", "Quién intentó entrar, de dónde viene y qué hizo"], paquetes: ["Paquetes", "Qué son y cuáles son peligrosos, explicado fácil"],
    ajustes: ["Ajustes", "Señuelos, avisos y notificaciones"], servidores: ["Servidores", "El estado de Sentinel en tus otros servidores"], "fw-puertos": ["Firewall · Puertos", "Qué está abierto desde afuera y qué se cerraría"], "fw-reglas": ["Firewall · Reglas y ajustes", "Reglas actuales y puertos que quieres mantener abiertos"] };
  function go(v) {
    if (!TITLES[v]) v = "resumen";
    st.view = v;
    document.querySelectorAll(".view").forEach((s) => (s.hidden = s.id !== "view-" + v));
    document.querySelectorAll(".nav").forEach((b) => b.setAttribute("aria-current", b.dataset.view === v ? "page" : "false"));
    $("#title").textContent = TITLES[v][0]; $("#subtitle").textContent = TITLES[v][1];
    if (location.hash !== "#" + v) history.replaceState(null, "", "#" + v);
    if (narrow()) setSidebar(false);
    if (v.startsWith("fw-")) loadFirewall();
    if (v === "ajustes") loadSettings();
    if (v === "servidores") loadServers();
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
  // Mini-gráficas de 7 días en las tarjetas (área suave, sin números: el número grande ya es el dato)
  function renderSparks(o) {
    [["sp-crit", "critical"], ["sp-high", "high"], ["sp-med", "medium"]].forEach(([id, sev]) => {
      const s = $("#" + id); clear(s);
      const v = (o.days || []).map((d) => d.c[sev]), max = Math.max(1, ...v), n = v.length - 1;
      if (v.length < 2) return;
      const pts = v.map((y, i) => [(i / n) * 100, 26 - (y / max) * 22]);
      const line = pts.map((p, i) => (i ? "L" : "M") + p[0].toFixed(1) + " " + p[1].toFixed(1)).join(" ");
      s.appendChild(svg("path", { d: line + " L100 28 L0 28 Z", fill: SEV_COL[sev], "fill-opacity": ".16", stroke: "none" }));
      s.appendChild(svg("path", { d: line, fill: "none", stroke: SEV_COL[sev], "stroke-width": 1.8, "vector-effect": "non-scaling-stroke", "stroke-linejoin": "round" }));
      const t = svg("title", {}, "Últimos 7 días: " + v.join(" · ")); s.appendChild(t);
    });
  }
  // Dona: reparto por gravedad de las últimas 24 horas (cada porción con su nombre y número en la leyenda: nunca solo color)
  function renderDonut(o) {
    const box = $("#donut"), lg = $("#donut-l"); clear(box); clear(lg);
    const order = ["critical", "high", "medium", "low", "info"], total = order.reduce((a, k) => a + o.counts24[k], 0);
    const s = svg("svg", { viewBox: "0 0 120 120", role: "img", "aria-label": "Eventos por gravedad en las últimas 24 horas" });
    const r = 46, c = 2 * Math.PI * r; let off = 0;
    s.appendChild(svg("circle", { cx: 60, cy: 60, r, fill: "none", stroke: "currentColor", "stroke-opacity": ".1", "stroke-width": 14 }));
    if (total) order.forEach((k) => {
      const n = o.counts24[k]; if (!n) return;
      const len = (n / total) * c, gap = total > n ? 2 : 0;
      s.appendChild(svg("circle", { cx: 60, cy: 60, r, fill: "none", stroke: SEV_COL[k], "stroke-width": 14, "stroke-dasharray": Math.max(0, len - gap) + " " + c, "stroke-dashoffset": -off, transform: "rotate(-90 60 60)" }, null));
      off += len;
    });
    s.appendChild(svg("text", { x: 60, y: 58, "text-anchor": "middle", class: "dn-n" }, nf.format(total)));
    s.appendChild(svg("text", { x: 60, y: 74, "text-anchor": "middle", class: "dn-l" }, "eventos"));
    box.appendChild(s);
    order.forEach((k) => {
      const li = el("li"); const i = el("i"); i.style.setProperty("--c", SEV_COL[k]); li.appendChild(i);
      li.appendChild(el("span", null, SEV_ES[k])); li.appendChild(el("b", null, nf.format(o.counts24[k])));
      lg.appendChild(li);
    });
  }
  // Barras horizontales: eventos por módulo (un solo color: aquí importa la cantidad, no la gravedad)
  function renderMods(o) {
    const ul = $("#mods"); clear(ul);
    if (!(o.modules || []).length) { ul.appendChild(el("li", "empty", "Sin eventos relevantes en las últimas 24 horas.")); return; }
    const NAMES = { fim: "Archivos", auth: "Accesos", host: "Equipo", web: "Sitio web", ban: "Bloqueos", decoy: "Señuelos", packets: "Paquetes", monitor: "Monitor", firewall: "Firewall", pin: "PIN", update: "Actualización", test: "Prueba" };
    const m = o.modules[0].n;
    o.modules.forEach((x) => {
      const li = el("li"); li.appendChild(el("span", "hb-n", NAMES[x.name] || x.name)); li.appendChild(el("b", null, nf.format(x.n)));
      const b = el("div", "hb-bar"); const i = el("i"); i.style.width = Math.max(3, (x.n / m) * 100) + "%"; b.appendChild(i); li.appendChild(b); ul.appendChild(li);
    });
  }
  function renderLegend() {
    const lg = $("#legend"); if (lg.firstChild) return;
    ["critical", "high", "medium", "low", "info"].forEach((s) => { const sp = el("span", null, SEV_ES[s]); const i = el("i"); i.style.setProperty("--c", SEV_COL[s]); sp.prepend(i); lg.appendChild(sp); });
  }
  function renderChart(o) {
    const box = $("#chart"); clear(box);
    const W = 720, H = 250, L = 34, B = 26, T = 8, bw = (W - L) / 24;
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
    renderHero(o); renderKpis(o); renderSparks(o); renderLegend(); renderChart(o); renderDonut(o); renderMods(o); renderServices(o); renderIps(o); renderFeed(o); renderBans(o);
    $("#clock").textContent = new Date().toLocaleTimeString("es-CL", { hour: "2-digit", minute: "2-digit", hour12: false });
  }

  // ---------- Eventos
  const SEVN = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
  function chips() {
    const c = $("#sev-chips"); clear(c);
    const all = st.evAll || [], mod = $("#f-mod").value;
    [["info", "Todo"], ["low", "Baja+"], ["medium", "Media+"], ["high", "Alta+"], ["critical", "Crítica"]].forEach(([k, l]) => {
      const n = all.filter((e) => SEVN[e.sev] >= SEVN[k] && (!mod || e.source === mod) && (!e.resolved || $("#f-res").checked)).length;
      const b = el("button", "chip", l + " · " + n, { "aria-pressed": String(st.minSev === k) });
      b.addEventListener("click", () => { st.minSev = k; renderEvents(); });
      c.appendChild(b);
    });
  }
  let evTimer = 0;
  async function loadEvents() {
    const q = new URLSearchParams({ hours: $("#f-hours").value, min: "info", q: $("#f-q").value, limit: 500 });
    st.evAll = await api("/api/events?" + q);
    const sel = $("#f-mod"), cur = sel.value, mods = [...new Set(st.evAll.map((e) => e.source))].sort();
    clear(sel); sel.appendChild(el("option", null, "Todos los módulos", { value: "" }));
    mods.forEach((m) => sel.appendChild(el("option", null, m, { value: m })));
    sel.value = mods.includes(cur) ? cur : "";
    renderEvents();
  }
  function renderEvents() {
    chips();
    const mod = $("#f-mod").value;
    const list = (st.evAll || []).filter((e) => SEVN[e.sev] >= SEVN[st.minSev] && (!mod || e.source === mod) && (!e.resolved || $("#f-res").checked));
    const body = $("#ev-body"); clear(body);
    $("#ev-empty").hidden = list.length > 0;
    list.forEach((e) => {
      const tr = el("tr", e.resolved ? "row done" : "row");
      tr.appendChild(el("td", "mono", when(e.epoch)));
      const t = el("td"); t.appendChild(el("span", "badge sev-" + e.sev, SEV_ES[e.sev])); tr.appendChild(t);
      tr.appendChild(el("td", null, e.source + "/" + e.kind));
      const d = el("td", "msg"); d.appendChild(el("div", null, e.msg)); tr.appendChild(d);
      let pre = null;
      let box = null;
      tr.addEventListener("click", (ev) => {
        if (ev.target.closest("button")) return;
        if (box) { box.remove(); box = null; return; }
        box = el("div", "ev-more"); box.appendChild(el("pre", null, JSON.stringify(e.data || {}, null, 2) + "\nclave: " + e.key));
        if (!e.resolved && SEVN[e.sev] >= 1) {
          const r = el("button", "btn sm", "Marcar como resuelto");
          r.title = "Deja de contar en el resumen y en los informes (sigue en el historial). Pide tu PIN y tu clave";
          r.addEventListener("click", async () => { const x = await runAction("resolver", { epoch: e.epoch, key: e.key }, r); if (x && x.ok) loadEvents(); });
          box.appendChild(r);
        }
        if (e.normal) {
          const b = el("button", "btn sm", "Esto es normal");
          b.title = "Lo acepta como normal para que no vuelva a avisar (pide tu PIN y tu clave)";
          b.addEventListener("click", async () => { const r = await runAction("normal", { epoch: e.epoch, key: e.key }, b); if (r && r.ok) loadEvents(); });
          box.appendChild(b);
        }
        d.appendChild(box);
      });
      body.appendChild(tr);
    });
  }

  // ---------- Servidores (varios Sentinel en un panel)
  async function loadServers() {
    const g = $("#srv-grid"); let r;
    try { r = await api("/api/servers"); } catch (e) { return; }
    clear(g); $("#srv-empty").hidden = r.servers.length > 0;
    const bad = r.servers.filter((s) => !s.ok || (s.data && (s.data.level === "peligro" || s.data.level === "atencion"))).length; const nb = $("#nav-srv"); nb.hidden = !bad; nb.textContent = String(bad);
    r.servers.forEach((s) => {
      const lv = s.ok ? s.data.level : "desconocido", c = el("div", "srv hero-" + lv);
      const h = el("div", "srv-h"); h.appendChild(el("b", null, s.name));
      h.appendChild(el("span", "badge sev-" + (lv === "protegido" ? "low" : lv === "revision" ? "medium" : lv === "desconocido" ? "info" : "critical"), s.ok ? TXT[lv] || lv : "Sin respuesta"));
      c.appendChild(h); c.appendChild(el("small", "mu", s.target));
      if (s.ok) {
        const d = s.data; c.appendChild(el("p", null, d.why));
        const k = el("div", "srv-k");
        [["Críticas", d.counts24.critical], ["Altas", d.counts24.high], ["Medias", d.counts24.medium], ["Bloqueadas", d.bans]].forEach(([l, n]) => { const x = el("div"); x.appendChild(el("b", null, nf.format(n))); x.appendChild(el("span", null, l)); k.appendChild(x); });
        c.appendChild(k);
        c.appendChild(el("small", "mu", (d.hostname || "") + " · Sentinel " + d.version + (d.heartbeat_age != null ? " · latido " + ago(d.heartbeat_age) : "") + (d.firewall && d.firewall.pendientes ? " · firewall: " + d.firewall.pendientes + " cambio(s) pendientes" : "")));
      } else c.appendChild(el("p", "srv-err", s.error));
      const b = el("button", "btn sm", "Quitar"); b.addEventListener("click", async () => { if (!(await confirmDlg("Quitar el servidor", "Se quita de esta lista; no se toca el servidor.", "Quitar"))) return; await api("/api/servers", { op: "remove", target: s.target }); loadServers(); });
      c.appendChild(b); g.appendChild(c);
    });
  }
  $("#srv-reload").addEventListener("click", loadServers);
  $("#srv-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const r = await api("/api/servers", { op: "add", name: $("#srv-name").value, target: $("#srv-target").value });
    toast((r.ok ? "✔ " : "✖ ") + r.out, !r.ok); if (r.ok) { $("#srv-form").reset(); loadServers(); }
  });

  // ---------- Ajustes
  async function loadSettings() {
    const s = await api("/api/settings"), v = s.values;
    $("#st-desk").value = v["general.enable_desktop"] === "no" ? "no" : "yes"; $("#st-min").value = v["general.notify_min"]; $("#st-style").value = v["general.notify_style"] || "corner";
    $("#st-secs").value = v["general.notify_seconds"]; $("#st-secs-c").value = v["general.notify_seconds_critical"]; $("#st-popup").value = v["general.popup_min"]; $("#st-hb").value = v["alerts.heartbeat_url"] || ""; $("#st-qf").value = v["general.quiet_from"] || ""; $("#st-qt").value = v["general.quiet_to"] || ""; $("#st-ntfy").value = v["general.ntfy_url"] || ""; $("#st-mail").value = v["general.email_to"] || "";
    st.pinSet = !!s.pin.enabled; $("#pin-st").textContent = st.pinSet ? "activo" : "sin PIN"; $("#pin-st").className = "badge sev-" + (st.pinSet ? "low" : "medium");
    $("#pin-old-l").hidden = !st.pinSet; $("#pin-clear").hidden = !st.pinSet; $("#pin-save").textContent = st.pinSet ? "Cambiar PIN" : "Activar PIN";
    const lr = $("#st-learn"); if (lr) { lr.textContent = s.learning ? "activo hasta " + new Date(s.learning * 1000).toLocaleDateString("es-CL", { day: "2-digit", month: "short" }) : "apagado"; lr.className = "badge sev-" + (s.learning ? "medium" : "info"); $("#st-learn-btn").textContent = s.learning ? "Terminar aprendizaje" : "Aprender por 3 días"; $("#st-learn-btn").dataset.on = s.learning ? "1" : ""; }
    const on = s.honeypot.active;
    $("#st-hp").textContent = on ? "activos" : "apagados"; $("#st-hp").className = "badge sev-" + (on ? "high" : "low");
    $("#st-hp-ports").textContent = s.honeypot.ports.join(", "); $("#st-hp-btn").textContent = on ? "Apagar señuelos" : "Activar señuelos"; $("#st-hp-btn").dataset.on = on ? "1" : "";
    $("#st-note").textContent = s.toast_available ? "" : "Falta GTK para el aviso de esquina (paquete python3-gi): se usará la notificación del sistema.";
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
  const KIND_ES = { ssh_clave: "Adivinar contraseñas", ssh_usuario_invalido: "Probar usuarios", ssh_llave: "Probar llaves", escaneo_puertos: "Revisar puertas", escaneo_syn: "Escaneo de puertos", escaneo_sigiloso: "Escaneo sigiloso", escaneo_udp: "Escaneo UDP", inundacion_syn: "Inundación de timbres", ping_masivo: "Ping masivo", senuelo: "Cayó en el señuelo", web_rce: "Comandos en el sitio web", web_sqli: "Inyección SQL", web_traversal: "Salir de la carpeta (../)", web_xss: "Scripts (XSS)", web_secretos: "Archivos secretos", web_escaner: "Escáner web", web_sondeo: "Buscar paneles de admin", web_login: "Fuerza bruta de login web", web_404: "Ráfaga de 404" };
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


  // ---------- Actualizaciones
  let upd = null;
  const dismissed = () => { try { return localStorage.getItem("sentinel-upd-later"); } catch (e) { return null; } };
  async function loadUpdate(force) {
    try { upd = force ? await api("/api/update/refresh", {}) : await api("/api/update"); } catch (e) { return; }
    $("#upd-ver").textContent = "v" + upd.current;
    const show = upd.available && dismissed() !== upd.latest;
    $("#upd").hidden = !show;
    if (!show) return;
    $("#upd-t").textContent = "Hay una versión nueva de Sentinel: " + upd.latest;
    $("#upd-s").textContent = "Tienes la " + upd.current + ". Se descarga de GitHub, se verifica su huella y se instala; los servicios se reinician solos. Te pedirá tu clave de administrador.";
    $("#upd-n").hidden = !upd.notes; $("#upd-pre").textContent = upd.notes || "";
  }
  async function doUpdate() {
    if (!(await confirmDlg("Actualizar Sentinel", "Se instalará la versión " + upd.latest + ". Se verifica la huella del archivo antes de instalar y el panel se reiniciará. ¿Continuar?", "Actualizar"))) return;
    const r = await runAction("update", null, $("#upd-go"));
    if (!r || !r.ok) return;
    const bz = $("#busy"); bz.hidden = false; $("#busy-t").textContent = "Reiniciando con la versión " + upd.latest + "…";
    const t0 = Date.now();
    const poll = setInterval(async () => {
      try { const o = await (await fetch("/api/overview")).json(); if (o.version === upd.latest) { clearInterval(poll); location.reload(); } } catch (e) { /* el panel se está reiniciando */ }
      if (Date.now() - t0 > 90000) { clearInterval(poll); bz.hidden = true; toast("Se instaló, pero el panel no volvió solo: ciérralo y ábrelo de nuevo.", true); }
    }, 2000);
  }
  $("#upd-go").addEventListener("click", doUpdate);
  $("#upd-later").addEventListener("click", () => { try { localStorage.setItem("sentinel-upd-later", upd.latest); } catch (e) { /* sin almacenamiento */ } $("#upd").hidden = true; });
  $("#upd-check").addEventListener("click", async () => {
    toast("Buscando actualizaciones…"); try { localStorage.removeItem("sentinel-upd-later"); } catch (e) { /* sin almacenamiento */ }
    await loadUpdate(true); await new Promise((r) => setTimeout(r, 2500)); await loadUpdate(false);
    if (!upd.available) toast(upd.error && !upd.checking ? "No se pudo buscar: " + (upd.error === "sin_publicaciones" ? "todavía no hay versiones publicadas" : upd.error === "sin_conexion" ? "sin conexión con GitHub" : upd.error) : "Estás al día: versión " + upd.current);
  });

  // ---------- ciclo
  // ---------- Firewall (módulo aparte de la detección)
  let fwDeadline = 0;
  setInterval(() => { const b = $("#fw-pending"); if (!fwDeadline || b.hidden) return; const s = Math.round(fwDeadline - Date.now() / 1000); $("#fw-count").textContent = s > 0 ? s + " s" : "revirtiendo…"; if (s < -3) loadFirewall(); }, 1000);
  async function loadFirewall() {
    const f = await api("/api/firewall");
    fwDeadline = f && f.pending ? f.pending.deadline : 0; $("#fw-pending").hidden = !fwDeadline;
    const ok = f && f.ok;
    const age = ok ? Math.max(0, Date.now() / 1000 - Date.parse(f.time) / 1000) : null;
    document.querySelectorAll(".fw-age").forEach((e) => { e.textContent = age == null ? "" : "Información " + ago(age); e.classList.toggle("old", age != null && age > 180); });
    $("#fw-be").textContent = ok ? f.backend : "sin datos"; $("#fw-be").className = "badge sev-" + (ok ? "low" : "medium");
    const ul = $("#fw-plan"); clear(ul);
    const row = (ic, t, d, cls) => { const li = el("li"); li.appendChild(el("div", "ic " + cls, ic)); const m = el("div"); m.appendChild(el("h4", null, t)); if (d) m.appendChild(el("p", null, d)); li.appendChild(m); li.appendChild(el("span")); ul.appendChild(li); };
    if (!ok) {
      $("#fw-sum").textContent = (f && f.error) ? "No pude leer el firewall: " + f.error : "Aún no hay datos: el monitor guarda una foto del firewall cada 5 minutos. Pulsa «Actualizar».";
      $("#fw-apply").disabled = true; $("#nav-fw").hidden = true; clear($("#fw-listen")); clear($("#fw-rules")); return;
    }
    const p = f.plan, n = p.remove.length + p.missing.length + (p.missing_from || []).length;
    $("#fw-sum").textContent = "Quedarán abiertos desde afuera: " + (p.keep_ports.join(", ") || "ninguno") + (f.ssh.ports.length ? " · SSH de este equipo: " + f.ssh.ports.join(", ") : " · este equipo no sirve SSH (tus despliegues por SSH hacia otros servidores no se tocan)") + " · foto de " + when(Date.parse(f.time) / 1000);
    p.remove.forEach((r) => row("−", "Se cerrará: " + r.label, r.comment || "Permite entrar a cualquiera", "aviso"));
    p.missing.forEach((m) => row("+", "Se abrirá el puerto " + m, "Lo pediste en los ajustes (o es el SSH de este equipo)", "info"));
    (p.missing_from || []).forEach(([po, src]) => row("+", "Se abrirá el puerto " + po + " solo desde " + src, "Limitado a ese origen", "info"));
    p.review.forEach((r) => row("?", "Revisar a mano: " + r.label, "Permite a un equipo concreto (" + r.from + "): no se toca solo", "info"));
    if (f.ssh.sessions.length) row("✓", "Sesiones SSH abiertas ahora", f.ssh.sessions.join(", ") + " (se mantienen)", "ok");
    if (!n && !p.review.length) row("✓", "El firewall ya está como lo pediste", "", "ok");
    if (!f.safe) row("!", "El tráfico saliente no está permitido", "No se aplica nada para no cortar tus conexiones SSH de despliegue", "fallo");
    $("#fw-apply").disabled = !n && !f.needs_harden || !f.safe;
    $("#fw-note").textContent = f.needs_harden ? "iptables acepta todo por defecto: al aplicar se pondrá la política de entrada en DROP (dejando pasar lo local y lo ya iniciado)." : "Antes de aplicar se guarda una copia de las reglas.";
    const nb = $("#nav-fw"); nb.hidden = !n; nb.textContent = String(n);
    const lb = $("#fw-listen"); clear(lb);
    const ST = { docker: ["critical", "Sí, salta el firewall (Docker)"], abierto: ["medium", "Sí, abierto"], bloqueado: ["low", "No, bloqueado"], privada: ["info", "Solo red privada"] };
    f.listening.filter((l) => !l.local).forEach((l) => {
      const tr = el("tr"); tr.appendChild(el("td", null, l.proto + "/" + l.port));
      const pr = el("td", null, l.proc || "—"); pr.appendChild(el("div", "hint", l.addr)); tr.appendChild(pr);
      const t = el("td"); const s = ST[l.status] || ["info", l.status]; t.appendChild(el("span", "badge sev-" + s[0], s[1])); if (l.advice) t.appendChild(el("div", "hint", l.advice)); tr.appendChild(t); lb.appendChild(tr);
    });
    if (!lb.firstChild) lb.appendChild(el("tr")).appendChild(el("td", "empty", "Nada escucha hacia afuera."));
    const ru = $("#fw-rules"); clear(ru);
    f.rules.forEach((r) => { const li = el("li"); li.appendChild(el("div", "ic " + (r.action === "ALLOW" ? "ok" : "info"), r.action === "ALLOW" ? "✓" : "×")); const m = el("div"); m.appendChild(el("h4", null, r.label)); m.appendChild(el("p", null, r.action + " desde " + r.from + (r.comment ? " · " + r.comment : ""))); li.appendChild(m); li.appendChild(el("span")); ru.appendChild(li); });
    if (!ru.firstChild) ru.appendChild(el("li", "empty", "Sin reglas de entrada."));
    if (document.activeElement && !["fw-tcp", "fw-udp", "fw-ssh", "fw-backend", "fw-profile", "fw-restrict", "fw-sshlimit"].includes(document.activeElement.id)) {
      $("#fw-tcp").value = f.conf.allow_tcp.join(","); $("#fw-udp").value = f.conf.allow_udp.join(","); $("#fw-ssh").value = f.conf.keep_ssh ? "yes" : "no"; $("#fw-backend").value = f.conf.backend; $("#fw-profile").value = f.conf.profile || "custom"; $("#fw-sshlimit").value = f.conf.ssh_limit ? "yes" : "no"; $("#fw-restrict").value = Object.entries(f.conf.restrict || {}).map(([p, s]) => p + "=" + s.join("|")).join(", ");
    }
  }

  async function refresh() {
    try { render(await api("/api/overview")); } catch (e) { $("#mini").className = "mini bad"; $("#mini-t").textContent = "Sin conexión con el panel"; $("#live").classList.add("off"); }
  }
  document.querySelectorAll(".nav").forEach((b) => b.addEventListener("click", () => go(b.dataset.view)));
  document.querySelectorAll("[data-goto]").forEach((b) => b.addEventListener("click", () => go(b.dataset.goto)));
  document.querySelectorAll("[data-action]").forEach((b) => b.addEventListener("click", () => runAction(b.dataset.action, null, b)));
  document.querySelectorAll(".fw-reload").forEach((b) => b.addEventListener("click", async () => { b.disabled = true; try { await loadFirewall(); toast("Información recargada"); } finally { b.disabled = false; } }));
  $("#fw-confirm").addEventListener("click", async (e) => { await runAction("fw_confirmar", null, e.currentTarget); fwDeadline = 0; loadFirewall(); });
  $("#fw-revert").addEventListener("click", async (e) => { await runAction("fw_revertir", null, e.currentTarget); fwDeadline = 0; loadFirewall(); });
  $("#fw-apply").addEventListener("click", async (e) => {
    if (!(await confirmDlg("Aplicar el plan del firewall", "Se cerrarán los puertos indicados y quedará abierto solo lo que elegiste. Se aplica A PRUEBA: tendrás 90 segundos para confirmar; si no confirmas, vuelve solo a como estaba. Tu SSH se mantiene.", "Aplicar"))) return;
    const f = await api("/api/firewall"); await runAction("fw_aplicar", { endurecer: !!(f && f.needs_harden) }, e.currentTarget); loadFirewall();
  });
  $("#fw-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const pares = {}; for (const [k, id] of [["profile", "fw-profile"], ["allow_tcp", "fw-tcp"], ["allow_udp", "fw-udp"], ["restrict", "fw-restrict"], ["keep_ssh", "fw-ssh"], ["ssh_limit", "fw-sshlimit"], ["backend", "fw-backend"]]) pares[k] = $("#" + id).value.trim();
    const r = await runAction("fw_config_varios", { pares }); if (!r || !r.ok) return;
    toast("Ajustes guardados. El plan de Puertos ya está actualizado."); loadFirewall();
  });
  $("#f-mod").addEventListener("change", renderEvents);
  $("#f-res").addEventListener("change", renderEvents);
  $("#st-hp-btn").addEventListener("click", async (e) => {
    const on = !e.currentTarget.dataset.on;
    if (on && !(await confirmDlg("Activar los señuelos", "Se abrirán puertos falsos en este equipo (el firewall los mantiene cerrados hacia afuera). ¿Seguro?", "Activar"))) return;
    await runAction("senuelos", { on }, e.currentTarget); loadSettings();
  });
  $("#st-learn-btn").addEventListener("click", async (e) => { const r = await runAction("aprender", { dias: e.currentTarget.dataset.on ? 0 : 3 }, e.currentTarget); if (r && r.ok) loadSettings(); });
  $("#pin-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    if ($("#pin-new").value !== $("#pin-new2").value) { toast("Los PIN nuevos no coinciden", true); return; }
    const r = await runAction("pin_establecer", { pin: $("#pin-old").value, nuevo: $("#pin-new").value });
    if (r && r.ok) { $("#pin-form").reset(); pinCache = { v: "", until: 0 }; loadSettings(); }
  });
  $("#pin-clear").addEventListener("click", async (e) => {
    if (!(await confirmDlg("Quitar el PIN", "Sentinel dejará de pedir PIN para detenerlo o cambiar su configuración.", "Quitar"))) return;
    const p = await askPin(); if (p == null) return;
    const r = await runAction("pin_quitar", { pin: p }, e.currentTarget); if (r && r.ok) { pinCache = { v: "", until: 0 }; loadSettings(); }
  });
  $("#st-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const r = await runAction("ajustes", { pares: { "general.enable_desktop": $("#st-desk").value, "general.notify_min": $("#st-min").value, "general.notify_style": $("#st-style").value, "general.notify_seconds": $("#st-secs").value, "general.notify_seconds_critical": $("#st-secs-c").value, "general.popup_min": $("#st-popup").value, "alerts.heartbeat_url": $("#st-hb").value.trim(), "general.quiet_from": $("#st-qf").value, "general.quiet_to": $("#st-qt").value, "general.ntfy_url": $("#st-ntfy").value.trim(), "general.email_to": $("#st-mail").value.trim() } });
    if (r && r.ok) loadSettings();
  });
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
  api("/api/settings").then((s) => { st.pinSet = !!s.pin.enabled; }).catch(() => {});
  loadUpdate(false); setTimeout(() => loadUpdate(false), 4000); setInterval(() => loadUpdate(false), 600000);
  setInterval(() => { if (!document.hidden) { refresh(); if (st.view === "eventos" && !$("#f-q").value) loadEvents(); if (st.view === "atacantes" && !$("#att-q").value) loadAttackers(); if (st.view === "paquetes") loadPackets(); } }, 3000);
  setInterval(() => { if (!document.hidden && st.view.startsWith("fw-")) loadFirewall(); }, 5000);
  setInterval(() => ($("#clock").textContent = new Date().toLocaleTimeString("es-CL", { hour: "2-digit", minute: "2-digit", hour12: false })), 15000);
})();
