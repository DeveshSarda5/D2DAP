"use strict";
// Dashboard client: every value is fetched from the running backend (no hard-coded data).

const STATE_COLOR = {
  normal: "var(--good)", monitor: "var(--info)", restrict: "var(--warning)",
  reauthenticate: "var(--serious)", quarantine: "var(--critical)",
};
const SERIES = ["var(--s1)", "var(--s2)", "var(--s3)", "var(--s4)"];
const MAX_HIGHLIGHT = 4;
const selected = new Set();
let lastEventId = 0;
let drones = [];

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
const svgEl = (tag, attrs = {}) => {
  const el = document.createElementNS("http://www.w3.org/2000/svg", tag);
  for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
  return el;
};

async function api(path, opts = {}) {
  const res = await fetch(path, { headers: { "Content-Type": "application/json" }, ...opts });
  if (!res.ok) throw new Error((await res.json().catch(() => ({}))).detail || res.statusText);
  return res.json();
}

function badge(state) {
  return `<span class="badge" style="--c:${STATE_COLOR[state] || "var(--muted)"}">${esc(state.toUpperCase())}</span>`;
}

// ------------------------------------------------------------------ tiles
function renderTiles(m) {
  if (!m || m.sim_time_s === undefined) { $("tiles").innerHTML = ""; return; }
  const delivered = m.packets_sent ? (m.packets_delivered / Math.max(1, m.packets_delivered + m.packets_dropped)) : 0;
  const s = m.states || {};
  const tiles = [
    ["Simulation time", `${m.sim_time_s.toFixed(1)} s`],
    ["Packets delivered", `${(100 * delivered).toFixed(1)} %`],
    ["D2DAP sessions / failures", `${m.auth_success} / ${m.auth_failures}`],
    ["IDS alerts", m.ids_alerts],
    ["Policy decisions", m.policy_decisions],
    ["Restricted or worse", (s.restrict || 0) + (s.reauthenticate || 0) + (s.quarantine || 0)],
    ["Quarantined", s.quarantine || 0],
    ["Monitor ms / window", m.monitor_ms_per_window ?? "n/a"],
  ];
  $("tiles").innerHTML = tiles.map(([k, v]) => `<div class="tile"><div class="v">${esc(v)}</div><div class="k">${esc(k)}</div></div>`).join("");
}

// ------------------------------------------------------------------ topology
function renderTopology(st) {
  const svg = $("topology");
  svg.replaceChildren();
  const nodes = st.drones.filter((d) => d.active);
  if (!nodes.length) return;
  const xs = nodes.map((d) => d.position[0]), ys = nodes.map((d) => d.position[1]);
  const [x0, x1, y0, y1] = [Math.min(...xs), Math.max(...xs), Math.min(...ys), Math.max(...ys)];
  const sx = (x) => 30 + (440 * (x - x0)) / Math.max(1, x1 - x0);
  const sy = (y) => 390 - (360 * (y - y0)) / Math.max(1, y1 - y0);
  const pos = Object.fromEntries(nodes.map((d) => [d.drone_id, [sx(d.position[0]), sy(d.position[1])]]));
  for (const e of st.edges) {
    if (!pos[e.a] || !pos[e.b]) continue;
    svg.append(svgEl("line", { x1: pos[e.a][0], y1: pos[e.a][1], x2: pos[e.b][0], y2: pos[e.b][1], stroke: "var(--axis)", "stroke-width": 1 }));
  }
  for (const d of nodes) {
    const [x, y] = pos[d.drone_id];
    const g = svgEl("g");
    if (d.external_radio) {
      g.append(svgEl("rect", { x: x - 5, y: y - 5, width: 10, height: 10, fill: "var(--muted)", stroke: "var(--surface)", "stroke-width": 2 }));
    } else {
      g.append(svgEl("circle", { cx: x, cy: y, r: d.role === "leader" ? 11 : 8, fill: STATE_COLOR[d.security_state], stroke: selected.has(d.drone_id) ? "var(--ink)" : "var(--surface)", "stroke-width": selected.has(d.drone_id) ? 2.5 : 2 }));
    }
    const label = svgEl("text", { x: x + 11, y: y - 9, "font-size": 11, fill: "var(--ink-2)" });
    label.textContent = d.external_radio ? `${d.drone_id} (radio)` : d.drone_id + (d.role === "leader" ? " (leader)" : "");
    g.append(label);
    g.addEventListener("mousemove", (ev) => showTip(ev, `<b>${esc(d.drone_id)}</b> · ${esc(d.role)}<br>trust ${d.trust_score.toFixed(3)} · ${esc(d.security_state)}<br>auth ${esc(d.auth_state)} · battery ${d.battery_level.toFixed(1)}%`));
    g.addEventListener("mouseleave", hideTip);
    svg.append(g);
  }
  $("topo-meta").textContent = `${nodes.length} nodes · ${st.edges.length} links`;
}

// ------------------------------------------------------------------ table
function renderTable(st) {
  const rows = st.drones.filter((d) => !d.external_radio).sort((a, b) => a.drone_id.localeCompare(b.drone_id, undefined, { numeric: true }));
  $("drones").querySelector("tbody").innerHTML = rows.map((d) => `
    <tr data-id="${esc(d.drone_id)}" class="${selected.has(d.drone_id) ? "sel" : ""}">
      <td><b>${esc(d.drone_id)}</b></td><td>${esc(d.role)}</td><td>${esc(d.auth_state)}</td>
      <td><span class="trustbar"><i style="width:${(100 * d.trust_score).toFixed(0)}%"></i></span>${d.trust_score.toFixed(3)}</td>
      <td>${badge(d.security_state)}</td><td>${d.battery_level.toFixed(1)}%</td>
      <td>${d.sessions.length}</td><td>${d.crp_remaining ?? "–"}</td></tr>`).join("");
  for (const tr of $("drones").querySelectorAll("tbody tr")) {
    tr.addEventListener("click", () => {
      const id = tr.dataset.id;
      if (selected.has(id)) selected.delete(id);
      else { if (selected.size >= MAX_HIGHLIGHT) selected.delete(selected.values().next().value); selected.add(id); }
      refresh();
    });
  }
  const sel = $("atk-target"), cur = sel.value;
  sel.innerHTML = rows.map((d) => `<option ${d.drone_id === cur ? "selected" : ""}>${esc(d.drone_id)}</option>`).join("");
  if (!cur && rows.length > 2) sel.value = rows[2].drone_id;
}

// ------------------------------------------------------------------ charts
function highlighted(series) {
  if (selected.size) return [...selected].filter((id) => series[id]);
  // Default: the drones whose trust dipped lowest in the visible window (keeps a recovered
  // attacker highlighted), at most four so categorical colours stay distinguishable.
  const lows = Object.entries(series).map(([id, pts]) => [id, Math.min(...pts.map((p) => p.trust))]);
  return lows.sort((a, b) => a[1] - b[1]).slice(0, MAX_HIGHLIGHT).map(([id]) => id);
}

function lineChart(container, series, key, { bands = {}, yLabel = "" } = {}) {
  const el = $(container);
  const W = el.clientWidth || 800, H = el.clientHeight || 240, m = { l: 44, r: 90, t: 10, b: 28 };
  const svg = svgEl("svg", { viewBox: `0 0 ${W} ${H}` });
  const all = Object.values(series).flat().filter((p) => p[key] !== null);
  el.replaceChildren(svg);
  if (!all.length) { const t = svgEl("text", { x: W / 2, y: H / 2, "text-anchor": "middle", fill: "var(--muted)", "font-size": 12 }); t.textContent = "Waiting for data…"; svg.append(t); return []; }
  const tMin = Math.min(...all.map((p) => p.t)), tMax = Math.max(...all.map((p) => p.t), tMin + 1);
  const X = (t) => m.l + ((W - m.l - m.r) * (t - tMin)) / (tMax - tMin);
  const Y = (v) => m.t + (H - m.t - m.b) * (1 - v);
  for (const v of [0, 0.25, 0.5, 0.75, 1]) {
    svg.append(svgEl("line", { x1: m.l, x2: W - m.r, y1: Y(v), y2: Y(v), stroke: "var(--grid)" }));
    const t = svgEl("text", { x: m.l - 6, y: Y(v) + 4, "text-anchor": "end", "font-size": 10.5, fill: "var(--muted)" }); t.textContent = v.toFixed(2); svg.append(t);
  }
  for (const [name, v] of Object.entries(bands)) {
    svg.append(svgEl("line", { x1: m.l, x2: W - m.r, y1: Y(v), y2: Y(v), stroke: "var(--axis)", "stroke-dasharray": "3 3" }));
    const t = svgEl("text", { x: W - m.r + 4, y: Y(v) + 3, "font-size": 9.5, fill: "var(--muted)" }); t.textContent = name.toUpperCase(); svg.append(t);
  }
  const xl = svgEl("text", { x: (W - m.r + m.l) / 2, y: H - 6, "text-anchor": "middle", "font-size": 10.5, fill: "var(--muted)" });
  xl.textContent = `simulation time (s) ${tMin.toFixed(0)}–${tMax.toFixed(0)}${yLabel ? " · " + yLabel : ""}`; svg.append(xl);
  const hi = highlighted(series);
  const path = (pts) => pts.filter((p) => p[key] !== null).map((p, i) => `${i ? "L" : "M"}${X(p.t).toFixed(1)},${Y(p[key]).toFixed(1)}`).join("");
  for (const [id, pts] of Object.entries(series)) if (!hi.includes(id)) svg.append(svgEl("path", { d: path(pts), fill: "none", stroke: "var(--axis)", "stroke-width": 1 }));
  hi.forEach((id, i) => svg.append(svgEl("path", { d: path(series[id]), fill: "none", stroke: SERIES[i], "stroke-width": 2 })));
  // Hover crosshair + tooltip with every highlighted drone's value at that time.
  const cross = svgEl("line", { y1: m.t, y2: H - m.b, stroke: "var(--ink-2)", "stroke-width": 1, visibility: "hidden" });
  const hit = svgEl("rect", { x: m.l, y: m.t, width: W - m.l - m.r, height: H - m.t - m.b, fill: "transparent" });
  svg.append(cross, hit);
  hit.addEventListener("mousemove", (ev) => {
    const box = svg.getBoundingClientRect();
    const t = tMin + ((ev.clientX - box.left) * (W / box.width) - m.l) / (W - m.l - m.r) * (tMax - tMin);
    cross.setAttribute("x1", X(t)); cross.setAttribute("x2", X(t)); cross.setAttribute("visibility", "visible");
    const lines = hi.map((id, i) => {
      const pts = series[id].filter((p) => p[key] !== null);
      if (!pts.length) return "";
      const p = pts.reduce((a, b) => (Math.abs(b.t - t) < Math.abs(a.t - t) ? b : a));
      return `<span class="sw" style="background:${SERIES[i]}"></span>${esc(id)}: ${p[key].toFixed(3)}`;
    });
    showTip(ev, `<b>t = ${t.toFixed(1)} s</b><br>${lines.join("<br>")}`);
  });
  hit.addEventListener("mouseleave", () => { cross.setAttribute("visibility", "hidden"); hideTip(); });
  return hi;
}

function renderCharts(tr) {
  const hi = lineChart("trust-chart", tr.series, "trust", { bands: tr.bands, yLabel: "trust" });
  lineChart("prob-chart", tr.series, "p", { bands: { alert: 0.5 }, yLabel: "P(attack)" });
  $("trust-legend").innerHTML = hi.map((id, i) => `<span><span class="sw" style="background:${SERIES[i]}"></span>${esc(id)}</span>`).join("") +
    (Object.keys(tr.series).length > hi.length ? `<span><span class="sw" style="background:var(--axis)"></span>other drones</span>` : "");
}

// ------------------------------------------------------------------ events
function renderEvents(evts) {
  const list = $("events");
  for (const e of evts) {
    lastEventId = Math.max(lastEventId, e.id);
    const li = document.createElement("li");
    const head = `<span class="t">${(e.t_ms / 1000).toFixed(1)}s</span><span class="kind">${esc(e.kind)}</span>${e.state ? badge(e.state) + " " : ""}${esc(e.message)}`;
    li.innerHTML = e.explanation ? `<details><summary>${head}</summary><pre>${esc(e.explanation)}</pre></details>` : head;
    list.prepend(li);
  }
  while (list.children.length > 200) list.lastChild.remove();
}

// ------------------------------------------------------------------ tooltip
function showTip(ev, html) {
  const tip = $("tooltip"); tip.innerHTML = html; tip.hidden = false;
  tip.style.left = `${Math.min(ev.clientX + 14, window.innerWidth - 260)}px`; tip.style.top = `${ev.clientY + 14}px`;
}
function hideTip() { $("tooltip").hidden = true; }

// ------------------------------------------------------------------ loop
async function refresh() {
  try {
    const [st, met, tr, evts] = await Promise.all([api("/api/state"), api("/api/metrics"), api("/api/trust"), api(`/api/events?since=${lastEventId}`)]);
    drones = st.drones;
    $("notice").hidden = !st.notice; $("notice").textContent = st.notice || "";
    renderTiles(met); renderTopology(st); renderTable(st); renderCharts(tr); renderEvents(evts);
    $("active-attacks").textContent = st.active_attacks && st.active_attacks.length
      ? "Active (ground truth): " + st.active_attacks.map((a) => `${a.kind} on ${a.target}`).join(", ") : "No attack active.";
  } catch (err) { $("notice").hidden = false; $("notice").textContent = `Backend unreachable: ${err.message}`; }
}

async function init() {
  $("state-legend").innerHTML = Object.keys(STATE_COLOR).map((s) => badge(s)).join(" ");
  const kinds = await api("/api/attacks/kinds");
  $("atk-kind").innerHTML = kinds.map((k) => `<option value="${esc(k.kind)}">${esc(k.kind)} [${esc(k.stride)}]${k.insider ? " insider" : ""}</option>`).join("");
  $("btn-start").addEventListener("click", async () => {
    lastEventId = 0; $("events").replaceChildren(); selected.clear();
    await api("/api/simulation/start", { method: "POST", body: JSON.stringify({
      num_drones: +$("cfg-drones").value, seed: +$("cfg-seed").value, variant: $("cfg-variant").value, speed: +$("cfg-speed").value }) });
    refresh();
  });
  $("btn-stop").addEventListener("click", () => api("/api/simulation/stop", { method: "POST" }).then(refresh));
  $("btn-attack").addEventListener("click", async () => {
    try {
      await api("/api/attacks", { method: "POST", body: JSON.stringify({ kind: $("atk-kind").value, target: $("atk-target").value,
        duration_s: +$("atk-dur").value, rate_pps: +$("atk-rate").value }) });
      selected.add($("atk-target").value); refresh();
    } catch (err) { alert(err.message); }
  });
  refresh();
  setInterval(refresh, 1000);
}
init();
