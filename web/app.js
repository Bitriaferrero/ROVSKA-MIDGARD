/* ROVSKA — panel web. Sin dependencias: fetch + DOM + SSE. */
"use strict";

const SEV_ORDER = ["CRÍTICO", "ALTO", "MEDIO", "BAJO", "INFO"];
const SEV_CLASS = { "CRÍTICO": "crit", "ALTO": "high", "MEDIO": "med", "BAJO": "low", "INFO": "info" };
const SEV_VAR = {
  "CRÍTICO": "var(--crit)",
  "ALTO": "var(--high)",
  "MEDIO": "var(--med)",
  "BAJO": "var(--low)",
  "INFO": "var(--info)",
};
const RISK_VAR = {
  crit: "var(--crit)",
  high: "var(--high)",
  med: "var(--med)",
  low: "var(--low)",
  info: "var(--info)",
  ok: "var(--ok)",
};
const PROFILES = [
  ["discovery", "Descubrimiento"],
  ["quick", "Rápido"],
  ["full", "Completo"],
  ["web", "Web"],
  ["infra", "Infraestructura"],
  ["deep", "Profundo"],
  ["attack", "Ataque controlado"],
];

const state = {
  data: null,
  health: null,
  tools: [],
  view: "overview",
  hostIp: null,
  hostTab: "summary",
  query: "",
  findFilter: "ALL",
  compareBase: "",
  compareTarget: "",
  tasks: null,
  tasksAt: "",
  tasksError: "",
  loading: false,
  modalStream: null,
  modalTimer: null,
  mg: {
    profiles: [],
    runs: [],
    jobs: [],
    job: null,
    log: [],
    timer: null,
  },
  nm: {
    data: null,
    jobs: [],
    job: null,
    log: [],
    timer: null,
  },
  pve: {
    expanded: new Set(),
  },
};

const $ = (sel) => document.querySelector(sel);
const nav = $("#nav");
const brand = $("#brand");
const search = $("#search");
const refreshBtn = $("#refresh");
const sidebar = $("#sidebar");
const detail = $("#detail");
const topMeta = $("#top-meta");
const footMeta = $("#foot-meta");
const toastEl = $("#toast");
const modal = $("#modal");
const modalTitle = $("#modal-title");
const modalBody = $("#modal-body");

let toastTimer = null;

/* ---------- utilidades ---------- */

function esc(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function nl2br(value) {
  return esc(value).replace(/\n/g, "<br>");
}

function sevClass(sev) {
  return SEV_CLASS[sev] || "info";
}

function typeClass(type) {
  const value = String(type || "").toLowerCase();
  if (value.includes("nodo proxmox")) return "proxmox-node";
  if (value.includes("lxc") && !value.includes("vm")) return "lxc";
  if (value.includes("guest") || value.includes("invitado")) return "guest";
  if (value.includes("virtual") || value === "vm" || value.includes("máquina virtual") || value.includes("(vm")) return "vm";
  if (value.includes("router")) return "router";
  if (value.includes("iot") || value.includes("cliente")) return "iot";
  if (value.includes("este equipo")) return "this";
  return "";
}

function shortType(type) {
  const value = String(type || "");
  const map = {
    "Nodo Proxmox": "PVE",
    "Guest Proxmox (LXC/VM)": "GUEST",
    "LXC": "LXC",
    "Servidor / servicio": "SRV",
    "Cliente / IoT": "IOT",
    "Este equipo": "LOCAL",
    "Dispositivo": "DEV",
    "Router": "RTR",
  };
  if (map[value]) return map[value];
  const lower = value.toLowerCase();
  if (lower.includes("máquina virtual") || lower.includes("virtualbox") || lower.includes("vmware") || lower.includes("qemu")) return "VM";
  if (lower.includes("lxc")) return "LXC";
  if (lower.includes("router")) return "RTR";
  return value.slice(0, 10).toUpperCase();
}

function effectiveType(host) {
  return host.type_override || host.type || "Desconocido";
}

function hostName(host) {
  return host.name || (host.hostnames && host.hostnames[0]) || "";
}

function hostMatches(host, query) {
  if (!query) return true;
  const q = query.toLowerCase();
  const fields = [
    host.ip,
    host.name,
    host.mac,
    host.vendor,
    host.os,
    host.type,
    host.type_override,
    ...(host.hostnames || []),
    ...(host.ports || []).map((p) => `${p.port} ${p.name || ""} ${p.product || ""}`),
    ...(host.proxmox?.guests || []).flatMap((g) => [g.name, g.ip, g.vmid, g.kind, g.type]),
  ];
  return fields.some((value) => String(value || "").toLowerCase().includes(q));
}

function pveInfo() {
  return state.data?.proxmox || {};
}

function pveConfig() {
  return pveInfo().config || {};
}

function pveChip() {
  const pve = pveInfo();
  if (!pve.configured) return "";
  if (!pve.enabled) return `<span class="chip">proxmox <b>desactivado</b></span>`;
  if (!pve.ok) return `<span class="chip">proxmox <b>sin conexión</b></span>`;
  return `<span class="chip">proxmox <b>${pve.node_count || 0}</b> nodos · ${pve.guest_count || 0} invitados${pve.stale ? " · caché" : ""}</span>`;
}

function pveGuestLabel(guest) {
  const kind = guest.kind === "lxc" ? "LXC" : "VM";
  const name = String(guest.name || "").trim();
  return `${kind} ${guest.vmid || ""}${name ? ` · ${name}` : ""}`;
}

function findPveGuest(ip, vmid) {
  const wantedVmid = String(vmid || "");
  for (const host of state.data?.hosts || []) {
    for (const guest of host.proxmox?.guests || []) {
      if (ip && String(guest.ip || "") === String(ip)) return guest;
      if (wantedVmid && String(guest.vmid || "") === wantedVmid) return guest;
    }
  }
  return null;
}

function fmtDate(value) {
  return String(value || "").replace("T", " ").slice(0, 19);
}

function fmtTaskDate(value) {
  return fmtDate(value).slice(0, 16);
}

function fmtBytes(value) {
  const n = Number(value || 0);
  if (n > 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`;
  if (n > 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${n} B`;
}

function toast(message, isError = false) {
  toastEl.textContent = message;
  toastEl.className = `toast show${isError ? " err" : ""}`;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    toastEl.className = "toast";
  }, 3800);
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    cache: "no-store",
    ...options,
  });
  const text = await response.text();
  let data = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = { error: text };
  }
  if (!response.ok) {
    throw new Error((data && data.error) || `HTTP ${response.status}`);
  }
  return data;
}

/* ---------- gráficos ---------- */

function donutGradient(counts, total) {
  if (!total) return "var(--line)";
  let acc = 0;
  const parts = [];
  for (const sev of SEV_ORDER) {
    const n = counts[sev] || 0;
    if (!n) continue;
    const start = (acc / total) * 100;
    acc += n;
    const end = (acc / total) * 100;
    parts.push(`${SEV_VAR[sev]} ${start.toFixed(2)}% ${end.toFixed(2)}%`);
  }
  return `conic-gradient(${parts.join(", ")})`;
}

function donut(counts, total, label) {
  return `<div class="donut" style="background:${donutGradient(counts, total)}">
    <div class="donut-center"><div><div class="v">${total}</div><div class="l">${esc(label)}</div></div></div>
  </div>`;
}

function legend(counts) {
  const total = SEV_ORDER.reduce((acc, sev) => acc + (counts[sev] || 0), 0);
  return `<div class="legend">${SEV_ORDER.map((sev) => {
    const n = counts[sev] || 0;
    const pct = total ? Math.round((n / total) * 100) : 0;
    return `<div class="legend-row">
      <span class="legend-dot" style="background:${SEV_VAR[sev]}"></span>
      <span>${esc(sev)}</span>
      <span class="count">${n} · ${pct}%</span>
    </div>`;
  }).join("")}</div>`;
}

function bars(items, variant = "", maxOverride = 0) {
  if (!items || !items.length) return `<div class="muted small">Sin datos.</div>`;
  const max = maxOverride || Math.max(...items.map((item) => item.count || 0), 1);
  return `<div class="bar-list">${items.map((item) => {
    const value = item.count || 0;
    const pct = Math.max(2, Math.round((value / max) * 100));
    return `<div class="bar-row">
      <span class="bar-label" title="${esc(item.name)}">${esc(item.name)}</span>
      <span class="bar-track"><span class="bar-fill ${variant}" style="width:${pct}%"></span></span>
      <span class="bar-val">${value}</span>
    </div>`;
  }).join("")}</div>`;
}

function riskGauge(meta) {
  const score = Math.max(0, Math.min(100, Number(meta?.score || 0)));
  const cls = meta?.cls || "info";
  return `<div class="hero-risk">
    <div class="risk-gauge" style="--pct:${score};--gauge-color:${RISK_VAR[cls] || "var(--muted)"}">
      <div style="text-align:center"><div class="val">${score}</div><div class="unit">riesgo</div></div>
    </div>
    <div class="risk-label ${esc(cls)}">${esc(meta?.label || "Sin datos")}</div>
  </div>`;
}

function kpiCard(label, value, sub, cls = "") {
  return `<div class="kpi ${cls}"><div class="l">${esc(label)}</div><div class="v">${esc(value)}</div>${sub ? `<div class="s">${esc(sub)}</div>` : ""}</div>`;
}

function sparkline(history) {
  if (!history || !history.length) return `<div class="muted small">Sin historial.</div>`;
  const w = 600;
  const h = 120;
  const pad = 26;
  const risks = history.map((item) => Number(item.risk || 0));
  const ports = history.map((item) => Number(item.ports || 0));
  const maxP = Math.max(1, ...ports);
  const step = history.length > 1 ? (w - pad * 2) / (history.length - 1) : 0;
  const px = (i) => pad + i * step;
  const ry = (v) => h - pad - (v / 100) * (h - pad * 2);
  const py = (v) => h - pad - (v / maxP) * (h - pad * 2);
  const path = (values, fn) =>
    values.map((value, index) => `${index ? "L" : "M"}${px(index).toFixed(1)} ${fn(value).toFixed(1)}`).join(" ");
  const grid = [0, 25, 50, 75, 100]
    .map((v) => `<line class="grid" x1="${pad}" y1="${ry(v).toFixed(1)}" x2="${w - pad}" y2="${ry(v).toFixed(1)}"></line>
      <text class="axis" x="2" y="${(ry(v) + 3).toFixed(1)}">${v}</text>`)
    .join("");
  const dots = history
    .map((item, index) => `<circle class="dot-risk" cx="${px(index).toFixed(1)}" cy="${ry(Number(item.risk || 0)).toFixed(1)}" r="2.4"></circle>
      <circle class="dot-ports" cx="${px(index).toFixed(1)}" cy="${py(Number(item.ports || 0)).toFixed(1)}" r="2.2"></circle>`)
    .join("");
  return `<svg class="spark" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" role="img" aria-label="Evolución del riesgo">
    ${grid}
    <path class="line-ports" d="${path(ports, py)}"></path>
    <path class="line-risk" d="${path(risks, ry)}"></path>
    ${dots}
  </svg>
  <div class="spark-legend"><span><i class="r"></i>riesgo (0–100)</span><span><i class="p"></i>puertos</span></div>`;
}

/* ---------- piezas ---------- */

function findingCard(finding, showHost = true) {
  const cls = sevClass(finding.severity);
  const cves = (finding.cves || []).map((cve) => `<span class="cve">${esc(cve)}</span>`).join("");
  const cwes = (finding.cwe || []).map((cwe) => `<span class="cve cwe">${esc(cwe)}</span>`).join("");
  const attacks = (finding.attack || []).map((id) => `<span class="cve attack">${esc(id)}</span>`).join("");
  return `<article class="finding ${cls}">
    <div class="finding-head">
      <span class="badge ${cls}">${esc(finding.severity)}</span>
      <span class="finding-title">${esc(finding.title)}</span>
      ${showHost && finding.host ? `<span class="finding-host">${esc(finding.host)}</span>` : ""}
    </div>
    <div class="finding-evidence">${nl2br(finding.evidence || "")}</div>
    ${finding.recommendation ? `<div class="finding-rec"><b>Recomendación:</b> ${nl2br(finding.recommendation)}</div>` : ""}
    ${cves || cwes || attacks ? `<div class="cve-list">${cves}${cwes}${attacks}</div>` : ""}
  </article>`;
}

function goodList(items) {
  if (!items || !items.length) return `<div class="muted small">Sin comprobaciones positivas registradas.</div>`;
  return `<ul class="good-list">${items.map((item) => `<li>${esc(item)}</li>`).join("")}</ul>`;
}

function portsTable(host) {
  const ports = host.ports || [];
  if (!ports.length) return `<div class="muted small">Sin puertos abiertos detectados.</div>`;
  const rows = ports.map((port) => {
    const scripts = Object.entries(port.scripts || {});
    const detail = scripts.length
      ? `<details><summary>${scripts.length} script(s) NSE</summary><pre class="script">${esc(
          scripts.map(([name, output]) => `[${name}]\n${output}`).join("\n\n")
        )}</pre></details>`
      : "";
    return `<tr>
      <td class="port-num">${esc(port.port)}<span class="muted">/${esc(port.proto || "tcp")}</span></td>
      <td><div class="svc">${esc(port.name || "desconocido")}</div>
      <div class="svc-sub">${esc([port.product, port.version, port.extrainfo].filter(Boolean).join(" "))}</div>${detail}</td>
      <td>${esc(port.state || "open")}</td>
    </tr>`;
  }).join("");
  return `<div class="table-wrap"><table>
    <thead><tr><th>Puerto</th><th>Servicio / versión</th><th>Estado</th></tr></thead>
    <tbody>${rows}</tbody></table></div>`;
}

function annotationForm(host) {
  const options = (state.data?.type_options || [""]).map(
    (type) => `<option value="${esc(type)}"${type === (host.type_override || "") ? " selected" : ""}>${esc(type || "— sin tipo —")}</option>`
  ).join("");
  return `<form class="annot" data-form="annotation" data-ip="${esc(host.ip)}">
    <label for="ann-type">Anotación</label>
    <select id="ann-type" name="type">${options}</select>
    <input name="name" value="${esc(host.name || "")}" placeholder="nombre del equipo" maxlength="80">
    <button class="save" type="submit">Guardar</button>
    <span class="hint">se guarda en la base local</span>
  </form>`;
}

/* ---------- cabecera / sidebar ---------- */

function renderTopMeta() {
  const d = state.data;
  if (!d) {
    topMeta.innerHTML = "";
    return;
  }
  const g = d.global || {};
  const settings = d.settings || {};
  const pills = [];
  if (g.target) pills.push(`<span class="meta-pill">objetivo <b>${esc(g.target)}</b></span>`);
  if (g.scanned_at) pills.push(`<span class="meta-pill">${esc(fmtDate(g.scanned_at))}</span>`);
  if (g.risk) pills.push(`<span class="meta-pill risk ${esc(g.risk.cls || "info")}">${esc(g.risk.label || "")} · ${esc(g.risk.score ?? 0)}</span>`);
  pills.push(`<span class="meta-pill">runner <b>${esc(settings.runner || "?")}</b></span>`);
  if (settings.allow_attack) pills.push(`<span class="meta-pill risk crit">ataque real</span>`);
  topMeta.innerHTML = pills.join("");
}

function pveGuestMatches(guest, query) {
  if (!query) return true;
  const q = query.toLowerCase();
  return [guest.name, guest.ip, guest.vmid, guest.kind, guest.type, guest.node]
    .some((value) => String(value || "").toLowerCase().includes(q));
}

function pveGuestRowHtml(guest) {
  const kindClass = guest.kind === "lxc" ? "lxc" : "vm";
  const label = pveGuestLabel(guest);
  const status = String(guest.status || "");
  const statusHtml = status
    ? `<span class="child-state${status === "running" ? " on" : ""}">${esc(status)}</span>`
    : "";
  // Un invitado parado (o sin IP) se marca en naranja, igual que las VM
  // detenidas; los LXC en marcha conservan el punto verde.
  const off = status !== "running" || !guest.ip;
  const dot = `<span class="child-dot ${kindClass}${off ? " off" : ""}"></span>`;
  const active = state.view === "host" && state.hostIp === (guest.host_ip || guest.ip);
  const cls = (extra = "") => `host-child-row${extra}${active ? " active" : ""}`;
  if (guest.host_ip) {
    return `<button class="${cls()}" type="button" data-host="${esc(guest.host_ip)}" title="Abrir ficha de ${esc(guest.host_ip)}">
      ${dot}<span class="child-ip">${esc(guest.ip || guest.host_ip)}</span>
      <span class="child-name">${esc(label)}</span>${statusHtml}
    </button>`;
  }
  if (guest.ip) {
    return `<button class="${cls()}" type="button" data-guest-ip="${esc(guest.ip)}" data-guest-vmid="${esc(guest.vmid)}" title="Invitado sin escanear en este contexto">
      ${dot}<span class="child-ip">${esc(guest.ip)}</span>
      <span class="child-name">${esc(label)}</span>${statusHtml}
    </button>`;
  }
  return `<button class="${cls(" no-ip")}" type="button" data-guest-vmid="${esc(guest.vmid)}" title="Proxmox no devolvió una IP para este invitado">
    ${dot}<span class="child-name">${esc(label)}</span>
    <span class="child-ip">sin IP detectada</span>${statusHtml}
  </button>`;
}

function renderSidebar() {
  const d = state.data;
  if (!d) {
    sidebar.innerHTML = `<div class="side-empty">Cargando hosts…</div>`;
    return;
  }
  const g = d.global || {};
  const counts = g.counts || {};
  const topLevel = (d.hosts || []).filter((host) => !host.parent_ip);
  const hosts = topLevel.filter((host) => hostMatches(host, state.query)
    || (host.proxmox?.guests || []).some((guest) => pveGuestMatches(guest, state.query)));
  const isOverview = state.view === "overview";
  const emptyLabel = g.active_sweep
    ? `Barrido en curso${g.target ? ` · ${g.target}` : ""}…`
    : state.query
      ? "Sin coincidencias."
      : "Sin hosts todavía.";

  const rows = hosts.map((host) => {
    const type = effectiveType(host);
    const meta = host.risk_meta || {};
    const active = state.view === "host" && state.hostIp === host.ip;
    const name = hostName(host);
    const pve = host.proxmox;
    const guests = pve?.guests || [];
    const expanded = state.pve.expanded.has(host.ip);
    const chevron = guests.length
      ? `<span class="pve-chevron${expanded ? " open" : ""}" data-pve-toggle="${esc(host.ip)}" title="${expanded ? "Contraer" : "Desplegar"} invitados">${expanded ? "▾" : "▸"}</span>`
      : `<span class="pve-chevron spacer"></span>`;
    const children = guests.length && expanded
      ? `<div class="host-children">${guests.map(pveGuestRowHtml).join("")}</div>`
      : "";
    const pveLine = guests.length ? ` · ${guests.length} invitados` : "";
    return `<button class="host-row${active ? " active" : ""}${pve ? " pve-node" : ""}" data-host="${esc(host.ip)}" type="button"${guests.length ? ` aria-expanded="${expanded}"` : ""}>
      <span class="ip-line">
        ${chevron}
        <span class="sev-dot ${esc(meta.cls || "ok")}"></span>
        <span class="host-ip">${esc(host.ip)}</span>
        ${name ? `<span class="host-name">${esc(name)}</span>` : ""}
        <span class="type-badge ${typeClass(type)}">${esc(shortType(type))}</span>
      </span>
      <span class="host-os">${esc(host.os || "SO desconocido")}${host.ports?.length ? ` · ${host.ports.length} puertos` : ""}${pveLine}</span>
    </button>${children}`;
  }).join("");

  sidebar.innerHTML = `<div class="side-head">
    <button class="global-btn${isOverview ? " active" : ""}" id="global-btn" type="button">
      <span>Resumen general</span><span class="count">${(d.scans || []).length} escaneos</span>
    </button>
    <div class="side-stats">
      <div class="side-stat crit"><div class="n">${counts["CRÍTICO"] || 0}</div><div class="l">crít</div></div>
      <div class="side-stat high"><div class="n">${counts["ALTO"] || 0}</div><div class="l">alto</div></div>
      <div class="side-stat med"><div class="n">${counts["MEDIO"] || 0}</div><div class="l">med</div></div>
      <div class="side-stat ok"><div class="n">${topLevel.length}</div><div class="l">hosts</div></div>
    </div>
  </div>
  <div class="host-list">${rows || `<div class="side-empty">${esc(emptyLabel)}</div>`}</div>`;
}

function renderFoot() {
  const d = state.data;
  if (!d) {
    footMeta.textContent = "";
    return;
  }
  footMeta.textContent = `actualizado ${fmtDate(d.generated_at)} · ${d.reports_count || 0} informes · api ${d.api_version || ""}`;
}

/* ---------- vista: panel ---------- */

function scanForm(idPrefix = "ov") {
  const options = PROFILES.map(([value, label]) => `<option value="${esc(value)}"${value === "quick" ? " selected" : ""}>${esc(label)}</option>`).join("");
  const pve = pveConfig();
  const pveField = pve.configured
    ? `<div class="field full pve-scan-options">
        <label class="check"><input type="checkbox" name="proxmox_include" ${pve.include_in_scans !== false ? "checked" : ""}> Incluir VM/LXC de Proxmox en la lista</label>
        <label class="check"><input type="checkbox" name="proxmox_validate"> Validar acceso Proxmox antes de escanear</label>
        <span class="hint">Inventario por API de solo lectura. <a href="#settings">Ajustes Proxmox</a>.</span>
      </div>`
    : `<div class="field full"><span class="hint">Proxmox: <a href="#settings">configura la API de solo lectura</a> para mostrar VM/LXC.</span></div>`;
  return `<form class="form-grid" data-form="scan">
    <div class="field full">
      <label for="${idPrefix}-target">Objetivo autorizado</label>
      <input id="${idPrefix}-target" name="target" placeholder="192.168.1.0/24 · 10.0.0.10 · host.interno" required autocomplete="off">
      <span class="hint">Solo redes propias o con autorización expresa. Los objetivos públicos requieren ROVSKA_ALLOW_PUBLIC=1.</span>
    </div>
    <div class="field">
      <label for="${idPrefix}-profile">Perfil</label>
      <select id="${idPrefix}-profile" name="profile">${options}</select>
    </div>
    <div class="field">
      <label for="${idPrefix}-options">Opciones (JSON)</label>
      <input id="${idPrefix}-options" name="options" placeholder='{"top_ports":1000}' autocomplete="off">
    </div>
    ${pveField}
    <div class="field full">
      <label class="check"><input type="checkbox" name="authorization"> Confirmo autorización expresa (obligatorio para objetivos públicos)</label>
    </div>
    <div class="actions full">
      <button class="btn primary" type="submit">Lanzar escaneo</button>
      <span class="hint">Se ejecuta en segundo plano; el log se abre automáticamente.</span>
    </div>
  </form>`;
}

function renderWelcome() {
  const active = activeTaskList();
  return `<div class="empty">
    <div class="glyph">▚</div>
    <h2>${active.length ? "No hay escaneos ROVSKA todavía" : "ROVSKA"}</h2>
    <p>${active.length
      ? "Hay tareas en ejecución. Puedes seguirlas en la franja superior o en Tareas, y lanzar un escaneo ROVSKA aquí."
      : "No hay escaneos todavía. Arranca el contenedor de herramientas y lanza el primero."}</p>
    ${active.length ? "" : `<pre>docker compose up -d
python3 -m rovvska scan 192.168.1.0/24 --profile quick</pre>`}
    <div class="panel" style="padding:16px;margin-top:18px;text-align:left">
      <div class="section-title">Nuevo escaneo</div>
      ${scanForm("welcome")}
      <div class="note" style="margin-top:12px">${toolsAvailabilityHtml()}</div>
    </div>
  </div>`;
}

function renderOverview() {
  const d = state.data;
  const g = d?.global;
  if (!g || !g.scan_id) return renderWelcome();

  const counts = g.counts || {};
  const total = g.total_findings || 0;
  const topHosts = (g.top_hosts || []).map((host) => {
    const meta = host.risk_meta || {};
    return `<button class="host-risk-row" data-host="${esc(host.ip)}" type="button">
      <span class="ip">${esc(host.ip)}</span>
      <span class="type-badge ${typeClass(host.type)}">${esc(shortType(host.type))}</span>
      <span class="os">${esc(host.os || "")} · ${host.findings} hallazgos</span>
      <span class="score" style="color:${RISK_VAR[meta.cls] || "var(--text)"}">${host.risk}</span>
    </button>`;
  }).join("");

  const findings = (g.findings || []).filter(
    (finding) => state.findFilter === "ALL" || finding.severity === state.findFilter
  );
  const filters = ["ALL", ...SEV_ORDER]
    .map(
      (sev) => `<button class="btn small${state.findFilter === sev ? " primary" : ""}" data-action="filter" data-sev="${esc(sev)}" type="button">${sev === "ALL" ? "Todos" : sev}</button>`
    )
    .join("");

  const typeItems = Object.entries(g.type_counts || {}).map(([name, count]) => ({ name, count }));
  const trend = d.trend || [];

  return `
  <section class="panel hero">
    <div class="hero-main">
      <div class="kicker">Panel general · ${esc(g.profile || "")}</div>
      <h2>${esc(g.target)}</h2>
      <div class="hero-sub">${esc(fmtDate(g.scanned_at))} · ${esc(g.mode || "")} · ${esc(g.status || "")} · ${g.total_hosts} hosts · ${g.total_ports} puertos</div>
      <div class="hero-tags">
        <span class="chip">escaneo <b>${esc(g.scan_id)}</b></span>
        ${g.source ? `<span class="chip">origen <b>${esc(g.source === "midgard" ? "MIDGARD" : "ROVSKA")}</b></span>` : ""}
        ${pveChip()}
        <span class="chip">informes <b>${d.reports_count || 0}</b></span>
        <span class="chip">servicios <b>${g.unique_services || 0}</b></span>
        <span class="chip">operaciones <b>${(d.operations || []).length}</b></span>
      </div>
    </div>
    ${riskGauge(g.risk)}
  </section>

  <div class="kpis">
    ${kpiCard("Hosts", g.total_hosts || 0, `${g.hosts_with_ports || 0} con puertos`)}
    ${kpiCard("Puertos", g.total_ports || 0, `${g.unique_services || 0} servicios únicos`)}
    ${kpiCard("Hallazgos", total, `${counts["CRÍTICO"] || 0} críticos · ${counts["ALTO"] || 0} altos`, counts["CRÍTICO"] ? "crit" : "")}
    ${kpiCard("Riesgo", `${g.risk?.score ?? 0}/100`, g.risk?.label || "", g.risk?.cls || "")}
  </div>

  <div class="charts">
    <div class="chart-card">
      <div class="chart-title">Severidad <span>${total} hallazgos</span></div>
      <div class="donut-wrap">${donut(counts, total, "hallazgos")}${legend(counts)}</div>
    </div>
    <div class="chart-card">
      <div class="chart-title">Servicios más vistos <span>top 10</span></div>
      ${bars(g.top_services || [], "blue")}
    </div>
    <div class="chart-card">
      <div class="chart-title">Puertos más abiertos <span>top 10</span></div>
      ${bars((g.top_ports || []).map((p) => ({ name: `${p.port}/${p.name || "?"}`, count: p.count })), "purple")}
    </div>
    <div class="chart-card">
      <div class="chart-title">Tipos de host <span>${(d.hosts || []).length} hosts</span></div>
      ${bars(typeItems, "green")}
    </div>
  </div>

  <div class="dash-grid">
    <div class="chart-card wide">
      <div class="chart-title">Evolución entre escaneos <span>${trend.length} puntos</span></div>
      <div class="spark-wrap" style="border:0;padding:0;margin:0;background:none">${sparkline(trend)}</div>
    </div>
    <div class="chart-card">
      <div class="chart-title">Hosts con más riesgo <span>top 10</span></div>
      ${topHosts || `<div class="muted small">Sin hosts con hallazgos.</div>`}
    </div>
    <div class="chart-card">
      <div class="chart-title">Últimos escaneos <span>${(d.scans || []).length}</span></div>
      <div class="scan-list">${(d.scans || []).slice(-6).reverse().map((scan) => `<div class="scan-row">
        <span>${esc(fmtDate(scan.started_at).slice(5))}</span>
        <b>${esc(scan.target)}</b>
        <span>${esc(scan.profile)}</span>
        <span class="num">${scan.findings} h</span>
      </div>`).join("") || `<div class="muted small">Sin escaneos.</div>`}</div>
    </div>
  </div>

  <div class="section-title mt">Hallazgos <span class="muted small">(${findings.length})</span></div>
  <div class="actions" style="margin-top:0;margin-bottom:10px">${filters}</div>
  ${findings.slice(0, 12).map((finding) => findingCard(finding)).join("") || `<div class="note">Sin hallazgos para este filtro.</div>`}
  ${findings.length > 12 ? `<button class="btn" data-action="all-findings" type="button">Ver los ${findings.length} hallazgos</button>` : ""}

  <div class="section-title mt">Comprobaciones positivas</div>
  ${goodList(g.good_checks)}

  <div class="section-title mt">Nuevo escaneo</div>
  <div class="panel" style="padding:16px">${scanForm("ov")}</div>
  <div class="note" style="margin-top:10px">${toolsAvailabilityHtml()}</div>

  <div class="section-title mt">Limitaciones</div>
  <div class="note"><ul style="margin:0;padding-left:18px">${(g.limitations || []).map((item) => `<li>${esc(item)}</li>`).join("")}</ul></div>
  `;
}

/* ---------- vista: host ---------- */

function renderHost(host) {
  const meta = host.risk_meta || {};
  const counts = host.severity_counts || {};
  const findings = host.findings || [];
  const tabs = [
    ["summary", "Resumen", findings.length],
    ["ports", "Puertos", (host.ports || []).length],
    ["findings", "Hallazgos", findings.length],
    ["attack", "ATT&CK", uniqueAttack(findings).length],
    ["history", "Historial", (host.history || []).length],
  ];

  return `
  <section class="panel hero">
    <div class="hero-main">
      <div class="kicker">${esc(effectiveType(host))}</div>
      <h2>${esc(host.ip)}${hostName(host) ? ` <span class="thin">· ${esc(hostName(host))}</span>` : ""}</h2>
      <div class="hero-sub">${esc(host.os || "SO desconocido")}${host.mac ? ` · ${esc(host.mac)}` : ""}${host.vendor ? ` · ${esc(host.vendor)}` : ""}</div>
      <div class="hero-tags">
        <span class="chip">puertos <b>${(host.ports || []).length}</b></span>
        <span class="chip">hallazgos <b>${findings.length}</b></span>
        <span class="chip">visto <b>${host.seen_count || 1}</b> vez/veces</span>
        ${host.proxmox ? `<span class="chip">proxmox <b>${esc(host.proxmox.node || "")}</b> · ${(host.proxmox.guests || []).length} invitados</span>` : ""}
        ${host.parent_ip ? `<span class="chip">invitado de <b>${esc(host.parent_ip)}</b></span>` : ""}
        ${(host.hostnames || []).map((name) => `<span class="chip">${esc(name)}</span>`).join("")}
      </div>
    </div>
    ${riskGauge(meta)}
  </section>

  <div class="kpis">
    ${kpiCard("Puertos", (host.ports || []).length, (host.ports || []).map((p) => p.port).slice(0, 6).join(", "))}
    ${kpiCard("Críticos", counts["CRÍTICO"] || 0, "requieren acción inmediata", "crit")}
    ${kpiCard("Altos", counts["ALTO"] || 0, "prioridad alta", "high")}
    ${kpiCard("Riesgo", `${meta.score ?? 0}/100`, meta.label || "", meta.cls || "")}
  </div>

  <div class="tabs">${tabs.map(([id, label, n]) => `<button class="tab${state.hostTab === id ? " active" : ""}" data-tab="${id}" type="button">${label}<span class="n">${n}</span></button>`).join("")}</div>
  <div class="tab-body">${renderHostTab(host)}</div>
  ${annotationForm(host)}
  `;
}

function uniqueAttack(findings) {
  const ids = new Set();
  for (const finding of findings) for (const id of finding.attack || []) ids.add(id);
  return [...ids].sort();
}

function techniqueIndex() {
  const index = {};
  const matrix = state.data?.global?.attack?.matrix;
  for (const tactic of matrix?.tactics || []) {
    for (const technique of tactic.techniques || []) index[technique.id] = technique;
  }
  return index;
}

function pveHostBlock(host) {
  if (host.proxmox) {
    const pve = host.proxmox;
    const guests = pve.guests || [];
    const rows = guests.map((guest) => {
      const kind = guest.kind === "lxc" ? "LXC" : "VM";
      const ip = guest.host_ip
        ? `<button class="btn small" type="button" data-host="${esc(guest.host_ip)}">${esc(guest.ip || guest.host_ip)}</button>`
        : esc(guest.ip || "sin IP detectada");
      return `<tr>
        <td>${kind} <b>${esc(guest.vmid || "")}</b></td>
        <td>${esc(guest.name || "—")}</td>
        <td>${ip}</td>
        <td>${esc(guest.status || "—")}</td>
        <td>${guest.scanned ? "escaneado" : "solo inventario"}</td>
      </tr>`;
    }).join("");
    return `<div class="section-title mt">Proxmox · nodo ${esc(pve.node || "")}</div>
      <div class="note" style="margin-bottom:8px">Inventario obtenido por API de solo lectura${pve.fetched_at ? ` · ${esc(pve.fetched_at)}` : ""}. Los invitados sin IP se muestran como «sin IP detectada».</div>
      ${rows ? `<div class="table-wrap"><table><thead><tr><th>Invitado</th><th>Nombre</th><th>IP</th><th>Estado</th><th>Contexto</th></tr></thead><tbody>${rows}</tbody></table></div>` : `<div class="note">El nodo no tiene VM/LXC visibles con el token actual.</div>`}`;
  }
  if (host.parent_ip) {
    const guest = host.proxmox_guest || {};
    const kind = guest.kind === "lxc" ? "LXC" : "VM";
    return `<div class="section-title mt">Proxmox</div>
      <div class="note">Invitado ${kind} <b>${esc(guest.vmid || "")}</b>${guest.name ? ` · ${esc(guest.name)}` : ""} del nodo <b>${esc(guest.node || "")}</b>.
      <button class="btn small" type="button" data-host="${esc(host.parent_ip)}">Abrir nodo ${esc(host.parent_ip)}</button></div>`;
  }
  return "";
}

function renderHostTab(host) {
  const findings = host.findings || [];
  if (state.hostTab === "ports") return portsTable(host);

  if (state.hostTab === "findings") {
    return findings.map((finding) => findingCard(finding, false)).join("") || `<div class="note">Sin hallazgos en este host.</div>`;
  }

  if (state.hostTab === "attack") {
    const index = techniqueIndex();
    const ids = uniqueAttack(findings);
    if (!ids.length) return `<div class="note">Sin técnicas ATT&amp;CK asociadas.</div>`;
    return `<div class="tool-grid">${ids.map((id) => {
      const tech = index[id] || { id, name: id, max_severity: "INFO", count: 1, hosts: [host.ip] };
      return `<div class="tool-card">
        <div class="tname"><span class="sev-dot ${sevClass(tech.max_severity)}"></span>${esc(tech.id)}</div>
        <div class="tdesc">${esc(tech.name)}</div>
        <div class="tmeta"><span class="chip">${esc(tech.tactic || "")}</span><span class="chip">${tech.count || 1} evidencia(s)</span></div>
      </div>`;
    }).join("")}</div>`;
  }

  if (state.hostTab === "history") {
    const history = host.history || [];
    if (!history.length) return `<div class="note">Sin historial.</div>`;
    return `<div class="spark-wrap">${sparkline(history)}</div>
      <div class="timeline">${history.slice().reverse().map((item) => `<div class="tl-row">
        <span class="when">${esc(fmtDate(item.scanned_at))}</span>
        <span class="ty">${esc(item.profile)} · ${esc(item.target)}</span>
        <span class="num">${item.ports} puertos</span>
        <span class="num">${item.risk}</span>
      </div>`).join("")}</div>`;
  }

  const top = findings.slice(0, 4);
  return `
    <div class="table-wrap"><table>
      <thead><tr><th>Propiedad</th><th>Valor</th></tr></thead>
      <tbody>
        <tr><td>IP</td><td>${esc(host.ip)}</td></tr>
        <tr><td>Nombre</td><td>${esc(hostName(host) || "—")}</td></tr>
        <tr><td>Tipo</td><td>${esc(effectiveType(host))}</td></tr>
        <tr><td>Sistema operativo</td><td>${esc(host.os || "SO desconocido")}</td></tr>
        <tr><td>MAC / fabricante</td><td>${esc([host.mac, host.vendor].filter(Boolean).join(" · ") || "—")}</td></tr>
        <tr><td>Hostnames</td><td>${esc((host.hostnames || []).join(", ") || "—")}</td></tr>
        ${host.proxmox ? `<tr><td>Proxmox</td><td>nodo <b>${esc(host.proxmox.node || "")}</b> · ${(host.proxmox.guests || []).length} invitados</td></tr>` : ""}
        ${host.parent_ip ? `<tr><td>Proxmox</td><td>invitado de ${esc(host.parent_ip)}</td></tr>` : ""}
        <tr><td>Primera / última vez</td><td>${esc(fmtDate(host.first_seen))} → ${esc(fmtDate(host.last_seen))}</td></tr>
      </tbody></table></div>
    ${pveHostBlock(host)}
    <div class="section-title mt">Puertos abiertos</div>
    ${portsTable(host)}
    <div class="section-title mt">Hallazgos principales</div>
    ${top.map((finding) => findingCard(finding, false)).join("") || `<div class="note">Sin hallazgos.</div>`}
  `;
}

/* ---------- vista: operaciones ---------- */

function toolOptions(selected = "") {
  const tools = state.tools || [];
  if (!tools.length) return `<option value="">(catálogo no cargado)</option>`;
  return tools.map((tool) => `<option value="${esc(tool.name)}"${tool.name === selected ? " selected" : ""}>${esc(tool.name)}${tool.requires_attack ? " (ataque)" : ""}${tool.available ? "" : " · no disponible"}</option>`).join("");
}

function operationForm() {
  return `<form class="form-grid" data-form="operation">
    <div class="field">
      <label for="op-tool">Herramienta</label>
      <select id="op-tool" name="tool">${toolOptions()}</select>
    </div>
    <div class="field">
      <label for="op-target">Objetivo</label>
      <input id="op-target" name="target" placeholder="10.0.0.10" required autocomplete="off">
    </div>
    <div class="field full">
      <label for="op-params">Parámetros (JSON)</label>
      <textarea id="op-params" name="params" placeholder='{"ports":[22,80],"module":"auxiliary/scanner/ssh/ssh_version"}'></textarea>
    </div>
    <div class="field">
      <label class="check"><input type="checkbox" name="dry_run" checked> Dry-run (no toca el objetivo)</label>
    </div>
    <div class="field">
      <label class="check"><input type="checkbox" name="authorization"> Autorización expresa</label>
    </div>
    <div class="actions full">
      <button class="btn primary" type="submit">Lanzar operación</button>
      <span class="hint">Hydra/Metasploit requieren ROVSKA_ALLOW_ATTACK=1 además de autorización.</span>
    </div>
  </form>`;
}

function renderOperations() {
  const operations = state.data?.operations || [];
  const rows = operations.map((op) => `<tr class="op-row" data-op-id="${esc(op.id)}">
    <td>${esc(fmtDate(op.started_at))}</td>
    <td><b>${esc(op.tool)}</b><div class="svc-sub">${esc(op.kind)}</div></td>
    <td>${esc(op.target)}</td>
    <td><span class="op-status ${esc(op.status)}">${esc(op.status)}</span></td>
    <td><span class="dry-tag${op.dry_run ? "" : " real"}">${op.dry_run ? "dry-run" : "real"}</span></td>
    <td class="num">${op.exit_code ?? "—"}</td>
  </tr>`).join("");

  return `
  <section class="panel hero">
    <div class="hero-main">
      <div class="kicker">Operaciones</div>
      <h2>Herramientas bajo control</h2>
      <div class="hero-sub">Cada operación queda registrada con su comando, estado y evidencia. Las ofensivas son dry-run por defecto.</div>
      <div class="hero-tags">
        <span class="chip">total <b>${operations.length}</b></span>
        <span class="chip">en curso <b>${operations.filter((op) => ["queued", "running"].includes(op.status)).length}</b></span>
        <span class="chip">reales <b>${operations.filter((op) => !op.dry_run).length}</b></span>
      </div>
    </div>
  </section>

  <div class="section-title mt">Nueva operación</div>
  <div class="panel" style="padding:16px">${operationForm()}</div>

  <div class="section-title mt">Herramientas disponibles</div>
  <div class="note" style="margin-bottom:10px">Catálogo de herramientas que puedes lanzar desde el formulario de operación. El estado indica si el binario está disponible en el runner actual.</div>
  ${toolsCatalogHtml()}

  <div class="section-title mt">Historial</div>
  <div class="table-wrap"><table>
    <thead><tr><th>Inicio</th><th>Herramienta</th><th>Objetivo</th><th>Estado</th><th>Modo</th><th class="num">Exit</th></tr></thead>
    <tbody>${rows || `<tr><td colspan="6" class="muted">Sin operaciones.</td></tr>`}</tbody>
  </table></div>
  <div class="note" style="margin-top:10px">Haz clic en una fila para ver el comando, el resultado y el log en vivo.</div>
  `;
}

/* ---------- vista: tareas ---------- */

const TASK_STATUS_LABELS = {
  queued: "En cola",
  running: "Activo",
  cancelling: "Cancelando",
  done: "Completado",
  error: "Fallido",
  cancelled: "Cancelado",
  interrupted: "Interrumpido",
  unknown: "Desconocido",
};
const TASK_ACTIVE = new Set(["queued", "running", "cancelling"]);

function taskStatusLabel(status) {
  return TASK_STATUS_LABELS[status] || status || "—";
}

function taskTypeLabel(type) {
  const value = String(type || "").toLowerCase();
  if (value === "scan") return "Escaneo";
  if (value === "operation") return "Operación";
  if (value === "import") return "Importación";
  if (value === "orchestration") return "Orquestación";
  if (value === "midgard") return "Auditoría MIDGARD";
  if (value === "netmap") return "Barrido NetMap";
  return type || "Tarea";
}

function fmtDuration(seconds) {
  const total = Math.max(0, Number(seconds || 0));
  if (total < 60) return `${total}s`;
  const minutes = Math.floor(total / 60);
  const secs = total % 60;
  if (minutes < 60) return `${minutes}m ${String(secs).padStart(2, "0")}s`;
  const hours = Math.floor(minutes / 60);
  return `${hours}h ${String(minutes % 60).padStart(2, "0")}m`;
}

function taskDuration(startedAt, finishedAt) {
  if (!startedAt) return 0;
  const start = Date.parse(String(startedAt).replace(" ", "T"));
  const end = finishedAt ? Date.parse(String(finishedAt).replace(" ", "T")) : Date.now();
  if (!Number.isFinite(start) || !Number.isFinite(end)) return 0;
  return Math.max(0, Math.round((end - start) / 1000));
}

function taskStatusOf(status, job) {
  const dbStatus = String(status || "").toLowerCase();
  if (["done", "error", "cancelled"].includes(dbStatus)) return dbStatus;
  if (job && ["done", "error", "cancelled", "cancelling", "running", "queued"].includes(job.status)) {
    return job.status;
  }
  if (["queued", "running"].includes(dbStatus)) return "interrupted";
  return dbStatus || "unknown";
}

function tasksFallback() {
  const d = state.data || {};
  const jobs = new Map((d.jobs || []).map((job) => [job.id, job]));
  const operations = d.operations || [];
  const tasks = [];
  const seen = new Set();

  for (const scan of d.scans || []) {
    if (!scan.id) continue;
    const operation = operations.find((op) => op.kind === "scan" && op.scan_id === scan.id);
    const job = jobs.get(scan.id);
    const status = taskStatusOf(scan.status, job);
    tasks.push({
      id: scan.id,
      entity_id: scan.id,
      operation_id: operation?.id || "",
      scan_id: scan.id,
      type: String(scan.profile || "").toLowerCase() === "import" ? "import" : "scan",
      target: scan.target || "",
      label: scan.profile || "scan",
      profile: scan.profile || "",
      tool: "",
      status,
      status_label: taskStatusLabel(status),
      started_at: scan.started_at || "",
      finished_at: scan.finished_at || "",
      duration_seconds: taskDuration(scan.started_at, scan.finished_at),
      active: TASK_ACTIVE.has(status),
      can_cancel: TASK_ACTIVE.has(status) || status === "interrupted",
      cancel_kind: "scan",
      dry_run: operation ? Boolean(operation.dry_run) : scan.profile !== "attack",
      log_available: Boolean(operation?.id),
      error: scan.error || "",
      current: "",
      current_at: "",
    });
    seen.add(scan.id);
    if (operation?.id) seen.add(operation.id);
  }

  for (const operation of operations) {
    if (operation.kind === "scan" || seen.has(operation.id)) continue;
    const job = jobs.get(operation.id);
    const status = taskStatusOf(operation.status, job);
    tasks.push({
      id: operation.id,
      entity_id: operation.id,
      operation_id: operation.id,
      scan_id: operation.scan_id || "",
      type: "operation",
      target: operation.target || "",
      label: operation.tool || "tool",
      profile: "",
      tool: operation.tool || "",
      status,
      status_label: taskStatusLabel(status),
      started_at: operation.started_at || "",
      finished_at: operation.finished_at || "",
      duration_seconds: taskDuration(operation.started_at, operation.finished_at),
      active: TASK_ACTIVE.has(status),
      can_cancel: TASK_ACTIVE.has(status) || status === "interrupted",
      cancel_kind: "operation",
      dry_run: Boolean(operation.dry_run),
      log_available: true,
      error: operation.error || "",
      current: "",
      current_at: "",
    });
    seen.add(operation.id);
  }

  for (const job of d.jobs || []) {
    if (seen.has(job.id)) continue;
    const status = taskStatusOf("", job);
    tasks.push({
      id: job.id,
      entity_id: job.id,
      operation_id: "",
      scan_id: "",
      type: job.kind || "job",
      target: job.target || "—",
      label: job.kind || "job",
      profile: "",
      tool: "",
      status,
      status_label: taskStatusLabel(status),
      started_at: job.started_at || "",
      finished_at: "",
      duration_seconds: taskDuration(job.started_at, ""),
      active: TASK_ACTIVE.has(status),
      can_cancel: false,
      cancel_kind: "",
      dry_run: false,
      log_available: false,
      error: job.error || "",
      current: "",
      current_at: "",
    });
  }

  tasks.sort((a, b) => String(b.started_at || "").localeCompare(String(a.started_at || "")));
  tasks.sort((a, b) => {
    const rank = (task) => (task.active || task.status === "interrupted" ? 0 : 1);
    return rank(a) - rank(b);
  });
  return {
    generated_at: new Date().toISOString(),
    tasks,
    counts: {
      total: tasks.length,
      active: tasks.filter((task) => task.active).length,
      queued: tasks.filter((task) => task.status === "queued").length,
      running: tasks.filter((task) => task.status === "running").length,
      done: tasks.filter((task) => task.status === "done").length,
      error: tasks.filter((task) => task.status === "error").length,
      cancelled: tasks.filter((task) => task.status === "cancelled").length,
      interrupted: tasks.filter((task) => task.status === "interrupted").length,
    },
  };
}

function renderTaskRows(tasks) {
  if (!tasks.length) {
    return `<div class="note">No hay tareas todavía. Lanza un escaneo u operación para verlas aquí.</div>`;
  }
  return `<div class="table-wrap"><table class="task-table">
    <thead><tr><th>Objetivo</th><th>Tipo</th><th>Perfil / herramienta</th><th>Estado</th><th>Inicio</th><th class="num">Duración</th><th>Último paso</th><th>Acciones</th></tr></thead>
    <tbody>${tasks.map((task) => {
      const current = task.current || task.error || (task.active ? "esperando salida…" : "");
      const mode = task.type === "operation" ? `<span class="dry-tag${task.dry_run ? "" : " real"}">${task.dry_run ? "dry-run" : "real"}</span>` : "";
      const logButton = task.log_available
        ? `<button class="btn small" type="button" data-task-log="${esc(task.id)}">Ver log</button>`
        : "";
      const cancelButton = task.can_cancel
        ? `<button class="btn small danger" type="button" data-task-cancel="${esc(task.id)}" data-cancel-kind="${esc(task.cancel_kind)}">Cancelar</button>`
        : "";
      return `<tr class="task-row${task.active ? " active" : ""}">
        <td class="mono"><b>${esc(task.target || "—")}</b>${task.scan_id && task.type !== "scan" && task.type !== "import" ? `<div class="svc-sub">${esc(task.scan_id)}</div>` : ""}</td>
        <td>${esc(taskTypeLabel(task.type))}</td>
        <td>${esc(task.label || "—")} ${mode}</td>
        <td><span class="task-status ${esc(task.status)}"><i></i>${esc(task.status_label || taskStatusLabel(task.status))}</span></td>
        <td class="mono">${esc(fmtTaskDate(task.started_at) || "—")}</td>
        <td class="num">${fmtDuration(task.duration_seconds)}</td>
        <td class="task-current" title="${esc(task.current || task.error || "")}">${esc(current || "—")}</td>
        <td><div class="task-actions">${logButton}${cancelButton}${!logButton && !cancelButton ? `<span class="muted small">—</span>` : ""}</div></td>
      </tr>`;
    }).join("")}</tbody>
  </table></div>`;
}

function renderTasksBody(data) {
  if (state.tasksError) {
    return `<div class="note" style="border-color:var(--crit)">No se pudieron cargar las tareas: ${esc(state.tasksError)}</div>`;
  }
  const counts = data?.counts || {};
  const tasks = data?.tasks || [];
  return `
    <div class="hero-tags task-chips">
      <span class="chip">total <b>${counts.total ?? tasks.length}</b></span>
      <span class="chip">activas <b>${counts.active ?? 0}</b></span>
      <span class="chip">en cola <b>${counts.queued ?? 0}</b></span>
      <span class="chip">completadas <b>${counts.done ?? 0}</b></span>
      <span class="chip">fallidas <b>${counts.error ?? 0}</b></span>
      <span class="chip">interrumpidas <b>${counts.interrupted ?? 0}</b></span>
      <span class="chip muted">actualizado <b>${esc(fmtDate(data?.generated_at) || "—")}</b></span>
    </div>
    ${renderTaskRows(tasks)}`;
}

function renderTasks() {
  return `
  <section class="panel hero">
    <div class="hero-main">
      <div class="kicker">Tareas</div>
      <h2>Qué está pasando ahora</h2>
      <div class="hero-sub">Escaneos, operaciones e importaciones en segundo plano. La tabla se actualiza cada 5 segundos; puedes abrir el log o cancelar una tarea activa.</div>
    </div>
    <div class="hero-risk">
      <button class="btn" type="button" data-action="tasks-refresh">Actualizar</button>
      <button class="btn danger" type="button" data-action="tasks-clear">Limpiar completadas</button>
    </div>
  </section>
  <div id="tasks-body">${state.tasks ? renderTasksBody(state.tasks) : `<div class="muted small">Cargando tareas…</div>`}</div>`;
}

function taskAlertCount(data) {
  const counts = data?.counts || {};
  return Number(counts.active || 0) + Number(counts.interrupted || 0);
}

function updateTaskBadge(count) {
  const badge = document.getElementById("task-count");
  if (!badge) return;
  const active = Number(count || 0);
  badge.hidden = active <= 0;
  badge.textContent = active > 99 ? "99+" : String(active);
}

async function loadTasks() {
  try {
    const data = await api("/api/tasks");
    state.tasks = data;
    state.tasksAt = data.generated_at || "";
    state.tasksError = "";
  } catch (error) {
    // Compatibilidad con un servidor aún no reiniciado: reconstruye la vista
    // con /api/data mientras /api/tasks no exista.
    if (/404|no encontrada/i.test(error.message || "")) {
      state.tasks = tasksFallback();
      state.tasksAt = state.tasks.generated_at;
      state.tasksError = "";
    } else {
      state.tasksError = error.message || "error desconocido";
    }
  }
  updateTaskBadge(taskAlertCount(state.tasks));
  renderActiveStrip();
  const body = document.getElementById("tasks-body");
  if (body && state.view === "tasks") body.innerHTML = renderTasksBody(state.tasks);
}

async function openTaskLog(taskId) {
  const task = (state.tasks?.tasks || []).find((item) => item.id === taskId);
  if (!task) return;
  if (task.operation_id) {
    try {
      const operation = await api(`/api/operations/${encodeURIComponent(task.operation_id)}`);
      watchOperation(operation);
    } catch (error) {
      toast(error.message, true);
    }
    return;
  }
  if (task.scan_id) {
    watchScan(task.scan_id);
    return;
  }
  if (task.type === "midgard" || task.type === "netmap") {
    watchIntegrationJob(task.type, task.id);
    return;
  }
  toast("Esta tarea no tiene log disponible", true);
}

async function cancelTask(taskId, cancelKind) {
  const task = (state.tasks?.tasks || []).find((item) => item.id === taskId);
  const target = task?.target || taskId;
  if (!window.confirm(`¿Cancelar la tarea ${target}? La herramienta en curso puede terminar su paso actual.`)) {
    return;
  }
  const endpoint = {
    scan: `/api/scans/${encodeURIComponent(taskId)}/cancel`,
    operation: `/api/operations/${encodeURIComponent(taskId)}/cancel`,
    midgard: `/api/midgard/jobs/${encodeURIComponent(taskId)}/cancel`,
    netmap: `/api/netmap/jobs/${encodeURIComponent(taskId)}/cancel`,
  }[cancelKind];
  if (!endpoint) {
    toast("Esta tarea no se puede cancelar desde el panel", true);
    return;
  }
  try {
    await api(endpoint, { method: "POST", body: "{}" });
    toast("Cancelación solicitada");
    await loadTasks();
    setTimeout(() => load(), 800);
  } catch (error) {
    toast(error.message, true);
  }
}

/* ---------- vista: ATT&CK ---------- */

function renderAttack() {
  const g = state.data?.global;
  const matrix = g?.attack?.matrix;
  if (!matrix || !matrix.tactics?.length) return `<div class="note">Sin datos ATT&amp;CK. Ejecuta un escaneo primero.</div>`;
  const chain = g.attack.kill_chain || { stages: [] };
  const coverage = g.attack.coverage || {};

  const columns = matrix.tactics.map((tactic) => {
    const cells = (tactic.techniques || []).map((technique) => `<div class="matrix-cell ${sevClass(technique.max_severity)}" data-tech="${esc(technique.id)}">
      <div class="id">${esc(technique.id)}</div>
      <div class="nm">${esc(technique.name)}</div>
      <div class="cnt">${technique.count} evidencia(s) · ${(technique.hosts || []).length} host(s)</div>
    </div>`).join("");
    return `<div class="matrix-col">
      <div class="matrix-head"><b>${esc(tactic.name)}</b><span class="n">${tactic.techniques_count} técnicas · ${tactic.count} obs.</span></div>
      ${cells || `<div class="matrix-empty">sin evidencia</div>`}
    </div>`;
  }).join("");

  const stages = (chain.stages || []).map((stage) => {
    const cls = stage.status === "observado" ? "observed" : stage.status === "no evaluado" ? "unassessed" : "";
    const steps = (stage.steps || []).slice(0, 5).map((step) => `<div class="stage-step"><b>${esc(step.technique || "")}</b> ${esc(step.title)}${step.host ? ` <em>${esc(step.host)}</em>` : ""}</div>`).join("");
    return `<div class="stage ${cls}">
      <div class="stage-name">${esc(stage.name)}</div>
      <div class="stage-status">${esc(stage.status)}</div>
      ${steps || `<div class="stage-step muted">sin evidencia</div>`}
    </div>`;
  }).join("");

  return `
  <section class="panel hero">
    <div class="hero-main">
      <div class="kicker">MITRE ATT&amp;CK · Enterprise</div>
      <h2>Matriz de técnicas observadas</h2>
      <div class="hero-sub">Cada técnica enlaza los hallazgos y operaciones que la evidencian. Las celdas vacías indican táctica sin evidencia.</div>
      <div class="hero-tags">
        <span class="chip">técnicas únicas <b>${matrix.unique}</b></span>
        <span class="chip">observaciones <b>${matrix.total}</b></span>
        <span class="chip">catálogo cubierto <b>${coverage.total_covered || 0}/${coverage.total_catalog || 0}</b></span>
      </div>
    </div>
  </section>

  <div class="section-title mt">Matriz</div>
  <div class="matrix-wrap"><div class="matrix">${columns}</div></div>

  <div class="section-title mt">Cadena de ataque reconstruida</div>
  <div class="chain">${stages}</div>
  <div class="note" style="margin-top:10px">Fases como instalación, C2 y acciones sobre objetivos no se evalúan sin agente: se marcan como <b>no evaluado</b> para no inventar evidencia.</div>
  `;
}

/* ---------- vista: marcos ---------- */

function renderFrameworks() {
  const g = state.data?.global;
  const fw = g?.frameworks;
  if (!fw || !fw.ptes) return `<div class="note">Sin datos de marcos. Ejecuta un escaneo primero.</div>`;

  const ptesRows = (fw.ptes || []).map((phase) => `<tr>
    <td><b>${esc(phase.name)}</b></td><td>${esc(phase.description)}</td><td class="num">${phase.count}</td>
  </tr>`).join("");

  const osstmm = (fw.osstmm?.channels || []).map((channel) => `<tr>
    <td><b>${esc(channel.name)}</b></td>
    <td>${channel.modules.map((mod) => `<span class="chip">${esc(mod.id)} · ${esc(mod.name)} (${mod.count})</span>`).join(" ")}</td>
  </tr>`).join("");

  const owaspRows = (fw.owasp?.top10 || []).map((item) => `<tr class="${item.count ? "" : "muted"}">
    <td><b>${esc(item.id)}</b></td><td>${esc(item.name)}</td><td class="num">${item.count}</td>
  </tr>`).join("");

  const wstgRows = (fw.owasp?.wstg || []).filter((item) => item.count).map((item) => `<tr>
    <td><b>${esc(item.id)}</b></td><td>${esc(item.name)}</td><td class="num">${item.count}</td>
  </tr>`).join("");

  const cweRows = (fw.cwe || []).map((item) => `<tr>
    <td><b>${esc(item.id)}</b></td><td>${esc(item.name)}</td><td class="num">${item.count}</td>
  </tr>`).join("");

  return `
  <section class="panel hero">
    <div class="hero-main">
      <div class="kicker">Metodologías</div>
      <h2>PTES · OSSTMM · OWASP · CWE</h2>
      <div class="hero-sub">Cada hallazgo se clasifica en una fase PTES, un módulo OSSTMM, una categoría OWASP y una debilidad CWE para que el informe sea trazable.</div>
    </div>
  </section>

  <div class="section-title mt">PTES</div>
  <div class="table-wrap"><table><thead><tr><th>Fase</th><th>Descripción</th><th class="num">Hallazgos</th></tr></thead><tbody>${ptesRows}</tbody></table></div>

  <div class="section-title mt">OSSTMM</div>
  <div class="table-wrap"><table><thead><tr><th>Canal</th><th>Módulos</th></tr></thead><tbody>${osstmm}</tbody></table></div>

  <div class="section-title mt">OWASP Top 10 (2021)</div>
  <div class="table-wrap"><table><thead><tr><th>ID</th><th>Categoría</th><th class="num">Hallazgos</th></tr></thead><tbody>${owaspRows}</tbody></table></div>

  <div class="section-title mt">OWASP WSTG</div>
  <div class="table-wrap"><table><thead><tr><th>ID</th><th>Área</th><th class="num">Hallazgos</th></tr></thead><tbody>${wstgRows || `<tr><td colspan="3" class="muted">Sin hallazgos web mapeados.</td></tr>`}</tbody></table></div>

  <div class="section-title mt">CWE</div>
  <div class="table-wrap"><table><thead><tr><th>ID</th><th>Debilidad</th><th class="num">Hallazgos</th></tr></thead><tbody>${cweRows || `<tr><td colspan="3" class="muted">Sin CWE.</td></tr>`}</tbody></table></div>
  `;
}

/* ---------- vista: comparativa ---------- */

function scanLabel(scan) {
  return `${scan.target || "?"} · ${scan.started_at || ""} · ${scan.profile || ""}`;
}

function renderCompare() {
  const scans = state.data?.scans || [];
  if (scans.length < 2) {
    return `<section class="panel hero"><div class="hero-main"><div class="kicker">Comparativa</div>
      <h2>Diferencias entre escaneos</h2>
      <div class="hero-sub">Necesitas al menos dos escaneos para comparar. Lanza otro escaneo o importa un informe JSON/XML.</div>
    </div></section>`;
  }
  const ids = scans.map((scan) => scan.id);
  let base = state.compareBase && ids.includes(state.compareBase) ? state.compareBase : ids[Math.max(0, ids.length - 2)];
  let target = state.compareTarget && ids.includes(state.compareTarget) ? state.compareTarget : ids[ids.length - 1];
  if (base === target && ids.length > 1) base = ids[ids.length - 2];
  state.compareBase = base;
  state.compareTarget = target;
  const options = (selected) => scans.slice().reverse().map((scan) => `
    <option value="${esc(scan.id)}" ${scan.id === selected ? "selected" : ""}>${esc(scanLabel(scan))}</option>`).join("");
  return `
  <section class="panel hero">
    <div class="hero-main">
      <div class="kicker">Comparativa</div>
      <h2>Evolución entre escaneos</h2>
      <div class="hero-sub">Nuevos hallazgos, cerrados, cambios de severidad, puertos y técnicas ATT&amp;CK. El diff se calcula sobre los informes normalizados.</div>
    </div>
  </section>
  <form data-form="compare" class="panel cmp-form">
    <div class="field">
      <label for="compare-base">Escaneo base</label>
      <select id="compare-base" name="base">${options(base)}</select>
    </div>
    <div class="field">
      <label for="compare-target">Escaneo objetivo</label>
      <select id="compare-target" name="target">${options(target)}</select>
    </div>
    <div class="actions"><button class="btn primary" type="submit">Comparar</button></div>
  </form>
  <div id="compare-body"><div class="muted small">Calculando diferencias…</div></div>`;
}

function deltaClass(value) {
  if (Number(value) > 0) return "delta-up";
  if (Number(value) < 0) return "delta-down";
  return "delta-flat";
}

function signed(value) {
  const n = Number(value || 0);
  return n > 0 ? `+${n}` : String(n);
}

function compareFindingRows(items, emptyLabel) {
  if (!items || !items.length) return `<div class="note">${esc(emptyLabel)}</div>`;
  return `<div class="table-wrap"><table>
    <thead><tr><th>Severidad</th><th>Hallazgo</th><th>Host</th><th>Origen</th><th>CVE / CWE</th></tr></thead>
    <tbody>${items.map((finding) => `<tr>
      <td><span class="badge ${sevClass(finding.severity)}">${esc(finding.severity)}</span></td>
      <td>${esc(finding.title)}</td>
      <td class="mono">${esc(finding.host || "—")}</td>
      <td>${esc(finding.source || "—")}</td>
      <td>${esc([...(finding.cves || []), ...(finding.cwe || [])].join(" · ") || "—")}</td>
    </tr>`).join("")}</tbody></table></div>`;
}

function comparePortRows(items, emptyLabel) {
  if (!items || !items.length) return `<div class="note">${esc(emptyLabel)}</div>`;
  return `<div class="table-wrap"><table>
    <thead><tr><th>Host</th><th>Puerto</th><th>Servicio</th><th>Producto</th><th>Versión</th></tr></thead>
    <tbody>${items.map((port) => `<tr>
      <td class="mono">${esc(port.ip)}</td>
      <td class="num">${esc(port.port)}/${esc(port.proto)}</td>
      <td>${esc(port.name || "—")}</td>
      <td>${esc(port.product || "—")}</td>
      <td>${esc(port.version || "—")}</td>
    </tr>`).join("")}</tbody></table></div>`;
}

function compareHostRows(items, emptyLabel) {
  if (!items || !items.length) return `<div class="note">${esc(emptyLabel)}</div>`;
  return `<div class="table-wrap"><table>
    <thead><tr><th>IP</th><th>Tipo</th><th>SO</th><th class="num">Puertos</th><th class="num">Riesgo</th></tr></thead>
    <tbody>${items.map((host) => `<tr>
      <td class="mono">${esc(host.ip)}</td>
      <td>${esc(host.type || "—")}</td>
      <td>${esc(host.os || "—")}</td>
      <td class="num">${(host.ports || []).length}</td>
      <td class="num">${esc(host.risk ?? 0)}</td>
    </tr>`).join("")}</tbody></table></div>`;
}

function renderCompareResult(data) {
  const delta = data.delta || {};
  const f = data.findings || {};
  const p = data.ports || {};
  const h = data.hosts || {};
  const attack = data.attack || {};
  const base = data.base || {};
  const target = data.target || {};
  const changedRows = (f.changed || []).map((item) => `<tr>
      <td><span class="badge ${sevClass(item.before)}">${esc(item.before)}</span> → <span class="badge ${sevClass(item.after)}">${esc(item.after)}</span></td>
      <td>${esc(item.title)}</td><td class="mono">${esc(item.host || "—")}</td>
      <td>${esc(item.direction || "")}</td></tr>`).join("");
  return `
  <div class="cmp-grid">
    <div class="kpi ${delta.direction === "empeora" ? "warn" : delta.direction === "mejora" ? "ok" : ""}">
      <div class="l">Riesgo</div><div class="v ${deltaClass(delta.risk)}">${signed(delta.risk)}</div>
      <div class="s">${esc(base.risk?.score ?? 0)} → ${esc(target.risk?.score ?? 0)} · ${esc(delta.direction || "")}</div>
    </div>
    <div class="kpi"><div class="l">Hallazgos nuevos</div><div class="v delta-up">${(f.added || []).length}</div><div class="s">cerrados: ${(f.removed || []).length}</div></div>
    <div class="kpi"><div class="l">Puertos nuevos</div><div class="v delta-up">${(p.added || []).length}</div><div class="s">cerrados: ${(p.removed || []).length}</div></div>
    <div class="kpi"><div class="l">Hosts nuevos</div><div class="v delta-up">${(h.added || []).length}</div><div class="s">retirados: ${(h.removed || []).length}</div></div>
  </div>

  <div class="note cmp-headline">${esc(delta.headline || "")}</div>

  <div class="cmp-scan-row">
    <div class="cmp-scan"><span>Base</span><b>${esc(base.target || "?")}</b><i>${esc(base.scanned_at || "")}</i><em>${esc(base.profile || "")} · ${base.hosts ?? 0} hosts · ${base.findings ?? 0} hallazgos</em></div>
    <div class="cmp-arrow">→</div>
    <div class="cmp-scan"><span>Objetivo</span><b>${esc(target.target || "?")}</b><i>${esc(target.scanned_at || "")}</i><em>${esc(target.profile || "")} · ${target.hosts ?? 0} hosts · ${target.findings ?? 0} hallazgos</em></div>
  </div>

  <div class="section-title mt">Hallazgos nuevos · ${(f.added || []).length}</div>
  ${compareFindingRows(f.added, "Sin hallazgos nuevos.")}

  <div class="section-title mt">Hallazgos cerrados · ${(f.removed || []).length}</div>
  ${compareFindingRows(f.removed, "Sin hallazgos cerrados.")}

  <div class="section-title mt">Cambios de severidad · ${(f.changed || []).length}</div>
  ${changedRows ? `<div class="table-wrap"><table><thead><tr><th>Cambio</th><th>Hallazgo</th><th>Host</th><th>Dirección</th></tr></thead><tbody>${changedRows}</tbody></table></div>` : `<div class="note">Sin cambios de severidad.</div>`}

  <div class="section-title mt">Hosts</div>
  <div class="cmp-cols">
    <div><h4>Nuevos · ${(h.added || []).length}</h4>${compareHostRows(h.added, "Sin hosts nuevos.")}</div>
    <div><h4>Retirados · ${(h.removed || []).length}</h4>${compareHostRows(h.removed, "Sin hosts retirados.")}</div>
  </div>

  <div class="section-title mt">Puertos</div>
  <div class="cmp-cols">
    <div><h4>Nuevos · ${(p.added || []).length}</h4>${comparePortRows(p.added, "Sin puertos nuevos.")}</div>
    <div><h4>Cerrados · ${(p.removed || []).length}</h4>${comparePortRows(p.removed, "Sin puertos cerrados.")}</div>
  </div>
  ${(p.changed || []).length ? `<div class="section-title mt">Puertos con cambios · ${(p.changed || []).length}</div>
    <div class="table-wrap"><table><thead><tr><th>Host</th><th>Puerto</th><th>Cambios</th></tr></thead><tbody>
    ${(p.changed || []).map((port) => `<tr><td class="mono">${esc(port.ip)}</td><td class="num">${esc(port.port)}/${esc(port.proto)}</td>
      <td>${Object.entries(port.changes || {}).map(([field, change]) => `${esc(field)}: ${esc(change.before || "—")} → ${esc(change.after || "—")}`).join("<br>")}</td></tr>`).join("")}
    </tbody></table></div>` : ""}

  <div class="section-title mt">Técnicas ATT&amp;CK</div>
  <div class="cmp-cols">
    <div><h4>Nuevas · ${(attack.added || []).length}</h4>${(attack.added || []).length ? `<div class="chips">${attack.added.map((t) => `<i title="${esc(t.name)}">${esc(t.id)}</i>`).join("")}</div>` : `<div class="note">Sin técnicas nuevas.</div>`}</div>
    <div><h4>Desaparecidas · ${(attack.removed || []).length}</h4>${(attack.removed || []).length ? `<div class="chips">${attack.removed.map((t) => `<i title="${esc(t.name)}">${esc(t.id)}</i>`).join("")}</div>` : `<div class="note">Sin técnicas desaparecidas.</div>`}</div>
  </div>`;
}

async function loadCompare() {
  const body = document.getElementById("compare-body");
  if (!body) return;
  const base = document.getElementById("compare-base")?.value || state.compareBase;
  const target = document.getElementById("compare-target")?.value || state.compareTarget;
  if (!base || !target) {
    body.innerHTML = `<div class="note">Selecciona dos escaneos.</div>`;
    return;
  }
  state.compareBase = base;
  state.compareTarget = target;
  body.innerHTML = `<div class="muted small">Calculando diferencias…</div>`;
  try {
    const data = await api(`/api/compare?base=${encodeURIComponent(base)}&target=${encodeURIComponent(target)}`);
    body.innerHTML = renderCompareResult(data);
  } catch (error) {
    body.innerHTML = `<div class="note">No se pudo comparar: ${esc(error.message)}</div>`;
  }
}

/* ---------- vista: informes ---------- */

function renderReports() {
  const latest = state.data?.latest || {};
  return `
  <section class="panel hero">
    <div class="hero-main">
      <div class="kicker">Informes</div>
      <h2>Exportaciones e importación</h2>
      <div class="hero-sub">JSON, XML, HTML, PDF profesional, SARIF y CSV. El PDF incluye portada, resumen ejecutivo, ATT&amp;CK y cadena de ataque.</div>
      <div class="hero-tags">
        <span class="chip">directorio <b>${esc(state.data?.reports_dir || "")}</b></span>
        <span class="chip">total <b>${state.data?.reports_count || 0}</b></span>
      </div>
    </div>
    <div class="hero-risk reports-actions">
      <button class="btn danger" data-action="reports-delete-all" type="button">Borrar informes e historial</button>
      <button class="btn primary" data-action="regen" data-scan="${esc(latest.scan_id || "")}" type="button">Regenerar último escaneo</button>
    </div>
  </section>
  <div class="section-title mt">Ficheros</div>
  <div id="reports-body"><div class="muted small">Cargando informes…</div></div>

  <div class="section-title mt">Importar informe JSON o XML</div>
  <div class="panel" style="padding:16px">
    <form data-form="import" class="form-grid">
      <div class="field full">
        <label for="import-file">Fichero de informe</label>
        <input id="import-file" name="file" type="file" accept=".json,.xml,application/json,application/xml,text/xml" required>
      </div>
      <div class="actions full">
        <button class="btn primary" type="submit">Importar y abrir en el panel</button>
      </div>
    </form>
    <p class="muted small">Se aceptan informes de ROVSKA y de terceros con claves habituales (<code>hosts</code>, <code>assets</code>, <code>findings</code>, <code>vulnerabilities</code>, <code>issues</code>). El original se conserva en <code>reports/imports/</code>.</p>
  </div>
  `;
}

async function loadReports() {
  const body = document.getElementById("reports-body");
  if (!body) return;
  try {
    const rows = await api("/api/reports");
    if (!rows.length) {
      body.innerHTML = `<div class="note">No hay informes. Lanza un escaneo para generarlos.</div>`;
      return;
    }
    body.innerHTML = `<div class="table-wrap"><table>
      <thead><tr><th>Fichero</th><th>Formato</th><th class="num">Tamaño</th><th>Modificado</th><th></th></tr></thead>
      <tbody>${rows.map((row) => `<tr>
        <td>${esc(row.name)}</td>
        <td>${esc(row.ext.toUpperCase())}</td>
        <td class="num">${esc(fmtBytes(row.size))}</td>
        <td>${esc(row.mtime)}</td>
        <td><a class="btn small" href="${esc(row.url)}" target="_blank" rel="noopener">Abrir</a></td>
      </tr>`).join("")}</tbody></table></div>`;
  } catch (error) {
    body.innerHTML = `<div class="note">No se pudieron cargar los informes: ${esc(error.message)}</div>`;
  }
}

/* ---------- vista: ajustes ---------- */

function proxmoxSettingsCard() {
  const info = pveInfo();
  const cfg = info.config || {};
  const inv = info.inventory || info;
  const configured = Boolean(cfg.configured);
  const enabled = Boolean(cfg.enabled);
  const invOk = Boolean(inv?.ok);
  const status = !configured
    ? `<span class="pve-pill off">sin configurar</span>`
    : !enabled
      ? `<span class="pve-pill off">desactivado</span>`
      : invOk
        ? `<span class="pve-pill on">conectado</span>`
        : `<span class="pve-pill err">sin conexión</span>`;
  const nodes = inv?.nodes || [];
  const guestCount = nodes.reduce(
    (total, node) => total + (node.guest_count ?? (node.guests?.length || 0)),
    0
  );
  let invLine;
  if (!configured) invLine = "Configura endpoint y token para consultar el inventario.";
  else if (!enabled) invLine = "Integración desactivada. Actívala para enriquecer la lista.";
  else if (invOk) {
    invLine = `${nodes.length} nodos · ${guestCount} invitados${info.skipped ? " · solo inventario (lista desactivada)" : ""}${inv.stale ? " · caché anterior" : ""}${inv.error ? ` · ${inv.error}` : ""}`;
  } else invLine = inv?.error || "Sin inventario todavía. Pulsa «Actualizar inventario».";
  const nodeRows = nodes.map((node) => `<tr>
      <td><b>${esc(node.name || "?")}</b></td>
      <td class="mono">${esc(node.ip || "sin IP")}</td>
      <td>${esc(node.status || "—")}</td>
      <td class="num">${node.guest_count ?? (node.guests || []).length}</td>
    </tr>`).join("");
  return `<div class="chart-card pve-card">
    <div class="chart-title">Proxmox · API de solo lectura ${status}</div>
    <form data-form="proxmox" class="form-grid">
      <div class="field full">
        <label for="pve-endpoint">Endpoint</label>
        <input id="pve-endpoint" name="endpoint" value="${esc(cfg.endpoint || "")}" placeholder="https://192.168.88.10:8006" autocomplete="off">
      </div>
      <div class="field">
        <label for="pve-token-id">Token ID</label>
        <input id="pve-token-id" name="token_id" value="${esc(cfg.token_id || "")}" placeholder="PVEAuditor@pve!rovska" autocomplete="off">
      </div>
      <div class="field">
        <label for="pve-token-secret">Token secreto</label>
        <input id="pve-token-secret" name="token_secret" type="password" placeholder="${cfg.has_secret ? "•••••• (guardado)" : "secreto del token"}" autocomplete="new-password">
      </div>
      <div class="field full">
        <label class="check"><input type="checkbox" name="verify_tls" ${cfg.verify_tls !== false ? "checked" : ""}> Verificar certificado TLS (recomendado)</label>
        <label class="check"><input type="checkbox" name="enabled" ${enabled || !configured ? "checked" : ""}> Activar enriquecimiento Proxmox</label>
        <label class="check"><input type="checkbox" name="include_in_scans" ${cfg.include_in_scans !== false ? "checked" : ""}> Incluir VM/LXC en la lista unificada</label>
      </div>
      <div class="actions full">
        <button class="btn primary" type="submit">Guardar y validar</button>
        <button class="btn" type="button" data-action="pve-test">Probar conexión</button>
        <button class="btn" type="button" data-action="pve-refresh">Actualizar inventario</button>
      </div>
    </form>
    <div class="pve-inventory">${esc(invLine)}</div>
    ${nodeRows ? `<div class="table-wrap pve-nodes"><table><thead><tr><th>Nodo</th><th>IP</th><th>Estado</th><th class="num">VM/LXC</th></tr></thead><tbody>${nodeRows}</tbody></table></div>` : ""}
    <div id="pve-status" class="pve-status"></div>
    <div class="note small" style="margin-top:8px">El token debe ser de solo lectura (PVEAuditor). Se guarda en <code>data/proxmox.json</code> con permisos 600 y nunca se envía al navegador.</div>
  </div>`;
}

function renderSettings() {
  const settings = state.data?.settings || {};
  const health = state.health || {};
  const runner = health.runner_status || {};
  const dockerState = runner.running ? `<span class="op-status done">en marcha</span>` : `<span class="op-status error">parado</span>`;

  return `
  <section class="panel hero">
    <div class="hero-main">
      <div class="kicker">Ajustes</div>
      <h2>Configuración y alcance</h2>
      <div class="hero-sub">Los valores se leen de variables de entorno (<code>.env</code>) al arrancar. Reinicia el servidor tras cambiarlos.</div>
      <div class="hero-tags">
        <span class="chip">runner <b>${esc(settings.runner || "?")}</b></span>
        <span class="chip">ataque <b>${settings.allow_attack ? "habilitado" : "dry-run"}</b></span>
        <span class="chip">token api <b>${settings.api_token_required ? "sí" : "no"}</b></span>
      </div>
    </div>
  </section>

  <div class="charts">
    <div class="chart-card">
      <div class="chart-title">Runner</div>
      <div class="table-wrap"><table><tbody>
        <tr><td>Modo</td><td><b>${esc(settings.runner || "?")}</b></td></tr>
        <tr><td>Contenedor</td><td>${esc(settings.container || "—")}</td></tr>
        <tr><td>Docker</td><td>${dockerState}</td></tr>
        <tr><td>Imagen</td><td>${esc(runner.image || "—")}</td></tr>
        <tr><td>Timeout</td><td>${esc(settings.tool_timeout || 0)} s</td></tr>
      </tbody></table></div>
    </div>
    <div class="chart-card">
      <div class="chart-title">Seguridad</div>
      <div class="table-wrap"><table><tbody>
        <tr><td>Objetivos públicos</td><td><b>${settings.allow_public ? "permitidos" : "bloqueados"}</b></td></tr>
        <tr><td>Operaciones ofensivas</td><td><b>${settings.allow_attack ? "habilitadas" : "dry-run"}</b></td></tr>
        <tr><td>Máx. hosts</td><td>${esc(settings.max_hosts || 0)}</td></tr>
        <tr><td>OpenCode</td><td>${health.opencode ? "disponible" : "no disponible"}</td></tr>
        <tr><td>Modelo</td><td>${esc(settings.opencode_model || "—")}</td></tr>
      </tbody></table></div>
    </div>
    ${proxmoxSettingsCard()}
    <div class="chart-card">
      <div class="chart-title">Rutas</div>
      <div class="table-wrap"><table><tbody>
        <tr><td>Datos</td><td>${esc(settings.data_dir || "—")}</td></tr>
        <tr><td>Informes</td><td>${esc(settings.reports_dir || "—")}</td></tr>
        <tr><td>Base de datos</td><td>${esc(health.db || "—")}</td></tr>
        <tr><td>Escaneos</td><td>${esc(health.scans ?? 0)}</td></tr>
        <tr><td>Operaciones</td><td>${esc(health.operations ?? 0)}</td></tr>
      </tbody></table></div>
    </div>
    <div class="chart-card">
      <div class="chart-title">Comprobación de alcance</div>
      <form data-form="scope" class="form-grid">
        <div class="field full">
          <label for="scope-target">Objetivo</label>
          <input id="scope-target" name="target" placeholder="192.168.1.0/24" required autocomplete="off">
        </div>
        <div class="field full">
          <label class="check"><input type="checkbox" name="authorization"> Autorización expresa</label>
        </div>
        <div class="actions full"><button class="btn" type="submit">Comprobar</button></div>
      </form>
      <div id="scope-result" style="margin-top:10px"></div>
    </div>
  </div>

  <div class="note mt">Los escaneos se lanzan desde el Panel. Las operaciones individuales y el catálogo de herramientas están en Operaciones.</div>
  `;
}

function toolsAvailabilityHtml() {
  const rows = state.tools || [];
  if (!rows.length) {
    return `Catálogo de herramientas en <a href="#operations">Operaciones</a>.`;
  }
  const available = rows.filter((tool) => tool.available).length;
  return `<b>${available}/${rows.length}</b> herramientas disponibles · <a href="#operations">ver catálogo en Operaciones</a>`;
}

function toolsCatalogHtml() {
  const rows = state.tools || [];
  if (!rows.length) return `<div class="muted small">Cargando catálogo…</div>`;
  return `<div class="tool-grid">${rows.map((tool) => `<div class="tool-card">
    <div class="tname"><span class="tool-dot ${tool.available ? "on" : "off"}"></span>${esc(tool.name)}</div>
    <div class="tdesc">${esc(tool.description)}</div>
    <div class="tmeta">
      <span class="chip">${esc(tool.category)}</span>
      <span class="chip">${esc(tool.phase)}</span>
      ${tool.requires_attack ? `<span class="chip" style="color:var(--crit)">ataque</span>` : ""}
      <span class="chip">${tool.available ? "disponible" : "no disponible"}</span>
    </div>
  </div>`).join("")}</div>`;
}

/* ---------- modal ---------- */

function openModal(title, html) {
  modalTitle.textContent = title;
  modalBody.innerHTML = html;
  modal.hidden = false;
  document.body.style.overflow = "hidden";
}

function closeModal() {
  modal.hidden = true;
  document.body.style.overflow = "";
  if (state.modalStream) {
    state.modalStream.close();
    state.modalStream = null;
  }
  if (state.modalTimer) {
    clearInterval(state.modalTimer);
    state.modalTimer = null;
  }
}

function appendLog(element, event) {
  if (!element) return;
  const line = document.createElement("div");
  line.className = event.level || "info";
  line.textContent = `[${event.ts || ""}] ${event.message || ""}`;
  element.appendChild(line);
  element.scrollTop = element.scrollHeight;
}

function watchOperation(operation) {
  const title = `Operación · ${operation.tool}`;
  const html = `
    <div class="hero-tags" style="margin-bottom:10px">
      <span class="chip">id <b>${esc(operation.id)}</b></span>
      <span class="chip">estado <b>${esc(operation.status)}</b></span>
      <span class="chip">${operation.dry_run ? "dry-run" : "ejecución real"}</span>
      <span class="chip">objetivo <b>${esc(operation.target)}</b></span>
    </div>
    ${operation.error ? `<div class="note" style="margin-bottom:10px;border-color:var(--crit)">${esc(operation.error)}</div>` : ""}
    <div class="section-title">Log</div>
    <div class="log" id="op-log"></div>`;
  openModal(title, html);
  const logEl = document.getElementById("op-log");

  if (operation.log) {
    logEl.textContent = operation.log;
    logEl.scrollTop = logEl.scrollHeight;
  }
  if (["queued", "running"].includes(operation.status)) {
    const stream = new EventSource(`/api/operations/${encodeURIComponent(operation.id)}/stream`);
    state.modalStream = stream;
    stream.onmessage = (message) => {
      try {
        appendLog(logEl, JSON.parse(message.data));
      } catch {
        /* ignorar */
      }
    };
    stream.addEventListener("end", () => {
      stream.close();
      state.modalStream = null;
      setTimeout(() => load(), 500);
    });
    stream.onerror = () => {
      stream.close();
      state.modalStream = null;
    };
  }
}

function watchScan(scanId) {
  openModal(`Escaneo · ${scanId}`, `<div class="hero-tags" style="margin-bottom:10px"><span class="chip">id <b>${esc(scanId)}</b></span><span class="chip">en curso</span></div><div class="section-title">Log en vivo</div><div class="log" id="scan-log"></div>`);
  const logEl = document.getElementById("scan-log");
  const stream = new EventSource("/api/events");
  state.modalStream = stream;
  stream.onmessage = (message) => {
    try {
      const event = JSON.parse(message.data);
      if (event.scan_id === scanId) appendLog(logEl, event);
    } catch {
      /* ignorar */
    }
  };
  stream.onerror = () => {
    stream.close();
    state.modalStream = null;
  };
  state.modalTimer = setInterval(async () => {
    try {
      const scan = await api(`/api/scans/${encodeURIComponent(scanId)}`);
      if (["done", "error", "cancelled"].includes(scan.status)) {
        clearInterval(state.modalTimer);
        state.modalTimer = null;
        stream.close();
        state.modalStream = null;
        appendLog(logEl, { level: scan.status === "done" ? "done" : "error", message: `Escaneo ${scan.status}.` });
        toast(`Escaneo ${scan.status}`);
        load();
      }
    } catch {
      /* el escaneo puede no estar listo aún */
    }
  }, 3000);
}

function watchIntegrationJob(kind, jobId) {
  const label = kind === "netmap" ? "NetMap" : "MIDGARD";
  const base = kind === "netmap" ? "/api/netmap/jobs/" : "/api/midgard/jobs/";
  openModal(`Trabajo · ${label}`, `
    <div class="hero-tags" style="margin-bottom:10px">
      <span class="chip">id <b>${esc(jobId)}</b></span>
      <span class="chip" id="integration-job-status">cargando…</span>
    </div>
    <div class="section-title">Log</div>
    <div class="log" id="integration-job-log"></div>`);
  const statusEl = document.getElementById("integration-job-status");
  const logEl = document.getElementById("integration-job-log");
  let lastStatus = "";

  const paint = (job) => {
    const status = job.status || "unknown";
    lastStatus = status;
    if (statusEl) {
      statusEl.innerHTML = `estado <b>${esc(status)}</b>${job.finished_at ? ` · fin ${esc(job.finished_at)}` : ""}`;
    }
    if (logEl) {
      const lines = job.log || job.log_tail || [];
      logEl.textContent = lines.length ? lines.join("\n") : "Esperando salida…";
      logEl.scrollTop = logEl.scrollHeight;
    }
  };

  const tick = async () => {
    try {
      const job = await api(`${base}${encodeURIComponent(jobId)}`);
      paint(job);
      if (!["running", "queued"].includes(job.status)) {
        if (state.modalTimer) {
          clearInterval(state.modalTimer);
          state.modalTimer = null;
        }
        toast(`Trabajo ${label}: ${job.status}`);
        loadTasks();
        if (job.status === "ok") load();
      }
    } catch (error) {
      if (state.modalTimer) {
        clearInterval(state.modalTimer);
        state.modalTimer = null;
      }
      if (logEl) logEl.textContent = `No se pudo leer el log: ${error.message}`;
    }
  };
  state.modalTimer = setInterval(() => {
    if (lastStatus && !["running", "queued"].includes(lastStatus)) return;
    tick();
  }, 2000);
  tick();
}

function showTechnique(id) {
  const index = techniqueIndex();
  const tech = index[id];
  if (!tech) return;
  openModal(`ATT&CK · ${tech.id}`, `
    <div class="hero-tags" style="margin-bottom:10px">
      <span class="chip">táctica <b>${esc(tech.tactic)}</b></span>
      <span class="chip">observaciones <b>${tech.count}</b></span>
      <span class="chip">severidad máx. <b>${esc(tech.max_severity)}</b></span>
    </div>
    <h3 style="margin:0 0 6px">${esc(tech.name)}</h3>
    <div class="section-title mt">Hosts</div>
    <div class="hero-tags">${(tech.hosts || []).map((host) => `<span class="chip">${esc(host)}</span>`).join("") || `<span class="muted small">—</span>`}</div>
    <div class="section-title mt">Fuentes</div>
    <div class="hero-tags">${(tech.sources || []).map((source) => `<span class="chip">${esc(source)}</span>`).join("") || `<span class="muted small">—</span>`}</div>
    <div class="section-title mt">Evidencias</div>
    <ul>${(tech.examples || []).map((example) => `<li>${esc(example)}</li>`).join("") || `<li class="muted">—</li>`}</ul>
  `);
}

function showAllFindings() {
  const findings = state.data?.global?.findings || [];
  const filtered = findings.filter((finding) => state.findFilter === "ALL" || finding.severity === state.findFilter);
  openModal(`Hallazgos · ${filtered.length}`, filtered.map((finding) => findingCard(finding)).join("") || `<div class="note">Sin hallazgos.</div>`);
}


/* ---------- vistas integradas: MIDGARD / NETMAP / LIBRENMS ---------- */

const INTEGRATION_VIEWS = new Set(["midgard", "netmap", "librenms"]);

function jobStatusClass(status) {
  const map = {
    ok: "done",
    done: "done",
    error: "error",
    running: "running",
    queued: "queued",
    cancelling: "queued",
    cancelled: "cancelled",
  };
  return map[String(status || "").toLowerCase()] || "";
}

function jobLines(job) {
  if (!job) return [];
  return job.log || job.log_tail || [];
}

function stopIntegrationTimers() {
  if (state.mg.timer) {
    clearInterval(state.mg.timer);
    state.mg.timer = null;
  }
  if (state.nm.timer) {
    clearInterval(state.nm.timer);
    state.nm.timer = null;
  }
}

/* ----- MIDGARD ----- */

function renderMidgard() {
  const mg = state.mg;
  return `
  <section class="panel hero">
    <div class="hero-main">
      <div class="kicker">MIDGARD</div>
      <h2>Auditoría determinista <span class="thin">sin IA</span></h2>
      <div class="hero-sub">nmap dentro de Docker, con perfiles y evidencias verificables. Mismo panel, mismo puerto, sin telemetría.</div>
      <div class="hero-tags">
        <span class="chip">perfiles <b id="mg-profiles-count">${mg.profiles.length}</b></span>
        <span class="chip">ejecuciones <b id="mg-runs-count">${mg.runs.length}</b></span>
        <span class="chip">estado <b id="mg-state">listo</b></span>
      </div>
    </div>
  </section>

  <div class="section-title mt">Nueva auditoría</div>
  <div class="panel tool-pad">
    <form data-form="midgard" class="tool-form-grid">
      <div class="field">
        <label for="mg-target">Objetivo</label>
        <input id="mg-target" name="target" placeholder="192.168.88.0/24" autocomplete="off" spellcheck="false" required>
      </div>
      <div class="field">
        <label for="mg-profile">Perfil</label>
        <select id="mg-profile" name="profile"><option value="quick">Rápido</option></select>
        <div class="hint" id="mg-profile-hint"></div>
      </div>
      <div class="field">
        <label aria-hidden="true">&nbsp;</label>
        <button class="btn primary" type="submit" id="mg-run">Lanzar auditoría</button>
      </div>
    </form>
    <label class="check" style="margin-top:10px">
      <input type="checkbox" name="authorized" id="mg-authorized">
      Tengo autorización escrita para auditar este objetivo
    </label>
    <div class="note" style="margin-top:10px">Los objetivos públicos quedan bloqueados salvo <code>MIDGARD_ALLOW_PUBLIC=1</code> y la casilla de autorización.</div>
    <div class="tool-status" id="mg-status">Listo. Elige objetivo y perfil.</div>
    <pre class="log tool-log" id="mg-log" hidden></pre>
  </div>

  <div class="tool-grid-2">
    <section class="panel tool-pad">
      <div class="section-title" style="margin-bottom:8px">Trabajos recientes
        <button class="btn small" type="button" data-action="mg-refresh">Actualizar</button>
      </div>
      <div class="table-wrap"><table>
        <thead><tr><th>Inicio</th><th>Perfil · objetivo</th><th>Estado</th><th></th></tr></thead>
        <tbody id="mg-jobs-body"><tr><td colspan="4" class="muted">Cargando…</td></tr></tbody>
      </table></div>
    </section>

    <section class="panel tool-pad">
      <div class="section-title" style="margin-bottom:8px">Evidencias en <span class="mono">evidence/</span></div>
      <div class="table-wrap"><table>
        <thead><tr><th>Fecha</th><th>Objetivo</th><th>Perfil</th><th class="num">Hosts</th><th></th></tr></thead>
        <tbody id="mg-runs-body"><tr><td colspan="5" class="muted">Cargando…</td></tr></tbody>
      </table></div>
    </section>
  </div>
  `;
}

function paintMidgardProfiles() {
  const select = document.getElementById("mg-profile");
  if (!select) return;
  const current = select.value;
  select.innerHTML = state.mg.profiles
    .map((profile) => `<option value="${esc(profile.id)}">${esc(profile.label)} · ${esc(profile.id)}</option>`)
    .join("");
  if (state.mg.profiles.some((profile) => profile.id === current)) {
    select.value = current;
  } else if (state.mg.profiles.some((profile) => profile.id === "quick")) {
    select.value = "quick";
  }
  const count = document.getElementById("mg-profiles-count");
  if (count) count.textContent = String(state.mg.profiles.length);
  updateMidgardProfileHint();
}

function updateMidgardProfileHint() {
  const select = document.getElementById("mg-profile");
  const hint = document.getElementById("mg-profile-hint");
  if (!select || !hint) return;
  const profile = state.mg.profiles.find((item) => item.id === select.value);
  hint.textContent = profile ? profile.description : "";
}

function paintMidgardJobs() {
  const tbody = document.getElementById("mg-jobs-body");
  if (tbody) {
    if (!state.mg.jobs.length) {
      tbody.innerHTML = '<tr><td colspan="4" class="muted">Sin trabajos todavía.</td></tr>';
    } else {
      tbody.innerHTML = state.mg.jobs.slice(0, 15).map((job) => `<tr>
        <td>${esc(fmtTaskDate(job.started_at))}</td>
        <td>${esc(job.label || job.id)}<div class="svc-sub">${esc(job.id)}</div></td>
        <td><span class="op-status ${jobStatusClass(job.status)}">${esc(job.status)}</span></td>
        <td><button class="btn small" type="button" data-action="mg-job" data-job="${esc(job.id)}">Log</button></td>
      </tr>`).join("");
    }
  }
  const count = document.getElementById("mg-jobs-count");
  if (count) count.textContent = String(state.mg.jobs.length);
}

function paintMidgardRuns() {
  const tbody = document.getElementById("mg-runs-body");
  if (tbody) {
    if (!state.mg.runs.length) {
      tbody.innerHTML = '<tr><td colspan="5" class="muted">Sin evidencias guardadas.</td></tr>';
    } else {
      tbody.innerHTML = state.mg.runs.map((run) => `<tr>
        <td>${esc(fmtDate(run.created_at) || run.run_id)}</td>
        <td>${esc(run.target || "—")}</td>
        <td>${esc(run.profile || "—")}</td>
        <td class="num">${esc(run.hosts ?? 0)}</td>
        <td><button class="btn small" type="button" data-action="mg-run" data-run="${esc(run.run_id)}">Ver</button></td>
      </tr>`).join("");
    }
  }
  const count = document.getElementById("mg-runs-count");
  if (count) count.textContent = String(state.mg.runs.length);
}

function paintMidgardJob(job, lines) {
  const statusEl = document.getElementById("mg-status");
  if (statusEl) {
    statusEl.innerHTML = `Trabajo <b>${esc(job.label || job.id)}</b> · <span class="op-status ${jobStatusClass(job.status)}">${esc(job.status)}</span>`;
  }
  const stateEl = document.getElementById("mg-state");
  if (stateEl) {
    stateEl.textContent = job.status === "running" ? "en curso" : job.status === "ok" ? "listo" : job.status;
  }
  const logEl = document.getElementById("mg-log");
  if (logEl) {
    logEl.hidden = false;
    logEl.textContent = lines.length ? lines.join("\n") : "Sin salida todavía…";
    logEl.scrollTop = logEl.scrollHeight;
  }
  const button = document.getElementById("mg-run");
  if (button) button.disabled = job.status === "running";
}

async function refreshMidgard(force = false) {
  const profilesPromise = state.mg.profiles.length && !force
    ? Promise.resolve(state.mg.profiles)
    : api("/api/midgard/profiles");
  try {
    const [profiles, runs, jobs] = await Promise.all([
      profilesPromise,
      api("/api/midgard/runs"),
      api("/api/midgard/jobs"),
    ]);
    state.mg.profiles = profiles || [];
    state.mg.runs = runs || [];
    state.mg.jobs = jobs || [];
    paintMidgardProfiles();
    paintMidgardJobs();
    paintMidgardRuns();
    const running = state.mg.jobs.find((job) => job.status === "running");
    if (running && !state.mg.timer) {
      const known = state.mg.job;
      if (!known || known.id !== running.id || known.status === "running") {
        followMidgardJob(running.id);
      }
    }
  } catch (error) {
    const statusEl = document.getElementById("mg-status");
    if (statusEl) statusEl.innerHTML = `<span class="op-status error">error</span> ${esc(error.message)}`;
  }
}

function followMidgardJob(jobId) {
  if (state.mg.timer) {
    clearInterval(state.mg.timer);
    state.mg.timer = null;
  }
  state.mg.job = { id: jobId, status: "running", label: jobId };
  const logEl = document.getElementById("mg-log");
  if (logEl) {
    logEl.hidden = false;
    logEl.textContent = "Esperando salida…";
  }
  const button = document.getElementById("mg-run");
  if (button) button.disabled = true;

  const tick = async () => {
    try {
      const job = await api(`/api/midgard/jobs/${encodeURIComponent(jobId)}`);
      state.mg.job = job;
      state.mg.log = jobLines(job);
      paintMidgardJob(job, state.mg.log);
      if (job.status !== "running") {
        clearInterval(state.mg.timer);
        state.mg.timer = null;
        if (button) button.disabled = false;
        toast(`MIDGARD ${job.status === "ok" ? "completado" : "terminado: " + job.status}`);
        refreshMidgard(true);
      }
    } catch (error) {
      clearInterval(state.mg.timer);
      state.mg.timer = null;
      if (button) button.disabled = false;
      const statusEl = document.getElementById("mg-status");
      if (statusEl) statusEl.innerHTML = `<span class="op-status error">error</span> ${esc(error.message)}`;
    }
  };
  tick();
  state.mg.timer = setInterval(tick, 1400);
}

async function submitMidgard(form) {
  const target = String(form.querySelector('[name="target"]')?.value || "").trim();
  const profile = String(form.querySelector('[name="profile"]')?.value || "quick");
  const authorized = Boolean(form.querySelector('[name="authorized"]')?.checked);
  if (!target) {
    toast("Escribe un objetivo", true);
    return;
  }
  const button = form.querySelector('button[type="submit"]');
  if (button) button.disabled = true;
  state.mg.job = null;
  state.mg.log = [];
  const statusEl = document.getElementById("mg-status");
  if (statusEl) statusEl.textContent = "Lanzando auditoría…";
  const logEl = document.getElementById("mg-log");
  if (logEl) {
    logEl.hidden = false;
    logEl.textContent = "Preparando nmap…";
  }
  try {
    const job = await api("/api/midgard/run", {
      method: "POST",
      body: JSON.stringify({ target, profile, authorized }),
    });
    toast(`MIDGARD ${job.id} en curso`);
    followMidgardJob(job.id);
    refreshMidgard(true);
    setTimeout(() => load(), 1200);
  } catch (error) {
    if (button) button.disabled = false;
    if (statusEl) statusEl.innerHTML = `<span class="op-status error">error</span> ${esc(error.message)}`;
    toast(error.message, true);
  }
}

async function showMidgardRun(runId) {
  try {
    const data = await api(`/api/midgard/runs/${encodeURIComponent(runId)}`);
    const manifest = data.manifest || {};
    const counts = manifest.counts || {};
    const report = data.report || JSON.stringify(manifest, null, 2);
    const hosts = data.hosts || [];
    const hostRows = hosts.map((host) => {
      const os = host.os || {};
      const osLabel = [os.name, os.version].filter(Boolean).join(" ") || host.os || "SO desconocido";
      const confidence = os.confidence ? ` · ${os.confidence}` : "";
      const device = host.type || os.device || "—";
      const open = (host.ports || []).filter((port) => port.state === "open");
      const ports = open.length
        ? open.map((port) => `${port.port}/${port.proto}`).join(", ")
        : "—";
      return `<tr>
        <td><b>${esc(host.ip || "—")}</b></td>
        <td class="mono">${esc(host.mac || "—")}</td>
        <td>${esc(host.vendor || "—")}</td>
        <td>${esc(device)}</td>
        <td>${esc(osLabel)}<span class="muted small">${esc(confidence)}</span></td>
        <td class="mono">${esc(ports)}</td>
      </tr>`;
    }).join("");
    openModal(`MIDGARD · ${runId}`, `
      <div class="hero-tags" style="margin-bottom:10px">
        <span class="chip">objetivo <b>${esc(manifest.target || "—")}</b></span>
        <span class="chip">perfil <b>${esc(manifest.profile || "—")}</b></span>
        <span class="chip">hosts <b>${esc(counts.hosts ?? hosts.length ?? data.artifacts?.length ?? 0)}</b></span>
        <span class="chip">estado <b>${esc(manifest.status || "—")}</b></span>
      </div>
      ${hosts.length ? `<div class="section-title">Hosts detectados</div>
      <div class="table-wrap"><table>
        <thead><tr><th>IP</th><th>MAC</th><th>Fabricante</th><th>Tipo</th><th>SO</th><th>Puertos</th></tr></thead>
        <tbody>${hostRows}</tbody>
      </table></div>` : ""}
      <div class="section-title mt">Informe</div>
      <pre class="log" style="max-height:62vh">${esc(report)}</pre>
      <div class="section-title mt">Artefactos</div>
      <div class="hero-tags">${(data.artifacts || []).map((item) => `<span class="chip">${esc(item.name)} <b>${fmtBytes(item.bytes)}</b></span>`).join("") || '<span class="muted small">—</span>'}</div>
    `);
  } catch (error) {
    toast(error.message, true);
  }
}

/* ----- NETMAP ----- */

function renderNetmap() {
  const data = state.nm.data || {};
  const hosts = data.hosts || [];
  return `
  <section class="panel hero">
    <div class="hero-main">
      <div class="kicker">NETMAP</div>
      <h2>Mapa de red <span class="thin">en vivo</span></h2>
      <div class="hero-sub">Descubrimiento por ARP y fingerprint de puertos, sin credenciales. El mapa se genera dentro del mismo proyecto.</div>
      <div class="hero-tags">
        <span class="chip">dispositivos <b id="nm-count">${hosts.length}</b></span>
        <span class="chip">ssid <b id="nm-ssid">${esc(data.ssid || "—")}</b></span>
        <span class="chip">actualizado <b id="nm-generated">${esc(data.generated || "sin datos")}</b></span>
      </div>
    </div>
  </section>

  <div class="section-title mt">Actualizar mapa</div>
  <div class="panel tool-pad">
    <form data-form="netmap" class="tool-form-grid">
      <div class="field">
        <label for="nm-iface">Interfaz</label>
        <input id="nm-iface" name="iface" value="wlan0" autocomplete="off" spellcheck="false">
      </div>
      <div class="field">
        <label>&nbsp;</label>
        <button class="btn primary" type="submit" id="nm-scan">Barrer la red</button>
      </div>
      <div class="field">
        <label>&nbsp;</label>
        <button class="btn" type="button" data-action="nm-refresh">Recargar inventario</button>
      </div>
    </form>
    <div class="note" style="margin-top:10px">Solo lectura: ARP + ping + nmap. No usa credenciales ni modifica equipos.</div>
    <div class="tool-status" id="nm-status">Listo.</div>
    <pre class="log tool-log" id="nm-log" hidden></pre>
  </div>

  <div class="section-title mt">Mapa
    <a class="btn small" href="/netmap/index.html" target="_blank" rel="noopener">Abrir en pestaña</a>
  </div>
  <section class="panel" style="padding:10px">
    <iframe class="tool-frame" id="nm-frame" src="/netmap/index.html" title="Mapa de red" loading="lazy"></iframe>
  </section>

  <div class="section-title mt">Inventario</div>
  <section class="panel tool-pad">
    <div class="muted small" id="nm-meta" style="margin-bottom:8px">${esc(`${hosts.length} dispositivos · SSID ${data.ssid || "—"} · ${data.generated || "sin fecha"}`)}</div>
    <div class="table-wrap"><table>
      <thead><tr><th>IP</th><th>MAC</th><th>Fabricante</th><th>Puertos</th><th class="num">Latencia</th></tr></thead>
      <tbody id="nm-hosts-body"><tr><td colspan="5" class="muted">Cargando…</td></tr></tbody>
    </table></div>
  </section>
  `;
}

function paintNetmap() {
  const data = state.nm.data || {};
  const hosts = data.hosts || [];
  const count = document.getElementById("nm-count");
  if (count) count.textContent = String(hosts.length);
  const ssid = document.getElementById("nm-ssid");
  if (ssid) ssid.textContent = data.ssid || "—";
  const generated = document.getElementById("nm-generated");
  if (generated) generated.textContent = data.generated || "sin datos";
  const meta = document.getElementById("nm-meta");
  if (meta) meta.textContent = `${hosts.length} dispositivos · SSID ${data.ssid || "—"} · ${data.generated || "sin fecha"}`;
  const tbody = document.getElementById("nm-hosts-body");
  if (tbody) {
    if (!hosts.length) {
      tbody.innerHTML = '<tr><td colspan="5" class="muted">Sin datos. Pulsa «Barrer la red».</td></tr>';
    } else {
      tbody.innerHTML = hosts.map((host) => `<tr>
        <td><b>${esc(host.ip)}</b></td>
        <td class="mono">${esc(host.mac || "—")}</td>
        <td>${esc(host.vendor || "—")}</td>
        <td class="mono">${esc((host.ports || []).join(", ") || "—")}</td>
        <td class="num">${host.latency_ms != null ? esc(host.latency_ms) + " ms" : "—"}</td>
      </tr>`).join("");
    }
  }
}

async function refreshNetmap() {
  try {
    const [data, jobs] = await Promise.all([
      api("/api/netmap"),
      api("/api/netmap/jobs"),
    ]);
    state.nm.data = data || {};
    state.nm.jobs = jobs || [];
    paintNetmap();
    const running = state.nm.jobs.find((job) => job.status === "running");
    if (running && !state.nm.timer) {
      const known = state.nm.job;
      if (!known || known.id !== running.id || known.status === "running") {
        followNetmapJob(running.id);
      }
    }
  } catch (error) {
    const statusEl = document.getElementById("nm-status");
    if (statusEl) statusEl.innerHTML = `<span class="op-status error">error</span> ${esc(error.message)}`;
  }
}

function reloadNetmapFrame() {
  const frame = document.getElementById("nm-frame");
  if (frame) frame.src = `/netmap/index.html?t=${Date.now()}`;
}

function paintNetmapJob(job, lines) {
  const statusEl = document.getElementById("nm-status");
  if (statusEl) {
    statusEl.innerHTML = `Trabajo <b>${esc(job.label || job.id)}</b> · <span class="op-status ${jobStatusClass(job.status)}">${esc(job.status)}</span>`;
  }
  const logEl = document.getElementById("nm-log");
  if (logEl) {
    logEl.hidden = false;
    logEl.textContent = lines.length ? lines.join("\n") : "Sin salida todavía…";
    logEl.scrollTop = logEl.scrollHeight;
  }
  const button = document.getElementById("nm-scan");
  if (button) button.disabled = job.status === "running";
}

function followNetmapJob(jobId) {
  if (state.nm.timer) {
    clearInterval(state.nm.timer);
    state.nm.timer = null;
  }
  state.nm.job = { id: jobId, status: "running", label: jobId };
  const logEl = document.getElementById("nm-log");
  if (logEl) {
    logEl.hidden = false;
    logEl.textContent = "Barriendo la red…";
  }
  const button = document.getElementById("nm-scan");
  if (button) button.disabled = true;

  const tick = async () => {
    try {
      const job = await api(`/api/netmap/jobs/${encodeURIComponent(jobId)}`);
      state.nm.job = job;
      state.nm.log = jobLines(job);
      paintNetmapJob(job, state.nm.log);
      if (job.status !== "running") {
        clearInterval(state.nm.timer);
        state.nm.timer = null;
        if (button) button.disabled = false;
        toast(`NETMAP ${job.status === "ok" ? "actualizado" : "terminado: " + job.status}`);
        reloadNetmapFrame();
        refreshNetmap();
      }
    } catch (error) {
      clearInterval(state.nm.timer);
      state.nm.timer = null;
      if (button) button.disabled = false;
      const statusEl = document.getElementById("nm-status");
      if (statusEl) statusEl.innerHTML = `<span class="op-status error">error</span> ${esc(error.message)}`;
    }
  };
  tick();
  state.nm.timer = setInterval(tick, 1400);
}

async function submitNetmap(form) {
  const iface = String(form.querySelector('[name="iface"]')?.value || "wlan0").trim() || "wlan0";
  const button = form.querySelector('button[type="submit"]');
  if (button) button.disabled = true;
  state.nm.job = null;
  state.nm.log = [];
  const statusEl = document.getElementById("nm-status");
  if (statusEl) statusEl.textContent = "Barriendo la red…";
  try {
    const job = await api("/api/netmap/scan", {
      method: "POST",
      body: JSON.stringify({ iface }),
    });
    toast(`NETMAP ${job.id} en curso`);
    followNetmapJob(job.id);
    setTimeout(() => load(), 1200);
  } catch (error) {
    if (button) button.disabled = false;
    if (statusEl) statusEl.innerHTML = `<span class="op-status error">error</span> ${esc(error.message)}`;
    toast(error.message, true);
  }
}

/* ----- LIBRENMS ----- */

function librenmsBase() {
  return `${location.protocol}//${location.hostname}:8000/`;
}

function renderLibrenms() {
  const url = librenmsBase();
  return `
  <section class="panel hero">
    <div class="hero-main">
      <div class="kicker">LIBRENMS</div>
      <h2>Inventario y topología <span class="thin">SNMP</span></h2>
      <div class="hero-sub">Servicio incluido en el proyecto, visible aquí sin cambiar de panel. Sin SNMP en los equipos no habrá topología L2, pero el inventario y el histórico siguen disponibles.</div>
      <div class="hero-tags">
        <span class="chip">servicio <b>:8000</b></span>
        <span class="chip">url <b>${esc(url)}</b></span>
        <span class="chip">red <b>LAN / Tailscale</b></span>
      </div>
    </div>
  </section>

  <div class="panel tool-pad" style="margin-top:12px">
    <div class="tool-link-row">
      <button class="btn" type="button" data-action="librenms-reload">Recargar</button>
      <a class="btn primary" href="${esc(url)}" target="_blank" rel="noopener">Abrir en pestaña</a>
      <span class="muted small">Credenciales en <span class="mono">deploy/librenms/ACCESO.txt</span>.</span>
    </div>
    <div class="note" style="margin-top:10px">Si el marco aparece vacío, el servicio aún no ha arrancado: <code>./run.sh librenms-up</code>.</div>
  </div>

  <section class="panel" style="padding:10px;margin-top:12px">
    <iframe class="tool-frame" id="librenms-frame" src="${esc(url)}" title="LibreNMS" loading="lazy"></iframe>
  </section>
  `;
}

function reloadLibrenmsFrame() {
  const frame = document.getElementById("librenms-frame");
  if (frame) frame.src = `${librenmsBase()}?t=${Date.now()}`;
}

/* ---------- render ---------- */

function renderDetail() {
  const d = state.data;
  if (!d) {
    detail.innerHTML = `<div class="empty"><div class="glyph">▚</div><h2>ROVSKA</h2><p>Conectando con el servidor local…</p></div>`;
    return;
  }
  if (!INTEGRATION_VIEWS.has(state.view)) {
    stopIntegrationTimers();
    detail.dataset.view = state.view;
  }
  if (state.view === "midgard") {
    if (detail.dataset.view !== "midgard") {
      detail.innerHTML = renderMidgard();
      detail.dataset.view = "midgard";
      refreshMidgard();
    }
    return;
  }
  if (state.view === "netmap") {
    if (detail.dataset.view !== "netmap") {
      detail.innerHTML = renderNetmap();
      detail.dataset.view = "netmap";
      refreshNetmap();
    }
    return;
  }
  if (state.view === "librenms") {
    if (detail.dataset.view !== "librenms") {
      detail.innerHTML = renderLibrenms();
      detail.dataset.view = "librenms";
    }
    return;
  }
  if (state.view === "overview") {
    detail.innerHTML = renderOverview();
    return;
  }
  if (state.view === "host") {
    const host = (d.hosts || []).find((item) => item.ip === state.hostIp);
    detail.innerHTML = host ? renderHost(host) : `<div class="empty"><div class="glyph">▚</div><h2>Host no encontrado</h2><p>Vuelve al panel general.</p></div>`;
    return;
  }
  if (state.view === "operations") {
    detail.innerHTML = renderOperations();
    return;
  }
  if (state.view === "tasks") {
    detail.innerHTML = renderTasks();
    loadTasks();
    return;
  }
  if (state.view === "attack") {
    detail.innerHTML = renderAttack();
    return;
  }
  if (state.view === "frameworks") {
    detail.innerHTML = renderFrameworks();
    return;
  }
  if (state.view === "compare") {
    detail.innerHTML = renderCompare();
    loadCompare();
    return;
  }
  if (state.view === "reports") {
    detail.innerHTML = renderReports();
    loadReports();
    return;
  }
  if (state.view === "settings") {
    detail.innerHTML = renderSettings();
    return;
  }
  detail.innerHTML = renderOverview();
}

function renderNav() {
  for (const button of nav.querySelectorAll(".nav-btn")) {
    button.classList.toggle("active", button.dataset.view === state.view);
  }
}

function render() {
  renderNav();
  renderTopMeta();
  renderSidebar();
  renderDetail();
  renderActiveStrip();
  renderFoot();
}

function activeTaskList() {
  return (state.tasks?.tasks || []).filter((task) => task.active);
}

function renderActiveStrip() {
  const strip = document.getElementById("active-strip");
  if (!strip) return;
  const active = activeTaskList();
  if (!active.length || state.view === "tasks") {
    strip.hidden = true;
    strip.innerHTML = "";
    return;
  }
  strip.hidden = false;
  const only = active.length === 1 ? active[0] : null;
  const cancelButton = only?.can_cancel
    ? `<button class="btn small danger" type="button" data-task-cancel="${esc(only.id)}" data-cancel-kind="${esc(only.cancel_kind)}">Cancelar</button>`
    : "";
  strip.innerHTML = `<span class="active-dot" aria-hidden="true"></span>
    <span class="active-title"><b>${active.length}</b> ${active.length === 1 ? "tarea en ejecución" : "tareas en ejecución"}</span>
    <div class="active-items">${active.slice(0, 4).map((task) => {
      const current = task.current || task.error || task.status_label || "";
      return `<span class="active-item" title="${esc(current)}"><b>${esc(taskTypeLabel(task.type))}</b> · ${esc(task.target || "—")}${current ? ` · ${esc(current)}` : ""}</span>`;
    }).join("")}${active.length > 4 ? `<span class="active-item">+${active.length - 4} más</span>` : ""}</div>
    <div class="active-actions">${cancelButton}<button class="btn small" type="button" data-action="go-tasks">Ver tareas</button></div>`;
}

/* ---------- acciones ---------- */

async function load(showSpinner = false) {
  if (state.loading) return;
  state.loading = true;
  if (showSpinner) refreshBtn.classList.add("spin");
  try {
    const [data, health, tasks, tools] = await Promise.all([
      api("/api/data"),
      api("/api/health").catch(() => null),
      api("/api/tasks").catch(() => null),
      api("/api/tools").catch(() => null),
    ]);
    state.data = data;
    state.health = health;
    if (tasks) state.tasks = tasks;
    if (tools) state.tools = tools;
    if (state.view === "host" && state.hostIp && !(data.hosts || []).some((host) => host.ip === state.hostIp)) {
      state.view = "overview";
      state.hostIp = null;
    }
    const activeJobs = (data.jobs || []).filter((job) => ["queued", "running", "cancelling"].includes(job.status)).length;
    const interrupted = state.tasks?.counts?.interrupted || 0;
    updateTaskBadge(
      state.tasks
        ? taskAlertCount(state.tasks)
        : activeJobs + interrupted
    );
    render();
  } catch (error) {
    detail.innerHTML = `<div class="empty"><div class="glyph">▚</div><h2>Sin conexión</h2><p>${esc(error.message)}</p><p>Comprueba que <code>python3 -m rovvska serve</code> sigue en marcha.</p></div>`;
  } finally {
    state.loading = false;
    refreshBtn.classList.remove("spin");
  }
}

async function submitScan(form) {
  const fd = new FormData(form);
  const target = String(fd.get("target") || "").trim();
  const profile = String(fd.get("profile") || "quick");
  const raw = String(fd.get("options") || "").trim();
  let options = {};
  if (raw) {
    try {
      options = JSON.parse(raw);
    } catch {
      toast("Las opciones no son JSON válido", true);
      return;
    }
  }
  const button = form.querySelector('button[type="submit"]');
  if (button) button.disabled = true;
  try {
    const pve = pveConfig();
    const pveInclude = form.querySelector('[name="proxmox_include"]');
    const pveValidate = form.querySelector('[name="proxmox_validate"]');
    if (pve.configured && pveInclude) {
      options.proxmox = pveInclude.checked;
      api("/api/proxmox/preferences", {
        method: "POST",
        body: JSON.stringify({ include_in_scans: pveInclude.checked }),
      }).catch(() => {});
    }
    if (pve.configured && pveValidate?.checked) {
      const check = await api("/api/proxmox/test", { method: "POST", body: "{}" })
        .catch((error) => ({ ok: false, error: error.message }));
      if (!check.ok) toast(`Proxmox no validó: ${check.error || "sin conexión"}. El escaneo continúa.`, true);
    }
    const result = await api("/api/scans", {
      method: "POST",
      body: JSON.stringify({
        target,
        profile,
        options,
        authorization: fd.get("authorization") === "on",
      }),
    });
    toast(`Escaneo ${result.scan_id} en cola`);
    watchScan(result.scan_id);
    setTimeout(() => load(), 1500);
  } catch (error) {
    toast(error.message, true);
  } finally {
    if (button) button.disabled = false;
  }
}

async function submitOperation(form) {
  const fd = new FormData(form);
  const tool = String(fd.get("tool") || "");
  const target = String(fd.get("target") || "").trim();
  const raw = String(fd.get("params") || "").trim();
  let params = {};
  if (raw) {
    try {
      params = JSON.parse(raw);
    } catch {
      toast("Los parámetros no son JSON válido", true);
      return;
    }
  }
  const button = form.querySelector('button[type="submit"]');
  if (button) button.disabled = true;
  try {
    const result = await api("/api/operations", {
      method: "POST",
      body: JSON.stringify({
        tool,
        target,
        params,
        dry_run: fd.get("dry_run") === "on",
        authorization: fd.get("authorization") === "on",
      }),
    });
    toast(`Operación ${result.operation_id} en cola`);
    const operation = await api(`/api/operations/${encodeURIComponent(result.operation_id)}`).catch(() => ({
      id: result.operation_id,
      tool,
      target,
      status: "queued",
      dry_run: result.dry_run,
    }));
    watchOperation(operation);
    setTimeout(() => load(), 1500);
  } catch (error) {
    toast(error.message, true);
  } finally {
    if (button) button.disabled = false;
  }
}

async function submitScope(form) {
  const fd = new FormData(form);
  const target = String(fd.get("target") || "").trim();
  const resultEl = document.getElementById("scope-result");
  if (resultEl) resultEl.innerHTML = `<span class="muted small">Comprobando…</span>`;
  try {
    const authorization = fd.get("authorization") === "on" ? "1" : "0";
    const decision = await api(`/api/scope?target=${encodeURIComponent(target)}&authorization=${authorization}`);
    if (!resultEl) return;
    resultEl.innerHTML = `<div class="note" style="border-color:${decision.allowed ? "var(--ok)" : "var(--crit)"}">
      <b>${decision.allowed ? "Dentro de alcance" : "Bloqueado"}</b> · ${esc(decision.reason)}<br>
      redes: ${esc((decision.networks || []).join(", ") || "—")} · hosts: ${esc(decision.host_count ?? 0)}${decision.public ? " · objetivo público" : ""}
    </div>`;
  } catch (error) {
    if (resultEl) resultEl.innerHTML = `<div class="note" style="border-color:var(--crit)">${esc(error.message)}</div>`;
  }
}

function proxmoxFormData(form) {
  const fd = new FormData(form);
  return {
    endpoint: String(fd.get("endpoint") || "").trim(),
    token_id: String(fd.get("token_id") || "").trim(),
    token_secret: String(fd.get("token_secret") || ""),
    verify_tls: fd.get("verify_tls") === "on",
    enabled: fd.get("enabled") === "on",
    include_in_scans: fd.get("include_in_scans") === "on",
  };
}

function pveStatusHtml(result) {
  if (!result) return "";
  const ms = result.latency_ms ? ` · ${result.latency_ms} ms` : "";
  if (result.ok) {
    const version = result.version ? ` · PVE ${esc(result.version)}` : "";
    const nodes = result.nodes !== undefined ? ` · ${result.nodes} nodos` : "";
    return `<span class="op-status done">ok</span> conexión validada${version}${nodes}${ms}`;
  }
  return `<span class="op-status error">error</span> ${esc(result.error || "sin conexión")}${ms}`;
}

function setPveStatus(html) {
  const el = document.getElementById("pve-status");
  if (el) el.innerHTML = html;
}

async function submitProxmox(form) {
  const body = proxmoxFormData(form);
  body.validate = true;
  const button = form.querySelector('button[type="submit"]');
  if (button) button.disabled = true;
  setPveStatus(`<span class="muted small">Guardando y validando…</span>`);
  try {
    const result = await api("/api/proxmox/config", { method: "POST", body: JSON.stringify(body) });
    const status = pveStatusHtml(result.test);
    toast(result.test?.ok ? "Proxmox guardado y validado" : "Proxmox guardado; revisa la validación", !result.test?.ok);
    await load();
    setPveStatus(status);
  } catch (error) {
    setPveStatus(`<span class="op-status error">error</span> ${esc(error.message)}`);
    toast(error.message, true);
  } finally {
    if (button) button.disabled = false;
  }
}

async function testProxmox(form) {
  const body = form ? proxmoxFormData(form) : {};
  const buttons = form ? form.querySelectorAll('[data-action="pve-test"]') : [];
  buttons.forEach((btn) => { btn.disabled = true; });
  setPveStatus(`<span class="muted small">Probando conexión…</span>`);
  try {
    const result = await api("/api/proxmox/test", { method: "POST", body: JSON.stringify(body) });
    setPveStatus(pveStatusHtml(result));
    toast(result.ok ? "Proxmox responde" : `Proxmox: ${result.error}`, !result.ok);
  } catch (error) {
    setPveStatus(`<span class="op-status error">error</span> ${esc(error.message)}`);
    toast(error.message, true);
  } finally {
    buttons.forEach((btn) => { btn.disabled = false; });
  }
}

async function refreshProxmox() {
  setPveStatus(`<span class="muted small">Actualizando inventario…</span>`);
  try {
    const result = await api("/api/proxmox/refresh", { method: "POST", body: "{}" });
    const inv = result.inventory || {};
    const count = (inv.nodes || []).reduce((total, node) => total + (node.guests?.length || 0), 0);
    const status = inv.ok
      ? `<span class="op-status done">ok</span> ${(inv.nodes || []).length} nodos · ${count} invitados`
      : `<span class="op-status error">error</span> ${esc(inv.error || "sin inventario")}`;
    toast(inv.ok ? "Inventario Proxmox actualizado" : "No se pudo actualizar el inventario", !inv.ok);
    await load();
    setPveStatus(status);
  } catch (error) {
    setPveStatus(`<span class="op-status error">error</span> ${esc(error.message)}`);
    toast(error.message, true);
  }
}

function showPveGuest(ip, vmid) {
  const guest = findPveGuest(ip, vmid);
  if (!guest) {
    toast("Invitado Proxmox no encontrado", true);
    return;
  }
  const kind = guest.kind === "lxc" ? "LXC" : "VM";
  openModal(`Proxmox · ${kind} ${guest.vmid}`, `
    <div class="table-wrap"><table><tbody>
      <tr><td>Invitado</td><td><b>${esc(kind)} ${esc(guest.vmid)}</b></td></tr>
      <tr><td>Nombre</td><td>${esc(guest.name || "—")}</td></tr>
      <tr><td>Nodo</td><td>${esc(guest.node || "—")} · ${esc(guest.node_ip || "sin IP")}</td></tr>
      <tr><td>IP</td><td class="mono">${esc(guest.ip || "sin IP detectada")}</td></tr>
      <tr><td>Estado</td><td>${esc(guest.status || "—")}</td></tr>
      <tr><td>Contexto</td><td>${guest.scanned ? "host escaneado" : "solo inventario Proxmox"}</td></tr>
    </tbody></table></div>
    <div class="note" style="margin-top:10px">Este invitado no está escaneado en el contexto actual. Lanza un escaneo de su IP para abrir su ficha.</div>`);
}

async function submitAnnotation(form) {
  const fd = new FormData(form);
  try {
    await api("/api/annotations", {
      method: "POST",
      body: JSON.stringify({
        ip: form.dataset.ip,
        type: fd.get("type") || "",
        name: fd.get("name") || "",
      }),
    });
    toast("Anotación guardada");
    await load();
  } catch (error) {
    toast(error.message, true);
  }
}

async function submitImport(form) {
  const input = form.querySelector('input[type="file"]');
  const file = input?.files?.[0];
  if (!file) {
    toast("Selecciona un informe JSON o XML", true);
    return;
  }
  const button = form.querySelector('button[type="submit"]');
  if (button) button.disabled = true;
  try {
    const content = await file.text();
    const result = await api("/api/import-report", {
      method: "POST",
      body: JSON.stringify({ filename: file.name, content }),
    });
    toast(`Importado ${result.scan_id} · ${result.findings} hallazgos`);
    form.reset();
    state.view = "overview";
    state.hostIp = null;
    await load(true);
  } catch (error) {
    toast(error.message, true);
  } finally {
    if (button) button.disabled = false;
  }
}

/* ---------- eventos ---------- */

nav.addEventListener("click", (event) => {
  const button = event.target.closest(".nav-btn");
  if (!button || !button.dataset.view) return;
  state.view = button.dataset.view;
  if (state.view !== "host") state.hostIp = null;
  setHash(state.view);
  render();
  window.scrollTo({ top: 0, behavior: "smooth" });
});

const activeStrip = document.getElementById("active-strip");
if (activeStrip) {
  activeStrip.addEventListener("click", (event) => {
    const cancelButton = event.target.closest("[data-task-cancel]");
    if (cancelButton) {
      cancelTask(cancelButton.dataset.taskCancel, cancelButton.dataset.cancelKind);
      return;
    }
    if (!event.target.closest('[data-action="go-tasks"]')) return;
    state.view = "tasks";
    state.hostIp = null;
    setHash("tasks");
    render();
    loadTasks();
  });
}

brand.addEventListener("click", () => {
  state.view = "overview";
  state.hostIp = null;
  setHash("overview");
  render();
});

brand.addEventListener("keydown", (event) => {
  if (event.key === "Enter" || event.key === " ") {
    event.preventDefault();
    state.view = "overview";
    state.hostIp = null;
    render();
  }
});

detail.addEventListener("change", (event) => {
  if (event.target && event.target.id === "mg-profile") updateMidgardProfileHint();
});

sidebar.addEventListener("click", (event) => {
  const global = event.target.closest("#global-btn");
  if (global) {
    state.view = "overview";
    state.hostIp = null;
    setHash("overview");
    render();
    return;
  }
  const toggle = event.target.closest("[data-pve-toggle]");
  if (toggle) {
    event.preventDefault();
    event.stopPropagation();
    const ip = toggle.dataset.pveToggle;
    if (state.pve.expanded.has(ip)) state.pve.expanded.delete(ip);
    else state.pve.expanded.add(ip);
    renderSidebar();
    return;
  }
  const child = event.target.closest(".host-child-row");
  if (child) {
    if (child.dataset.host) {
      state.hostIp = child.dataset.host;
      state.view = "host";
      state.hostTab = "summary";
      setHash("");
      render();
    } else {
      showPveGuest(child.dataset.guestIp || "", child.dataset.guestVmid || "");
    }
    return;
  }
  const row = event.target.closest(".host-row");
  if (!row) return;
  state.hostIp = row.dataset.host;
  state.view = "host";
  state.hostTab = "summary";
  setHash("");
  render();
});

detail.addEventListener("click", (event) => {
  const hostTarget = event.target.closest("[data-host]");
  if (hostTarget) {
    state.hostIp = hostTarget.dataset.host;
    state.view = "host";
    state.hostTab = "summary";
    setHash("");
    render();
    window.scrollTo({ top: 0, behavior: "smooth" });
    return;
  }
  const tab = event.target.closest("[data-tab]");
  if (tab) {
    state.hostTab = tab.dataset.tab;
    render();
    return;
  }
  const tech = event.target.closest("[data-tech]");
  if (tech) {
    showTechnique(tech.dataset.tech);
    return;
  }
  const opRow = event.target.closest("[data-op-id]");
  if (opRow) {
    const operation = (state.data?.operations || []).find((item) => item.id === opRow.dataset.opId);
    if (operation) watchOperation(operation);
    return;
  }
  const taskLog = event.target.closest("[data-task-log]");
  if (taskLog) {
    openTaskLog(taskLog.dataset.taskLog);
    return;
  }
  const taskCancel = event.target.closest("[data-task-cancel]");
  if (taskCancel) {
    cancelTask(taskCancel.dataset.taskCancel, taskCancel.dataset.cancelKind);
    return;
  }
  const action = event.target.closest("[data-action]");
  if (!action) return;
  if (action.dataset.action === "pve-test") {
    testProxmox(action.closest("form"));
    return;
  }
  if (action.dataset.action === "pve-refresh") {
    refreshProxmox();
    return;
  }
  if (action.dataset.action === "tasks-refresh") {
    action.disabled = true;
    loadTasks().finally(() => {
      action.disabled = false;
    });
    return;
  }
  if (action.dataset.action === "tasks-clear") {
    const counts = state.tasks?.counts || {};
    const finished = Math.max(0, Number(counts.total || 0) - Number(counts.active || 0));
    if (finished <= 0) {
      toast("No hay tareas terminadas que limpiar");
      return;
    }
    if (!window.confirm(`¿Ocultar ${finished} tareas terminadas del listado? No se borran escaneos, informes, evidencia ni anotaciones. Las tareas activas seguirán visibles.`)) {
      return;
    }
    action.disabled = true;
    api("/api/tasks/clear", { method: "POST", body: JSON.stringify({ confirm: true }) })
      .then((result) => {
        toast(`Tareas limpiadas: ${result.cleared}`);
        return loadTasks();
      })
      .catch((error) => toast(error.message, true))
      .finally(() => {
        action.disabled = false;
      });
    return;
  }
  if (action.dataset.action === "mg-refresh") {
    refreshMidgard(true);
    return;
  }
  if (action.dataset.action === "go-tasks") {
    state.view = "tasks";
    state.hostIp = null;
    setHash("tasks");
    render();
    loadTasks();
    return;
  }
  if (action.dataset.action === "mg-job") {
    followMidgardJob(action.dataset.job);
    return;
  }
  if (action.dataset.action === "mg-run") {
    showMidgardRun(action.dataset.run);
    return;
  }
  if (action.dataset.action === "nm-refresh") {
    refreshNetmap();
    return;
  }
  if (action.dataset.action === "librenms-reload") {
    reloadLibrenmsFrame();
    return;
  }
  if (action.dataset.action === "filter") {
    state.findFilter = action.dataset.sev;
    render();
  } else if (action.dataset.action === "all-findings") {
    showAllFindings();
  } else if (action.dataset.action === "reports-delete-all") {
    const count = Number(state.data?.reports_count || 0);
    const hosts = Number((state.data?.hosts || []).length);
    if (!window.confirm(`¿Borrar TODOS los informes del historial (${count}) y los datos de ${hosts} hosts? Esta acción no se puede deshacer.`)) {
      return;
    }
    if (!window.confirm("Confirma de nuevo: se eliminarán los ficheros informe_*, la tabla de IPs y el historial de escaneos para empezar de cero. Se conservan los informes importados, las anotaciones y el registro de eventos.")) {
      return;
    }
    action.disabled = true;
    api("/api/reports/delete", { method: "POST", body: JSON.stringify({ confirm: true, purge_history: true }) })
      .then((result) => {
        const history = result.history || {};
        const purged = `escaneos ${history.scans || 0}, hosts ${history.hosts || 0}`;
        if (result.errors?.length) {
          toast(`Borrados ${result.deleted} informes y ${purged}; ${result.errors.length} con error`, true);
        } else {
          toast(`Informes borrados: ${result.deleted} · Historial limpio: ${purged}`);
        }
        loadReports();
        load();
      })
      .catch((error) => toast(error.message, true))
      .finally(() => {
        action.disabled = false;
      });
  } else if (action.dataset.action === "regen") {
    const scanId = action.dataset.scan;
    if (!scanId) {
      toast("No hay escaneo para regenerar", true);
      return;
    }
    action.disabled = true;
    api("/api/reports", { method: "POST", body: JSON.stringify({ scan_id: scanId }) })
      .then(() => {
        toast("Informes regenerados");
        loadReports();
        load();
      })
      .catch((error) => toast(error.message, true))
      .finally(() => {
        action.disabled = false;
      });
  }
});

document.addEventListener("submit", (event) => {
  const form = event.target.closest("form[data-form]");
  if (!form) return;
  event.preventDefault();
  const kind = form.dataset.form;
  if (kind === "scan") submitScan(form);
  else if (kind === "operation") submitOperation(form);
  else if (kind === "scope") submitScope(form);
  else if (kind === "annotation") submitAnnotation(form);
  else if (kind === "compare") {
    state.compareBase = form.querySelector('select[name="base"]')?.value || "";
    state.compareTarget = form.querySelector('select[name="target"]')?.value || "";
    loadCompare();
  } else if (kind === "import") submitImport(form);
  else if (kind === "midgard") submitMidgard(form);
  else if (kind === "netmap") submitNetmap(form);
  else if (kind === "proxmox") submitProxmox(form);
});

search.addEventListener("input", () => {
  state.query = search.value.trim();
  renderSidebar();
});

refreshBtn.addEventListener("click", () => load(true));

$("#modal-close").addEventListener("click", closeModal);

modal.addEventListener("click", (event) => {
  if (event.target === modal) closeModal();
});

document.addEventListener("keydown", (event) => {
  const tag = (event.target.tagName || "").toLowerCase();
  const typing = ["input", "textarea", "select"].includes(tag) || event.target.isContentEditable;
  if (event.key === "Escape" && !modal.hidden) {
    closeModal();
    return;
  }
  if (typing) return;
  if (event.key === "/") {
    event.preventDefault();
    search.focus();
  } else if (event.key.toLowerCase() === "r") {
    event.preventDefault();
    load(true);
  }
});

/* ---------- hash y arranque ---------- */

const VIEW_IDS = new Set([
  "overview", "operations", "tasks", "attack", "frameworks",
  "compare", "reports", "settings", "midgard", "netmap", "librenms",
]);

function setHash(view) {
  const target = view ? `#${view}` : location.pathname;
  if (view && location.hash !== target) {
    history.replaceState(null, "", target);
  } else if (!view && location.hash) {
    history.replaceState(null, "", location.pathname);
  }
}

function applyHash() {
  const raw = String(location.hash || "").replace(/^#\/?/, "");
  if (!VIEW_IDS.has(raw) || raw === state.view) return;
  state.view = raw;
  state.hostIp = null;
  render();
  window.scrollTo({ top: 0, behavior: "smooth" });
}

window.addEventListener("hashchange", applyHash);

const initialView = String(location.hash || "").replace(/^#\/?/, "");
if (VIEW_IDS.has(initialView)) state.view = initialView;

render();
load(true).then(() => loadTasks());
setInterval(() => {
  if (document.hidden || !modal.hidden) return;
  const tag = (document.activeElement?.tagName || "").toLowerCase();
  if (["input", "textarea", "select"].includes(tag)) return;
  load();
}, 30000);
setInterval(() => {
  if (!document.hidden && modal.hidden && state.view === "tasks") loadTasks();
}, 5000);
setInterval(() => {
  if (document.hidden) return;
  if (state.view === "midgard" && !state.mg.timer) refreshMidgard();
  else if (state.view === "netmap" && !state.nm.timer) refreshNetmap();
}, 8000);
