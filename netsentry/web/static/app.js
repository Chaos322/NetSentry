/**
 * NetSentry Dashboard — app.js
 *
 * All API field names match the backend exactly:
 *
 * WebSocket messages received:
 *   {type:"snapshot", data:{state, interface, stats, packets:[], alerts:[]}}
 *   {type:"packets",  data:[{timestamp,protocol,src,sport,dst,dport,size,flags},...]}
 *   {type:"stats",    data:{count, bytes, pps, protocols:{TCP,UDP,...}}}
 *   {type:"alerts",   data:[{timestamp,type,severity,source_ip,destination_ip,
 *                             destination_port,reason},...]}
 *   {type:"status",   data:{state:"running"|"stopped"|"error", message}}
 *
 * HTTP responses used:
 *   GET  /api/interfaces  → {interfaces: [string,...]}
 *   GET  /api/capture/status → {state, message, interface, stats,
 *                               packet_count, alert_count}
 *   POST /api/capture/start  → 202 {state:"starting", interface, output}
 *                           or 409/422 {detail: string}
 *   POST /api/capture/stop   → 200 {state:"stopping"}
 *                           or 409 {detail: string}
 *
 * No external libraries. Vanilla JS + Canvas only.
 */

"use strict";

// ── Constants ──────────────────────────────────────────────────────────────
const WS_URL           = `ws://${location.host}/ws`;
const MAX_PACKET_ROWS  = 1000;   // browser-side cap
const MAX_ALERT_ROWS   = 500;    // browser-side cap
const PPS_HISTORY_LEN  = 60;     // seconds of pps trend kept
const PROTO_COLORS = {
  TCP:   "#58a6ff",
  UDP:   "#3fb950",
  DNS:   "#bc8cff",
  ICMP:  "#d29922",
  ARP:   "#e3600a",
  IPv6:  "#79c0ff",
  IP:    "#8b949e",
  OTHER: "#8b949e",
};

// ── State ──────────────────────────────────────────────────────────────────
const state = {
  captureState:  "idle",
  captureIface:  "",
  captureFilter: "",
  stats: { count: 0, bytes: 0, pps: 0, protocols: {} },
  totalAlerts:   0,

  // Rolling packet/alert buffers (newest first)
  packets:  [],   // max MAX_PACKET_ROWS
  alerts:   [],   // max MAX_ALERT_ROWS

  // PPS history for the trend chart
  ppsHistory: new Array(PPS_HISTORY_LEN).fill(0),

  ws:            null,
  wsState:       "disconnected",   // "connected"|"connecting"|"disconnected"
  reconnectMs:   1000,
  reconnectTimer: null,
};

// Pending DOM batch for packet table
let _pendingPackets = [];
let _rafScheduled   = false;

// ── DOM refs ───────────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);

// ── Initialisation ─────────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
  loadInterfaces();
  connectWS();
  $("btn-start").addEventListener("click",  onStart);
  $("btn-stop").addEventListener("click",   onStop);
  $("btn-clear-alerts").addEventListener("click", () => {
    state.alerts = [];
    renderAlerts();
  });
  $("pkt-search").addEventListener("input", debounce(applyPacketFilter, 200));
  $("pkt-proto-filter").addEventListener("change", applyPacketFilter);
});

// ── Interface loading ──────────────────────────────────────────────────────
async function loadInterfaces() {
  try {
    const r = await fetch("/api/interfaces");
    const j = await r.json();
    const sel = $("iface-select");
    sel.innerHTML = "";
    (j.interfaces || []).forEach(iface => {
      const opt = document.createElement("option");
      opt.value = opt.textContent = iface;
      sel.appendChild(opt);
    });
    if (!j.interfaces?.length) {
      const opt = document.createElement("option");
      opt.value = ""; opt.textContent = "No interfaces found";
      sel.appendChild(opt);
    }
  } catch (e) {
    showError("Failed to load interfaces: " + e.message);
  }
}

// ── WebSocket ─────────────────────────────────────────────────────────────
function connectWS() {
  clearTimeout(state.reconnectTimer);
  setWsState("connecting");

  const ws = new WebSocket(WS_URL);
  state.ws = ws;

  ws.onopen = () => {
    setWsState("connected");
    state.reconnectMs = 1000;
  };

  ws.onmessage = evt => {
    let msg;
    try { msg = JSON.parse(evt.data); } catch { return; }
    handleMessage(msg);
  };

  ws.onclose = () => {
    state.ws = null;
    setWsState("disconnected");
    // Exponential back-off, cap at 16 s
    state.reconnectTimer = setTimeout(connectWS, state.reconnectMs);
    state.reconnectMs = Math.min(state.reconnectMs * 2, 16000);
  };

  ws.onerror = () => {
    // onclose fires after onerror — reconnect logic lives there
  };
}

function setWsState(s) {
  state.wsState = s;
  const el  = $("ws-badge");
  const dot = $("ws-dot");
  const labels = { connected:"Connected", connecting:"Connecting…", disconnected:"Disconnected" };
  el.textContent = "";
  dot.className = "badge-dot dot-" + s;
  el.appendChild(dot);
  el.appendChild(document.createTextNode(" " + labels[s]));
  el.className = "badge ws-" + s;
}

// ── Message dispatch ──────────────────────────────────────────────────────
function handleMessage(msg) {
  switch (msg.type) {
    case "snapshot": onSnapshot(msg.data);  break;
    case "packets":  onPackets(msg.data);   break;
    case "stats":    onStats(msg.data);     break;
    case "alerts":   onAlerts(msg.data);    break;
    case "status":   onStatus(msg.data);    break;
  }
}

function onSnapshot(data) {
  // Full state on reconnect — replace buffers, don't accumulate duplicates
  state.packets = [];
  state.alerts  = [];
  if (data.packets) onPackets(data.packets, /*fromSnapshot=*/true);
  if (data.alerts)  onAlerts(data.alerts,   /*fromSnapshot=*/true);
  if (data.stats)   onStats(data.stats);
  if (data.state)   applyState(data.state, data.interface || "", data.message || "");
}

function onPackets(rows, fromSnapshot = false) {
  if (!Array.isArray(rows) || !rows.length) return;
  // Newest first: prepend
  const incoming = fromSnapshot ? rows.slice().reverse() : rows.slice().reverse();
  _pendingPackets.push(...incoming);
  if (!_rafScheduled) {
    _rafScheduled = true;
    requestAnimationFrame(flushPacketBatch);
  }
}

function flushPacketBatch() {
  _rafScheduled = false;
  if (!_pendingPackets.length) return;

  // Merge pending into state
  state.packets.unshift(..._pendingPackets);
  _pendingPackets = [];
  if (state.packets.length > MAX_PACKET_ROWS) {
    state.packets.length = MAX_PACKET_ROWS;
  }

  renderPacketTable();
}

function onStats(data) {
  if (!data) return;
  state.stats = data;
  state.totalAlerts = state.alerts.length;   // keep in sync
  // Append new pps value to rolling history
  state.ppsHistory.push(typeof data.pps === "number" ? data.pps : 0);
  if (state.ppsHistory.length > PPS_HISTORY_LEN) state.ppsHistory.shift();
  renderStats();
  drawPpsChart();
  drawProtoChart();
}

function onAlerts(list, fromSnapshot = false) {
  if (!Array.isArray(list) || !list.length) return;
  const incoming = fromSnapshot ? list.slice().reverse() : list.slice().reverse();
  state.alerts.unshift(...incoming);
  if (state.alerts.length > MAX_ALERT_ROWS) state.alerts.length = MAX_ALERT_ROWS;
  $("stat-alerts").textContent = state.alerts.length;
  renderAlerts();
}

function onStatus(data) {
  if (!data) return;
  applyState(data.state, state.captureIface, data.message || "");
}

function applyState(s, iface, message) {
  state.captureState = s;
  if (iface) state.captureIface = iface;

  updateCaptureStateBadge(s);
  updateControls(s);

  // Display message for non-idle states
  if (message && s !== "idle") {
    // For errors surface the message as a visible error
    if (s === "error") showError(message);
  }

  const ifaceDisplay = $("capture-iface-display");
  if (s === "idle" || s === "error") {
    ifaceDisplay.textContent = "";
  } else {
    const bpf = $("bpf-input").value.trim();
    ifaceDisplay.textContent = iface + (bpf ? ` · ${bpf}` : "");
  }
}

function updateCaptureStateBadge(s) {
  const el = $("capture-badge");
  const labels = {
    idle: "Idle", starting: "Starting…", running: "Capturing",
    stopping: "Stopping…", error: "Error",
  };
  el.textContent = labels[s] || s;
  el.className = "badge state-" + s;
}

// ── Controls ───────────────────────────────────────────────────────────────
function updateControls(s) {
  const canStart = (s === "idle" || s === "error");
  const canStop  = (s === "starting" || s === "running");
  $("btn-start").disabled = !canStart;
  $("btn-stop").disabled  = !canStop;
  $("iface-select").disabled = !canStart;
  $("bpf-input").disabled    = !canStart;
}

async function onStart() {
  clearError();
  const iface = $("iface-select").value.trim();
  const bpf   = $("bpf-input").value.trim();
  if (!iface) { showError("Select a network interface."); return; }

  // Reset per-session data immediately for responsive feel
  state.packets = [];
  state.alerts  = [];
  state.ppsHistory.fill(0);
  state.stats = { count: 0, bytes: 0, pps: 0, protocols: {} };
  renderStats();
  renderPacketTable();
  renderAlerts();

  try {
    const r = await fetch("/api/capture/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ interface: iface, bpf_filter: bpf }),
    });
    const j = await r.json();
    if (!r.ok) {
      showError(j.detail || `Start failed (HTTP ${r.status})`);
      return;
    }
    // Accepted — state will be confirmed via WebSocket status message
    applyState("starting", iface, "");
    state.captureFilter = bpf;
  } catch (e) {
    showError("Network error: " + e.message);
  }
}

async function onStop() {
  clearError();
  try {
    const r = await fetch("/api/capture/stop", { method: "POST" });
    const j = await r.json();
    if (!r.ok) {
      showError(j.detail || `Stop failed (HTTP ${r.status})`);
      return;
    }
    applyState("stopping", state.captureIface, "");
  } catch (e) {
    showError("Network error: " + e.message);
  }
}

// ── Stats rendering ────────────────────────────────────────────────────────
function renderStats() {
  const s = state.stats;
  $("stat-packets").textContent = fmtNum(s.count  ?? 0);
  $("stat-pps").textContent     = fmtPps(s.pps    ?? 0);
  $("stat-bytes").textContent   = fmtBytes(s.bytes ?? 0);
  $("stat-alerts").textContent  = state.alerts.length;
}

// ── Packet table ───────────────────────────────────────────────────────────
function renderPacketTable() {
  const search = $("pkt-search").value.toLowerCase();
  const proto  = $("pkt-proto-filter").value;
  const tbody  = $("pkt-tbody");

  let rows = state.packets;
  if (proto) rows = rows.filter(p => p.protocol === proto);
  if (search) rows = rows.filter(p =>
    p.src.includes(search) || p.dst.includes(search) ||
    p.protocol.toLowerCase().includes(search) ||
    p.sport.includes(search) || p.dport.includes(search)
  );

  $("pkt-count").textContent = rows.length
    ? `${rows.length.toLocaleString()} packet${rows.length === 1 ? "" : "s"}`
    : "";

  if (!rows.length) {
    tbody.innerHTML = `<tr><td colspan="8" class="empty-state">${
      state.captureState === "idle" || state.captureState === "error"
        ? "Start a capture to see live packets."
        : "Waiting for packets…"
    }</td></tr>`;
    return;
  }

  // Build fragment for efficient DOM insertion
  const frag = document.createDocumentFragment();
  const limit = Math.min(rows.length, MAX_PACKET_ROWS);
  for (let i = 0; i < limit; i++) {
    const p = rows[i];
    const tr = document.createElement("tr");
    tr.innerHTML =
      `<td>${p.timestamp}</td>` +
      `<td class="td-proto proto-${p.protocol}">${esc(p.protocol)}</td>` +
      `<td>${esc(p.src)}</td>` +
      `<td>${esc(p.sport)}</td>` +
      `<td>${esc(p.dst)}</td>` +
      `<td>${esc(p.dport)}</td>` +
      `<td class="td-size">${fmtBytes(p.size)}</td>` +
      `<td class="td-flags">${esc(p.flags)}</td>`;
    frag.appendChild(tr);
  }
  tbody.innerHTML = "";
  tbody.appendChild(frag);
}

function applyPacketFilter() { renderPacketTable(); }

// ── Alert rendering ────────────────────────────────────────────────────────
function renderAlerts() {
  const container = $("alert-list");
  if (!state.alerts.length) {
    container.innerHTML =
      `<p class="empty-state" style="padding:20px 0">No security alerts detected.</p>`;
    return;
  }
  const frag = document.createDocumentFragment();
  const limit = Math.min(state.alerts.length, MAX_ALERT_ROWS);
  for (let i = 0; i < limit; i++) {
    const a = state.alerts[i];
    const div = document.createElement("div");
    div.className = `alert-item sev-${a.severity}`;
    div.innerHTML =
      `<div class="alert-header">` +
        `<span class="alert-type">${esc(a.type)}</span>` +
        `<span class="sev-badge sev-${a.severity}-badge">${esc(a.severity)}</span>` +
        `<span class="alert-ts">${esc(a.timestamp)}</span>` +
      `</div>` +
      `<div class="alert-meta">` +
        `${esc(a.source_ip)} → ${esc(a.destination_ip)}` +
        (a.destination_port != null ? `:${a.destination_port}` : "") +
        ` &nbsp;·&nbsp; ${esc(a.reason)}` +
      `</div>`;
    frag.appendChild(div);
  }
  container.innerHTML = "";
  container.appendChild(frag);
}

// ── Charts ─────────────────────────────────────────────────────────────────
function drawPpsChart() {
  const canvas = $("chart-pps");
  const ctx    = canvas.getContext("2d");
  const W = canvas.width, H = canvas.height;
  const data   = state.ppsHistory;
  const max    = Math.max(...data, 1);

  ctx.clearRect(0, 0, W, H);

  // Grid lines
  ctx.strokeStyle = "#21262d";
  ctx.lineWidth   = 1;
  for (let i = 1; i <= 4; i++) {
    const y = Math.round(H - (i / 4) * H) + 0.5;
    ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(W, y); ctx.stroke();
  }

  // Line
  const step = W / (data.length - 1);
  ctx.beginPath();
  ctx.strokeStyle = "#388bfd";
  ctx.lineWidth   = 1.5;
  ctx.lineJoin    = "round";
  data.forEach((v, i) => {
    const x = i * step;
    const y = H - (v / max) * (H - 4) - 2;
    i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
  });
  ctx.stroke();

  // Fill
  ctx.lineTo((data.length - 1) * step, H);
  ctx.lineTo(0, H);
  ctx.closePath();
  ctx.fillStyle = "rgba(56,139,253,0.10)";
  ctx.fill();

  // Max label
  ctx.fillStyle = "#8b949e";
  ctx.font      = "10px monospace";
  ctx.fillText(`${fmtPps(max)} max`, 4, 12);
}

function drawProtoChart() {
  const canvas = $("chart-proto");
  const ctx    = canvas.getContext("2d");
  const W = canvas.width, H = canvas.height;
  const protocols = state.stats.protocols || {};

  // Collapse non-primary protocols into "Other"
  const PRIMARY = ["TCP","UDP","DNS","ICMP","ARP"];
  const counts  = {};
  let otherCount = 0;
  for (const [k, v] of Object.entries(protocols)) {
    if (PRIMARY.includes(k)) counts[k] = v;
    else otherCount += v;
  }
  if (otherCount > 0) counts["OTHER"] = otherCount;

  const entries = Object.entries(counts).sort((a, b) => b[1] - a[1]);
  const total   = entries.reduce((s, [, v]) => s + v, 0);

  ctx.clearRect(0, 0, W, H);

  if (!entries.length || total === 0) {
    ctx.fillStyle = "#8b949e"; ctx.font = "11px sans-serif";
    ctx.textAlign = "center";
    ctx.fillText("No data", W / 2, H / 2 + 4);
    ctx.textAlign = "left";
    return;
  }

  // Horizontal bar chart
  const barH  = Math.min(22, (H - 8) / entries.length - 4);
  const labelW = 42;
  const barW   = W - labelW - 44;
  const pad    = 4;

  entries.forEach(([proto, count], i) => {
    const y    = pad + i * (barH + 4);
    const pct  = count / total;
    const fill = Math.max(2, pct * barW);
    const color = PROTO_COLORS[proto] || "#8b949e";

    // Label
    ctx.fillStyle = "#8b949e"; ctx.font = "10px monospace";
    ctx.textAlign = "right";
    ctx.fillText(proto.padStart(5), labelW - 4, y + barH - 3);
    ctx.textAlign = "left";

    // Bar background
    ctx.fillStyle = "#21262d";
    ctx.beginPath();
    ctx.roundRect(labelW, y, barW, barH, 3);
    ctx.fill();

    // Bar fill
    ctx.fillStyle = color;
    ctx.globalAlpha = 0.75;
    ctx.beginPath();
    ctx.roundRect(labelW, y, fill, barH, 3);
    ctx.fill();
    ctx.globalAlpha = 1;

    // Count
    ctx.fillStyle = "#8b949e"; ctx.font = "10px monospace";
    ctx.fillText(fmtNum(count), labelW + barW + 4, y + barH - 3);
  });
}

// ── Resize canvases to match CSS layout ────────────────────────────────────
function resizeCanvases() {
  for (const id of ["chart-pps", "chart-proto"]) {
    const c = $(id);
    if (!c) continue;
    const rect = c.getBoundingClientRect();
    if (rect.width > 0) {
      c.width  = Math.round(rect.width  * devicePixelRatio);
      c.height = Math.round(rect.height * devicePixelRatio);
      c.style.width  = rect.width  + "px";
      c.style.height = rect.height + "px";
      c.getContext("2d").scale(devicePixelRatio, devicePixelRatio);
    }
  }
  drawPpsChart();
  drawProtoChart();
}
window.addEventListener("resize", debounce(resizeCanvases, 150));
// Initial resize after layout settles
setTimeout(resizeCanvases, 100);

// ── Utility ────────────────────────────────────────────────────────────────
function fmtNum(n) {
  return Number(n).toLocaleString();
}
function fmtPps(v) {
  const n = Number(v);
  if (n >= 1000) return (n / 1000).toFixed(1) + "k/s";
  return n.toFixed(n >= 10 ? 0 : 1) + "/s";
}
function fmtBytes(b) {
  const n = Number(b);
  if (n >= 1073741824) return (n / 1073741824).toFixed(1) + " GB";
  if (n >= 1048576)    return (n / 1048576).toFixed(1)    + " MB";
  if (n >= 1024)       return (n / 1024).toFixed(1)       + " KB";
  return n + " B";
}

function esc(s) {
  if (s == null) return "";
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function showError(msg) {
  const el = $("error-msg");
  el.textContent = msg;
  el.classList.add("visible");
}
function clearError() {
  $("error-msg").classList.remove("visible");
}

function debounce(fn, ms) {
  let t;
  return (...args) => { clearTimeout(t); t = setTimeout(() => fn(...args), ms); };
}

// ── Canvas roundRect polyfill for older browsers ────────────────────────────
if (!CanvasRenderingContext2D.prototype.roundRect) {
  CanvasRenderingContext2D.prototype.roundRect = function(x, y, w, h, r) {
    r = Math.min(r, w / 2, h / 2);
    this.moveTo(x + r, y);
    this.arcTo(x + w, y, x + w, y + h, r);
    this.arcTo(x + w, y + h, x,     y + h, r);
    this.arcTo(x,     y + h, x,     y,     r);
    this.arcTo(x,     y,     x + w, y,     r);
    this.closePath();
    return this;
  };
}
