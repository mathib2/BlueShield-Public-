/**
 * BlueShield v5.0 — Bluetooth Intelligence Platform Dashboard
 *
 * Features: Tab navigation, device table (clustered/raw), split-pane detail,
 * risk scoring, movement indicators, proximity radar w/ trails, RSSI charts,
 * tracker detection, ecosystem graph, analytics, packet inspector, ghost mode,
 * trust/untrust toggle, configurable alerts, channel grid, timeline,
 * AI classification, people detection, BT weather, time travel playback,
 * following detection, shadow devices, environment fingerprint,
 * conversation graph, device life story, advanced mode.
 */

/* ── Helpers ───────────────────────────────────────────────── */
const $ = id => document.getElementById(id);
const clamp = (v, lo, hi) => Math.max(lo, Math.min(hi, v));

/* ── SVG Icon Map — replaces emojis with professional stroke icons ── */
const _s = (d, w=16) => `<svg viewBox="0 0 24 24" width="${w}" height="${w}" fill="none" stroke="currentColor" stroke-width="2">${d}</svg>`;
const ICO = {
    phone:    _s('<rect x="5" y="2" width="14" height="20" rx="2" ry="2"/><line x1="12" y1="18" x2="12.01" y2="18"/>'),
    audio:    _s('<path d="M3 18v-6a9 9 0 0 1 18 0v6"/><path d="M21 19a2 2 0 0 1-2 2h-1a2 2 0 0 1-2-2v-3a2 2 0 0 1 2-2h3zM3 19a2 2 0 0 0 2 2h1a2 2 0 0 0 2-2v-3a2 2 0 0 0-2-2H3z"/>'),
    input:    _s('<path d="M12 2a6 6 0 0 0-6 6v8a6 6 0 0 0 12 0V8a6 6 0 0 0-6-6z"/><line x1="12" y1="6" x2="12" y2="10"/>'),
    watch:    _s('<circle cx="12" cy="12" r="7"/><polyline points="12 9 12 12 13.5 13.5"/><path d="M16.51 17.35l-.35 3.83a2 2 0 0 1-2 1.82H9.83a2 2 0 0 1-2-1.82l-.35-3.83m.01-10.7l.35-3.83A2 2 0 0 1 9.83 1h4.35a2 2 0 0 1 2 1.82l.35 3.83"/>'),
    computer: _s('<rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/>'),
    tv:       _s('<rect x="2" y="7" width="20" height="15" rx="2" ry="2"/><polyline points="17 2 12 7 7 2"/>'),
    tracker:  _s('<circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/>'),
    health:   _s('<path d="M20.84 4.61a5.5 5.5 0 0 0-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 0 0-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 5.5 0 0 0 0-7.78z"/>'),
    gaming:   _s('<line x1="6" y1="12" x2="10" y2="12"/><line x1="8" y1="10" x2="8" y2="14"/><line x1="15" y1="13" x2="15.01" y2="13"/><line x1="18" y1="11" x2="18.01" y2="11"/><rect x="2" y="6" width="20" height="12" rx="2"/>'),
    iot:      _s('<path d="M9 18h6M10 22h4M12 2a7 7 0 0 1 7 7c0 2.38-1.19 4.47-3 5.74V17a1 1 0 0 1-1 1h-6a1 1 0 0 1-1-1v-2.26C6.19 13.47 5 11.38 5 9a7 7 0 0 1 7-7z"/>'),
    apple:    _s('<path d="M12 20.94c1.5 0 2.75 1.06 4 1.06 3 0 5-4 5-8.5C21 9 18.22 6 15.5 6c-1.5 0-2.72.72-3.5.72S10 6 8.5 6C5.78 6 3 9 3 13.5 3 18 5 22 8 22c1.25 0 2.5-1.06 4-1.06z"/><path d="M12 2c1 .5 2 2 2 3.5S13 8 12 8"/>'),
    signal:   _s('<path d="M5 12.55a11 11 0 0 1 14.08 0M1.42 9a16 16 0 0 1 21.16 0M8.53 16.11a6 6 0 0 1 6.95 0"/><line x1="12" y1="20" x2="12.01" y2="20"/>'),
    unknown:  _s('<circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><line x1="12" y1="17" x2="12.01" y2="17"/>'),
    radio:    _s('<circle cx="12" cy="12" r="2"/><path d="M16.24 7.76a6 6 0 0 1 0 8.49m-8.48-.01a6 6 0 0 1 0-8.49m11.31-2.82a10 10 0 0 1 0 14.14m-14.14 0a10 10 0 0 1 0-14.14"/>'),
    bell:     _s('<path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9M13.73 21a2 2 0 0 1-3.46 0"/>'),
    pkg:      _s('<line x1="16.5" y1="9.4" x2="7.5" y2="4.21"/><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/><polyline points="3.27 6.96 12 12.01 20.73 6.96"/><line x1="12" y1="22.08" x2="12" y2="12"/>'),
    cpu:      _s('<rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/><line x1="9" y1="1" x2="9" y2="4"/><line x1="15" y1="1" x2="15" y2="4"/><line x1="9" y1="20" x2="9" y2="23"/><line x1="15" y1="20" x2="15" y2="23"/><line x1="20" y1="9" x2="23" y2="9"/><line x1="20" y1="14" x2="23" y2="14"/><line x1="1" y1="9" x2="4" y2="9"/><line x1="1" y1="14" x2="4" y2="14"/>'),
    alert:    _s('<path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>'),
    shield:   _s('<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>'),
    shieldOk: _s('<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/>'),
    moon:     _s('<path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>'),
    ghost:    _s('<path d="M12 2C7 2 3 6 3 11v9l3-3 3 3 3-3 3 3 3-3 3 3v-9c0-5-4-9-9-9z"/><circle cx="9" cy="10" r="1" fill="currentColor"/><circle cx="15" cy="10" r="1" fill="currentColor"/>'),
    eye:      _s('<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>'),
    siren:    _s('<polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>'),
    book:     _s('<path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"/><path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"/>'),
    keyboard: _s('<rect x="2" y="4" width="20" height="16" rx="2" ry="2"/><line x1="6" y1="8" x2="6.01" y2="8"/><line x1="10" y1="8" x2="10.01" y2="8"/><line x1="14" y1="8" x2="14.01" y2="8"/><line x1="18" y1="8" x2="18.01" y2="8"/><line x1="8" y1="12" x2="8.01" y2="12"/><line x1="12" y1="12" x2="12.01" y2="12"/><line x1="16" y1="12" x2="16.01" y2="12"/><line x1="7" y1="16" x2="17" y2="16"/>'),
    speaker:  _s('<rect x="4" y="2" width="16" height="20" rx="2" ry="2"/><circle cx="12" cy="14" r="4"/><line x1="12" y1="6" x2="12.01" y2="6"/>'),
    // Weather icons
    sun:      _s('<circle cx="12" cy="12" r="5"/><path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/>'),
    cloud:    _s('<path d="M18 10h-1.26A8 8 0 1 0 9 20h9a5 5 0 0 0 0-10z"/>'),
    waves:    _s('<path d="M2 6c2-2 4-2 6 0s4 2 6 0 4-2 6 0"/><path d="M2 12c2-2 4-2 6 0s4 2 6 0 4-2 6 0"/><path d="M2 18c2-2 4-2 6 0s4 2 6 0 4-2 6 0"/>'),
    activity: _s('<polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>'),
    trendDn:  _s('<polyline points="23 18 13.5 8.5 8.5 13.5 1 6"/><polyline points="17 18 23 18 23 12"/>'),
    trendUp:  _s('<polyline points="23 6 13.5 15.5 8.5 10.5 1 18"/><polyline points="17 6 23 6 23 12"/>'),
    thermo:   _s('<path d="M14 14.76V3.5a2.5 2.5 0 0 0-5 0v11.26a4.5 4.5 0 1 0 5 0z"/>'),
    battery:  _s('<rect x="1" y="6" width="18" height="12" rx="2" ry="2"/><line x1="23" y1="13" x2="23" y2="11"/>'),
    zap:      _s('<polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>'),
    disk:     _s('<line x1="22" y1="12" x2="2" y2="12"/><path d="M5.45 5.11L2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"/>'),
    clock:    _s('<circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>'),
    pin:      _s('<path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z"/><circle cx="12" cy="10" r="3"/>'),
};

/* ── State ─────────────────────────────────────────────────── */
let currentDevices   = [];
let currentClustered = [];
let clusterSummary   = {};
let trackerSuspects  = [];
let analyticsData    = {};
let alertRules       = [];
let alertList        = [];
let timeline         = [];
let channelStats     = new Array(40).fill(0);
let viewMode         = "clustered";       // "clustered" | "raw"
let selectedDeviceId = null;
let searchFilter     = "";
let sortCol          = "";
let sortDir          = "asc";
let autoScan         = true;
let jammerActive     = false;
let startTime        = Date.now();
let radarAnimFrame   = null;
let radarAngle       = 0;
let classifications  = {};
let peopleData       = {};
let safetyData       = {};
let weatherData      = {};
let scanSnapshots    = [];
let timeTravelMode   = false;
let followingAlerts  = [];
let shadowDevices    = [];
let envData          = {};
let trailData        = {};
let advancedMode     = false;
let graphData        = null;
let correlatedDevices = [];
let correlatorStats  = {};
let _prevDeviceCount = 0;
let _animeReady      = typeof anime !== 'undefined';

/* ── Socket.IO ─────────────────────────────────────────────── */
const socket = io();

socket.on("connect", () => {
    $("pill-conn").classList.add("on");
    $("conn-text").textContent = "Connected";
});
socket.on("disconnect", () => {
    $("pill-conn").classList.remove("on");
    $("conn-text").textContent = "Disconnected";
});

socket.on("status", data => {
    currentDevices   = data.devices || [];
    currentClustered = data.clustered_devices || [];
    clusterSummary   = data.cluster_summary || {};
    trackerSuspects  = data.tracker_suspects || [];
    analyticsData    = data.analytics || {};
    alertRules       = data.alert_rules || [];
    if (data.people) peopleData = data.people;
    if (data.safety) safetyData = data.safety;
    if (data.weather) weatherData = data.weather;
    if (data.classifications) classifications = data.classifications;
    if (data.following) followingAlerts = data.following;
    if (data.shadows) shadowDevices = data.shadows;
    if (data.environment) envData = data.environment;
    if (data.trails) trailData = data.trails;
    if (data.advanced_mode !== undefined) advancedMode = data.advanced_mode;
    autoScan = data.auto_scan !== false;
    updateAutoScanBtn();
    updateAdvancedModeBtn();
    updateAll();
    updatePlatform(data.platform || {});
    updateJammer(data.jammer || {});
    renderAlertList(data.alerts || []);
    renderAlertRules();
    if (data.range_presets) $("range-select").value = Object.entries(data.range_presets).find(([k,v]) => v === data.rssi_filter)?.[0] || "all";
    if (data.scan_interval) {
        $("scan-interval").value = data.scan_interval;
        $("interval-display").textContent = data.scan_interval + "s";
    }
});

socket.on("scan_result", data => {
    $("pill-scan").classList.remove("scanning");
    $("scan-text").textContent = `${data.total_devices || 0} found`;
    addTimelineEvent("scan", `Scan #${data.scan_id}: ${data.total_devices} devices, ${data.new_devices} new`);
    simulateChannelActivity(data.total_devices || 0);
});

socket.on("device_update", data => {
    _prevDeviceCount = currentClustered.length;
    currentDevices   = data.devices || currentDevices;
    currentClustered = data.clustered_devices || currentClustered;
    clusterSummary   = data.cluster_summary || clusterSummary;
    if (data.tracker_suspects) trackerSuspects = data.tracker_suspects;
    if (data.analytics) analyticsData = data.analytics;
    if (data.classifications) classifications = data.classifications;
    if (data.people) peopleData = data.people;
    if (data.safety) safetyData = data.safety;
    if (data.weather) weatherData = data.weather;
    if (data.following) followingAlerts = data.following;
    if (data.shadows) shadowDevices = data.shadows;
    if (data.environment) envData = data.environment;
    if (data.trails) trailData = data.trails;
    if (data.correlated_devices) correlatedDevices = data.correlated_devices;
    if (data.correlator_stats) correlatorStats = data.correlator_stats;
    updateAll();
    updateCorrelatorBar();
    animateNewDeviceRows();
    /* keep jammer picker fresh when jammer tab is visible */
    if (document.getElementById("tab-jammer")?.classList.contains("active")) renderJammerPicker();
});
socket.on("advanced_mode", data => {
    advancedMode = data.enabled;
    updateAdvancedModeBtn();
});

socket.on("alert", data => {
    const d = data.data || data;
    alertList.unshift(data);
    if (alertList.length > 200) alertList.length = 200;
    renderAlertList();
    addTimelineEvent("alert", d.message || "Alert triggered");
    if (d.rule_id === "tracker_detected") addTimelineEvent("tracker", d.message);
});

socket.on("jammer_update", data => updateJammer(data));
socket.on("autoscan_changed", data => { autoScan = data.enabled; updateAutoScanBtn(); });
socket.on("range_changed", data => { $("sb-range").textContent = `Range: ${data.preset || "custom"}`; });
socket.on("ghost_mode", data => {
    if (data.status === "shutting_down") addTimelineEvent("alert", "GHOST MODE ACTIVATED — System shutting down!");
});

/* ── Update Everything ─────────────────────────────────────── */
function updateAll() {
    renderDeviceTable();
    renderStatsStrip();
    renderEnvStats();
    renderSignalPanels();
    renderChannelGrid();
    renderTrackerGrid();
    renderFollowingGrid();
    renderShadowGrid();
    renderConversationGraph();
    renderAnalytics();
    renderLiveDemo();
    updateStatusBar();
    if (selectedDeviceId) renderDetailPanel();
    $("sf-scans").textContent = clusterSummary.total_physical_devices || currentClustered.length || 0;
    $("nav-dev-count").textContent = viewMode === "clustered" ? currentClustered.length : currentDevices.length;
}

/* ── Tab Navigation ────────────────────────────────────────── */
document.querySelectorAll(".nav-item[data-tab]").forEach(btn => {
    btn.addEventListener("click", () => switchTab(btn.dataset.tab));
});
function switchTab(tab) {
    document.querySelectorAll(".nav-item[data-tab]").forEach(b => b.classList.toggle("active", b.dataset.tab === tab));
    document.querySelectorAll(".tab-pane").forEach(p => p.classList.toggle("active", p.id === "tab-" + tab));
    if (tab === "radar") startRadar(); else stopRadar();
    if (tab === "analytics") requestAnimationFrame(() => renderAnalytics());
    if (tab === "jammer") renderJammerPicker();
    if (tab === "graph") renderConversationGraph();
    if (tab === "following") renderFollowingGrid();
    if (tab === "shadows") renderShadowGrid();
    if (tab === "live") { renderLiveDemo(); fetchTimeTravel(); }
    healthTabActive = (tab === "health");
    if (tab === "health") fetchSystemHealth();
}

/* ── Sidebar Toggle ────────────────────────────────────────── */
$("sidebar-toggle").addEventListener("click", () => $("sidebar").classList.toggle("collapsed"));

/* ── Theme Toggle ──────────────────────────────────────────── */
$("btn-theme").addEventListener("click", () => {
    const isDark = document.documentElement.getAttribute("data-theme") === "dark";
    document.documentElement.setAttribute("data-theme", isDark ? "light" : "dark");
    $("ico-sun").style.display  = isDark ? "none" : "";
    $("ico-moon").style.display = isDark ? "" : "none";
    localStorage.setItem("theme", isDark ? "light" : "dark");
});
{ const t = localStorage.getItem("theme"); if (t === "light") { document.documentElement.setAttribute("data-theme","light"); $("ico-sun").style.display="none"; $("ico-moon").style.display=""; } }

/* ── Clock ─────────────────────────────────────────────────── */
setInterval(() => {
    const d = new Date();
    $("clock").textContent = d.toTimeString().slice(0, 8);
    const up = Math.floor((Date.now() - startTime) / 1000);
    const m = Math.floor(up / 60), s = up % 60;
    $("sf-uptime").textContent = `${m}:${String(s).padStart(2, "0")}`;
}, 1000);

/* ── Scan Controls ─────────────────────────────────────────── */
$("btn-scan").addEventListener("click", async () => {
    $("pill-scan").classList.add("scanning"); $("scan-text").textContent = "Scanning...";
    try { await fetch("/api/scan", { method: "POST" }); } catch {}
});
$("btn-autoscan").addEventListener("click", () => {
    autoScan = !autoScan;
    socket.emit("toggle_autoscan", { enabled: autoScan });
    updateAutoScanBtn();
});
function updateAutoScanBtn() {
    $("btn-autoscan").textContent = autoScan ? "Auto: ON" : "Auto: OFF";
    $("btn-autoscan").classList.toggle("active", autoScan);
}
$("scan-interval").addEventListener("input", e => {
    $("interval-display").textContent = e.target.value + "s";
    socket.emit("set_scan_interval", { interval: parseInt(e.target.value) });
});
$("range-select").addEventListener("change", e => {
    socket.emit("set_range", { preset: e.target.value });
});

/* ── View Mode ─────────────────────────────────────────────── */
$("vt-clustered").addEventListener("click", () => { viewMode = "clustered"; $("vt-clustered").classList.add("active"); $("vt-raw").classList.remove("active"); renderDeviceTable(); });
$("vt-raw").addEventListener("click", () => { viewMode = "raw"; $("vt-raw").classList.add("active"); $("vt-clustered").classList.remove("active"); renderDeviceTable(); });
$("device-search").addEventListener("input", e => { searchFilter = e.target.value.toLowerCase(); renderDeviceTable(); });

/* ── Ghost Mode ────────────────────────────────────────────── */
function ghostMode() {
    if (confirm("GHOST MODE: This will immediately shut down the system.\nAre you sure?")) {
        if (confirm("FINAL WARNING: The Raspberry Pi will power off NOW.\nContinue?")) {
            fetch("/api/ghost", { method: "POST" });
        }
    }
}
$("btn-ghost").addEventListener("click", ghostMode);
if ($("btn-ghost-cfg")) $("btn-ghost-cfg").addEventListener("click", ghostMode);

/* ── USB Reset ────────────────────────────────────────────── */
async function usbReset() {
    if (!confirm("Reset USB hub? This will briefly disconnect all USB devices and remap adapters.")) return;
    try {
        const r = await fetch("/api/usb-reset", { method: "POST" });
        const d = await r.json();
        if (d.status === "ok") {
            const m = d.mapping;
            alert(`USB Reset OK!\n\nScanner: ${m.scanner}\nJammer 1: ${m.jammer_primary}\nJammer 2: ${m.jammer_secondary || "N/A"}\nnRF: ${m.nrf_dongles.map(n => n.port + (n.available ? " OK" : " MISSING")).join(", ")}`);
            location.reload();
        } else {
            alert("USB reset error: " + (d.error || "unknown"));
        }
    } catch (e) {
        alert("USB reset failed: " + e.message);
    }
}

/* ── Device Table ──────────────────────────────────────────── */
const CLUSTERED_COLS = ["", "Name", "Category", "Risk", "Motion", "RSSI", "MACs", "Duration", "Status", "Actions"];
const RAW_COLS = ["", "Address", "Name", "Category", "RSSI", "Type", "Manufacturer", "Status"];

function renderDeviceTable() {
    const thead = $("dev-thead");
    const tbody = $("dev-tbody");
    const cols = viewMode === "clustered" ? CLUSTERED_COLS : RAW_COLS;

    thead.innerHTML = cols.map(c => `<th>${c}${sortCol === c ? (sortDir === "asc" ? " ↑" : " ↓") : ""}</th>`).join("");
    thead.querySelectorAll("th").forEach((th, i) => {
        th.addEventListener("click", () => {
            const col = cols[i];
            if (sortCol === col) sortDir = sortDir === "asc" ? "desc" : "asc";
            else { sortCol = col; sortDir = "asc"; }
            renderDeviceTable();
        });
    });

    let devs = viewMode === "clustered" ? [...currentClustered] : [...currentDevices];

    if (searchFilter) {
        devs = devs.filter(d => {
            const haystack = JSON.stringify(d).toLowerCase();
            return haystack.includes(searchFilter);
        });
    }

    if (!devs.length) {
        tbody.innerHTML = '<tr class="empty-row"><td colspan="10">Waiting for first scan...</td></tr>';
        return;
    }

    tbody.innerHTML = devs.map(d => viewMode === "clustered" ? renderClusteredRow(d) : renderRawRow(d)).join("");
}

function renderClusteredRow(d) {
    const id = d.fingerprint_id || "";
    const rssi = Math.round(d.avg_rssi || -100);
    const pct = clamp(((rssi + 100) / 60) * 100, 0, 100);
    const rssiColor = rssi > -50 ? "var(--green)" : rssi > -70 ? "var(--orange)" : "var(--red)";
    const rowCls = d.is_known ? "row-ok" : (d.risk_level === "critical" ? "row-crit" : d.alert_level === "warning" ? "row-warn" : "");
    const sel = selectedDeviceId === id ? "selected" : "";
    const followCls = !d.is_known && d.rssi_trend === "stationary" && (d.duration_seconds || 0) > 1800 ? "follow-suspect" : "";

    /* Correlator info: find matching correlated device */
    const corrDev = correlatedDevices.find(c => c.primary_mac === (d.mac_addresses?.[0] || ""));
    const macCount = corrDev ? corrDev.mac_count : (d.mac_count || 0);
    const isRandomMac = corrDev ? corrDev.is_random_mac : false;
    const corrTrend = corrDev ? corrDev.rssi_trend : "";
    const multiMacCls = macCount > 1 ? "multi-mac correlated dev-row" : "dev-row";

    const riskBadge = `<span class="risk-badge risk-${d.risk_level || 'low'}">${d.risk_score || 0} ${(d.risk_level || 'low').toUpperCase()}</span>`;

    const motionArrows = { approaching: "↑ Nearing", leaving: "↓ Leaving", stationary: "— Idle" };
    const motionCls = `movement-${d.rssi_trend || "stationary"}`;
    const trendCls = corrTrend === "approaching" ? "trend-approaching" : corrTrend === "receding" ? "trend-receding" : "trend-stable";
    const motion = `<span class="movement-ind ${motionCls} ${trendCls}">${motionArrows[d.rssi_trend] || "— Idle"}</span>`;

    const action = d.is_known
        ? `<button class="btn-untrust" onclick="untrustDevice('${id}');event.stopPropagation()">Untrust</button>`
        : `<button class="btn-trust" onclick="trustFingerprint('${id}');event.stopPropagation()">Trust</button>`;

    const eco = d.ecosystem ? `<span class="eco-badge eco-${d.ecosystem || 'other'}">${d.ecosystem}</span>` : "";
    const macBadge = macCount > 1 ? `<span class="mac-badge">${macCount} MACs</span>` : (isRandomMac ? `<span class="mac-badge random">RND</span>` : "");

    return `<tr class="${rowCls} ${sel} ${followCls} ${multiMacCls}" onclick="selectDevice('${id}')">
        <td>${d.category_icon || ICO.unknown}</td>
        <td><strong>${escHtml(d.best_name || "Unknown")}</strong> ${eco} ${macBadge}<br><span class="mono" style="font-size:.62rem;color:var(--tx-3)">${id}</span></td>
        <td><span class="cat-pill">${d.category_icon || "?"} ${d.category || "?"}</span></td>
        <td>${riskBadge}</td>
        <td>${motion}</td>
        <td><span class="mono">${rssi}</span> <div class="rssi-bar"><div class="rssi-fill" style="width:${pct}%;background:${rssiColor}"></div></div></td>
        <td><span class="mac-chip">${macCount}</span></td>
        <td><span class="mono">${d.duration_display || "0s"}</span></td>
        <td>${d.is_known ? '<span class="tag tag-ok">Trusted</span>' : '<span class="tag tag-warn">Unknown</span>'}</td>
        <td>${action}</td>
    </tr>`;
}

function renderRawRow(d) {
    const addr = d.address || "";
    const rssi = d.rssi || 0;
    const pct = clamp(((rssi + 100) / 60) * 100, 0, 100);
    const rssiColor = rssi > -50 ? "var(--green)" : rssi > -70 ? "var(--orange)" : "var(--red)";
    const rowCls = d.is_known ? "row-ok" : d.alert_level === "critical" ? "row-crit" : d.alert_level === "warning" ? "row-warn" : "";
    const sel = selectedDeviceId === addr ? "selected" : "";

    return `<tr class="${rowCls} ${sel}" onclick="selectDevice('${addr}')">
        <td>${d.category_icon || ICO.unknown}</td>
        <td><span class="mono">${addr}</span></td>
        <td>${escHtml(d.name || "Unknown")}</td>
        <td><span class="cat-pill">${d.category_icon || "?"} ${d.category || "?"}</span></td>
        <td><span class="mono">${rssi}</span> <div class="rssi-bar"><div class="rssi-fill" style="width:${pct}%;background:${rssiColor}"></div></div></td>
        <td>${d.device_type || "?"}</td>
        <td>${escHtml(d.manufacturer || "Unknown")}</td>
        <td>${d.is_known ? '<span class="tag tag-ok">Trusted</span>' : `<button class="btn-trust" onclick="trustDevice('${addr}');event.stopPropagation()">Trust</button>`}</td>
    </tr>`;
}

function escHtml(s) { return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;"); }

/* ── Device Selection & Detail Panel ───────────────────────── */
window.selectDevice = function(id) {
    selectedDeviceId = id;
    $("device-detail").classList.add("open");
    renderDetailPanel();
    renderDeviceTable();
};
$("close-detail").addEventListener("click", () => {
    selectedDeviceId = null;
    $("device-detail").classList.remove("open");
    renderDeviceTable();
});

function renderDetailPanel() {
    const body = $("detail-body");
    let d = null;
    if (viewMode === "clustered") d = currentClustered.find(x => x.fingerprint_id === selectedDeviceId);
    else d = currentDevices.find(x => x.address === selectedDeviceId);
    if (!d) { body.innerHTML = '<div class="empty-msg">Device not found</div>'; return; }

    let html = "";

    // Basic Info
    html += `<div class="detail-section"><div class="detail-section-title">Device Info</div>`;
    html += detailRow("Name", d.best_name || d.name || "Unknown");
    html += detailRow("Category", `${d.category_icon || ""} ${d.category || "unknown"}`);
    if (d.fingerprint_id) html += detailRow("Fingerprint", d.fingerprint_id);
    html += detailRow("Manufacturer", d.manufacturer_name || d.manufacturer || "Unknown");
    if (d.ecosystem) html += detailRow("Ecosystem", `<span class="eco-badge eco-${d.ecosystem}">${d.ecosystem}</span>`);
    html += detailRow("RSSI", `${Math.round(d.avg_rssi || d.rssi || -100)} dBm`);
    if (d.confidence_score !== undefined) html += detailRow("Confidence", `${Math.round(d.confidence_score * 100)}%`);
    html += detailRow("Duration", d.duration_display || "0s");
    html += detailRow("Observations", d.observation_count || d.seen_count || 0);
    html += `</div>`;

    // AI Classification
    const cls = classifications[d.fingerprint_id || ""];
    if (cls && cls.top) {
        const confPct = Math.round(cls.top.confidence * 100);
        const confCls = confPct >= 60 ? "aif-conf-high" : confPct >= 30 ? "aif-conf-med" : "aif-conf-low";
        html += `<div class="detail-section"><div class="detail-section-title">${ICO.cpu} AI Classification</div>`;
        html += `<div class="ai-class-card">`;
        html += `<div class="ai-class-top"><span class="ai-class-icon">${cls.top.icon}</span><span class="ai-class-label">${escHtml(cls.top.label)}</span><span class="ai-class-conf ${confCls}">${confPct}%</span></div>`;
        html += `<div class="ai-class-desc">${escHtml(cls.top.description)}</div>`;
        if (cls.alternatives && cls.alternatives.length) {
            html += `<div class="ai-class-alts"><div style="margin-bottom:2px;font-weight:600">Other possibilities:</div>`;
            cls.alternatives.forEach(a => {
                html += `<div class="ai-class-alt"><span>${a.icon}</span><span>${escHtml(a.label)}</span><span style="margin-left:auto">${Math.round(a.confidence*100)}%</span></div>`;
            });
            html += `</div>`;
        }
        html += `</div></div>`;
    }

    // Risk Assessment
    if (d.risk_score !== undefined) {
        const rLevel = d.risk_level || "low";
        const rColor = rLevel === "critical" ? "var(--risk-crit)" : rLevel === "high" ? "var(--risk-high)" : rLevel === "medium" ? "var(--risk-med)" : "var(--risk-low)";
        html += `<div class="detail-section"><div class="detail-section-title">Risk Assessment</div>`;
        html += `<div style="display:flex;align-items:center;gap:8px;margin-bottom:4px"><span class="risk-badge risk-${rLevel}">${d.risk_score} ${rLevel.toUpperCase()}</span></div>`;
        html += `<div class="risk-meter"><div class="risk-meter-fill" style="width:${d.risk_score}%;background:${rColor}"></div></div>`;
        html += `<div class="risk-meter-label"><span>0</span><span>100</span></div>`;
        if (d.risk_factors && d.risk_factors.length) {
            html += `<div style="margin-top:6px;font-size:.68rem;color:var(--tx-3)">`;
            d.risk_factors.forEach(f => { html += `<div style="padding:1px 0">${escHtml(f)}</div>`; });
            html += `</div>`;
        }
        html += `</div>`;
    }

    // Movement
    if (d.rssi_trend) {
        const arrows = { approaching: "↑ Approaching", leaving: "↓ Leaving", stationary: "— Stationary" };
        html += `<div class="detail-section"><div class="detail-section-title">Movement</div>`;
        html += `<span class="movement-ind movement-${d.rssi_trend}">${arrows[d.rssi_trend] || "—"}</span>`;
        html += `</div>`;
    }

    // RSSI History Chart
    if (d.rssi_history && d.rssi_history.length > 1) {
        html += `<div class="detail-section"><div class="detail-section-title">RSSI History</div>`;
        html += `<div class="rssi-chart-mini">${renderRSSIChart(d.rssi_history)}</div>`;
        html += `</div>`;
    }

    // Tracker Status
    if (d.tracker_suspect) {
        html += `<div class="detail-section"><div class="detail-section-title" style="color:var(--red)">${ICO.alert} Tracker Suspect</div>`;
        html += detailRow("Type", d.tracker_type || "Unknown");
        html += detailRow("Confidence", `${Math.round((d.tracker_confidence || 0) * 100)}%`);
        html += `</div>`;
    }

    // Packet Inspector
    if (d.packet_data && Object.keys(d.packet_data).length) {
        const pkt = d.packet_data;
        html += `<div class="detail-section"><div class="detail-section-title">Packet Inspector</div>`;
        html += `<div class="packet-inspector">`;
        if (pkt.manufacturer_data_hex) html += `<div class="pi-section"><span class="pi-label">Mfr Data</span><span class="pi-val">${pkt.manufacturer_data_hex}</span></div>`;
        if (pkt.service_uuids && pkt.service_uuids.length) html += `<div class="pi-section"><span class="pi-label">UUIDs</span><span class="pi-val">${pkt.service_uuids.join(", ")}</span></div>`;
        if (pkt.tx_power) html += `<div class="pi-section"><span class="pi-label">TX Power</span><span class="pi-val">${pkt.tx_power} dBm</span></div>`;
        if (pkt.flags) html += `<div class="pi-section"><span class="pi-label">Flags</span><span class="pi-val">${pkt.flags}</span></div>`;
        if (pkt.service_data && Object.keys(pkt.service_data).length) {
            for (const [uuid, hex] of Object.entries(pkt.service_data)) {
                html += `<div class="pi-section"><span class="pi-label">Svc ${uuid.slice(0,8)}</span><span class="pi-val">${hex}</span></div>`;
            }
        }
        html += `</div></div>`;
    }

    // MAC Addresses
    if (d.mac_addresses && d.mac_addresses.length) {
        html += `<div class="detail-section"><div class="detail-section-title">MAC Addresses (${d.mac_addresses.length})</div>`;
        d.mac_addresses.forEach(m => { html += `<span class="mac-chip" style="margin:2px">${m}</span> `; });
        html += `</div>`;
    }

    // Service UUIDs
    if (d.service_uuids && d.service_uuids.length) {
        html += `<div class="detail-section"><div class="detail-section-title">Service UUIDs</div>`;
        html += `<div style="font-size:.68rem;font-family:'JetBrains Mono',monospace;color:var(--tx-2)">`;
        d.service_uuids.forEach(u => { html += `<div>${u}</div>`; });
        html += `</div></div>`;
    }

    // Quick Actions
    const fpId = d.fingerprint_id || "";
    html += `<div class="detail-section"><div class="detail-section-title">Quick Actions</div>`;
    html += `<div class="quick-actions">`;
    html += `<button class="qa-btn qa-track" onclick="switchTab('radar')">${ICO.radio} Radar</button>`;
    html += `<button class="qa-btn qa-alert" onclick="watchDevice('${fpId}')">${ICO.bell} Watch</button>`;
    html += `<button class="qa-btn qa-export" onclick="exportPackets('${fpId}')">${ICO.pkg} Packets</button>`;
    html += `</div>`;
    if (d.is_known) {
        html += `<button class="btn-untrust" onclick="untrustDevice('${fpId}')">Remove Trust</button>`;
    } else {
        html += `<button class="btn-trust" style="width:100%;margin-top:6px" onclick="trustFingerprint('${fpId}')">Trust This Device</button>`;
    }
    html += `</div>`;

    // Life Story placeholder (loaded async)
    html += `<div id="life-story-section"></div>`;

    body.innerHTML = html;

    // Async load life story
    if (fpId) {
        fetchLifeStory(fpId).then(story => {
            const el = document.getElementById("life-story-section");
            if (el) el.innerHTML = renderLifeStorySection(story);
        });
    }
}

function detailRow(label, val) {
    return `<div class="detail-row"><span class="dr-label">${label}</span><span class="dr-val">${val}</span></div>`;
}

/* ── RSSI History SVG Chart ────────────────────────────────── */
function renderRSSIChart(rssiData) {
    const w = 300, h = 60, pad = 5;
    const pts = rssiData.slice(-25);
    if (pts.length < 2) return '<div class="empty-msg" style="padding:4px">Collecting...</div>';

    const vals = pts.map(p => Array.isArray(p) ? p[1] : p.rssi || -100);
    const minR = Math.min(...vals);
    const maxR = Math.max(...vals);
    const range = Math.max(maxR - minR, 5);

    const points = vals.map((v, i) => {
        const x = pad + (i / (vals.length - 1)) * (w - 2 * pad);
        const y = pad + (1 - (v - minR) / range) * (h - 2 * pad);
        return `${x.toFixed(1)},${y.toFixed(1)}`;
    });

    const firstX = pad, lastX = pad + ((vals.length-1)/(vals.length-1))*(w-2*pad);
    const fillPoints = `${firstX},${h-pad} ${points.join(" ")} ${lastX},${h-pad}`;

    return `<svg viewBox="0 0 ${w} ${h}" class="rssi-chart-svg">
        <polygon points="${fillPoints}" fill="var(--accent-bg)" stroke="none"/>
        <polyline points="${points.join(" ")}" fill="none" stroke="var(--accent)" stroke-width="1.5"/>
        <text x="4" y="10" class="chart-label">${maxR} dBm</text>
        <text x="4" y="${h-2}" class="chart-label">${minR} dBm</text>
    </svg>`;
}

/* ── Trust / Untrust ───────────────────────────────────────── */
window.trustFingerprint = async function(fpId) {
    await fetch("/api/whitelist", { method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({ fingerprint_id: fpId }) });
};
window.trustDevice = async function(addr) {
    await fetch("/api/whitelist", { method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({ address: addr }) });
};
window.untrustDevice = async function(fpId) {
    await fetch("/api/whitelist", { method:"DELETE", headers:{"Content-Type":"application/json"}, body:JSON.stringify({ fingerprint_id: fpId }) });
};
window.watchDevice = async function(fpId) {
    await fetch("/api/alerts/watch", { method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({ fingerprint_id: fpId }) });
    addTimelineEvent("alert", `Watching device ${fpId}`);
};
window.exportPackets = async function(fpId) {
    try {
        const res = await fetch(`/api/device/${fpId}/packets`);
        const data = await res.json();
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
        const a = document.createElement("a");
        a.href = URL.createObjectURL(blob);
        a.download = `${fpId}_packets.json`;
        a.click();
    } catch {}
};

/* ── Stats Strip ───────────────────────────────────────────── */
function renderStatsStrip() {
    const cs = clusterSummary;
    $("ss-physical").textContent = cs.total_physical_devices || 0;
    $("ss-macs").textContent = cs.total_mac_addresses || 0;
    $("ss-trusted").textContent = cs.known_devices || 0;
    $("ss-unknown").textContent = cs.unknown_devices || 0;
    $("ss-clustered").textContent = cs.mac_reduction || 0;
    $("ss-scans").textContent = currentDevices.length;
}

/* ── Environment Stats ─────────────────────────────────────── */
function renderEnvStats() {
    $("env-nearby").textContent = currentClustered.length;
    $("env-peak").textContent = analyticsData.today_peak || 0;
    $("env-new").textContent = analyticsData.today_new || 0;
    $("env-trusted").textContent = clusterSummary.known_devices || 0;
    $("env-clusters").textContent = clusterSummary.mac_reduction || 0;
}

/* ── Signal Panels ─────────────────────────────────────────── */
function renderSignalPanels() {
    renderRSSIPanel();
    renderCategoryPanel();
    renderEcosystemPanel();
    renderHeatmap();
}

function renderRSSIPanel() {
    const devs = viewMode === "clustered" ? currentClustered : currentDevices;
    const el = $("rssi-full");
    if (!devs.length) { el.innerHTML = '<div class="empty-msg">No devices</div>'; return; }
    el.innerHTML = devs.slice(0, 15).map(d => {
        const name = (d.best_name || d.name || "?").slice(0, 12);
        const rssi = Math.round(d.avg_rssi || d.rssi || -100);
        const pct = clamp(((rssi + 100) / 60) * 100, 0, 100);
        const color = rssi > -50 ? "var(--green)" : rssi > -70 ? "var(--orange)" : "var(--red)";
        return `<div class="rssi-row"><span class="rssi-name">${escHtml(name)}</span><div class="rssi-bar-o"><div class="rssi-bar-i" style="width:${pct}%;background:${color}"></div></div><span class="rssi-v">${rssi} dBm</span></div>`;
    }).join("");
}

function renderCategoryPanel() {
    const cats = clusterSummary.categories || {};
    const el = $("cat-full");
    if (!Object.keys(cats).length) { el.innerHTML = '<div class="empty-msg">No data</div>'; return; }
    const icons = { phone:ICO.phone, audio:ICO.audio, input:ICO.input, watch:ICO.watch, computer:ICO.computer, tv:ICO.tv, tracker:ICO.tracker, health:ICO.health, gaming:ICO.gaming, iot:ICO.iot, apple:ICO.apple, nearby:ICO.signal, unknown:ICO.unknown };
    el.innerHTML = Object.entries(cats).sort((a,b) => b[1]-a[1]).map(([cat, cnt]) =>
        `<div class="cat-row"><span class="cat-icon">${icons[cat] || ICO.unknown}</span><span class="cat-name">${cat}</span><span class="cat-count">${cnt}</span></div>`
    ).join("");
}

function renderEcosystemPanel() {
    const ecos = clusterSummary.ecosystems || {};
    const el = $("eco-full");
    if (!Object.keys(ecos).length) { el.innerHTML = '<div class="empty-msg">No data</div>'; return; }
    const total = Object.values(ecos).reduce((a, b) => a + b, 0) || 1;
    const ecoColors = { apple:"var(--purple)", samsung:"var(--accent)", google:"var(--green)", microsoft:"var(--cyan)", amazon:"var(--orange)" };
    el.innerHTML = Object.entries(ecos).sort((a,b) => b[1]-a[1]).map(([eco, cnt]) => {
        const pct = (cnt / total * 100).toFixed(0);
        const color = ecoColors[eco] || "var(--tx-3)";
        return `<div class="eco-row"><span class="eco-name">${eco}</span><div class="eco-bar"><div class="eco-bar-fill" style="width:${pct}%;background:${color}"></div></div><span class="eco-count">${cnt}</span></div>`;
    }).join("");
}

function renderHeatmap() {
    const devs = viewMode === "clustered" ? currentClustered : currentDevices;
    const el = $("heatmap");
    if (!devs.length) { el.innerHTML = '<div class="empty-msg">No data</div>'; return; }
    const buckets = 12;
    el.innerHTML = devs.slice(0, 10).map(d => {
        const name = (d.best_name || d.name || "?").slice(0, 10);
        const rssiHist = d.rssi_history || [];
        let cells = "";
        for (let b = 0; b < buckets; b++) {
            const idx = Math.floor(b * rssiHist.length / buckets);
            const val = rssiHist[idx] ? (Array.isArray(rssiHist[idx]) ? rssiHist[idx][1] : rssiHist[idx]) : (d.avg_rssi || d.rssi || -100);
            const intensity = clamp(((val + 100) / 60), 0, 1);
            const r = Math.round(255 * (1 - intensity)), g = Math.round(255 * intensity);
            cells += `<div class="hm-cell" style="background:rgba(${r},${g},80,.5)" title="${Math.round(val)} dBm"></div>`;
        }
        return `<div class="hm-row"><span class="hm-name">${escHtml(name)}</span><div class="hm-cells">${cells}</div></div>`;
    }).join("");
}

/* ── Timeline ──────────────────────────────────────────────── */
function addTimelineEvent(type, msg) {
    timeline.unshift({ type, msg, time: new Date().toLocaleTimeString() });
    if (timeline.length > 200) timeline.length = 200;
    renderTimeline();
}
function renderTimeline() {
    const el = $("tl-list");
    if (!timeline.length) { el.innerHTML = '<div class="empty-msg">Events appear as scans run...</div>'; return; }
    el.innerHTML = timeline.slice(0, 100).map(e => {
        const cls = e.type === "scan" ? "tl-scan" : e.type === "alert" ? "tl-alert" : e.type === "jam" ? "tl-jam" : e.type === "tracker" ? "tl-tracker" : "tl-risk";
        return `<div class="tl-entry"><span class="tl-time">${e.time}</span><span class="tl-type ${cls}">${e.type}</span><span class="tl-msg">${escHtml(e.msg)}</span></div>`;
    }).join("");
}
$("btn-clear-tl").addEventListener("click", () => { timeline = []; renderTimeline(); });

/* ── Channel Grid (real data from nRF sniffer/Sniffle) ──────── */
function updateChannelActivityFromBackend(channelData) {
    // channelData is a dict {channel_idx: count} from nRF sniffer's
    // real packet capture. If backend didn't send it, we show zeros
    // rather than fabricated numbers.
    if (!channelData || typeof channelData !== 'object') return;
    for (let i = 0; i < 40; i++) {
        if (channelData[i] !== undefined) {
            channelStats[i] = channelData[i];
        }
    }
}
// Backward-compat stub — does nothing. Was previously Math.random() fabricator.
function simulateChannelActivity(devCount) { /* DELETED: v7 no fake data */ }
function renderChannelGrid() {
    const el = $("ch-grid");
    const maxCount = Math.max(...channelStats, 1);
    el.innerHTML = channelStats.map((cnt, i) => {
        const isAdv = [37, 38, 39].includes(i);
        const freq = 2402 + (i < 11 ? i * 2 : i < 37 ? (i + 1) * 2 : i === 37 ? 0 : i === 38 ? 24 : 78);
        const intensity = cnt / maxCount;
        const bg = isAdv ? `rgba(210,153,34,${.1 + intensity * .5})` : `rgba(88,166,255,${.05 + intensity * .3})`;
        return `<div class="ch-cell" style="background:${bg};border-color:${isAdv ? 'var(--orange)' : 'var(--border)'}"><div class="ch-num">${i}</div><div class="ch-freq">${freq} MHz</div><div class="ch-count">${cnt}</div></div>`;
    }).join("");
}

/* ── Proximity Radar ───────────────────────────────────────── */
function startRadar() {
    if (radarAnimFrame) return;
    const canvas = $("radar-canvas");
    if (!canvas) return;
    const dpr = window.devicePixelRatio || 1;
    const size = Math.min(canvas.parentElement.clientWidth - 200, canvas.parentElement.clientHeight - 20, 600);
    canvas.width = size * dpr;
    canvas.height = size * dpr;
    canvas.style.width = size + "px";
    canvas.style.height = size + "px";
    const ctx = canvas.getContext("2d");
    ctx.scale(dpr, dpr);
    renderRadarFrame(ctx, size, size);
}
function stopRadar() { if (radarAnimFrame) { cancelAnimationFrame(radarAnimFrame); radarAnimFrame = null; } }

function renderRadarFrame(ctx, w, h) {
    const cx = w / 2, cy = h / 2, maxR = Math.min(cx, cy) - 30;
    const styles = getComputedStyle(document.documentElement);
    const bg = styles.getPropertyValue("--bg-1").trim() || "#0d1117";
    const txFaint = styles.getPropertyValue("--tx-3").trim() || "#484f58";

    ctx.fillStyle = bg;
    ctx.fillRect(0, 0, w, h);

    // Range rings
    const rings = [{ r: 0.33, label: "-40 dBm" }, { r: 0.66, label: "-60 dBm" }, { r: 1.0, label: "-80 dBm" }];
    rings.forEach(ring => {
        ctx.beginPath();
        ctx.arc(cx, cy, maxR * ring.r, 0, Math.PI * 2);
        ctx.strokeStyle = "rgba(88,166,255,0.12)";
        ctx.lineWidth = 1;
        ctx.stroke();
        ctx.fillStyle = txFaint;
        ctx.font = "9px 'JetBrains Mono'";
        ctx.fillText(ring.label, cx + 4, cy - maxR * ring.r + 12);
    });

    // Crosshairs
    ctx.strokeStyle = "rgba(88,166,255,0.06)";
    ctx.beginPath(); ctx.moveTo(cx, 10); ctx.lineTo(cx, h - 10); ctx.stroke();
    ctx.beginPath(); ctx.moveTo(10, cy); ctx.lineTo(w - 10, cy); ctx.stroke();

    // Sweep line
    radarAngle = (radarAngle + 0.015) % (Math.PI * 2);
    ctx.beginPath();
    ctx.moveTo(cx, cy);
    ctx.lineTo(cx + Math.cos(radarAngle) * maxR, cy + Math.sin(radarAngle) * maxR);
    ctx.strokeStyle = "rgba(63,185,80,0.5)";
    ctx.lineWidth = 2;
    ctx.stroke();
    ctx.lineWidth = 1;

    // Sweep trail
    ctx.beginPath();
    ctx.moveTo(cx, cy);
    ctx.arc(cx, cy, maxR, radarAngle - 0.4, radarAngle);
    ctx.closePath();
    const grad = ctx.createRadialGradient(cx, cy, 0, cx, cy, maxR);
    grad.addColorStop(0, "rgba(63,185,80,0.08)");
    grad.addColorStop(1, "rgba(63,185,80,0.02)");
    ctx.fillStyle = grad;
    ctx.fill();

    // Plot devices
    const devs = viewMode === "clustered" ? currentClustered : currentDevices;
    $("radar-count").textContent = devs.length + " devices";

    devs.forEach(d => {
        const rssi = Math.round(d.avg_rssi || d.rssi || -100);
        if (rssi <= -100) return;
        const dist = clamp(((rssi + 30) / -60) * maxR, 15, maxR - 5);
        const angle = hashToAngle(d.fingerprint_id || d.address || "");
        const x = cx + Math.cos(angle) * dist;
        const y = cy + Math.sin(angle) * dist;

        const riskColors = { low: "#3fb950", medium: "#d29922", high: "#e67e22", critical: "#f85149" };
        const color = riskColors[d.risk_level || "low"] || "#3fb950";

        // Glow for high risk
        if (d.risk_level === "critical" || d.risk_level === "high") {
            ctx.beginPath();
            ctx.arc(x, y, 12, 0, Math.PI * 2);
            ctx.fillStyle = color + "22";
            ctx.fill();
        }

        // Device dot
        ctx.beginPath();
        ctx.arc(x, y, d.tracker_suspect ? 7 : 5, 0, Math.PI * 2);
        ctx.fillStyle = color;
        ctx.fill();

        // Label
        const name = ((d.best_name || d.name || "?")).slice(0, 12);
        ctx.fillStyle = txFaint;
        ctx.font = "9px Inter";
        ctx.fillText(name, x + 10, y + 3);

        // Category icon
        ctx.font = "11px serif";
        ctx.fillText(d.category_icon || "?", x - 16, y + 4);
    });

    // Center dot (scanner)
    ctx.beginPath();
    ctx.arc(cx, cy, 5, 0, Math.PI * 2);
    ctx.fillStyle = "#58a6ff";
    ctx.fill();
    ctx.fillStyle = txFaint;
    ctx.font = "8px 'JetBrains Mono'";
    ctx.fillText("YOU", cx + 8, cy + 3);

    radarAnimFrame = requestAnimationFrame(() => renderRadarFrame(ctx, w, h));
}

function hashToAngle(str) {
    let hash = 0;
    for (let i = 0; i < str.length; i++) hash = ((hash << 5) - hash + str.charCodeAt(i)) | 0;
    return (Math.abs(hash) % 628) / 100;
}

/* ── Tracker Detection Panel ───────────────────────────────── */
function renderTrackerGrid() {
    const grid = $("tracker-grid");
    const badge = $("nav-tracker-badge");
    const topBadge = $("tracker-top");
    const statusCard = $("tracker-overview");

    if (!trackerSuspects.length) {
        grid.innerHTML = "";
        badge.style.display = "none";
        topBadge.textContent = "0";
        statusCard.innerHTML = `<div class="tracker-status-card"><div class="tsc-icon">${ICO.shieldOk}</div><div class="tsc-info"><div class="tsc-title">Environment Clear</div><div class="tsc-desc">No suspected trackers detected nearby.</div></div></div>`;
        return;
    }

    badge.style.display = "";
    badge.textContent = trackerSuspects.length;
    topBadge.textContent = trackerSuspects.length;

    statusCard.innerHTML = `<div class="tracker-status-card alert"><div class="tsc-icon">${ICO.alert}</div><div class="tsc-info"><div class="tsc-title">${trackerSuspects.length} Suspected Tracker(s)</div><div class="tsc-desc">Potential tracking devices detected in your vicinity.</div></div></div>`;

    grid.innerHTML = trackerSuspects.map(t => {
        const cls = t.confidence > 0.7 ? "tracker-high" : "tracker-med";
        const icon = t.tracker_type.includes("airtag") ? ICO.apple : t.tracker_type.includes("smarttag") ? ICO.phone : ICO.tracker;
        return `<div class="tracker-card ${cls}">
            <div class="tc-icon">${icon}</div>
            <div class="tc-info">
                <div class="tc-type">${escHtml(t.tracker_type || "Unknown Tracker")}</div>
                <div class="tc-conf">Confidence: ${Math.round(t.confidence * 100)}%</div>
                <div class="tc-conf-bar"><div class="tc-conf-fill" style="width:${Math.round(t.confidence * 100)}%"></div></div>
                <div class="tc-reasons">${(t.detection_reasons || []).map(r => `<div class="tc-reason">• ${escHtml(r)}</div>`).join("")}</div>
                <div class="tc-duration">${t.duration_minutes ? t.duration_minutes.toFixed(0) + " min nearby" : ""} ${t.is_following ? "· FOLLOWING" : ""}</div>
            </div>
        </div>`;
    }).join("");
}

/* ── Following Detection Panel ─────────────────────────────── */
function renderFollowingGrid() {
    const grid = $("follow-grid");
    const badge = $("nav-follow-badge");
    const topBadge = $("follow-top");
    const overview = $("follow-overview");
    if (!grid || !badge) return;

    if (!followingAlerts || !followingAlerts.length) {
        grid.innerHTML = "";
        badge.style.display = "none";
        if (topBadge) topBadge.textContent = "0";
        if (overview) overview.innerHTML = `<div class="follow-status-card"><div class="fsc-icon">${ICO.shieldOk}</div><div class="fsc-info"><div class="fsc-title">All Clear</div><div class="fsc-desc">No devices appear to be following you.</div></div></div>`;
        return;
    }

    badge.style.display = "";
    badge.textContent = followingAlerts.length;
    if (topBadge) topBadge.textContent = followingAlerts.length;

    const threat = followingAlerts.some(f => f.threat_level === "following");
    if (overview) overview.innerHTML = `<div class="follow-status-card${threat ? " alert" : ""}"><div class="fsc-icon">${threat ? ICO.alert : ICO.eye}</div><div class="fsc-info"><div class="fsc-title">${followingAlerts.length} Device(s) of Interest</div><div class="fsc-desc">${threat ? "One or more devices may be following you!" : "Monitoring suspicious patterns."}</div></div></div>`;

    grid.innerHTML = followingAlerts.map(f => {
        const threatCls = f.threat_level === "following" ? "threat-following" : f.threat_level === "suspicious" ? "threat-suspicious" : "threat-monitoring";
        const icon = f.threat_level === "following" ? ICO.siren : f.threat_level === "suspicious" ? ICO.eye : ICO.radio;
        const conf = Math.round((f.confidence || 0) * 100);
        return `<div class="follow-card ${threatCls}">
            <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
                <span style="font-size:1.4rem">${icon}</span>
                <div>
                    <div style="font-weight:700;color:var(--tx-1);font-size:.88rem">${escHtml(f.device_name || f.device_id || "Unknown")}</div>
                    <div style="font-size:.72rem;color:var(--tx-3);text-transform:uppercase">${escHtml(f.threat_level || "monitoring")}</div>
                </div>
            </div>
            <div style="margin-bottom:6px">
                <div style="font-size:.72rem;color:var(--tx-3);margin-bottom:2px">Confidence: ${conf}%</div>
                <div style="height:4px;background:var(--bg-3);border-radius:2px;overflow:hidden"><div style="height:100%;width:${conf}%;background:${conf > 70 ? 'var(--red)' : conf > 40 ? 'var(--orange)' : 'var(--accent)'};border-radius:2px"></div></div>
            </div>
            ${f.reasons ? `<div style="font-size:.68rem;color:var(--tx-2)">${(Array.isArray(f.reasons) ? f.reasons : []).map(r => `<div>• ${escHtml(r)}</div>`).join("")}</div>` : ""}
            ${f.duration_minutes ? `<div style="font-size:.68rem;color:var(--tx-3);margin-top:4px">Tracking for ${Math.round(f.duration_minutes)} min</div>` : ""}
            ${f.scan_count ? `<div style="font-size:.68rem;color:var(--tx-3)">Seen in ${f.scan_count} scans</div>` : ""}
        </div>`;
    }).join("");
}

/* ── Shadow Device Detection Panel ────────────────────────── */
function renderShadowGrid() {
    const grid = $("shadow-grid");
    const badge = $("nav-shadow-badge");
    const topBadge = $("shadow-top");
    const overview = $("shadow-overview");
    if (!grid || !badge) return;

    if (!shadowDevices || !shadowDevices.length) {
        grid.innerHTML = "";
        badge.style.display = "none";
        if (topBadge) topBadge.textContent = "0";
        if (overview) overview.innerHTML = `<div class="shadow-status-card"><div class="shsc-icon">${ICO.moon}</div><div class="shsc-info"><div class="shsc-title">No Shadows Detected</div><div class="shsc-desc">No devices exhibiting stealth behavior.</div></div></div>`;
        return;
    }

    badge.style.display = "";
    badge.textContent = shadowDevices.length;
    if (topBadge) topBadge.textContent = shadowDevices.length;

    const high = shadowDevices.filter(s => (s.stealth_score || 0) > 0.7).length;
    if (overview) overview.innerHTML = `<div class="shadow-status-card${high ? " alert" : ""}"><div class="shsc-icon">${high ? ICO.ghost : ICO.moon}</div><div class="shsc-info"><div class="shsc-title">${shadowDevices.length} Shadow Device(s)</div><div class="shsc-desc">${high ? high + " high-stealth device(s) detected!" : "Monitoring devices with intermittent visibility."}</div></div></div>`;

    grid.innerHTML = shadowDevices.map(s => {
        const score = Math.round((s.stealth_score || 0) * 100);
        const cls = score > 70 ? "shadow-high" : "shadow-med";
        return `<div class="shadow-card ${cls}">
            <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
                <span style="font-size:1.4rem">${ICO.ghost}</span>
                <div>
                    <div style="font-weight:700;color:var(--tx-1);font-size:.88rem">${escHtml(s.device_name || s.device_id || "Unknown")}</div>
                    <div style="font-size:.72rem;color:var(--purple);text-transform:uppercase">Stealth Score: ${score}%</div>
                </div>
            </div>
            <div style="height:4px;background:var(--bg-3);border-radius:2px;overflow:hidden;margin-bottom:6px"><div style="height:100%;width:${score}%;background:var(--purple);border-radius:2px"></div></div>
            ${s.behavior ? `<div style="font-size:.72rem;color:var(--tx-2);margin-bottom:4px">${escHtml(s.behavior)}</div>` : ""}
            ${s.appearances ? `<div style="font-size:.68rem;color:var(--tx-3)">Appearances: ${s.appearances}</div>` : ""}
            ${s.disappearances ? `<div style="font-size:.68rem;color:var(--tx-3)">Disappearances: ${s.disappearances}</div>` : ""}
            ${s.avg_visible_duration ? `<div style="font-size:.68rem;color:var(--tx-3)">Avg visible: ${Math.round(s.avg_visible_duration)}s</div>` : ""}
        </div>`;
    }).join("");
}

/* ── Conversation Graph (BLE relationship visualization) ──── */
function renderConversationGraph() {
    const canvas = $("graph-canvas");
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    const dpr = window.devicePixelRatio || 1;
    const cw = canvas.parentElement.clientWidth * 0.85 || 800;
    const ch = canvas.parentElement.clientHeight * 0.85 || 600;
    canvas.width = cw * dpr;
    canvas.height = ch * dpr;
    canvas.style.width = cw + "px";
    canvas.style.height = ch + "px";
    ctx.scale(dpr, dpr);

    const styles = getComputedStyle(document.documentElement);
    const bgColor = styles.getPropertyValue("--bg-1").trim() || "#0d1117";
    const txColor = styles.getPropertyValue("--tx-1").trim() || "#e6edf3";
    const txFaint = styles.getPropertyValue("--tx-3").trim() || "#484f58";
    const accent = styles.getPropertyValue("--accent").trim() || "#58a6ff";
    const green = styles.getPropertyValue("--green").trim() || "#3fb950";
    const purple = styles.getPropertyValue("--purple").trim() || "#bc8cff";

    ctx.fillStyle = bgColor;
    ctx.fillRect(0, 0, cw, ch);

    // Build nodes from clustered devices
    const devices = currentClustered || [];
    if (!devices.length) {
        ctx.fillStyle = txFaint;
        ctx.font = "14px Inter";
        ctx.textAlign = "center";
        ctx.fillText("No devices to visualize", cw / 2, ch / 2);
        if ($("graph-info")) $("graph-info").textContent = "0 nodes, 0 connections";
        return;
    }

    const cx = cw / 2, cy = ch / 2;
    const radius = Math.min(cw, ch) * 0.35;
    const nodes = devices.map((d, i) => {
        const angle = (i / devices.length) * Math.PI * 2 - Math.PI / 2;
        return {
            x: cx + Math.cos(angle) * radius,
            y: cy + Math.sin(angle) * radius,
            id: d.fingerprint_id || d.address || `dev-${i}`,
            name: d.best_name || d.name || "Unknown",
            ecosystem: d.ecosystem || "",
            category: d.category || "unknown",
            risk: d.risk_level || "low",
            rssi: d.avg_rssi || -100,
            icon: d.category_icon || ICO.radio,
        };
    });

    // Build edges: ecosystem + proximity + co-occurrence
    const edges = [];
    for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
            const a = nodes[i], b = nodes[j];
            // Ecosystem match
            if (a.ecosystem && b.ecosystem && a.ecosystem === b.ecosystem) {
                edges.push({ from: i, to: j, type: "ecosystem", color: purple });
            }
            // Proximity (both have strong RSSI)
            if (a.rssi > -70 && b.rssi > -70) {
                edges.push({ from: i, to: j, type: "proximity", color: accent });
            }
            // Co-occurrence (same category)
            if (a.category !== "unknown" && a.category === b.category && !edges.find(e => e.from === i && e.to === j)) {
                edges.push({ from: i, to: j, type: "co-occurrence", color: green });
            }
        }
    }

    // Draw edges
    edges.forEach(e => {
        const a = nodes[e.from], b = nodes[e.to];
        ctx.beginPath();
        ctx.moveTo(a.x, a.y);
        ctx.lineTo(b.x, b.y);
        ctx.strokeStyle = e.color + "55";
        ctx.lineWidth = 1.5;
        ctx.stroke();
    });

    // Draw nodes
    const riskColors = { low: green, medium: "#f0ad4e", high: "#e67e22", critical: "#e74c3c" };
    nodes.forEach(n => {
        const nodeR = 18;
        ctx.beginPath();
        ctx.arc(n.x, n.y, nodeR, 0, Math.PI * 2);
        ctx.fillStyle = (riskColors[n.risk] || accent) + "33";
        ctx.fill();
        ctx.strokeStyle = riskColors[n.risk] || accent;
        ctx.lineWidth = 2;
        ctx.stroke();

        ctx.fillStyle = txColor;
        ctx.font = "16px sans-serif";
        ctx.textAlign = "center";
        ctx.textBaseline = "middle";
        ctx.fillText("●", n.x, n.y);

        ctx.fillStyle = txFaint;
        ctx.font = "9px 'JetBrains Mono'";
        ctx.textBaseline = "top";
        const label = n.name.length > 14 ? n.name.slice(0, 12) + "…" : n.name;
        ctx.fillText(label, n.x, n.y + nodeR + 4);
    });

    if ($("graph-info")) $("graph-info").textContent = `${nodes.length} nodes, ${edges.length} connections`;
}

/* ── Advanced Mode Toggle ─────────────────────────────────── */
function updateAdvancedModeBtn() {
    const btn = $("btn-advanced");
    if (!btn) return;
    btn.classList.toggle("active", advancedMode);
    btn.title = advancedMode ? "Advanced Mode: ON" : "Advanced Mode: OFF";
    // Show/hide advanced-only nav items
    const advTabs = ["following", "shadows"];
    advTabs.forEach(tab => {
        const navItem = document.querySelector(`.nav-item[data-tab="${tab}"]`);
        if (navItem) navItem.style.display = advancedMode ? "" : "";
    });
}
if ($("btn-advanced")) {
    $("btn-advanced").addEventListener("click", async () => {
        advancedMode = !advancedMode;
        updateAdvancedModeBtn();
        try { await fetch("/api/advanced-mode", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ enabled: advancedMode }) }); } catch {}
    });
}

/* ── Device Life Story (in detail panel) ──────────────────── */
async function fetchLifeStory(deviceId) {
    try {
        const res = await fetch(`/api/device/${encodeURIComponent(deviceId)}/life-story`);
        const data = await res.json();
        return data;
    } catch { return { events: [] }; }
}

function renderLifeStorySection(story) {
    if (!story || !story.events || !story.events.length) return "";
    const events = story.events.slice(-20); // Show last 20 events
    return `<div class="detail-section">
        <div class="detail-section-title" style="color:var(--cyan);font-weight:600;font-size:.78rem">${ICO.book} Device Life Story</div>
        <div style="font-family:'JetBrains Mono',monospace;font-size:.65rem;color:var(--tx-2);max-height:200px;overflow-y:auto">
            ${events.map(e => {
                const ts = e.timestamp ? new Date(e.timestamp).toLocaleTimeString() : "";
                return `<div class="ls-entry" style="display:flex;gap:6px;padding:2px 0;border-bottom:1px solid var(--border)">
                    <span class="ls-time" style="color:var(--tx-3);min-width:60px">${ts}</span>
                    <span class="ls-msg" style="color:var(--tx-1)">${escHtml(e.event || e.message || "State change")}</span>
                </div>`;
            }).join("")}
        </div>
    </div>`;
}

/* ── Analytics Dashboard ───────────────────────────────────── */
function renderAnalytics() {
    const a = analyticsData;
    if (!a) return;
    if ($("an-today")) $("an-today").textContent = a.today_devices || 0;
    if ($("an-week")) $("an-week").textContent = a.week_total || 0;
    if ($("an-peak")) $("an-peak").textContent = a.today_peak || 0;
    if ($("an-returning")) $("an-returning").textContent = a.today_returning || 0;
    if ($("an-new")) $("an-new").textContent = a.today_new || 0;
    if ($("an-alltime")) $("an-alltime").textContent = a.all_time_total || 0;

    // Weekly chart
    const canvas = $("an-weekly-chart");
    if (!canvas || !a.daily_chart) return;
    const ctx = canvas.getContext("2d");
    const dpr = window.devicePixelRatio || 1;
    const cw = Math.min(
        canvas.parentElement?.clientWidth || 9999,
        canvas.parentElement?.parentElement?.clientWidth || 9999,
        window.innerWidth
    ) - 32;
    canvas.width = cw * dpr;
    canvas.height = 150 * dpr;
    canvas.style.width = cw + "px";
    canvas.style.height = "150px";
    ctx.scale(dpr, dpr);

    const ch = 150;
    const bars = a.daily_chart || [];
    const maxVal = Math.max(...bars.map(b => b.count || 0), 1);
    const barW = (cw - 40) / Math.max(bars.length, 1);
    const styles = getComputedStyle(document.documentElement);
    const accent = styles.getPropertyValue("--accent").trim() || "#58a6ff";
    const txFaint = styles.getPropertyValue("--tx-3").trim() || "#484f58";

    ctx.clearRect(0, 0, cw, ch);
    bars.forEach((bar, i) => {
        const h = ((bar.count || 0) / maxVal) * (ch - 30);
        const x = 30 + i * barW;
        const y = ch - 20 - h;

        ctx.fillStyle = accent + "88";
        ctx.beginPath();
        if (ctx.roundRect) ctx.roundRect(x + 4, y, barW - 8, h, 3);
        else ctx.rect(x + 4, y, barW - 8, h);
        ctx.fill();

        if (bar.peak) {
            const peakH = (bar.peak / maxVal) * (ch - 30);
            ctx.fillStyle = "#f85149";
            ctx.beginPath();
            ctx.arc(x + barW / 2, ch - 20 - peakH, 3, 0, Math.PI * 2);
            ctx.fill();
        }

        ctx.fillStyle = txFaint;
        ctx.font = "9px 'JetBrains Mono'";
        ctx.textAlign = "center";
        ctx.fillText(bar.date ? bar.date.slice(5) : "", x + barW / 2, ch - 4);
        ctx.fillText(bar.count || 0, x + barW / 2, y - 4);
    });
}

/* ── Alert List & Rules ────────────────────────────────────── */
function renderAlertList(alerts) {
    if (alerts) alertList = alerts;
    const el = $("alert-full");
    const badge = $("nav-alert-badge");
    const topBadge = $("alert-top");

    badge.textContent = alertList.length;
    topBadge.textContent = alertList.length;

    if (!alertList.length) { el.innerHTML = '<div class="empty-msg">No alerts. System clean.</div>'; return; }
    el.innerHTML = alertList.slice(0, 100).map(a => {
        const d = a.data || a;
        const lvl = d.level || "warning";
        const cls = lvl === "critical" ? "al-crit" : lvl === "warning" ? "al-warn" : "al-info";
        const ts = a.timestamp ? new Date(a.timestamp).toLocaleTimeString() : "";
        return `<div class="alert-entry"><span class="al-time">${ts}</span><span class="al-lvl ${cls}">${lvl}</span><span class="al-msg">${escHtml(d.message || "Alert")}</span></div>`;
    }).join("");
}

function renderAlertRules() {
    const el = $("alert-rules");
    if (!el || !alertRules.length) return;
    el.innerHTML = alertRules.map(r =>
        `<div class="ar-item ${r.enabled ? 'enabled' : 'disabled'}" onclick="toggleAlertRule('${r.id}', ${!r.enabled})"><span class="ar-dot"></span>${escHtml(r.name)}</div>`
    ).join("");
}
window.toggleAlertRule = async function(id, enabled) {
    await fetch("/api/alerts/rules", { method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({ id, enabled }) });
    const rule = alertRules.find(r => r.id === id);
    if (rule) rule.enabled = enabled;
    renderAlertRules();
};

/* ── Jammer Controls ───────────────────────────────────────── */
let _jamPrevPkts = 0;
let _jamPrevTime = 0;
let _jamStartTime = 0;
let _jamDurTimer  = null;

$("j-mode").addEventListener("change", e => {
    const mode = e.target.value;
    const needsTarget = ["targeted", "deauth"].includes(mode);
    $("j-target-grp").style.display = needsTarget ? "" : "none";

    // Show capability hint on mode change (without needing active session)
    const hintEl = $("j-capability-hint");
    if (hintEl) {
        let hint = "", cls = "";
        if (mode === "airpods_killer") {
            hint = "🎯 Optimized for AirPods A2DP disruption. Sweeps all 79 BR/EDR channels at +8 dBm, 1ms dwell. Saturates AFH → audio drops in 2-4s. REQUIRES nRF52840 with radio_test firmware.";
            cls = "cap-ok";
        } else if (mode.startsWith("rf_sweep")) {
            hint = "✓ Real RF sweep via nRF52840 radio_test firmware. Direct NRF_RADIO register control bypasses BlueZ entirely. +8 dBm, all 2.4 GHz ISM band.";
            cls = "cap-ok";
        } else if (mode === "rf_cw_carrier") {
            hint = "⚠ Single-channel CW. AFH will route around it within 2-3 seconds. Use sweep modes for sustained disruption.";
            cls = "cap-warn";
        } else if (mode === "rf_modulated") {
            hint = "ℹ Single-channel modulated (PRBS9) burst. More disruptive than CW but still AFH-routable.";
            cls = "cap-info";
        } else if (mode === "full_spectrum") {
            hint = "ℹ HCI-level BLE+BR/EDR. Inquiry loop is ~1/sec (too slow for audio). Affects discovery only.";
            cls = "cap-info";
        } else if (["flood", "phantom_flood", "sweep", "continuous"].includes(mode)) {
            hint = "ℹ BLE advertising channels 37/38/39 only. Disrupts discovery/pairing, NOT active BR/EDR audio.";
            cls = "cap-info";
        } else if (["deauth", "connection_disrupt"].includes(mode)) {
            hint = "⚠ Sends ADV_DIRECT_IND (no real BLE deauth primitive exists). Target will ignore.";
            cls = "cap-warn";
        } else if (mode === "targeted") {
            hint = "ℹ Random-address nudge toward target — not true targeting. Same effect as flood.";
            cls = "cap-info";
        } else if (mode === "reactive") {
            hint = "ℹ Duty-cycled spam (80% jam / 20% quiet). No actual reactive trigger logic.";
            cls = "cap-info";
        }
        hintEl.textContent = hint;
        hintEl.className = "jam-capability-hint " + cls;
        hintEl.style.display = hint ? "" : "none";
    }
});
// Trigger once on load
setTimeout(() => $("j-mode").dispatchEvent(new Event("change")), 300);

$("btn-jam").addEventListener("click", async () => {
    if (jammerActive) {
        await fetch("/api/jammer/stop", { method: "POST" });
        addTimelineEvent("jam", "Jammer stopped");
    } else {
        const mode = $("j-mode").value;
        const ch   = parseInt($("j-channel").value);
        const tgt  = $("j-target")?.value.trim() || "";
        if (["targeted", "deauth"].includes(mode) && !tgt) {
            $("j-target").focus();
            $("j-target").style.borderColor = "var(--red)";
            setTimeout(() => { $("j-target").style.borderColor = ""; }, 1500);
            return;
        }
        await fetch("/api/jammer/start", { method: "POST",
            headers: {"Content-Type":"application/json"},
            body: JSON.stringify({ mode, channel: ch, target: tgt })
        });
        addTimelineEvent("jam", `Jammer started: ${mode} mode`);
    }
});

/* Picker search filter */
$("j-picker-search").addEventListener("input", () => renderJammerPicker());

/* Channel bar click → sync select */
document.querySelectorAll(".ch-strip .ch-bar").forEach(bar => {
    bar.addEventListener("click", () => {
        $("j-channel").value = bar.dataset.ch;
    });
});

function selectJamTarget(addr, name) {
    $("j-target").value = addr;
    $("j-target-grp").style.display = "";
    $("j-target-hint").textContent = name ? `→ ${name}` : "";
    const mode = $("j-mode").value;
    if (!["targeted", "deauth"].includes(mode)) {
        $("j-mode").value = "targeted";
    }
    /* highlight selected row */
    document.querySelectorAll(".jam-picker-item").forEach(el => {
        el.classList.toggle("selected", el.dataset.addr === addr);
    });
}

function renderJammerPicker() {
    const el = $("jam-device-picker");
    const q  = ($("j-picker-search")?.value || "").toLowerCase();
    const devs = (currentDevices.length ? currentDevices : currentClustered);

    if (!devs.length) {
        el.innerHTML = '<div class="jam-picker-empty">No devices in scan — start scanning first.</div>';
        return;
    }

    const filtered = devs.filter(d => {
        const name = (d.name || d.display_name || "").toLowerCase();
        const addr = (d.address || "").toLowerCase();
        return !q || name.includes(q) || addr.includes(q);
    });

    if (!filtered.length) {
        el.innerHTML = '<div class="jam-picker-empty">No devices match filter.</div>';
        return;
    }

    /* sort by RSSI descending (strongest first) */
    const sorted = [...filtered].sort((a,b) => (b.rssi||b.signal_strength||-100) - (a.rssi||a.signal_strength||-100));

    el.innerHTML = sorted.map(d => {
        const addr  = d.address || d.mac || "";
        const name  = d.name || d.display_name || d.fingerprint_name || "Unknown";
        const rssi  = d.rssi || d.signal_strength || -99;
        const icon  = deviceIcon(d);
        const rClass = rssi > -60 ? "rssi-strong" : rssi > -80 ? "rssi-med" : "rssi-weak";
        const selected = ($("j-target")?.value === addr) ? " selected" : "";
        return `<div class="jam-picker-item${selected}" data-addr="${addr}" onclick="selectJamTarget('${addr}','${name.replace(/'/g,"\\'")}')">
            <span class="jam-picker-icon">${icon}</span>
            <div class="jam-picker-info">
                <div class="jam-picker-name">${name}</div>
                <div class="jam-picker-mac">${addr}</div>
            </div>
            <span class="jam-picker-rssi ${rClass}">${rssi} dBm</span>
        </div>`;
    }).join("");
}

function deviceIcon(d) {
    const type = (d.device_type || d.ai_classification?.label || "").toLowerCase();
    if (type.includes("phone"))      return ICO.phone;
    if (type.includes("headphone") || type.includes("earbud") || type.includes("audio")) return ICO.audio;
    if (type.includes("watch"))      return ICO.watch;
    if (type.includes("laptop") || type.includes("computer")) return ICO.computer;
    if (type.includes("tracker"))    return ICO.siren;
    if (type.includes("speaker"))    return ICO.speaker;
    if (type.includes("keyboard"))   return ICO.keyboard;
    if (type.includes("mouse"))      return ICO.input;
    return ICO.radio;
}

function updateJammer(status) {
    jammerActive = status.is_jamming || false;
    const sess = status.active_session || {};
    const btn  = $("btn-jam");

    btn.textContent = jammerActive ? "⏹ Stop Jammer" : "▶ Start Jammer";
    btn.classList.toggle("active", jammerActive);
    $("jam-ind").classList.toggle("on", jammerActive);
    $("jam-ind-txt").textContent = jammerActive ? "● JAMMING ACTIVE" : "Inactive";

    /* packets/sec */
    const pkts = sess.packets_sent || 0;
    const now  = Date.now();
    if (jammerActive && _jamPrevTime) {
        const dt  = (now - _jamPrevTime) / 1000;
        const pps = dt > 0 ? Math.round((pkts - _jamPrevPkts) / dt) : 0;
        $("jl-pps").textContent = pps;
        const ppsLabel = $("jam-pps-label");
        if (ppsLabel) { ppsLabel.textContent = `${pps} pkts/s`; ppsLabel.style.display = ""; }
    } else if (!jammerActive) {
        $("jl-pps").textContent = "0";
        const ppsLabel = $("jam-pps-label");
        if (ppsLabel) ppsLabel.style.display = "none";
    }
    _jamPrevPkts = pkts;
    _jamPrevTime = now;

    /* duration counter */
    if (jammerActive && !_jamDurTimer) {
        _jamStartTime = now;
        _jamDurTimer = setInterval(() => {
            const s = Math.floor((Date.now() - _jamStartTime) / 1000);
            const h = Math.floor(s/3600), m = Math.floor((s%3600)/60), sec = s%60;
            $("jl-dur").textContent = h ? `${h}h${m}m` : m ? `${m}m${sec}s` : `${sec}s`;
        }, 1000);
    } else if (!jammerActive && _jamDurTimer) {
        clearInterval(_jamDurTimer);
        _jamDurTimer = null;
        $("jl-dur").textContent = "0s";
    }

    $("jl-pkts").textContent = pkts.toLocaleString();
    $("jl-mode").textContent = sess.mode || "--";
    $("jl-ch").textContent   = sess.channel || "--";
    $("jl-be").textContent   = status.backend || "--";
    $("nav-jam-badge").style.display = jammerActive ? "" : "none";
    $("pill-scan").classList.toggle("jamming", jammerActive);
    updateJammerGlow(jammerActive);
    applyFullSpectrumEffect(sess.mode || "");

    // ── Honest capability display ──
    const tier = status.effectiveness_tier || "unknown";
    const affectsAudio = status.affects_bredr_audio;
    const nrfActive = status.nrf_active;
    const nrfAvailable = status.nrf_available;
    const capabilityEl = $("j-capability-hint");
    if (capabilityEl) {
        const selectedMode = $("j-mode")?.value || sess.mode;
        let hint = "";
        let cls = "";
        if (selectedMode) {
            if (selectedMode.startsWith("rf_") || selectedMode === "airpods_killer") {
                if (nrfAvailable) {
                    hint = `✓ Real RF jamming — nRF52840 radio_test backend (+8 dBm, all 2.4 GHz). Tier S effectiveness.`;
                    cls = "cap-ok";
                } else {
                    hint = `⚠ nRF52840 firmware not detected. Flash: tools/deploy_nrf_jammer.sh`;
                    cls = "cap-warn";
                }
            } else {
                hint = `ℹ BLE advertising only (channels 37/38/39). Does NOT affect BR/EDR audio. Tier ${tier}.`;
                cls = "cap-info";
            }
        }
        capabilityEl.textContent = hint;
        capabilityEl.className = "jam-capability-hint " + cls;
        capabilityEl.style.display = hint ? "" : "none";
    }

    // Use OTA-estimated PPS for honest reporting
    if (jammerActive && status.ota_packets_per_second_est !== undefined) {
        const otaEl = $("jl-pps");
        if (otaEl && status.ota_packets_per_second_est > 0) {
            otaEl.textContent = Math.round(status.ota_packets_per_second_est);
            otaEl.title = "OTA-estimated packets/sec (honest, not Python loop rate)";
        }
    }

    document.querySelectorAll(".ch-strip .ch-bar").forEach(bar => {
        bar.classList.toggle("active", jammerActive && bar.dataset.ch == sess.channel);
    });
    $("sb-jam").textContent = jammerActive ? `Jammer: ${sess.mode}` : "Jammer: Off";
}

/* ── Platform ──────────────────────────────────────────────── */
function updatePlatform(p) {
    $("pill-plat").textContent = p.os || "--";
    $("cfg-plat").innerHTML = `
        <div>OS: <strong>${p.os || "?"}</strong></div>
        <div>Host: ${p.hostname || "?"}</div>
        <div>Bleak: ${p.has_bleak ? "✓" : "✗"}</div>
        <div>hcitool: ${p.has_hcitool ? "✓" : "✗"}</div>
        <div>hcidump: ${p.has_hcidump ? "✓" : "✗"}</div>
    `;
}

/* ── Status Bar ────────────────────────────────────────────── */
function updateStatusBar() {
    const devCount = viewMode === "clustered" ? currentClustered.length : currentDevices.length;
    $("sb-dev").textContent = `${devCount} devices`;
    $("sb-scans").textContent = `${clusterSummary.total_physical_devices || 0} physical`;

    let maxRisk = "low";
    currentClustered.forEach(d => {
        if (d.risk_level === "critical") maxRisk = "critical";
        else if (d.risk_level === "high" && maxRisk !== "critical") maxRisk = "high";
        else if (d.risk_level === "medium" && maxRisk === "low") maxRisk = "medium";
    });
    $("sb-risk").textContent = `Risk: ${maxRisk.toUpperCase()}`;
}

/* ── Config Controls ───────────────────────────────────────── */
$("btn-save-cfg").addEventListener("click", async () => {
    const data = {
        scan_interval: parseInt($("cfg-interval").value),
        scan_duration: parseInt($("cfg-duration").value),
        alert_threshold: parseInt($("cfg-threshold").value),
    };
    await fetch("/api/config", { method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify(data) });
});
$("btn-reset").addEventListener("click", async () => {
    if (confirm("Reset all device data?")) await fetch("/api/reset", { method:"POST" });
});
$("btn-export").addEventListener("click", async () => {
    try {
        const res = await fetch("/api/export", { method:"POST" });
        const blob = await res.blob();
        const a = document.createElement("a");
        a.href = URL.createObjectURL(blob);
        a.download = "blueshield_report.json";
        a.click();
    } catch {}
});

/* ── Live Demo Dashboard ───────────────────────────────────── */
function renderLiveDemo() {
    renderSafetyGauge();
    renderPeoplePanel();
    renderWeatherPanel();
    renderLiveStats();
    renderAIFeed();
}

function renderSafetyGauge() {
    const s = safetyData;
    if (!s || s.score === undefined) return;
    const score = s.score || 0;
    const circumference = 2 * Math.PI * 85; // r=85
    const offset = circumference * (1 - score / 100);
    const arc = $("sg-arc");
    if (arc) {
        arc.style.strokeDasharray = circumference;
        arc.style.strokeDashoffset = offset;
        arc.style.stroke = s.color || "var(--green)";
        arc.style.transition = "stroke-dashoffset 1s ease, stroke .5s";
    }
    if ($("sg-score")) { $("sg-score").textContent = score; $("sg-score").style.color = s.color || "var(--green)"; }
    if ($("sg-grade")) { $("sg-grade").textContent = s.grade || "?"; $("sg-grade").style.color = s.color || "var(--green)"; }

    const factorsEl = $("sg-factors");
    if (factorsEl && s.factors) {
        factorsEl.innerHTML = s.factors.map(f => {
            const cls = f.impact < 0 ? "sg-factor-neg" : "sg-factor-pos";
            return `<div class="sg-factor ${cls}">${f.icon || ""} ${escHtml(f.name)}: ${f.impact > 0 ? "+" : ""}${f.impact}</div>`;
        }).join("");
    }
}

function renderPeoplePanel() {
    const p = peopleData;
    if (!p) return;
    if ($("lp-count")) $("lp-count").textContent = p.estimated_people || 0;
    if ($("lp-movement")) $("lp-movement").textContent = `Movement: ${p.movement_pattern || "—"}`;
    const detail = $("lp-detail");
    if (detail && p.clusters) {
        detail.innerHTML = p.clusters.slice(0, 5).map(c =>
            `<div>${c.ecosystem ? c.ecosystem.charAt(0).toUpperCase() + c.ecosystem.slice(1) : "?"}: ${c.devices.join(", ")}</div>`
        ).join("") + (p.unassigned > 0 ? `<div style="color:var(--tx-3)">${p.unassigned} unassociated device(s)</div>` : "");
    }
}

function renderWeatherPanel() {
    const w = weatherData;
    if (!w) return;
    if ($("lw-density")) $("lw-density").textContent = w.density || "Clear";
    if ($("lw-density-icon")) $("lw-density-icon").innerHTML = ICO.sun;
    if ($("lw-turb")) $("lw-turb").textContent = w.turbulence || "Calm";
    if ($("lw-turb-icon")) $("lw-turb-icon").innerHTML = ICO.waves;
    if ($("lw-wind")) $("lw-wind").textContent = w.wind || "Stable";
    if ($("lw-wind-icon")) $("lw-wind-icon").innerHTML = ICO.activity;
    if ($("lw-forecast")) $("lw-forecast").textContent = w.forecast || "Quiet";
    if ($("lw-forecast-icon")) $("lw-forecast-icon").innerHTML = ICO.trendDn;
}

function renderLiveStats() {
    if ($("ls-devices")) $("ls-devices").textContent = currentClustered.length;
    if ($("ls-trackers")) $("ls-trackers").textContent = trackerSuspects.length;
    if ($("ls-scans")) $("ls-scans").textContent = clusterSummary.total_physical_devices || 0;
    if ($("ls-new")) $("ls-new").textContent = analyticsData.today_new || 0;
}

function renderAIFeed() {
    const el = $("aif-scroll");
    if (!el) return;
    if (!Object.keys(classifications).length) {
        el.innerHTML = '<div class="empty-msg" style="padding:8px">Scanning for devices...</div>';
        return;
    }
    el.innerHTML = currentClustered.slice(0, 12).map(d => {
        const cls = classifications[d.fingerprint_id || ""];
        if (!cls || !cls.top) return "";
        const confPct = Math.round(cls.top.confidence * 100);
        const confCls = confPct >= 60 ? "aif-conf-high" : confPct >= 30 ? "aif-conf-med" : "aif-conf-low";
        return `<div class="aif-item">
            <span class="aif-icon">${cls.top.icon}</span>
            <span class="aif-name">${escHtml(d.best_name || "Unknown")}</span>
            <span class="aif-type">${escHtml(cls.top.label)}</span>
            <span class="aif-conf ${confCls}">${confPct}%</span>
        </div>`;
    }).filter(Boolean).join("");
}

/* ── Time Travel ───────────────────────────────────────────── */
async function fetchTimeTravel() {
    try {
        const res = await fetch("/api/time-travel");
        const data = await res.json();
        scanSnapshots = data.snapshots || [];
        const slider = $("tt-slider");
        if (slider && scanSnapshots.length > 0) {
            slider.max = scanSnapshots.length - 1;
            slider.value = scanSnapshots.length - 1;
            const first = new Date(scanSnapshots[0].timestamp);
            $("tt-start").textContent = first.toLocaleTimeString().slice(0, 5);
            $("tt-end").textContent = "NOW";
        }
    } catch {}
}

if ($("tt-slider")) {
    $("tt-slider").addEventListener("input", e => {
        const idx = parseInt(e.target.value);
        if (idx >= scanSnapshots.length - 1) {
            timeTravelMode = false;
            $("tt-live-btn").innerHTML = '<span class="live-dot"></span> LIVE';
            $("tt-live-btn").style.color = "";
            $("tt-info").textContent = "Live mode — showing real-time data";
            return;
        }
        timeTravelMode = true;
        $("tt-live-btn").textContent = "⏪ REPLAY";
        $("tt-live-btn").style.color = "var(--orange)";
        const snap = scanSnapshots[idx];
        if (snap) {
            const ts = new Date(snap.timestamp);
            $("tt-info").textContent = `${ts.toLocaleTimeString()} — ${snap.device_count} devices, ${snap.people_count} people, safety: ${snap.safety_score}/100`;
            // Update people count and safety for time travel view
            if ($("lp-count")) $("lp-count").textContent = snap.people_count || 0;
            if ($("sg-score")) $("sg-score").textContent = snap.safety_score || 0;
            if ($("ls-devices")) $("ls-devices").textContent = snap.device_count || 0;
        }
    });
}
if ($("tt-live-btn")) {
    $("tt-live-btn").addEventListener("click", () => {
        timeTravelMode = false;
        const slider = $("tt-slider");
        if (slider && scanSnapshots.length) slider.value = scanSnapshots.length - 1;
        $("tt-live-btn").innerHTML = '<span class="live-dot"></span> LIVE';
        $("tt-live-btn").style.color = "";
        $("tt-info").textContent = "Live mode — showing real-time data";
        renderLiveDemo();
    });
}

/* ── Pi Health Monitor ─────────────────────────────────────── */
async function fetchSystemHealth() {
    try {
        const res = await fetch("/api/system");
        if (!res.ok) return;
        const d = await res.json();
        renderHealthTab(d);
    } catch {}
}

function renderHealthTab(d) {
    const now = new Date().toLocaleTimeString();
    if ($("health-updated")) $("health-updated").textContent = `Updated ${now}`;

    const alerts = [];

    // CPU Temp
    if (d.cpu_temp !== null) {
        const t = d.cpu_temp;
        $("hv-temp").textContent = `${t}°C`;
        const pct = Math.min((t / 90) * 100, 100);
        $("hb-temp").style.width = pct + "%";
        const col = t > 80 ? "var(--red)" : t > 65 ? "var(--orange)" : "var(--green)";
        $("hb-temp").style.background = col;
        $("hs-temp").textContent = t > 80 ? "CRITICAL — throttling!" : t > 65 ? "Warm — check cooling" : "Normal";
        const hcard = $("hc-temp");
        if (hcard) { hcard.classList.toggle("crit", t > 80); hcard.classList.toggle("warn", t > 65 && t <= 80); }
        if (t > 80) alerts.push({ cls: "crit", msg: `CPU temp ${t}°C — Pi is throttling! Add a heatsink/fan.` });
        else if (t > 65) alerts.push({ cls: "warn", msg: `CPU temp ${t}°C — Running warm. Consider a heatsink.` });
    } else {
        $("hv-temp").textContent = "N/A";
        $("hs-temp").textContent = "Not available (non-Linux)";
    }

    // CPU Usage
    if (d.cpu_percent !== null) {
        const c = d.cpu_percent;
        $("hv-cpu").textContent = `${c}%`;
        $("hb-cpu").style.width = c + "%";
        $("hb-cpu").style.background = c > 85 ? "var(--red)" : c > 60 ? "var(--orange)" : "var(--green)";
        $("hs-cpu").textContent = c > 85 ? "Very high load" : c > 60 ? "Moderate load" : "Normal";
        if (c > 90) alerts.push({ cls: "warn", msg: `CPU usage ${c}% — Pi 3 is under heavy load.` });
    } else {
        $("hv-cpu").textContent = "N/A";
    }

    // RAM
    if (d.ram_percent !== null) {
        const r = d.ram_percent;
        $("hv-ram").textContent = `${d.ram_used_mb}MB / ${d.ram_total_mb}MB`;
        $("hb-ram").style.width = r + "%";
        $("hb-ram").style.background = r > 85 ? "var(--red)" : r > 65 ? "var(--orange)" : "var(--green)";
        $("hs-ram").textContent = `${r}% used`;
        if (r > 85) alerts.push({ cls: "warn", msg: `RAM ${r}% used — Pi 3 only has 1GB. Consider reducing scan load.` });
    } else {
        $("hv-ram").textContent = "N/A";
    }

    // Voltage / Throttle
    if (d.undervoltage !== undefined) {
        const uv = d.undervoltage;
        const th = d.throttled;
        $("hv-volt").textContent = uv ? "UNDER-VOLTAGE" : th ? "THROTTLED" : "Good";
        $("hs-volt").textContent = uv ? "Use 5V 2.5A PSU" : th ? "Check power supply" : "Power OK";
        const hcard = $("hc-volt");
        if (hcard) { hcard.classList.toggle("crit", uv); hcard.classList.toggle("warn", th && !uv); }
        if (uv) alerts.push({ cls: "crit", msg: "Undervoltage detected! Use an official 5V 2.5A Raspberry Pi PSU. This causes USB instability and scan failures." });
        else if (th) alerts.push({ cls: "warn", msg: "Pi is throttling due to power. Check your power supply." });
    } else {
        $("hv-volt").textContent = "N/A";
        $("hs-volt").textContent = "vcgencmd not available";
    }

    // Disk
    if (d.disk_total_gb !== null) {
        const pct = Math.round(d.disk_used_gb / d.disk_total_gb * 100);
        $("hv-disk").textContent = `${d.disk_used_gb}GB / ${d.disk_total_gb}GB`;
        $("hb-disk").style.width = pct + "%";
        $("hb-disk").style.background = pct > 90 ? "var(--red)" : pct > 75 ? "var(--orange)" : "var(--accent)";
        $("hs-disk").textContent = `${pct}% used`;
        if (pct > 90) alerts.push({ cls: "warn", msg: `Disk ${pct}% full — clear old logs soon.` });
    }

    // Uptime + IP
    if (d.uptime_seconds !== null) {
        const h = Math.floor(d.uptime_seconds / 3600);
        const m = Math.floor((d.uptime_seconds % 3600) / 60);
        $("hv-uptime").textContent = `${h}h ${m}m`;
    }
    if (d.ip_address && $("hs-ip")) {
        $("hs-ip").textContent = `IP: ${d.ip_address}`;
    }

    // BLE Adapter inventory
    const adGrid = $("bt-adapter-grid");
    if (adGrid && d.bt_adapters) {
        // Dynamic role detection from server config
        const roleMap = d.adapter_roles || {
            "hci0": "Primary Jammer (Realtek BT5.4)",
            "hci1": "Secondary Jammer (Realtek BT5.3)",
            "hci2": "Scanner (Broadcom BT4.1)",
            "hci3": "Secondary Jammer (Realtek BT5.3)",
        };
        // Check for any DOWN adapters
        const hasDown = d.bt_adapters.some(a => !a.up);
        adGrid.innerHTML = d.bt_adapters.map(a => {
            const role = roleMap[a.name] || a.role || a.name;
            const statusDot = a.up ? '<span style="color:var(--green)">●</span>' : '<span style="color:var(--red)">●</span>';
            return `<div class="bt-adapter-card">
                <div style="display:flex;align-items:center;gap:6px;margin-bottom:4px">
                    ${statusDot}
                    <span style="font-weight:600;font-size:.76rem;color:var(--tx-1)">${a.name}</span>
                    <span style="font-size:.64rem;color:var(--tx-3);margin-left:auto">${role}</span>
                </div>
                <div style="font-family:var(--font-mono);font-size:.66rem;color:var(--cyan)">${a.address || "N/A"}</div>
                <div style="font-size:.62rem;color:var(--tx-3);margin-top:2px">${a.type || "Unknown"}</div>
            </div>`;
        }).join("");
        // Add nRF sniffer cards
        for (const key of ["nrf_sniffer", "nrf_sniffer_2"]) {
            if (d[key]) {
                const nrf = d[key];
                const nrfDot = nrf.running ? '<span style="color:var(--green)">●</span>' : '<span style="color:var(--tx-3)">●</span>';
                const label = key === "nrf_sniffer" ? "nRF52840 #1" : "nRF52840 #2";
                adGrid.innerHTML += `<div class="bt-adapter-card">
                    <div style="display:flex;align-items:center;gap:6px;margin-bottom:4px">
                        ${nrfDot}
                        <span style="font-weight:600;font-size:.76rem;color:var(--tx-1)">${label}</span>
                        <span style="font-size:.64rem;color:var(--tx-3);margin-left:auto">BLE Sniffer</span>
                    </div>
                    <div style="font-family:var(--font-mono);font-size:.66rem;color:var(--cyan)">${nrf.port}</div>
                    <div style="font-size:.62rem;color:var(--tx-3);margin-top:2px">${nrf.simulated ? "Simulated" : "Hardware"} — ${nrf.running ? "Scanning" : "Idle"}</div>
                </div>`;
            }
        }
        // USB Reset button if any adapter is DOWN
        if (hasDown) {
            adGrid.innerHTML += `<div class="bt-adapter-card" style="border:1px solid var(--red);cursor:pointer" onclick="usbReset()">
                <div style="text-align:center;padding:4px 0">
                    <span style="color:var(--red);font-weight:700;font-size:.8rem">USB Reset & Remap</span>
                    <div style="font-size:.6rem;color:var(--tx-3);margin-top:2px">Adapter down — click to reset USB hub</div>
                </div>
            </div>`;
        }
    }

    // Health badge on nav
    const badge = $("nav-health-badge");
    if (badge) badge.style.display = alerts.filter(a => a.cls === "crit").length ? "" : "none";

    // Render alerts
    const container = $("health-alerts");
    if (container) {
        if (!alerts.length) {
            const onLinux = d && d.cpu_temp !== null;
            container.innerHTML = onLinux
                ? `<div class="health-alert-item ok">All systems nominal — Pi 3 is running healthy.</div>`
                : `<div class="health-alert-item warn">Hardware metrics unavailable — connect to Raspberry Pi to see live stats.</div>`;
        } else {
            container.innerHTML = alerts.map(a => `<div class="health-alert-item ${a.cls}">${a.msg}</div>`).join("");
        }
    }
}

// Fetch health when health tab is opened, and refresh every 15s while on that tab
let healthTabActive = false;
setInterval(() => { if (healthTabActive) fetchSystemHealth(); }, 15000);

/* ═══════════════════════════════════════════════════════════
   SNIFFER MODULE
   ═══════════════════════════════════════════════════════════ */

/* ── Sniffer State ─────────────────────────────────────────── */
let snifferRunning    = false;
let snifferPackets    = [];     // all raw packet dicts (capped at 2000)
let snifferFiltered   = [];     // after type + search filter
let snifferConnections = [];
let snifferPairings   = [];
let snifferSimulated  = false;
let _snfPendingCrackleSession = null;

const SNF_MAX_LOG = 500;        // rows rendered in table at once

/* ── Socket.IO — sniffer events ────────────────────────────── */
socket.on("sniffer_packet", pkt => {
    snifferPackets.push(pkt);
    if (snifferPackets.length > 2000) snifferPackets.shift();
    _snfUpdateCounters();
    if (document.getElementById("tab-sniffer")?.classList.contains("active")) {
        _snfAppendRow(pkt);
    }
});

socket.on("sniffer_connection", conn => {
    // Update or push
    const idx = snifferConnections.findIndex(c => c.session_id === conn.session_id);
    if (idx >= 0) snifferConnections[idx] = conn; else snifferConnections.push(conn);
    _snfUpdateCounters();
    _snfRenderConnections();
});

socket.on("sniffer_pairing", session => {
    const idx = snifferPairings.findIndex(p => p.session_id === session.session_id);
    if (idx >= 0) snifferPairings[idx] = session; else snifferPairings.push(session);
    _snfUpdateCounters();
    _snfRenderPairings();
    // Show crackle card if a crackable session appeared
    if (session.crackable && !snifferSimulated) {
        _snfPendingCrackleSession = session;
        const card = $("snf-crackle-card");
        if (card) card.style.display = "";
    }
});

socket.on("sniffer_state", data => {
    const state = data.state || "IDLE";
    snifferSimulated = !!data.simulated;
    snifferRunning   = (state === "SCANNING" || state === "CONNECTED");
    _snfUpdateControlState(state);
});

socket.on("sniffer_error", data => {
    const st = $("sniffer-status-text");
    if (st) { st.textContent = "Error: " + (data.message || "unknown"); st.style.color = "var(--red)"; }
});

socket.on("gatt_result", result => {
    _snfRenderGATTResult(result);
});

socket.on("crackle_result", result => {
    _snfRenderCrackleResult(result);
});

/* ── Tab hook ──────────────────────────────────────────────── */
const _origSwitchTab = switchTab;
// Extend switchTab to hook sniffer tab activation
(function() {
    const _orig = switchTab;
    switchTab = function(tab) {
        _orig(tab);
        if (tab === "sniffer") _snfOnTabOpen();
    };
})();

function _snfOnTabOpen() {
    fetch("/api/sniffer/status")
        .then(r => r.json())
        .then(data => {
            if (data.running !== undefined) {
                snifferRunning = data.running;
                snifferSimulated = !!data.simulated;
            }
            if (data.connections)    snifferConnections = data.connections;
            if (data.pairing_sessions) snifferPairings  = data.pairing_sessions;
            _snfUpdateControlState(data.running ? "SCANNING" : "IDLE");
            _snfUpdateCounters();
            _snfRenderConnections();
            _snfRenderPairings();
            renderSnifferTable();
            // Show crackle card if there is a crackable pairing
            const crackable = snifferPairings.find(p => p.crackable);
            if (crackable) {
                _snfPendingCrackleSession = crackable;
                const card = $("snf-crackle-card");
                if (card) card.style.display = "";
            }
        })
        .catch(() => {});
}

/* ── Controls ──────────────────────────────────────────────── */
async function snifferToggle() {
    if (snifferRunning) {
        await fetch("/api/sniffer/stop", { method: "POST" });
    } else {
        const mac    = ($("snf-target-mac")?.value || "").trim() || null;
        const rssi   = parseInt($("snf-rssi-min")?.value || "-100");
        const coded  = $("snf-phy")?.value === "coded";
        await fetch("/api/sniffer/start", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ target_mac: mac, rssi_min: rssi, coded_phy: coded }),
        });
    }
}

/* ── nRF52840 Sniffer Toggle ───────────────────────────────── */
let _nrfRunning = false;
async function nrfSnifferToggle() {
    const endpoint = _nrfRunning ? "/api/nrf-sniffer/stop" : "/api/nrf-sniffer/start";
    try {
        const res = await fetch(endpoint, { method: "POST" });
        const data = await res.json();
        if (data.status === "started" || data.status === "already_running") {
            _nrfRunning = true;
        } else {
            _nrfRunning = false;
        }
        _nrfUpdateBadge();
    } catch (e) {
        console.error("nRF sniffer toggle error:", e);
    }
}
function _nrfUpdateBadge() {
    const badge = $("nrf-badge");
    const label = $("nrf-btn-label");
    if (badge) {
        badge.textContent = _nrfRunning ? "nRF ON" : "nRF OFF";
        badge.style.background = _nrfRunning ? "rgba(34,211,238,0.18)" : "rgba(255,255,255,0.06)";
        badge.style.color = _nrfRunning ? "var(--cyan)" : "var(--tx-3)";
    }
    if (label) label.textContent = _nrfRunning ? "nRF Stop" : "nRF Start";
}
// Poll nRF status every 5s
setInterval(async () => {
    try {
        const res = await fetch("/api/nrf-sniffer/status");
        if (!res.ok) return;
        const data = await res.json();
        _nrfRunning = data.running;
        _nrfUpdateBadge();
    } catch (e) { /* ignore */ }
}, 5000);

function snifferClearLog() {
    snifferPackets   = [];
    snifferFiltered  = [];
    const tb = $("snf-log-body");
    if (tb) tb.innerHTML = `<tr class="snf-empty-row"><td colspan="7">Log cleared.</td></tr>`;
    _snfUpdateCounters();
}

function snifferExportPCAP() {
    window.location.href = "/api/sniffer/pcap/export";
}

async function snifferStartGATT() {
    const mac = ($("snf-gatt-mac")?.value || "").trim().toUpperCase();
    if (!mac || !mac.match(/^([0-9A-F]{2}:){5}[0-9A-F]{2}$/i)) {
        const st = $("snf-gatt-status");
        if (st) { st.textContent = "Invalid MAC address format."; st.style.color = "var(--red)"; }
        return;
    }
    const btn = $("snf-gatt-btn");
    const st  = $("snf-gatt-status");
    if (btn) btn.disabled = true;
    if (st)  { st.textContent = `Connecting to ${mac}…`; st.style.color = "var(--tx-3)"; }

    try {
        const res = await fetch("/api/sniffer/gatt", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ mac, read_values: true }),
        });
        const data = await res.json();
        if (data.status === "already_inspecting") {
            if (st) st.textContent = "Already inspecting — waiting for result…";
        } else if (data.error) {
            if (st) { st.textContent = data.error; st.style.color = "var(--red)"; }
            if (btn) btn.disabled = false;
        } else {
            if (st) st.textContent = `Enumerating GATT services for ${mac}…`;
        }
    } catch (e) {
        if (st) { st.textContent = "Request failed: " + e; st.style.color = "var(--red)"; }
        if (btn) btn.disabled = false;
    }
}

async function snifferRunCrackle() {
    const btn = $("snf-crackle-btn");
    const res = $("snf-crackle-result");
    const passkey_max = parseInt($("snf-crackle-mode")?.value || "0");
    const session_id  = _snfPendingCrackleSession?.session_id || "manual";

    if (btn) btn.disabled = true;
    if (res) { res.textContent = "Running crackle…"; res.className = "snf-crackle-result snf-crackle-log"; }

    try {
        await fetch("/api/sniffer/crackle", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ session_id, passkey_max }),
        });
    } catch (e) {
        if (res) { res.textContent = "Request failed: " + e; res.className = "snf-crackle-result snf-crackle-fail"; }
        if (btn) btn.disabled = false;
    }
    // Result arrives via socket.on("crackle_result")
}

/* ── Table rendering ───────────────────────────────────────── */
function renderSnifferTable() {
    const typeFilter = $("snf-type-filter")?.value || "all";
    const search     = ($("snf-search")?.value || "").toLowerCase();

    snifferFiltered = snifferPackets.filter(p => {
        if (typeFilter !== "all") {
            if (typeFilter === "smp"         && !_snfIsSMP(p))      return false;
            if (typeFilter === "connect_ind" && p.pkt_type !== "connect_ind") return false;
            if (typeFilter === "adv"         && p.pkt_type !== "adv" && p.pkt_type !== "scan_rsp") return false;
            if (typeFilter === "data"        && p.pkt_type !== "data") return false;
        }
        if (search) {
            const hay = [p.adv_address, p.adv_type_name, p.adv_name, p.manufacturer, p.payload_hex]
                .filter(Boolean).join(" ").toLowerCase();
            if (!hay.includes(search)) return false;
        }
        return true;
    });

    const tb = $("snf-log-body");
    if (!tb) return;

    const slice = snifferFiltered.slice(-SNF_MAX_LOG);
    if (!slice.length) {
        tb.innerHTML = `<tr class="snf-empty-row"><td colspan="7">No matching packets.</td></tr>`;
        return;
    }

    tb.innerHTML = slice.map((p, i) => _snfRowHTML(p, snifferFiltered.length - slice.length + i)).join("");
}

function _snfAppendRow(pkt) {
    const typeFilter = $("snf-type-filter")?.value || "all";
    const search     = ($("snf-search")?.value || "").toLowerCase();

    // Check filter
    if (typeFilter !== "all") {
        if (typeFilter === "smp"         && !_snfIsSMP(pkt))        return;
        if (typeFilter === "connect_ind" && pkt.pkt_type !== "connect_ind") return;
        if (typeFilter === "adv"         && pkt.pkt_type !== "adv" && pkt.pkt_type !== "scan_rsp") return;
        if (typeFilter === "data"        && pkt.pkt_type !== "data") return;
    }
    if (search) {
        const hay = [pkt.adv_address, pkt.adv_type_name, pkt.adv_name, pkt.manufacturer, pkt.payload_hex]
            .filter(Boolean).join(" ").toLowerCase();
        if (!hay.includes(search)) return;
    }

    const tb = $("snf-log-body");
    if (!tb) return;

    // Remove "no packets" row
    const emptyRow = tb.querySelector(".snf-empty-row");
    if (emptyRow) emptyRow.remove();

    const idx  = snifferFiltered.length;
    snifferFiltered.push(pkt);

    const tr   = document.createElement("tr");
    tr.className = _snfRowClass(pkt);
    tr.innerHTML = _snfRowInnerHTML(pkt, idx);
    tr.addEventListener("click", () => _snfShowDetail(pkt));
    tb.appendChild(tr);

    // Prune to SNF_MAX_LOG rows
    while (tb.rows.length > SNF_MAX_LOG) tb.deleteRow(0);

    // Auto-scroll
    if ($("snf-autoscroll")?.checked) {
        const wrap = tb.closest(".snf-log-wrap");
        if (wrap) wrap.scrollTop = wrap.scrollHeight;
    }
}

/* ── Row builders ──────────────────────────────────────────── */
function _snfRowHTML(pkt, idx) {
    return `<tr class="${_snfRowClass(pkt)}" onclick="_snfShowDetail(snifferFiltered[${idx}])">${_snfRowInnerHTML(pkt, idx)}</tr>`;
}

function _snfRowInnerHTML(pkt, idx) {
    const t   = new Date(pkt.ts * 1000);
    const ts  = t.toTimeString().slice(0, 8) + "." + String(t.getMilliseconds()).padStart(3, "0");
    const ch  = pkt.channel ?? "?";
    const pdu = _snfPDUBadge(pkt);
    const mac = pkt.adv_address || (pkt.access_address ? pkt.access_address : "—");
    const rssi = pkt.rssi ? `${pkt.rssi} dBm` : "—";
    const len  = pkt.payload_len ?? pkt.data_length ?? "—";
    const info = _snfRowInfo(pkt);
    return `<td>${ts}</td><td>${ch}</td><td>${pdu}</td><td style="font-family:var(--font-mono)">${mac}</td><td>${rssi}</td><td>${len}</td><td style="max-width:260px;overflow:hidden;text-overflow:ellipsis;font-family:var(--font-sans);color:var(--tx-2)">${info}</td>`;
}

function _snfRowClass(pkt) {
    if (pkt.pkt_type === "connect_ind") return "snf-row--connect";
    if (_snfIsSMP(pkt))                 return "snf-row--smp";
    if (pkt.pkt_type === "data")        return "snf-row--data";
    return "snf-row--adv";
}

function _snfPDUBadge(pkt) {
    const name = pkt.adv_type_name || pkt.pkt_type || "?";
    let cls = "snf-pdu--adv";
    if (pkt.pkt_type === "connect_ind" || name === "CONNECT_IND") cls = "snf-pdu--conn";
    else if (pkt.pkt_type === "scan_rsp" || name === "SCAN_RSP")  cls = "snf-pdu--scan";
    else if (_snfIsSMP(pkt))                                       cls = "snf-pdu--smp";
    else if (pkt.pkt_type === "data")                              cls = "snf-pdu--data";
    return `<span class="snf-pdu ${cls}">${name.replace("_", " ")}</span>`;
}

function _snfRowInfo(pkt) {
    if (pkt.adv_name)      return pkt.adv_name;
    if (pkt.manufacturer)  return pkt.manufacturer;
    if (pkt.conn_aa)       return `AA:${pkt.conn_aa}  hop:${pkt.hop_increment}  crc:${pkt.crc_init}`;
    if (pkt.pkt_type === "data" && pkt.llid !== undefined) {
        const llid_names = {1: "L2CAP cont", 2: "L2CAP start", 3: "LLCP"};
        return llid_names[pkt.llid] || `LLID ${pkt.llid}`;
    }
    return "";
}

function _snfIsSMP(pkt) {
    // Heuristic: data PDU with payload containing L2CAP CID 0x0006
    if (pkt.pkt_type !== "data") return false;
    const hex = pkt.payload_hex || "";
    // L2CAP CID 0x0006 appears as "0600" bytes 4-6 in the payload after 2-byte LL header
    return hex.length >= 12 && hex.slice(8, 12).toLowerCase() === "0600";
}

/* ── Connection list ───────────────────────────────────────── */
function _snfRenderConnections() {
    const el = $("snf-conn-list");
    if (!el) return;
    if (!snifferConnections.length) {
        el.innerHTML = `<div class="snf-empty">No connections captured yet.</div>`;
        return;
    }
    el.innerHTML = snifferConnections.slice().reverse().map(c => `
        <div class="snf-conn-item">
            <div class="snf-conn-aa">${c.access_address}</div>
            <div class="snf-conn-macs">
                <span style="color:var(--accent)">${c.central_mac}</span>
                <span style="color:var(--tx-3)"> → </span>
                <span>${c.peripheral_mac}</span>
            </div>
            <div class="snf-conn-meta">
                <span>hop+${c.hop_increment}</span>
                <span>CRC ${c.crc_init}</span>
                <span>${c.packet_count} pkts</span>
                ${c.duration_s ? `<span>${c.duration_s}s</span>` : ""}
            </div>
        </div>
    `).join("");
    const cnt = $("snf-conn-count");
    if (cnt) cnt.textContent = snifferConnections.length;
}

/* ── Pairing list ──────────────────────────────────────────── */
function _snfRenderPairings() {
    const el = $("snf-pair-list");
    if (!el) return;
    if (!snifferPairings.length) {
        el.innerHTML = `<div class="snf-empty">No pairing sessions captured.</div>`;
        return;
    }

    el.innerHTML = snifferPairings.slice().reverse().map(s => {
        const isLESC     = s.pairing_type === "lesc";
        const isCrackable = s.crackable;
        const badgeCls   = isCrackable ? "snf-pair-type-badge--crackable"
                         : isLESC      ? "snf-pair-type-badge--lesc"
                         :               "snf-pair-type-badge--legacy";
        const badgeTxt   = isCrackable ? "CRACKABLE"
                         : isLESC      ? "✓ LESC / ECDH"
                         :               "LEGACY";
        const cardCls    = isCrackable ? "snf-pair-item--crackable"
                         : isLESC      ? "snf-pair-item--lesc"
                         :               "";

        const pktsHtml = (s.packets || []).map(p =>
            `<div class="snf-pair-pkt-row">
                <span class="snf-pair-pkt-cmd">${p.name}</span>
                <span style="color:var(--accent)">${p.hex ? p.hex.slice(0, 24) + (p.hex.length > 24 ? "…" : "") : ""}</span>
            </div>`
        ).join("");

        return `
        <div class="snf-pair-item ${cardCls}">
            <span class="snf-pair-type-badge ${badgeCls}">${badgeTxt}</span>
            <div class="snf-pair-macs">${s.central_mac} → ${s.peripheral_mac}</div>
            <div class="snf-pair-meta">
                <span>method: ${s.auth_method}</span>
                ${s.mitm_protected ? `<span style="color:var(--green)">MITM ✓</span>` : `<span style="color:var(--red)">No MITM</span>`}
                ${s.bonding ? `<span>Bonding</span>` : ""}
                <span>${s.packet_count} SMP pkts</span>
            </div>
            ${pktsHtml ? `<div class="snf-pair-pkts">${pktsHtml}</div>` : ""}
            ${isCrackable ? `<button class="snf-crack-btn" onclick="_snfSetCrackTarget('${s.session_id}')">Run Crackle</button>` : ""}
        </div>`;
    }).join("");

    const cnt = $("snf-pair-count");
    if (cnt) cnt.textContent = snifferPairings.length;
}

function _snfSetCrackTarget(session_id) {
    _snfPendingCrackleSession = snifferPairings.find(p => p.session_id === session_id) || null;
    const card = $("snf-crackle-card");
    if (card) {
        card.style.display = "";
        card.scrollIntoView({ behavior: "smooth", block: "nearest" });
    }
}

/* ── GATT result rendering ─────────────────────────────────── */
function _snfRenderGATTResult(result) {
    const btn = $("snf-gatt-btn");
    const st  = $("snf-gatt-status");
    const out = $("snf-gatt-result");

    if (btn) btn.disabled = false;

    if (result.error) {
        if (st)  { st.textContent = "Error: " + result.error; st.style.color = "var(--red)"; }
        if (out) out.innerHTML = "";
        return;
    }

    if (st) {
        st.textContent = `${result.name || result.mac} — ${(result.services||[]).length} services — ${result.duration_ms}ms`;
        st.style.color = "var(--green)";
    }

    if (!out) return;

    const services = result.services || [];
    out.innerHTML = services.map(svc => {
        const chars = (svc.characteristics || []).map(ch => {
            const propsHtml = (ch.properties || []).map(p =>
                `<span class="snf-gatt-prop">${p}</span>`
            ).join("");

            const valHtml = ch.value_text
                ? `<div class="snf-gatt-val snf-gatt-val-text">"${_escHtml(ch.value_text)}"</div>`
                : ch.value_decoded
                ? `<div class="snf-gatt-val">${_escHtml(JSON.stringify(ch.value_decoded))}</div>`
                : ch.value_hex
                ? `<div class="snf-gatt-val">${ch.value_hex}</div>`
                : ch.error
                ? `<div class="snf-gatt-err">${_escHtml(ch.error)}</div>`
                : "";

            const descsHtml = (ch.descriptors || []).filter(d => d.value_hex).map(d =>
                `<div class="snf-gatt-desc">↳ ${d.name}: ${d.value_hex}</div>`
            ).join("");

            return `
            <div class="snf-gatt-char">
                <div class="snf-gatt-char-hd">
                    <span class="snf-gatt-char-name">${_escHtml(ch.name)}</span>
                    <span class="snf-gatt-char-uuid">${ch.short_uuid || ch.uuid}</span>
                    <div class="snf-gatt-char-props">${propsHtml}</div>
                </div>
                ${valHtml}${descsHtml}
            </div>`;
        }).join("");

        return `
        <div class="snf-gatt-svc">
            <div class="snf-gatt-svc-hd">
                <span>${_escHtml(svc.name)}</span>
                <span class="snf-gatt-svc-uuid">${svc.short_uuid || svc.uuid}</span>
            </div>
            ${chars}
        </div>`;
    }).join("");
}

/* ── Crackle result rendering ──────────────────────────────── */
function _snfRenderCrackleResult(result) {
    const btn = $("snf-crackle-btn");
    const res = $("snf-crackle-result");
    if (btn) btn.disabled = false;
    if (!res) return;

    if (result.success) {
        const lines = [
            `CRACKED`,
            `TK  = ${result.tk_hex || result.tk}`,
            result.stk_hex  ? `STK = ${result.stk_hex}` : null,
            result.ltk_hex  ? `LTK = ${result.ltk_hex}` : null,
            `Method: ${result.method}`,
            `Time:   ${result.duration_ms}ms`,
            result.crackable_note ? `\n${result.crackable_note}` : null,
            result.decrypted_pcap_path ? `\nDecrypted PCAP:\n${result.decrypted_pcap_path}` : null,
        ].filter(Boolean).join("\n");
        res.textContent  = lines;
        res.className    = "snf-crackle-result snf-crackle-success";
    } else {
        const lines = [
            `${result.error || "Not cracked"}`,
            "",
            ...(result.log_lines || []),
        ].join("\n");
        res.textContent = lines;
        res.className   = "snf-crackle-result snf-crackle-fail";
    }
}

/* ── Packet detail drawer ──────────────────────────────────── */
function _snfShowDetail(pkt) {
    if (!pkt) return;
    const drawer = $("snf-detail-drawer");
    const body   = $("snf-detail-body");
    if (!drawer || !body) return;

    const fields = [
        ["Type",       pkt.adv_type_name || pkt.pkt_type],
        ["Address",    pkt.adv_address],
        ["Channel",    pkt.channel],
        ["RSSI",       pkt.rssi ? pkt.rssi + " dBm" : null],
        ["Access AA",  pkt.access_address],
        ["Payload len",pkt.payload_len ?? pkt.data_length],
        ["Name",       pkt.adv_name],
        ["Manufacturer", pkt.manufacturer],
        ["Conn AA",    pkt.conn_aa],
        ["Hop incr",   pkt.hop_increment],
        ["CRC init",   pkt.crc_init],
        ["LLID",       pkt.llid],
        ["Payload",    pkt.payload_hex ? (pkt.payload_hex.match(/.{1,2}/g)||[]).join(" ") : null],
    ].filter(([, v]) => v !== null && v !== undefined);

    body.innerHTML = fields.map(([label, val]) => `
        <div class="snf-detail-field">
            <span class="snf-detail-label">${label}</span>
            <span class="snf-detail-value">${_escHtml(String(val))}</span>
        </div>
    `).join("");

    drawer.style.display = "flex";
}

/* ── Internal helpers ──────────────────────────────────────── */
function _snfUpdateCounters() {
    const p = $("snf-cnt-pkts");
    const c = $("snf-cnt-conns");
    const s = $("snf-cnt-pairs");
    if (p) p.textContent = snifferPackets.length;
    if (c) c.textContent = snifferConnections.length;
    if (s) s.textContent = snifferPairings.length;
}

function _snfUpdateControlState(state) {
    const btn    = $("snf-start-btn");
    const lbl    = $("snf-btn-label");
    const icon   = $("snf-btn-icon");
    const st     = $("sniffer-status-text");
    const badge  = $("snf-hw-badge");
    const navBdg = $("nav-sniffer-badge");
    const expBtn = $("snf-export-btn");

    snifferRunning = (state === "SCANNING" || state === "CONNECTED");

    if (btn) {
        btn.classList.toggle("btn-danger", snifferRunning);
        btn.classList.toggle("btn-primary", !snifferRunning);
    }
    if (lbl)  lbl.textContent  = snifferRunning ? "Stop Capture" : "Start Capture";
    if (icon) icon.innerHTML   = snifferRunning
        ? `<rect x="4" y="4" width="16" height="16" fill="currentColor" rx="2"/>`
        : `<polygon points="5,3 19,12 5,21" fill="currentColor"/>`;

    if (st) {
        const stateLabels = {
            SCANNING: "Scanning — monitoring advertising channels",
            CONNECTED: "Following connection — capturing data PDUs",
            IDLE: "Idle — press Start to capture",
        };
        st.textContent  = stateLabels[state] || state;
        st.style.color  = snifferRunning ? "var(--green)" : "";
    }

    if (badge) {
        badge.textContent = snifferSimulated ? "SIM" : "LIVE";
        badge.className   = "snf-badge " + (snifferRunning ? (snifferSimulated ? "snf-badge--active" : "snf-badge--live") : "");
    }
    if (navBdg) {
        navBdg.style.display  = snifferRunning ? "" : "none";
        navBdg.style.color    = "var(--green)";
    }
    if (expBtn) expBtn.disabled = !snifferRunning && snifferPackets.length === 0;
}

function _escHtml(s) {
    return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}

/* ════════════════════════════════════════════════════════════════���══════════
   AI Correlator Bar + anime.js Animation System
   ═══════════════════════════════════════════════════════════════════════════ */

function updateCorrelatorBar() {
    const s = correlatorStats || {};
    animateCounter("cb-physical", s.total_clusters || 0);
    animateCounter("cb-macs", s.total_macs_tracked || 0);
    animateCounter("cb-merges", s.merges || 0);
    animateCounter("cb-random", s.random_mac_devices || 0);
    animateCounter("cb-train", (s.model && s.model.train_samples) || 0);
}

/* Animated number counter with anime.js (falls back to direct set) */
function animateCounter(elId, targetVal) {
    const el = $(elId);
    if (!el) return;
    const curVal = parseInt(el.textContent) || 0;
    if (curVal === targetVal) return;

    if (_animeReady && typeof anime !== 'undefined' && anime.animate) {
        const obj = { v: curVal };
        try {
            anime.animate(obj, {
                v: [curVal, targetVal],
                duration: 800,
                ease: 'outExpo',
                onUpdate: () => { el.textContent = Math.round(obj.v); }
            });
        } catch(e) {
            el.textContent = targetVal;
        }
    } else {
        el.textContent = targetVal;
    }
    // Flash effect
    el.classList.remove('val-flash');
    void el.offsetWidth; // force reflow
    el.classList.add('val-flash');
}

/* Animate new device rows entering the table */
function animateNewDeviceRows() {
    if (!_animeReady || typeof anime === 'undefined' || !anime.animate) return;
    const newCount = currentClustered.length;
    if (newCount <= _prevDeviceCount) return;

    try {
        const rows = document.querySelectorAll('#dev-tbody .dev-row');
        const newRows = Array.from(rows).slice(0, newCount - _prevDeviceCount);
        if (newRows.length === 0) return;

        newRows.forEach(r => {
            r.style.opacity = '0';
            r.style.transform = 'translateY(8px)';
        });

        anime.animate(newRows, {
            opacity: [0, 1],
            translateY: ['8px', '0px'],
            delay: anime.stagger ? anime.stagger(40) : 0,
            duration: 400,
            ease: 'outExpo'
        });
    } catch(e) { /* anime.js not loaded or API mismatch */ }
}

/* Pulse the scan indicator during active scanning */
function pulseScanning() {
    const pill = $("pill-scan");
    if (!pill) return;
    pill.classList.add("scanning");
    setTimeout(() => pill.classList.remove("scanning"), 3000);
}

/* Jammer glow effect when active */
function updateJammerGlow(active) {
    const badge = $("nav-jam-badge");
    if (!badge) return;
    if (active) {
        badge.style.display = "";
        badge.classList.add("jam-active-glow");
    } else {
        badge.classList.remove("jam-active-glow");
    }
}

/* Full-spectrum mode rainbow effect on jammer card */
function applyFullSpectrumEffect(mode) {
    const jamCard = document.querySelector(".jam-status");
    if (!jamCard) return;
    if (mode === "full_spectrum") {
        jamCard.classList.add("full-spectrum-active");
    } else {
        jamCard.classList.remove("full-spectrum-active");
    }
}

/* USB Reset with animated feedback */
async function usbReset() {
    const btn = document.querySelector('.usb-reset-btn');
    if (btn) {
        btn.disabled = true;
        btn.textContent = "Resetting...";
    }
    try {
        const res = await fetch('/api/usb-reset', {method:'POST'});
        const data = await res.json();
        if (data.status === 'ok') {
            if (btn) btn.textContent = "Reset OK";
            addTimelineEvent("system", `USB Reset: scanner=${data.mapping?.scanner}, jammer1=${data.mapping?.jammer_primary}`);
        } else {
            if (btn) btn.textContent = "Error: " + (data.error || "unknown");
        }
    } catch(e) {
        if (btn) btn.textContent = "Error: " + e.message;
    }
    setTimeout(() => { if (btn) { btn.disabled = false; btn.textContent = "Reset USB"; } }, 3000);
}

/* Startup entrance animation — stagger sidebar + main content */
function playStartupAnimation() {
    if (!_animeReady || typeof anime === 'undefined' || !anime.animate) return;
    try {
        // Stagger sidebar nav items
        const navItems = document.querySelectorAll('.nav-item');
        anime.animate(navItems, {
            opacity: [0, 1],
            translateX: ['-12px', '0px'],
            delay: anime.stagger ? anime.stagger(30) : 0,
            duration: 500,
            ease: 'outExpo'
        });

        // Fade in main content
        const content = document.querySelector('.content');
        if (content) {
            anime.animate(content, {
                opacity: [0, 1],
                duration: 600,
                ease: 'outQuad'
            });
        }

        // Pulse the brand icon
        const brand = document.querySelector('.brand-icon');
        if (brand) {
            anime.animate(brand, {
                scale: [0.8, 1],
                opacity: [0, 1],
                duration: 800,
                ease: 'outElastic(1, .6)'
            });
        }

        // Animate correlator bar stats
        const cbStats = document.querySelectorAll('.cb-stat');
        if (cbStats.length) {
            anime.animate(cbStats, {
                opacity: [0, 1],
                translateY: ['6px', '0px'],
                delay: anime.stagger ? anime.stagger(60, {start: 300}) : 300,
                duration: 400,
                ease: 'outExpo'
            });
        }
    } catch(e) { /* silent */ }
}

/* Hook scan button to show scanning pulse */
(function hookScanPulse() {
    const scanBtn = $("btn-scan");
    if (scanBtn) {
        const origClick = scanBtn.onclick;
        scanBtn.addEventListener("click", () => pulseScanning());
    }
})();

/* ── Initial fetch ─────────────────────────────────────────── */
(async function init() {
    try {
        const res = await fetch("/api/status");
        const data = await res.json();
        currentDevices = data.devices || [];
        currentClustered = data.clustered_devices || [];
        clusterSummary = data.cluster_summary || {};
        trackerSuspects = data.tracker_suspects || [];
        analyticsData = data.analytics || {};
        alertRules = data.alert_rules || [];
        if (data.people) peopleData = data.people;
        if (data.safety) safetyData = data.safety;
        if (data.weather) weatherData = data.weather;
        if (data.classifications) classifications = data.classifications;
        updateAll();
        updatePlatform(data.platform || {});
        updateJammer(data.jammer || {});
        renderAlertList(data.alerts || []);
        renderAlertRules();
    } catch {}
    // Play entrance animation after initial load
    requestAnimationFrame(() => setTimeout(playStartupAnimation, 100));
})();
