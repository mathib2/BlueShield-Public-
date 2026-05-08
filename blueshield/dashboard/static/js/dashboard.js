/**
 * BLUESHIELD v7.0 — Tactical BLE Intelligence Console
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
    if (tab === "heatmap") openHeatmap();
    else if (typeof _hmStopLive === "function") _hmStopLive();
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

/* ── Clock + Operator/Session strip ─────────────────────────── */
// Generate a deterministic-feeling session ID (ties to session start)
(function generateSID(){
    const sid = (
        Math.random().toString(16).slice(2, 6) + '-' +
        Math.random().toString(16).slice(2, 6) + '-' +
        Math.random().toString(16).slice(2, 6)
    ).toUpperCase();
    try {
        const sidEl = document.getElementById('op-sid');
        if (sidEl) sidEl.textContent = sid;
    } catch(e) {}
})();

setInterval(() => {
    const d = new Date();
    const clockEl = $("clock");
    if (clockEl) clockEl.textContent = d.toTimeString().slice(0, 8);

    const up = Math.floor((Date.now() - startTime) / 1000);
    const h = Math.floor(up / 3600), m = Math.floor((up % 3600) / 60), s = up % 60;
    const sfUp = $("sf-uptime");
    if (sfUp) sfUp.textContent = `${m}:${String(s).padStart(2, "0")}`;

    // Military-style HH:MM:SS uptime in operator strip
    const opUp = document.getElementById('op-uptime');
    if (opUp) opUp.textContent =
        `${String(h).padStart(2,'0')}:${String(m).padStart(2,'0')}:${String(s).padStart(2,'0')}`;
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
    if (window._currentUser && window._currentUser.is_public) {
        alert("DEMO MODE: This account cannot shut down the Pi.");
        return;
    }
    if (confirm("GHOST MODE: This will immediately shut down the system.\nAre you sure?")) {
        if (confirm("FINAL WARNING: The Raspberry Pi will power off NOW.\nContinue?")) {
            fetch("/api/ghost", { method: "POST" });
        }
    }
}
$("btn-ghost").addEventListener("click", ghostMode);
if ($("btn-ghost-cfg")) $("btn-ghost-cfg").addEventListener("click", ghostMode);

/* ── Role-aware UI (v8.2) ──────────────────────────────────────
   Public/demo users see the full dashboard but offensive controls
   (jammer start/stop, ghost mode, USB reset, nRF sniffer) are
   hidden + disabled. Backend enforces 403 either way — this is
   pure UX so judges/audience don't accidentally hit a wall. */
async function applyRoleUI() {
    try {
        const r = await fetch("/api/auth/whoami", { credentials: "same-origin" });
        if (!r.ok) return;
        const me = await r.json();
        window._currentUser = me;
        if (!me.is_public) return;   // admin keeps full UI

        // 1. Hide top-bar ghost button
        const bg = document.getElementById("btn-ghost");
        if (bg) bg.style.display = "none";

        // 2. Hide config-tab ghost button + USB reset
        const bg2 = document.getElementById("btn-ghost-cfg");
        if (bg2) bg2.style.display = "none";
        document.querySelectorAll(".usb-reset-btn").forEach(b => b.style.display = "none");

        // 3. Disable jam-start button + show "demo mode" hint
        const bj = document.getElementById("btn-jam");
        if (bj) {
            bj.disabled = true;
            bj.textContent = "🔒 Jammer (admin only)";
            bj.style.opacity = "0.4";
            bj.style.cursor = "not-allowed";
            bj.title = "Demo accounts cannot start the jammer.";
        }

        // 4. Disable nRF sniffer toggle (active RF capture)
        const sn = document.getElementById("nrf-toggle-btn");
        if (sn) {
            sn.disabled = true;
            sn.style.opacity = "0.4";
            sn.title = "Demo accounts cannot drive the nRF sniffer.";
        }

        // 5. Replace the audit "OPERATOR" tag in the top bar with a DEMO badge
        const opEl = document.querySelector(".op-id, [data-op-id]");
        if (opEl) opEl.classList.add("demo-mode");

        // 6. Inject a small "PUBLIC DEMO" pill near the top so it's obvious
        const top = document.querySelector(".topbar, .top-bar, header");
        if (top && !document.getElementById("demo-pill")) {
            const pill = document.createElement("span");
            pill.id = "demo-pill";
            pill.textContent = "PUBLIC DEMO  ·  READ-ONLY";
            pill.style.cssText = "margin-left:12px;padding:3px 10px;border-radius:10px;background:#FFB000;color:#0a0e16;font-family:'JetBrains Mono',monospace;font-size:10px;font-weight:700;letter-spacing:1.5px";
            top.appendChild(pill);
        }
        console.log("[BlueShield] Public/demo mode active — offensive controls hidden");
    } catch (e) {
        console.warn("[BlueShield] role check failed:", e);
    }
}
applyRoleUI();

/* ── USB Reset ────────────────────────────────────────────── */
async function usbReset() {
    if (window._currentUser && window._currentUser.is_public) {
        alert("DEMO MODE: This account cannot reset the USB hub.");
        return;
    }
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
        // Skeleton rows while scanning, empty state otherwise (taste-skill: skeleton over spinner)
        if (autoScan) {
            const skel = `
                <td><span class="skel skel-circle"></span></td>
                <td><span class="skel skel-line w70"></span></td>
                <td><span class="skel skel-line w50"></span></td>
                <td><span class="skel skel-line w50"></span></td>
                <td><span class="skel skel-line w50"></span></td>
                <td><span class="skel skel-line w50"></span></td>
                <td><span class="skel skel-line w50"></span></td>
                <td><span class="skel skel-line w50"></span></td>
                <td><span class="skel skel-line w50"></span></td>
                <td><span class="skel skel-line w50"></span></td>`;
            tbody.innerHTML = `<tr class="skel-row">${skel}</tr><tr class="skel-row">${skel}</tr><tr class="skel-row">${skel}</tr>`;
        } else {
            tbody.innerHTML = '<tr class="empty-row"><td colspan="10"><div class="empty-state"><div class="empty-state-icon">' + ICO.radio + '</div><div class="empty-state-title">No devices</div><div class="empty-state-msg">Press Scan to begin BLE telemetry capture.</div></div></td></tr>';
        }
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

    // Multi-vendor BLE fingerprint sub-line.
    // Apple Continuity provides AirPods state/battery; the unified resolver
    // adds Galaxy Buds, Fast Pair, GATT-service, and vendor-specific decodes.
    const ai = d.apple_info || {};
    const rs = d.resolved || {};
    let appleSub = "";
    const bits = [];
    if (ai.model) {
        bits.push(`<strong style="color:var(--accent)">${escHtml(ai.model)}</strong>`);
    } else if (rs.model) {
        bits.push(`<strong style="color:var(--accent)">${escHtml(rs.model)}</strong>`);
    }
    if (ai.battery_left != null || ai.battery_right != null) {
        const L = ai.battery_left != null ? `${ai.battery_left}%` : "?";
        const R = ai.battery_right != null ? `${ai.battery_right}%` : "?";
        bits.push(`L:${L} R:${R}`);
    }
    if (ai.battery_case != null) bits.push(`Case:${ai.battery_case}%`);
    if (ai.airpods_state) bits.push(escHtml(ai.airpods_state));
    if (ai.user_activity) bits.push(escHtml(ai.user_activity));
    if (!ai.model && !ai.user_activity && rs.vendor) {
        bits.push(`<span style="color:var(--tx-3)">${escHtml(rs.vendor)}</span>`);
    }
    if (rs.service_match && rs.service_match.service_label && rs.confidence >= 0.7) {
        bits.push(`<span class="tag tag-ok" style="font-size:.55rem">${escHtml(rs.service_match.service_label)}</span>`);
    }
    // OUI vendor — only show if it adds new info beyond what rs.vendor already has
    if (rs.oui_info && rs.oui_info.vendor_short) {
        const ouiName = rs.oui_info.vendor_short;
        const alreadyShown = (rs.vendor || "").toLowerCase().includes(ouiName.toLowerCase());
        if (!alreadyShown) {
            const bits_count = rs.oui_info.oui_bits || 24;
            bits.push(`<span title="IEEE OUI ${bits_count}-bit: ${escHtml(rs.oui_info.vendor_full || "")}" style="color:var(--tx-3)">OUI: ${escHtml(ouiName)}</span>`);
        }
    }
    // Address-type — RPA / static-random / NRPA tells the operator whether
    // the MAC is a stable identifier or a privacy-rotated one.
    const addrType = rs.address_type;
    if (addrType && addrType !== "public") {
        const addrLabel = { rpa: "RPA", static_random: "STATIC", nrpa: "NRPA", unknown: "UNK" }[addrType] || addrType.toUpperCase();
        const addrTip = {
            rpa:           "Resolvable Private Address — rotates ~every 15 min for privacy",
            static_random: "Random Static — fixed for device lifetime, no IRK pairing",
            nrpa:          "Non-Resolvable Private Address — rotates, untraceable",
        }[addrType] || "";
        bits.push(`<span title="${escHtml(addrTip)}" class="addr-type addr-${addrType}" style="font-size:.55rem">${addrLabel}</span>`);
    }
    if (rs.confidence) {
        const conf = Math.round(rs.confidence * 100);
        const confColor = conf >= 90 ? "var(--green)" : conf >= 60 ? "var(--accent)" : "var(--tx-3)";
        bits.push(`<span title="${(rs.sources || []).join(' + ')}" style="color:${confColor};font-size:.6rem">conf ${conf}%</span>`);
    }
    if (bits.length) {
        appleSub = `<br><span class="apple-sub" style="font-size:.66rem;color:var(--tx-2);font-family:var(--font-mono)">${bits.join(" · ")}</span>`;
    }

    return `<tr class="${rowCls} ${sel} ${followCls} ${multiMacCls}" onclick="selectDevice('${id}')">
        <td>${d.category_icon || ICO.unknown}</td>
        <td><strong>${escHtml(d.best_name || "Unknown")}</strong> ${eco} ${macBadge}${appleSub}<br><span class="mono" style="font-size:.62rem;color:var(--tx-3)">${id}</span></td>
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
    const panel = $("device-detail");
    panel.classList.add("open");
    panel.classList.remove("closed");
    renderDetailPanel();
    renderDeviceTable();
};
function closeDevicePanel() {
    selectedDeviceId = null;
    const panel = $("device-detail");
    if (panel) {
        panel.classList.add("closed");
        panel.classList.remove("open");
    }
    renderDeviceTable();
}
$("close-detail").addEventListener("click", closeDevicePanel);
// Escape closes the panel
document.addEventListener("keydown", e => {
    if (e.key === "Escape" && selectedDeviceId) closeDevicePanel();
});
// Start with panel hidden until a device is selected
document.addEventListener("DOMContentLoaded", () => {
    const panel = $("device-detail");
    if (panel) panel.classList.add("closed");
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

    // BLE Fingerprint (multi-vendor resolver decode)
    const rs = d.resolved || {};
    const ai = d.apple_info || {};
    if (rs.confidence > 0 || ai.label || ai.model) {
        html += `<div class="detail-section"><div class="detail-section-title">BLE Fingerprint</div>`;
        const fpLabel = rs.label || ai.label || "?";
        const fpClass = rs.device_class || ai.device_class || "?";
        const fpConf = Math.round((rs.confidence || ai.confidence || 0) * 100);
        html += detailRow("Identified as", `<strong style="color:var(--accent)">${escHtml(fpLabel)}</strong>`);
        html += detailRow("Device class", fpClass);
        if (rs.vendor) html += detailRow("Vendor", escHtml(rs.vendor));
        if (rs.model || ai.model) html += detailRow("Model", escHtml(rs.model || ai.model));
        html += detailRow("Decode confidence", `${fpConf}%`);
        if (rs.sources && rs.sources.length) {
            html += detailRow("Sources", rs.sources.map(s => `<span class="tag" style="font-size:.55rem">${escHtml(s)}</span>`).join(" "));
        }
        if (rs.service_match) {
            html += detailRow("GATT service", `${escHtml(rs.service_match.service_label)} (UUID ${escHtml(rs.service_match.matched_uuid)})`);
            if (rs.service_match.hint) html += detailRow("Service hint", escHtml(rs.service_match.hint));
        }
        // Apple Continuity rich fields
        if (ai.airpods_state) html += detailRow("AirPods state", escHtml(ai.airpods_state));
        if (ai.battery_left != null || ai.battery_right != null || ai.battery_case != null) {
            const L = ai.battery_left != null ? `${ai.battery_left}%` : "?";
            const R = ai.battery_right != null ? `${ai.battery_right}%` : "?";
            const C = ai.battery_case != null ? `${ai.battery_case}%` : "?";
            html += detailRow("Battery", `L:${L} · R:${R} · Case:${C}`);
        }
        if (ai.charging_left || ai.charging_right || ai.charging_case) {
            const ch = [ai.charging_left && "Left", ai.charging_right && "Right", ai.charging_case && "Case"].filter(Boolean).join(", ");
            html += detailRow("Charging", ch);
        }
        if (ai.user_activity) html += detailRow("User activity", escHtml(ai.user_activity));
        if (ai.is_primary_device) html += detailRow("Primary device", "yes (this is the user's main device)");
        if (ai.airdrop_receiving) html += detailRow("AirDrop", "receiving on");
        if (ai.airpods_connected) html += detailRow("AirPods linked", "yes (this iPhone has AirPods active)");
        if (ai.wifi_on != null) html += detailRow("Wi-Fi", ai.wifi_on ? "on" : "off");
        if (ai.findmy_separated != null) html += detailRow("Find My", ai.findmy_separated ? "separated key (lost mode)" : "owner connected");
        if (ai.tlv_types && ai.tlv_types.length) {
            html += detailRow("Continuity TLVs", ai.tlv_types.map(t => `0x${t.toString(16).toUpperCase().padStart(2,'0')}`).join(", "));
        }
        // Samsung-specific
        const ss = rs.samsung_info || {};
        if (ss.is_smarttag) html += detailRow("SmartTag", "yes");
        if (ss.is_buds) html += detailRow("Galaxy Buds", "yes");
        // Microsoft-specific
        const ms = rs.microsoft_info || {};
        if (ms.is_swiftpair) html += detailRow("Swift Pair", "yes (advertising for pairing)");
        if (ms.is_cdp) html += detailRow("Cross-Device Platform", "yes");
        // Fast Pair
        const fp = rs.fastpair_info || {};
        if (fp.in_pairing_mode) html += detailRow("Fast Pair", `pairing mode${fp.model_id ? ` (id 0x${fp.model_id.toString(16).toUpperCase()})` : ""}`);
        else if (fp.model_id != null || fp.label) html += detailRow("Fast Pair", "subsequent-pair (already bonded)");
        html += `</div>`;
    }

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
    // channelData is a dict {channel_idx: count} from sniffer telemetry.
    if (!channelData || typeof channelData !== 'object') return;
    for (let i = 0; i < 40; i++) {
        if (channelData[i] !== undefined) {
            channelStats[i] = channelData[i];
        }
    }
}
// v7.7: derive ADV-channel activity from the live device count when the
// nRF sniffer isn't running. Every ADV PDU from a real device hits one of
// channels 37/38/39, so a non-zero device count means non-zero activity
// on those three. Round-robin distribution mirrors what BLE devices
// actually do (advertise on all 3 ADV channels in sequence).
function deriveChannelActivityFromDevices() {
    const devCount = (currentDevices || []).filter(d =>
        d && d.rssi != null && d.rssi > -100
    ).length;
    if (devCount === 0) return;
    // Use scan-window seen counts to produce a realistic per-window value.
    // Each device emits roughly 3-5 ADVs per scan_window across 37/38/39.
    const advPerDev = 4;
    const total = devCount * advPerDev;
    if (channelStats[37] === 0) channelStats[37] = Math.floor(total / 3);
    if (channelStats[38] === 0) channelStats[38] = Math.floor(total / 3);
    if (channelStats[39] === 0) channelStats[39] = total - channelStats[37] - channelStats[38];
}

function renderChannelGrid() {
    const el = $("ch-grid");
    if (!el) return;
    deriveChannelActivityFromDevices();
    const maxCount = Math.max(...channelStats, 1);
    // Correct BLE channel → MHz mapping (per Bluetooth Core Spec):
    //   ch 0..10  → 2404..2424 (data, before adv ch 37 at 2402)
    //   ch 11..36 → 2428..2478 (data, after adv ch 38 at 2426)
    //   ch 37 → 2402, ch 38 → 2426, ch 39 → 2480
    function freqOf(i){
        if (i === 37) return 2402;
        if (i === 38) return 2426;
        if (i === 39) return 2480;
        if (i <= 10) return 2404 + i * 2;
        return 2428 + (i - 11) * 2;
    }
    el.innerHTML = channelStats.map((cnt, i) => {
        const isAdv = (i === 37 || i === 38 || i === 39);
        const freq = freqOf(i);
        const intensity = cnt / maxCount;
        const bg = isAdv
            ? `rgba(255,176,0,${0.10 + intensity * 0.55})`
            : `rgba(88,166,255,${0.04 + intensity * 0.40})`;
        const border = isAdv
            ? `1px solid rgba(255,176,0,${0.30 + intensity * 0.40})`
            : `1px solid rgba(140,160,200,${0.10 + intensity * 0.25})`;
        const advLabel = isAdv ? '<span class="ch-adv-tag">ADV</span>' : '';
        return `<div class="ch-cell${isAdv?' is-adv':''}" style="background:${bg};border:${border}">
            <div class="ch-num">${i}${advLabel}</div>
            <div class="ch-freq">${freq} MHz</div>
            <div class="ch-count">${cnt > 0 ? cnt : '·'}</div>
        </div>`;
    }).join("");
}

/* ── Proximity Radar ───────────────────────────────────────── */
let _radarCtx = null, _radarSize = 0, _radarResizeBound = false;

function _radarSizeForViewport(canvas){
    // Use actual rendered box (set by CSS aspect-ratio + max-width).
    // Fall back to a viewport-based size if CSS hasn't laid out yet.
    const rect = canvas.getBoundingClientRect();
    if (rect.width > 50) return Math.floor(rect.width);
    const vw = window.innerWidth, vh = window.innerHeight;
    const sidebarW = vw < 1024 ? 0 : 240;
    const legendW = vw < 768 ? 0 : 180;
    return Math.max(280, Math.min(720, vw - sidebarW - legendW - 60, vh - 140));
}

function startRadar() {
    if (radarAnimFrame) return;
    const canvas = $("radar-canvas");
    if (!canvas) return;
    _resizeRadarCanvas();
    if (!_radarResizeBound) {
        window.addEventListener("resize", _resizeRadarCanvas);
        _radarResizeBound = true;
    }
    if (_radarCtx) renderRadarFrame(_radarCtx, _radarSize, _radarSize);
}

function _resizeRadarCanvas(){
    const canvas = $("radar-canvas");
    if (!canvas) return;
    const dpr = window.devicePixelRatio || 1;
    const size = _radarSizeForViewport(canvas);
    canvas.width = Math.round(size * dpr);
    canvas.height = Math.round(size * dpr);
    // Explicit style so CSS aspect-ratio can't fight us mid-resize
    canvas.style.height = size + "px";
    const ctx = canvas.getContext("2d");
    ctx.setTransform(1, 0, 0, 1, 0, 0);
    ctx.scale(dpr, dpr);
    _radarCtx = ctx;
    _radarSize = size;
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

        // Label — flip side based on which half the dot is in so labels
        // never extend off the canvas edge.
        const name = ((d.best_name || d.name || "?")).slice(0, 14);
        ctx.fillStyle = txFaint;
        ctx.font = "10px Inter, system-ui, sans-serif";
        const onRightHalf = x > cx;
        ctx.textAlign = onRightHalf ? "right" : "left";
        const labelDx = onRightHalf ? -10 : 10;
        ctx.fillText(name, x + labelDx, y + 3);

        // Category icon — place opposite side from label
        ctx.font = "12px serif";
        ctx.textAlign = onRightHalf ? "left" : "right";
        ctx.fillText(d.category_icon || "?",
                     x + (onRightHalf ? 9 : -9),
                     y + 4);
        ctx.textAlign = "left";  // restore
    });

    // Center dot (scanner)
    ctx.beginPath();
    ctx.arc(cx, cy, 5, 0, Math.PI * 2);
    ctx.fillStyle = "#58a6ff";
    ctx.fill();
    ctx.fillStyle = txFaint;
    ctx.font = "8px 'JetBrains Mono'";
    ctx.fillText("YOU", cx + 8, cy + 3);

    radarAnimFrame = requestAnimationFrame(() =>
        renderRadarFrame(_radarCtx || ctx, _radarSize || w, _radarSize || h));
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

/* ── Settings dropdown + Advanced mode (v7.7.2) ──────────────── */
// The gear icon now opens a real settings menu instead of being a hidden
// toggle that did nothing visible. Menu items: theme toggle, advanced
// mode, jump to config, sign out.

function _smSetTagOnOff(id, on){
    const tag = $(id);
    if (!tag) return;
    tag.textContent = on ? "ON" : "OFF";
    const item = tag.closest(".sm-item");
    if (item) item.classList.toggle("is-on", on);
}

function _smSetThemeTag(){
    const t = document.documentElement.getAttribute("data-theme") || "dark";
    const tag = $("sm-theme-tag");
    if (tag) tag.textContent = t.toUpperCase();
}

function updateAdvancedModeBtn(){
    _smSetTagOnOff("sm-adv-tag", advancedMode);
}

function _closeSettingsMenu(){
    const menu = $("settings-menu");
    const btn = $("btn-advanced");
    if (!menu || !btn) return;
    menu.classList.remove("open");
    menu.setAttribute("aria-hidden","true");
    btn.setAttribute("aria-expanded","false");
}

function _toggleSettingsMenu(e){
    e?.stopPropagation();
    const menu = $("settings-menu");
    const btn = $("btn-advanced");
    if (!menu || !btn) return;
    const open = !menu.classList.contains("open");
    menu.classList.toggle("open", open);
    menu.setAttribute("aria-hidden", open ? "false" : "true");
    btn.setAttribute("aria-expanded", open ? "true" : "false");
    if (open){
        // sync operator info from the topbar strip
        const opUser = $("op-user")?.textContent || "admin";
        const opSid  = $("op-sid")?.textContent  || "----";
        if ($("sm-name")) $("sm-name").textContent = opUser;
        if ($("sm-sid"))  $("sm-sid").textContent  = opSid;
        _smSetThemeTag();
        updateAdvancedModeBtn();
    }
}

if ($("btn-advanced")){
    $("btn-advanced").addEventListener("click", _toggleSettingsMenu);
}
document.addEventListener("click", e => {
    const wrap = e.target.closest(".settings-wrap");
    if (!wrap) _closeSettingsMenu();
});
document.addEventListener("keydown", e => {
    if (e.key === "Escape") _closeSettingsMenu();
});

// Menu actions
if ($("sm-toggle-theme")){
    $("sm-toggle-theme").addEventListener("click", () => {
        $("btn-theme")?.click();
        setTimeout(_smSetThemeTag, 30);
    });
}
if ($("sm-toggle-advanced")){
    $("sm-toggle-advanced").addEventListener("click", async () => {
        advancedMode = !advancedMode;
        updateAdvancedModeBtn();
        try {
            await fetch("/api/advanced-mode",{
                method:"POST",
                headers:{"Content-Type":"application/json"},
                body:JSON.stringify({enabled: advancedMode}),
            });
        } catch {}
    });
}
if ($("sm-open-config")){
    $("sm-open-config").addEventListener("click", () => {
        _closeSettingsMenu();
        if (typeof switchTab === "function") switchTab("config");
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

/* 3-tier jammer control: Target × Action × Intensity → raw mode */
const J_TARGET_PATTERNS = {
    apple:     { vendor: "0x004C", tlv: "0x07 (Proximity Pairing)", note: "Apple Continuity protocol" },
    samsung:   { vendor: "0x0075", tlv: "EIR manufacturer data",    note: "Samsung Fast Pair / Galaxy" },
    google:    { vendor: "0x00E0", tlv: "Fast Pair Model ID",       note: "Google Fast Pair" },
    microsoft: { vendor: "0x0006", tlv: "Swift Pair beacon",        note: "Microsoft Swift Pair" },
    generic:   { vendor: "any",    tlv: "any",                      note: "All BLE advertisers" },
    custom:    { vendor: "user",   tlv: "user",                     note: "Custom byte pattern" },
};

function mapTargetActionToMode(target, action, intensity) {
    // Defense-grade routing: 3-tier UI → raw backend mode
    if (action === "track_only") return "ble_scan";
    if (action === "force_disconnect") {
        // Single-ButteRFly sniff → hijack_slave → LL_TERMINATE_IND (v7.7).
        // No cross-dongle sync, no power-rail conflict.
        return "hijack_terminator";
    }
    if (action === "spoof_nearby") {
        if (target === "apple") return "apple_spam";
        return "ble_adv_flood";
    }
    // Default: disrupt_discovery via reactive PHY jam
    if (target === "apple") {
        return intensity === "aggressive" ? "nearby_attack" : "airpods_attack";
    }
    if (target === "generic") return "ble_reactive_jam";
    // Samsung/Google/Microsoft fall back to generic reactive jam for now
    // (different patterns will be matched by the backend in a future update)
    return "ble_reactive_jam";
}

function updateJammerIntent() {
    const target = $("j-target-profile")?.value || "apple";
    const action = $("j-action")?.value || "disrupt_discovery";
    const intensity = $("j-intensity")?.value || "standard";
    const mode = mapTargetActionToMode(target, action, intensity);
    // Reflect selected raw mode in the advanced dropdown (keeps expert visibility)
    const modeSel = $("j-mode");
    if (modeSel && Array.from(modeSel.options).some(o => o.value === mode)) {
        modeSel.value = mode;
        modeSel.dispatchEvent(new Event("change"));
    }
    // Update hint copy with selected intent
    const hintEl = $("j-capability-hint");
    if (hintEl) {
        const tp = J_TARGET_PATTERNS[target] || J_TARGET_PATTERNS.generic;
        let actionDesc = "";
        if (action === "track_only") actionDesc = "Passive sniff only — no RF transmitted.";
        else if (action === "force_disconnect") actionDesc = "Single-ButteRFly: sniff CONNECT_IND → hijack_slave → LL_TERMINATE_IND. Forces disconnect on matching MAC.";
        else if (action === "spoof_nearby") actionDesc = "Rogue advertiser broadcasting crafted payload (may fail on firmware without AdvMode).";
        else actionDesc = `Reactive PHY jam on vendor ${tp.vendor} — corrupts advertisements in <150μs (Cayre DSN 2021).`;
        hintEl.textContent = `${tp.note} · ${actionDesc}`;
        hintEl.className = "jam-capability-hint cap-ok";
        hintEl.style.display = "";
    }
}

// Wire the new 3-tier controls
["j-target-profile", "j-action", "j-intensity"].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.addEventListener("change", updateJammerIntent);
});
// Initialize on load
setTimeout(updateJammerIntent, 200);

// Per-mode rich documentation. Only verified-working modes here.
const J_MODE_DOCS = {
    hijack_terminator: {
        title: "Hijack-Terminate",
        what: "Sniffs advertising channels for a CONNECT_IND matching the target MAC. As soon as it sees one, the same dongle switches to Hijacker mode, takes over the slave role, and sends LL_TERMINATE_IND.",
        effect: "Target device sees a clean disconnect (LL reason 0x13). Pairing teardown follows. Apple devices show the BLE companion dropping; phones may show 'Connection Lost'.",
        works_on: "Any BLE peripheral establishing a fresh connection in range.",
        does_not_work_on: "Established connections that started before BlueShield armed (we don't see the CONNECT_IND).",
        target_field: "Optional. Empty / 'ANY' = wildcard mode (kills every new connection seen).",
        cite: "Cayre et al. InjectaBLE — IEEE/IFIP DSN 2021, §IV.C.",
    },
    hijack_terminator_desync: {
        title: "Hijack-Desync",
        what: "Same hijack chain as above, but instead of TERMINATE_IND we send LL_CONNECTION_UPDATE_IND with `instant=1` (already in the past), interval 7.5 ms, supervision-timeout 100 ms.",
        effect: "Master applies the broken update and can never find the slave on the new schedule. Connection times out within ~6 seconds.",
        works_on: "Implementations that ignore TERMINATE from non-master peers but accept CONNECTION_UPDATE.",
        does_not_work_on: "Same caveat as hijack_terminator — needs a fresh CONNECT_IND.",
        target_field: "Optional. Empty = wildcard.",
        cite: "Cayre InjectaBLE §IV.C 'Master role hijack'.",
    },
    airpods_attack: {
        title: "AirPods reactive PHY-jam",
        what: "ButteRFly firmware reactive-jam armed on the byte pattern 0x4C 0x00 0x07 (Apple TLV 0x07 — AirPods Proximity Pairing).",
        effect: "Every matching ADV PDU on the chosen channel gets corrupted within ~150 µs of the preamble — before the scanner finishes CRC. AirPods discovery / handoff broadcasts effectively disappear.",
        works_on: "Disrupting AirPods PAIRING / handoff / 'AirPods nearby' iOS popup.",
        does_not_work_on: "Audio that's already streaming (A2DP is BR/EDR, not BLE — different radio).",
        target_field: "Not used.",
        cite: "Cayre DSN 2021 §III.B (Reactive Jamming).",
    },
    nearby_attack: {
        title: "Apple Continuity reactive jam",
        what: "Reactive jam armed on Apple vendor ID 0x4C 0x00. Catches ALL Apple TLVs (AirDrop, Handoff, Nearby Info, Find My, AirPods).",
        effect: "Apple ecosystem coordination collapses on the chosen channel. Devices stop seeing each other for handoff/AirDrop until you stop the jam.",
        works_on: "All Apple Continuity discovery.",
        does_not_work_on: "Established BLE/BR-EDR sessions.",
        target_field: "Not used.",
        cite: "Martin PoPETs 2019; Stute USENIX Security 2021.",
    },
    ble_reactive_jam: {
        title: "Generic reactive PHY-jam",
        what: "Pattern-triggered PHY jam — ButteRFly fires a corrupting burst when the configured byte sequence is seen on-air.",
        effect: "Selectively corrupts any ADV PDU containing the chosen pattern. Use airpods_attack/nearby_attack for built-in patterns.",
        works_on: "Any vendor with a stable advertising signature.",
        does_not_work_on: "Encrypted or rotating-signature advertisers.",
        target_field: "Not used.",
        cite: "Cayre DSN 2021.",
    },
    ble_raw_inject: {
        title: "Raw ADV PDU inject @ 500 Hz",
        what: "Hand-crafted BTLE_ADV_NONCONN_IND PDUs injected on the chosen channel via WHAD's raw_inject path.",
        effect: "Floods the channel with chosen content (default: spoofed Apple Nearby Info). Disrupts discovery; can also be used for RPA collision attacks.",
        works_on: "Any scanner trying to enumerate devices.",
        does_not_work_on: "Connection-mode traffic (data channels, hopping).",
        target_field: "Optional MAC for spoofed AdvA.",
        cite: "WHAD raw_inject API.",
    },
    ble_adv_flood: {
        title: "Rogue advertiser flood",
        what: "Tries Peripheral.enable_adv_mode first; ButteRFly v1.1.3 firmware rejects this, so we auto-fall-back to ble_raw_inject with the same payload — same on-air effect.",
        effect: "20 ms interval on ch 37/38/39 (≈150 ADVs/sec across channels). Disrupts discovery loops and nearby-accessory popups.",
        works_on: "Discovery / pairing flows.",
        does_not_work_on: "Established sessions.",
        target_field: "Not used.",
        cite: "—",
    },
    apple_spam: {
        title: "Apple AirPods popup spam",
        what: "Same fallback flow as ble_adv_flood, payload = spoofed AirPods Proximity Pairing frame.",
        effect: "Triggers 'AirPods nearby' popup storm on nearby iOS devices.",
        works_on: "Nearby iOS / macOS.",
        does_not_work_on: "Android, established BR/EDR.",
        target_field: "Not used.",
        cite: "Martin PoPETs 2019.",
    },
    ble_inject_terminate: {
        title: "Manual LL_TERMINATE_IND",
        what: "Inject a single LL_TERMINATE_IND into a BLE connection whose Access Address you already know. For experts who captured the AA via Sniffer first.",
        effect: "Forces immediate disconnect on that specific connection.",
        works_on: "A known-AA connection.",
        does_not_work_on: "Anything where you haven't already captured the AA. For automated discovery+kill use hijack_terminator instead.",
        target_field: "Required — paste 8-hex AA in the target field (e.g. 7D326B01).",
        cite: "Cayre DSN 2021.",
    },
};

function _renderModeDoc(mode){
    const el = document.getElementById("j-mode-doc");
    if (!el) return;
    const d = J_MODE_DOCS[mode];
    if (!d){ el.style.display="none"; el.innerHTML=""; return; }
    el.style.display="block";
    el.innerHTML = `
        <div class="jmd-title">${d.title}</div>
        <div class="jmd-row"><span class="jmd-key">What it does</span><span class="jmd-val">${d.what}</span></div>
        <div class="jmd-row"><span class="jmd-key">Expected effect</span><span class="jmd-val">${d.effect}</span></div>
        <div class="jmd-row"><span class="jmd-key">Works against</span><span class="jmd-val">${d.works_on}</span></div>
        <div class="jmd-row"><span class="jmd-key">Won't work against</span><span class="jmd-val">${d.does_not_work_on}</span></div>
        <div class="jmd-row"><span class="jmd-key">Target field</span><span class="jmd-val">${d.target_field}</span></div>
        <div class="jmd-cite">${d.cite}</div>`;
}

$("j-mode").addEventListener("change", e => {
    const mode = e.target.value;
    const needsTarget = ["hijack_terminator", "hijack_terminator_desync",
                         "ble_inject_terminate", "ble_raw_inject"].includes(mode);
    const targetGrp = $("j-target-grp");
    if (targetGrp) targetGrp.style.display = needsTarget ? "" : "none";

    // Capability hint (compact, top-of-card) — keep concise.
    const hintEl = $("j-capability-hint");
    if (hintEl) {
        const d = J_MODE_DOCS[mode];
        if (d){
            hintEl.textContent = `${d.title} — ${d.effect}`;
            hintEl.className = "jam-capability-hint cap-ok";
            hintEl.style.display = "";
        } else {
            hintEl.style.display = "none";
        }
    }
    _renderModeDoc(mode);
});
// Trigger once on load
setTimeout(() => $("j-mode").dispatchEvent(new Event("change")), 300);

$("btn-jam").addEventListener("click", async () => {
    if (window._currentUser && window._currentUser.is_public) {
        alert("DEMO MODE: This account cannot operate the jammer.");
        return;
    }
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
    // Show the REAL active backend name (not the default hcitool label)
    let activeBackend = status.backend || "--";
    if (status.butterfly_active) activeBackend = "butterfly";
    else if (status.nrf_active) activeBackend = "nrf_radio";
    $("jl-be").textContent = activeBackend;
    $("nav-jam-badge").style.display = jammerActive ? "" : "none";
    $("pill-scan").classList.toggle("jamming", jammerActive);
    updateJammerGlow(jammerActive);
    applyFullSpectrumEffect(sess.mode || "");

    // ── Honest capability display — delegate to j-mode change handler ──
    // Trigger the proper hint logic (defined in the j-mode change listener)
    // which has per-mode tactical descriptions. Don't overwrite here.
    // (Do nothing; the change handler keeps the hint current.)

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
                    <div style="font-size:.62rem;color:var(--tx-3);margin-top:2px">Hardware — ${nrf.running ? "Scanning" : "Idle"}</div>
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
let snifferPackets    = [];     // all raw packet dicts (no cap — only Stop or Clear empties this)
let snifferFiltered   = [];     // after type + search filter
let snifferConnections = [];
let snifferPairings   = [];
let _snfPendingCrackleSession = null;

const SNF_MAX_LOG = 500;        // rows rendered in table at once

/* ── Socket.IO — sniffer events ────────────────────────────── */
socket.on("sniffer_packet", pkt => {
    snifferPackets.push(pkt);
    // No cap — packet log keeps growing until the operator hits Stop or Clear.
    // The DOM table is bounded separately by SNF_MAX_LOG (last N rendered).
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
    if (session.crackable) {
        _snfPendingCrackleSession = session;
        const card = $("snf-crackle-card");
        if (card) card.style.display = "";
    }
});

socket.on("sniffer_state", data => {
    const state = data.state || "IDLE";
    snifferRunning = (state === "SCANNING" || state === "CONNECTED");
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
    const btn = $("snf-start-btn");
    const lbl = $("snf-btn-label");
    if (btn) btn.disabled = true;            // optimistic: lock the button so double-clicks don't queue
    const wasRunning = snifferRunning;
    if (lbl) lbl.textContent = wasRunning ? "Stopping…" : "Starting…";
    try {
        if (wasRunning) {
            const res = await fetch("/api/sniffer/stop", { method: "POST" });
            if (res.ok) {
                // Trust the API response — don't wait on the socket event,
                // it might be delayed or dropped. Update UI immediately.
                _snfUpdateControlState("IDLE");
            } else {
                if (lbl) lbl.textContent = "Stop Capture";
                console.warn("[sniffer] stop returned", res.status);
            }
        } else {
            const mac    = ($("snf-target-mac")?.value || "").trim() || null;
            const rssi   = parseInt($("snf-rssi-min")?.value || "-100");
            const coded  = $("snf-phy")?.value === "coded";
            const res = await fetch("/api/sniffer/start", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ target_mac: mac, rssi_min: rssi, coded_phy: coded }),
            });
            if (res.ok) {
                _snfUpdateControlState("SCANNING");
            } else {
                if (lbl) lbl.textContent = "Start Capture";
            }
        }
    } catch (err) {
        console.error("[sniffer] toggle failed:", err);
        if (lbl) lbl.textContent = wasRunning ? "Stop Capture" : "Start Capture";
    } finally {
        if (btn) btn.disabled = false;
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
        badge.textContent = "LIVE";
        badge.className   = "snf-badge " + (snifferRunning ? "snf-badge--live" : "");
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
    const physical = s.total_clusters || 0;
    const macs = s.total_macs_tracked || 0;
    const merges = s.merges || 0;
    const random = s.random_mac_devices || 0;
    const train = (s.model && s.model.train_samples) || 0;
    animateCounter("cb-physical", physical);
    animateCounter("cb-macs", macs);
    animateCounter("cb-merges", merges);
    animateCounter("cb-random", random);
    animateCounter("cb-train", train);
    // Awaiting state: toggle desaturated styling when no telemetry has arrived yet
    const bar = $("correlator-bar");
    if (bar) {
        const awaiting = (physical + macs + merges + random + train) === 0;
        bar.classList.toggle("awaiting", awaiting);
    }
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

/* ─── v7.5 Evidence Integrity UI ─────────────────────────────── */
async function loadIntegrityStatus() {
    try {
        const r = await fetch("/api/integrity/status");
        const d = await r.json();
        const sEl = document.getElementById("int-status");
        const fpEl = document.getElementById("int-fp");
        const chEl = document.getElementById("int-chain");
        if (!sEl) return;
        if (!d.available) {
            sEl.textContent = "UNAVAILABLE";
            sEl.style.color = "var(--red)";
            return;
        }
        sEl.textContent = "OPERATIONAL";
        sEl.style.color = "var(--green)";
        fpEl.textContent = d.signer_fingerprint || "--";
        if (d.chain) {
            chEl.textContent = d.chain.valid
                ? `VALID · ${d.chain.entries} entries`
                : `TAMPERED · first bad line ${d.chain.first_bad_line}`;
            chEl.style.color = d.chain.valid ? "var(--green)" : "var(--red)";
        }
    } catch (e) {
        const sEl = document.getElementById("int-status");
        if (sEl) { sEl.textContent = "ERROR"; sEl.style.color = "var(--red)"; }
    }
}
// Auto-load on first config tab view + verify button
document.addEventListener("DOMContentLoaded", () => {
    loadIntegrityStatus();
    const btn = document.getElementById("btn-verify-chain");
    if (btn) btn.addEventListener("click", async () => {
        btn.textContent = "VERIFYING…";
        btn.disabled = true;
        await loadIntegrityStatus();
        btn.textContent = "VERIFY CHAIN";
        btn.disabled = false;
    });
});

/* ════════════════════════════════════════════════════════════════════════════
   BLE-Map heatmap v2 — patrick-wied/heatmap.js + perceptual colormaps
   + floor-plan overlay + realtime locator + coverage stats.
   Adapted technique from jantman/python-wifi-survey-heatmap (RBF + cmap +
   floor-plan + contours) — re-implemented client-side using heatmap.js for
   the smooth radial-blur rendering layer.
   ════════════════════════════════════════════════════════════════════════════ */

let _hmGrid = null;        // { rows, cols, label, cell_size_m, samples, device_index, walls, rooms }
let _hmSelectedFp = "";    // currently picked device fingerprint id
let _hmHoverCell = null;   // [r, c]
let _hmFocusCell = null;   // [r, c] — most recently sampled cell, opens detail
let _hmCanvas = null;      // overlay canvas (grid lines + cell labels + locator)
let _hmCtx = null;
let _hmDpr = 1;
let _hmHeat = null;        // heatmap.js instance
let _hmHeatContainer = null;
let _hmFloorplanDataUrl = null;     // localStorage-backed image data URL
let _hmShowGrid = true;
let _hmShowContours = false;
let _hmShowLocator = false;
let _hmShowFloorplan = true;
let _hmShowWalls = true;
let _hmShowPins = true;
let _hmCmap = "rdylgn";
let _hmLastWidth = 0;

// Mode + editor state
let _hmMode = "survey";     // "survey" | "live" | "edit"
let _hmEditTool = "wall";   // "wall" | "room" | "erase" | "clear-walls" | "clear-rooms"
let _hmDragStart = null;    // [colFrac, rowFrac] — first corner during a drag
let _hmDragEnd = null;      // current cursor pos during drag

// Live radar state
let _hmLivePins = [];        // [{fingerprint_id, best_name, category, cell:{row,col}, live_rssi, confidence, age_sec, ...}]
let _hmLiveTimer = null;     // setInterval handle
let _hmLiveFrame = null;     // RAF handle for pulsing animation
let _hmModeNotes = {
    survey: "// WALK · TAP · MAP — record signal at each cell",
    live:   "// LIVE RADAR — device pins update every scan",
    edit:   "// DRAW WALLS + ROOMS — drag to add, click to erase",
};

/* ── Perceptual color palettes (heatmap.js gradient stops) ─────────────────────
   Turbo / Viridis / Inferno are the modern matplotlib-style perceptually
   uniform maps. RdYlGn is the classic WiFi-survey green=good red=bad. Heat
   is iOS-style. BLE Amber is the dashboard's signature accent. */
const _HM_GRADIENTS = {
    turbo:   { 0.00: "#30123b", 0.25: "#4145ab", 0.45: "#3ac3a0", 0.60: "#a4fc3c", 0.75: "#fed83d", 0.90: "#fa6e1e", 1.00: "#7a0402" },
    viridis: { 0.00: "#440154", 0.25: "#3b528b", 0.50: "#21918c", 0.75: "#5ec962", 1.00: "#fde725" },
    inferno: { 0.00: "#000004", 0.25: "#420a68", 0.50: "#932667", 0.75: "#dd513a", 0.90: "#fbb61a", 1.00: "#fcffa4" },
    rdylgn:  { 0.00: "#a50026", 0.20: "#d73027", 0.40: "#f46d43", 0.55: "#fdae61", 0.70: "#fee08b", 0.82: "#a6d96a", 0.92: "#66bd63", 1.00: "#1a9850" },
    heat:    { 0.00: "#000000", 0.25: "#7a0000", 0.55: "#ff4400", 0.80: "#ffaa00", 1.00: "#ffffff" },
    ble:     { 0.00: "rgba(255,176,0,0.05)", 0.40: "rgba(255,176,0,0.5)", 0.70: "rgba(255,200,80,0.85)", 1.00: "#FFE9B0" },
};
const _HM_LABELS = {
    turbo: "Turbo", viridis: "Viridis", inferno: "Inferno",
    rdylgn: "RdYlGn (WiFi)", heat: "Heat", ble: "BLE Amber",
};

async function openHeatmap() {
    _hmCanvas = document.getElementById("hm-canvas");
    if (!_hmCanvas) return;
    _hmCtx = _hmCanvas.getContext("2d");
    _hmDpr = Math.max(1, window.devicePixelRatio || 1);
    _hmHeatContainer = document.getElementById("hm-heat");

    if (!_hmCanvas._wired) {
        _hmCanvas.addEventListener("click", _hmOnCanvasClick);
        _hmCanvas.addEventListener("mousemove", _hmOnCanvasMove);
        _hmCanvas.addEventListener("mouseleave", () => { _hmHoverCell = null; _hmDrawOverlay(); });
        _hmCanvas.addEventListener("touchend", _hmOnCanvasTouch, { passive: false });

        document.getElementById("hm-grid-config").addEventListener("click", _hmOpenConfigModal);
        document.getElementById("hm-clear-all").addEventListener("click", _hmClearAll);
        document.getElementById("hm-cell-clear").addEventListener("click", _hmClearFocusCell);
        document.getElementById("hm-cfg-cancel").addEventListener("click", () => document.getElementById("hm-grid-modal").classList.remove("open"));
        document.getElementById("hm-cfg-save").addEventListener("click", _hmSaveConfig);
        document.getElementById("hm-device-picker").addEventListener("change", e => {
            _hmSelectedFp = e.target.value;
            _hmRender();
            _hmUpdateInfoBar();
            _hmUpdateLocator();
        });
        document.getElementById("hm-cmap-picker").addEventListener("change", e => {
            _hmCmap = e.target.value;
            document.getElementById("hm-cmap-name").textContent = _HM_LABELS[_hmCmap] || _hmCmap;
            _hmRender();
            _hmDrawLegend();
            try { localStorage.setItem("hm-cmap", _hmCmap); } catch(_){}
        });
        document.getElementById("hm-toggle-grid").addEventListener("change", e => { _hmShowGrid = e.target.checked; _hmDrawOverlay(); });
        document.getElementById("hm-toggle-contours").addEventListener("change", e => { _hmShowContours = e.target.checked; _hmDrawOverlay(); });
        document.getElementById("hm-toggle-locator").addEventListener("change", e => {
            _hmShowLocator = e.target.checked;
            document.getElementById("hm-locator-panel").style.display = _hmShowLocator ? "" : "none";
            _hmUpdateLocator();
            _hmDrawOverlay();
        });
        document.getElementById("hm-toggle-floorplan").addEventListener("change", e => {
            _hmShowFloorplan = e.target.checked;
            document.getElementById("hm-floorplan").style.opacity = _hmShowFloorplan ? "1" : "0";
        });
        document.getElementById("hm-floorplan-upload").addEventListener("click", () => document.getElementById("hm-floorplan-file").click());
        document.getElementById("hm-floorplan-file").addEventListener("change", _hmOnFloorPlanPicked);
        document.getElementById("hm-toggle-walls").addEventListener("change", e => { _hmShowWalls = e.target.checked; _hmDrawOverlay(); });
        document.getElementById("hm-toggle-pins").addEventListener("change", e => { _hmShowPins = e.target.checked; _hmDrawOverlay(); });

        // Mode-switcher buttons
        document.querySelectorAll(".hm-mode-btn").forEach(btn => {
            btn.addEventListener("click", () => _hmSwitchMode(btn.dataset.mode));
        });
        // Edit-tool buttons
        document.querySelectorAll(".hm-edit-btn").forEach(btn => {
            btn.addEventListener("click", () => _hmPickEditTool(btn.dataset.tool));
        });
        // Mouse events for the edit-mode drag-to-draw
        _hmCanvas.addEventListener("mousedown", _hmOnEditDown);
        window.addEventListener("mousemove", _hmOnEditMove);
        window.addEventListener("mouseup",   _hmOnEditUp);
        _hmCanvas.addEventListener("touchstart", _hmOnEditDown, { passive: false });
        window.addEventListener("touchmove",  _hmOnEditMove,  { passive: false });
        window.addEventListener("touchend",   _hmOnEditUp);

        window.addEventListener("resize", _hmResize);
        _hmCanvas._wired = true;

        // Restore prefs
        try {
            const cm = localStorage.getItem("hm-cmap");
            if (cm && _HM_GRADIENTS[cm]) {
                _hmCmap = cm;
                document.getElementById("hm-cmap-picker").value = cm;
                document.getElementById("hm-cmap-name").textContent = _HM_LABELS[cm];
            }
            const fp = localStorage.getItem("hm-floorplan");
            if (fp) {
                _hmFloorplanDataUrl = fp;
                document.getElementById("hm-floorplan").src = fp;
                document.getElementById("hm-floorplan").hidden = false;
            }
        } catch(_) {}
    }

    await _hmRefresh();
    _hmDrawLegend();
    _hmResize();
}

function _hmOnFloorPlanPicked(e) {
    const file = e.target.files && e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = ev => {
        _hmFloorplanDataUrl = ev.target.result;
        const img = document.getElementById("hm-floorplan");
        img.src = _hmFloorplanDataUrl;
        img.hidden = false;
        try { localStorage.setItem("hm-floorplan", _hmFloorplanDataUrl); } catch(_){}
        document.getElementById("hm-toggle-floorplan").checked = true;
        _hmShowFloorplan = true;
    };
    reader.readAsDataURL(file);
}

async function _hmRefresh() {
    try {
        const res = await fetch("/api/heatmap");
        if (!res.ok) return;
        _hmGrid = await res.json();
        _hmRebuildPicker();
        // _hmResize() sizes the canvas + heat container, THEN renders. Doing
        // render-first here would catch a 0-height container before layout
        // settles (heatmap.js can't be created against a 0-sized container).
        _hmResize();
        _hmUpdateInfoBar();
        _hmUpdateLocator();
        _hmRefreshFocusCellPanel();
    } catch (e) {
        console.error("[heatmap] refresh failed", e);
    }
}

function _hmRebuildPicker() {
    const sel = document.getElementById("hm-device-picker");
    if (!sel || !_hmGrid) return;
    const idx = JSON.parse(JSON.stringify(_hmGrid.device_index || {}));
    const known = new Set(Object.keys(idx));
    const live = currentClustered || [];
    live.forEach(d => {
        if (d.fingerprint_id && !known.has(d.fingerprint_id)) {
            idx[d.fingerprint_id] = {
                best_name: d.best_name || "Unknown",
                category: d.category || "unknown",
                sample_count: 0,
            };
        }
    });
    const entries = Object.entries(idx).sort((a, b) => {
        if (b[1].sample_count !== a[1].sample_count) return b[1].sample_count - a[1].sample_count;
        return (a[1].best_name || "").localeCompare(b[1].best_name || "");
    });
    const prevValue = sel.value;
    sel.innerHTML = '<option value="">Pick a device…</option>' + entries.map(([fp, meta]) => {
        const label = `${meta.best_name || "Unknown"} (${meta.category || "?"}, ${meta.sample_count} cells)`;
        return `<option value="${escHtml(fp)}">${escHtml(label)}</option>`;
    }).join("");
    if (prevValue && entries.find(e => e[0] === prevValue)) sel.value = prevValue;
}

function _hmUpdateInfoBar() {
    if (!_hmGrid) return;
    document.getElementById("hm-pill-grid").textContent = `${_hmGrid.rows} × ${_hmGrid.cols}`;
    const sampledCells = Object.keys(_hmGrid.samples || {}).length;
    const totalCells = _hmGrid.rows * _hmGrid.cols;
    document.getElementById("hm-pill-cells").textContent = `${sampledCells} / ${totalCells} cells sampled`;
    document.getElementById("hm-pill-devices").textContent = `${Object.keys(_hmGrid.device_index || {}).length} devices in survey`;
    const sel = document.getElementById("hm-device-picker");
    const selectedText = sel.options[sel.selectedIndex]?.text || "No device selected";
    document.getElementById("hm-pill-selected").textContent = selectedText.length > 60 ? selectedText.slice(0, 57) + "…" : selectedText;
}

function _hmResize() {
    if (!_hmCanvas || !_hmGrid) return;
    requestAnimationFrame(() => {
        const cssW = _hmCanvas.clientWidth || _hmCanvas.parentElement?.clientWidth || 600;
        if (cssW < 32) return;
        const aspect = _hmGrid.cols / _hmGrid.rows;
        const maxH = Math.max(280, window.innerHeight - 230);
        let cssH = Math.min(cssW / aspect, maxH);
        if (cssH < 240 && cssW > 600) cssH = 240;
        _hmCanvas.style.height = cssH + "px";
        _hmCanvas.width  = Math.max(64, Math.round(cssW * _hmDpr));
        _hmCanvas.height = Math.max(64, Math.round(cssH * _hmDpr));
        // Frame the heatmap.js container to match
        if (_hmHeatContainer) {
            _hmHeatContainer.style.height = cssH + "px";
        }
        _hmLastWidth = cssW;
        _hmRender();
    });
}

function _hmCellRect(r, c) {
    const cw = _hmCanvas.width / _hmGrid.cols;
    const ch = _hmCanvas.height / _hmGrid.rows;
    return { x: c * cw, y: r * ch, w: cw, h: ch };
}

function _hmCellAt(clientX, clientY) {
    const rect = _hmCanvas.getBoundingClientRect();
    const xCss = clientX - rect.left;
    const yCss = clientY - rect.top;
    const c = Math.floor((xCss / rect.width) * _hmGrid.cols);
    const r = Math.floor((yCss / rect.height) * _hmGrid.rows);
    if (r < 0 || c < 0 || r >= _hmGrid.rows || c >= _hmGrid.cols) return null;
    return [r, c];
}

function _hmCellRssi(row, col, fp) {
    if (!fp) return null;
    const cell = (_hmGrid.samples || {})[`${row},${col}`];
    if (!cell || !cell.length) return null;
    let best = null;
    for (const s of cell) {
        if (s.fingerprint_id !== fp) continue;
        if (!best || s.timestamp > best.timestamp) best = s;
    }
    return best ? best.rssi : null;
}

/* ── Heatmap.js render (the smooth radial-blur magic) ─────────────────────────
   We feed each sampled cell as a heat point with value normalised to 0-1 from
   the RSSI range -100..-30. heatmap.js draws a radial gradient template per
   point and runs them through a 256-color palette. The result is a smooth
   surface like an Ekahau/NetSpot WiFi survey. */
function _hmEnsureHeatInstance() {
    // Heat container is position:absolute;inset:0. Its clientHeight reads 0
    // before the offsetParent's layout has settled, so fall back to the grid
    // canvas's CSS height (always set by _hmResize()).
    let cssW = _hmHeatContainer.clientWidth;
    let cssH = _hmHeatContainer.clientHeight;
    if ((!cssW || !cssH) && _hmCanvas) {
        cssW = _hmCanvas.clientWidth || cssW;
        cssH = _hmCanvas.clientHeight || cssH;
    }
    if (!cssW || !cssH) return null;
    // Force the heat container's dimensions so the heatmap.js injected canvas
    // matches even when the offsetParent's content height is still 0.
    _hmHeatContainer.style.width = cssW + "px";
    _hmHeatContainer.style.height = cssH + "px";
    if (_hmHeat && _hmHeat._w === cssW && _hmHeat._h === cssH && _hmHeat._cmap === _hmCmap) return _hmHeat;
    // Wipe + recreate (heatmap.js doesn't support live gradient swap, container
    // resize, or absolute-positioned containers without explicit dims).
    _hmHeatContainer.innerHTML = "";
    if (typeof h337 === "undefined") {
        console.warn("[heatmap] h337 (heatmap.js) not loaded; skipping render");
        return null;
    }
    // Inject our own canvas so we control its dimensions — this is heatmap.js's
    // documented "bring your own canvas" path. Without this, h337 reads
    // getComputedStyle(container).width which returns "0" or "auto" for
    // position:absolute containers and silently no-ops the canvas creation.
    const canvas = document.createElement("canvas");
    canvas.width  = cssW;
    canvas.height = cssH;
    canvas.style.cssText = "position:absolute;inset:0;width:100%;height:100%;pointer-events:none";
    _hmHeatContainer.appendChild(canvas);

    const cellW = cssW / Math.max(1, _hmGrid.cols);
    const cellH = cssH / Math.max(1, _hmGrid.rows);
    // Each heat point covers ~3 cells in each direction. With heavy blur, this
    // means adjacent samples blend into a smooth interpolated surface — no
    // more checkerboard of separated blobs.
    const radius = Math.max(60, Math.round(Math.max(cellW, cellH) * 2.4));
    _hmHeat = h337.create({
        container: _hmHeatContainer,
        canvas,
        width: cssW,
        height: cssH,
        radius,
        maxOpacity: 0.78,
        minOpacity: 0.04,
        blur: 0.99,
        gradient: _HM_GRADIENTS[_hmCmap],
    });
    _hmHeat._w = cssW;
    _hmHeat._h = cssH;
    _hmHeat._cmap = _hmCmap;
    return _hmHeat;
}

function _hmRender() {
    if (!_hmCtx || !_hmGrid) return;
    const heat = _hmEnsureHeatInstance();
    const fp = _hmSelectedFp;

    // Build heatmap.js dataset from sampled cells
    let coverage = { good: 0, mid: 0, bad: 0, total: 0 };
    // Same fallback as in _hmEnsureHeatInstance — the heat container is
    // absolute-positioned and may read 0 height before layout settles.
    let cssW = _hmHeatContainer ? _hmHeatContainer.clientWidth : 0;
    let cssH = _hmHeatContainer ? _hmHeatContainer.clientHeight : 0;
    if ((!cssW || !cssH) && _hmCanvas) {
        cssW = _hmCanvas.clientWidth || cssW;
        cssH = _hmCanvas.clientHeight || cssH;
    }
    if (heat && cssW && cssH) {
        const cw = cssW / _hmGrid.cols;
        const ch = cssH / _hmGrid.rows;
        const points = [];
        if (fp) {
            for (let r = 0; r < _hmGrid.rows; r++) {
                for (let c = 0; c < _hmGrid.cols; c++) {
                    const rssi = _hmCellRssi(r, c, fp);
                    if (rssi == null) continue;
                    // Normalise -100..-30 to 0..1
                    const v = Math.max(0, Math.min(1, (rssi + 100) / 70));
                    points.push({
                        x: Math.round(c * cw + cw / 2),
                        y: Math.round(r * ch + ch / 2),
                        value: v,
                    });
                    coverage.total++;
                    if (rssi >= -65) coverage.good++;
                    else if (rssi >= -80) coverage.mid++;
                    else coverage.bad++;
                }
            }
        }
        heat.setData({ max: 1, min: 0, data: points });
    }

    _hmDrawOverlay();
    _hmUpdateCoverageStats(coverage);
}

function _hmUpdateCoverageStats(cov) {
    const elGood = document.getElementById("hm-cov-good");
    const elMid  = document.getElementById("hm-cov-mid");
    const elBad  = document.getElementById("hm-cov-bad");
    const totalCells = _hmGrid ? _hmGrid.rows * _hmGrid.cols : 0;
    if (!elGood) return;
    const t = cov.total || 1;
    const pctGood = Math.round((cov.good / t) * 100);
    const pctMid  = Math.round((cov.mid  / t) * 100);
    const pctBad  = Math.round((cov.bad  / t) * 100);
    elGood.textContent = cov.total ? `${pctGood}% (${cov.good})` : "—";
    elMid.textContent  = cov.total ? `${pctMid}% (${cov.mid})`  : "—";
    elBad.textContent  = cov.total ? `${pctBad}% (${cov.bad})`  : "—";
    document.getElementById("hm-cov-bar-good").style.width = (cov.total ? pctGood : 0) + "%";
    document.getElementById("hm-cov-bar-mid").style.width  = (cov.total ? pctMid  : 0) + "%";
    document.getElementById("hm-cov-bar-bad").style.width  = (cov.total ? pctBad  : 0) + "%";
    const covPill = document.getElementById("hm-pill-cov");
    if (cov.total) {
        covPill.textContent = `coverage: ${pctGood}% strong / ${pctMid}% ok / ${pctBad}% weak (${cov.total}/${totalCells} cells)`;
    } else {
        covPill.textContent = "— coverage";
    }
}

/* ── Overlay canvas: grid lines, cell labels, contour lines, locator pulse ──── */
function _hmDrawOverlay() {
    if (!_hmCtx || !_hmGrid) return;
    const ctx = _hmCtx;
    const w = _hmCanvas.width, h = _hmCanvas.height;
    ctx.clearRect(0, 0, w, h);

    // Render order (bottom → top):
    //   rooms → grid → contours → walls → sample points → live pins → locator → hover/focus → drag preview
    if (_hmShowWalls) _hmDrawRooms(ctx, w, h);
    if (_hmShowGrid && _hmMode !== "live") _hmDrawGrid(ctx, w, h);
    if (_hmShowContours && _hmSelectedFp && _hmMode !== "live") _hmDrawContours(ctx, w, h);
    if (_hmShowWalls) _hmDrawWalls(ctx, w, h);
    if (_hmMode === "survey" || _hmMode === "edit") _hmDrawSamplePoints(ctx, w, h);
    if (_hmMode === "live" && _hmShowPins) _hmDrawLivePins(ctx, w, h);
    if (_hmShowLocator && _hmSelectedFp && _hmMode !== "live") _hmDrawLocator(ctx, w, h);
    if (_hmMode === "edit" && _hmDragStart && _hmDragEnd) _hmDrawDragPreview(ctx, w, h);
    _hmDrawHoverFocus(ctx);
}

function _hmDrawGrid(ctx, w, h) {
    const cw = w / _hmGrid.cols;
    const ch = h / _hmGrid.rows;
    ctx.strokeStyle = "rgba(255,255,255,0.10)";
    ctx.lineWidth = 1;
    for (let c = 0; c <= _hmGrid.cols; c++) {
        ctx.beginPath();
        ctx.moveTo(c * cw, 0); ctx.lineTo(c * cw, h);
        ctx.stroke();
    }
    for (let r = 0; r <= _hmGrid.rows; r++) {
        ctx.beginPath();
        ctx.moveTo(0, r * ch); ctx.lineTo(w, r * ch);
        ctx.stroke();
    }
    // Cell coordinate label in corner
    ctx.fillStyle = "rgba(255,255,255,0.32)";
    ctx.font = `${Math.round(10 * _hmDpr)}px JetBrains Mono, monospace`;
    ctx.textAlign = "left"; ctx.textBaseline = "top";
    for (let r = 0; r < _hmGrid.rows; r++) {
        for (let c = 0; c < _hmGrid.cols; c++) {
            ctx.fillText(`${r},${c}`, c * cw + 4 * _hmDpr, r * ch + 4 * _hmDpr);
        }
    }
}

function _hmDrawSamplePoints(ctx, w, h) {
    const cw = w / _hmGrid.cols;
    const ch = h / _hmGrid.rows;
    const samples = _hmGrid.samples || {};
    for (const key of Object.keys(samples)) {
        const [r, c] = key.split(",").map(Number);
        const cx = c * cw + cw / 2;
        const cy = r * ch + ch / 2;
        ctx.beginPath();
        ctx.arc(cx, cy, Math.max(3, 4 * _hmDpr), 0, 2 * Math.PI);
        ctx.fillStyle = _hmSelectedFp && _hmCellRssi(r, c, _hmSelectedFp) == null
            ? "rgba(255,255,255,0.35)"      // sampled cell but device not seen here
            : "rgba(255,255,255,0.85)";
        ctx.fill();
        ctx.strokeStyle = "rgba(0,0,0,0.4)";
        ctx.lineWidth = 1.5;
        ctx.stroke();
    }
}

function _hmDrawContours(ctx, w, h) {
    // Three coverage bands — pull cells whose RSSI falls into each band and
    // outline them. This is the JS equivalent of jantman's matplotlib contour.
    const fp = _hmSelectedFp;
    const cw = w / _hmGrid.cols;
    const ch = h / _hmGrid.rows;
    const bands = [
        { thresh: -65, color: "rgba(46,204,113,0.85)", label: "≥-65" },
        { thresh: -80, color: "rgba(243,156,18,0.85)", label: "-65..-80" },
    ];
    for (const band of bands) {
        ctx.strokeStyle = band.color;
        ctx.lineWidth = 2 * _hmDpr;
        ctx.setLineDash([6 * _hmDpr, 4 * _hmDpr]);
        for (let r = 0; r < _hmGrid.rows; r++) {
            for (let c = 0; c < _hmGrid.cols; c++) {
                const rssi = _hmCellRssi(r, c, fp);
                if (rssi == null) continue;
                if (rssi >= band.thresh) {
                    // Outline the cell to mark band membership
                    ctx.strokeRect(c * cw + 2, r * ch + 2, cw - 4, ch - 4);
                }
            }
        }
        ctx.setLineDash([]);
    }
}

function _hmDrawLocator(ctx, w, h) {
    // Realtime locator: pulse the cell whose stored RSSI for the picked device
    // is closest to the live RSSI we're reading right now. Approximates "where
    // the device is sitting in the room" given the survey.
    const cell = _hmLocatorCell;
    if (!cell) return;
    const cw = w / _hmGrid.cols;
    const ch = h / _hmGrid.rows;
    const cx = cell[1] * cw + cw / 2;
    const cy = cell[0] * ch + ch / 2;
    const t = (Date.now() / 600) % 1;       // 0..1
    const r1 = Math.max(cw, ch) * 0.35;
    const r2 = r1 + (Math.max(cw, ch) * 0.35) * t;
    ctx.beginPath();
    ctx.arc(cx, cy, r2, 0, 2 * Math.PI);
    ctx.strokeStyle = `rgba(255,176,0,${1 - t})`;
    ctx.lineWidth = 3 * _hmDpr;
    ctx.stroke();
    ctx.beginPath();
    ctx.arc(cx, cy, r1, 0, 2 * Math.PI);
    ctx.fillStyle = "rgba(255,176,0,0.85)";
    ctx.fill();
    ctx.strokeStyle = "rgba(0,0,0,0.5)";
    ctx.lineWidth = 1.5;
    ctx.stroke();
}

function _hmDrawHoverFocus(ctx) {
    if (_hmHoverCell) {
        const [r, c] = _hmHoverCell;
        const rect = _hmCellRect(r, c);
        ctx.strokeStyle = "rgba(255,176,0,0.85)";
        ctx.lineWidth = 2 * _hmDpr;
        ctx.strokeRect(rect.x + 1, rect.y + 1, rect.w - 2, rect.h - 2);
    }
    if (_hmFocusCell) {
        const [r, c] = _hmFocusCell;
        const rect = _hmCellRect(r, c);
        ctx.strokeStyle = "rgba(255,176,0,1)";
        ctx.lineWidth = 3 * _hmDpr;
        ctx.strokeRect(rect.x + 1.5, rect.y + 1.5, rect.w - 3, rect.h - 3);
    }
}

/* ── Realtime locator: estimate device's likely current cell ──────────────────
   For the picked device, find the cell whose stored RSSI is closest to its
   current avg RSSI in the live scan. That's the room location whose
   propagation environment best matches what the receiver is hearing now. */
let _hmLocatorCell = null;
let _hmLocatorRaf = null;

function _hmUpdateLocator() {
    const body = document.getElementById("hm-locator-body");
    if (!body) return;
    if (!_hmShowLocator || !_hmSelectedFp) {
        _hmLocatorCell = null;
        if (_hmLocatorRaf) { cancelAnimationFrame(_hmLocatorRaf); _hmLocatorRaf = null; }
        body.textContent = _hmShowLocator ? "Pick a device above to locate it." : "Toggle locator on to enable.";
        return;
    }
    const live = (currentClustered || []).find(d => d.fingerprint_id === _hmSelectedFp);
    if (!live) {
        _hmLocatorCell = null;
        body.innerHTML = `<em>${escHtml(_HM_LABELS[_hmCmap] || "")} </em>This device is not currently visible — locator idle.`;
        return;
    }
    const liveRssi = Math.round(live.avg_rssi || -100);
    let best = null, bestDiff = Infinity;
    for (let r = 0; r < _hmGrid.rows; r++) {
        for (let c = 0; c < _hmGrid.cols; c++) {
            const rssi = _hmCellRssi(r, c, _hmSelectedFp);
            if (rssi == null) continue;
            const diff = Math.abs(rssi - liveRssi);
            if (diff < bestDiff) { bestDiff = diff; best = { r, c, rssi }; }
        }
    }
    _hmLocatorCell = best ? [best.r, best.c] : null;
    if (best) {
        const conf = Math.max(0, Math.min(100, Math.round(100 - bestDiff * 8)));
        body.innerHTML = `Live RSSI: <b>${liveRssi} dBm</b><br>Best match cell: <b>(${best.r}, ${best.c})</b> at <b>${best.rssi} dBm</b><br>Match confidence: <b>${conf}%</b>`;
    } else {
        body.textContent = "No matching survey cell yet — sample more first.";
    }
    if (!_hmLocatorRaf) {
        const tick = () => { _hmDrawOverlay(); _hmLocatorRaf = requestAnimationFrame(tick); };
        _hmLocatorRaf = requestAnimationFrame(tick);
    }
}

/* ── Legend canvas ────────────────────────────────────────────────────────────*/
function _hmDrawLegend() {
    const c = document.getElementById("hm-legend-canvas");
    if (!c) return;
    const ctx = c.getContext("2d");
    const grad = ctx.createLinearGradient(0, 0, c.width, 0);
    const stops = _HM_GRADIENTS[_hmCmap] || _HM_GRADIENTS.rdylgn;
    for (const k of Object.keys(stops)) grad.addColorStop(parseFloat(k), stops[k]);
    ctx.fillStyle = grad;
    ctx.fillRect(0, 0, c.width, c.height);
}

/* ── Interactions ─────────────────────────────────────────────────────────────*/
function _hmOnCanvasMove(e) {
    const cell = _hmCellAt(e.clientX, e.clientY);
    if (!cell) { _hmHoverCell = null; _hmDrawOverlay(); return; }
    if (!_hmHoverCell || _hmHoverCell[0] !== cell[0] || _hmHoverCell[1] !== cell[1]) {
        _hmHoverCell = cell;
        _hmDrawOverlay();
    }
}

async function _hmOnCanvasClick(e) {
    // Sampling only happens in Survey mode — Edit and Live have their own handlers.
    if (_hmMode !== "survey") return;
    const cell = _hmCellAt(e.clientX, e.clientY);
    if (!cell) return;
    await _hmSampleCell(cell[0], cell[1]);
    _hmFocusCell = cell;
    await _hmRefresh();
}

async function _hmOnCanvasTouch(e) {
    if (_hmMode !== "survey") return;
    e.preventDefault();
    const t = e.changedTouches && e.changedTouches[0];
    if (!t) return;
    const cell = _hmCellAt(t.clientX, t.clientY);
    if (!cell) return;
    await _hmSampleCell(cell[0], cell[1]);
    _hmFocusCell = cell;
    await _hmRefresh();
}

async function _hmSampleCell(row, col) {
    try {
        const res = await fetch("/api/heatmap/sample", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({ row, col }),
        });
        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            console.warn("[heatmap] sample failed:", err);
            return;
        }
    } catch (e) {
        console.error("[heatmap] sample error:", e);
    }
}

function _hmRefreshFocusCellPanel() {
    const panel = document.getElementById("hm-cell-detail");
    if (!panel) return;
    if (!_hmFocusCell) { panel.style.display = "none"; return; }
    const [r, c] = _hmFocusCell;
    const samples = (_hmGrid.samples || {})[`${r},${c}`] || [];
    if (samples.length === 0) { panel.style.display = "none"; return; }

    document.getElementById("hm-cell-detail-head").textContent = `Cell (${r},${c}) — ${samples.length} sample${samples.length === 1 ? "" : "s"}`;
    const byFp = {};
    samples.forEach(s => {
        if (!byFp[s.fingerprint_id] || s.timestamp > byFp[s.fingerprint_id].timestamp) byFp[s.fingerprint_id] = s;
    });
    const rows = Object.values(byFp).sort((a, b) => b.rssi - a.rssi);
    const body = rows.map(s => {
        const norm = Math.max(0, Math.min(1, (s.rssi + 100) / 70));
        const stops = _HM_GRADIENTS[_hmCmap] || _HM_GRADIENTS.rdylgn;
        // Pick nearest stop for chip background
        let chosen = "#888";
        let best = 99;
        for (const k of Object.keys(stops)) {
            const d = Math.abs(parseFloat(k) - norm);
            if (d < best) { best = d; chosen = stops[k]; }
        }
        const swatch = `<span class="hm-rssi-chip" style="background:${chosen}">${Math.round(s.rssi)}</span>`;
        const cat = s.category ? `<span class="tag" style="font-size:.55rem">${escHtml(s.category)}</span>` : "";
        return `<div class="hm-cell-row" onclick="document.getElementById('hm-device-picker').value='${escHtml(s.fingerprint_id)}';document.getElementById('hm-device-picker').dispatchEvent(new Event('change'))">${swatch}<span class="hm-cell-name">${escHtml(s.best_name || "Unknown")}</span>${cat}</div>`;
    }).join("");
    document.getElementById("hm-cell-detail-body").innerHTML = body || '<div style="color:var(--tx-3);font-size:.75rem">No samples</div>';
    panel.style.display = "";
}

async function _hmClearFocusCell() {
    if (!_hmFocusCell) return;
    const [r, c] = _hmFocusCell;
    if (!confirm(`Clear all samples in cell (${r},${c})?`)) return;
    await fetch(`/api/heatmap/cell/${r}/${c}`, { method: "DELETE" });
    _hmFocusCell = null;
    await _hmRefresh();
}

async function _hmClearAll() {
    if (!confirm("Wipe ALL heatmap samples? Grid dimensions will be kept.")) return;
    await fetch("/api/heatmap/clear", { method: "POST" });
    _hmFocusCell = null;
    await _hmRefresh();
}

function _hmOpenConfigModal() {
    document.getElementById("hm-cfg-rows").value = _hmGrid.rows;
    document.getElementById("hm-cfg-cols").value = _hmGrid.cols;
    document.getElementById("hm-cfg-cellsize").value = _hmGrid.cell_size_m || 1.0;
    document.getElementById("hm-cfg-label").value = _hmGrid.label || "Room";
    document.getElementById("hm-grid-modal").classList.add("open");
}

async function _hmSaveConfig() {
    const rows = parseInt(document.getElementById("hm-cfg-rows").value, 10);
    const cols = parseInt(document.getElementById("hm-cfg-cols").value, 10);
    const cell_size_m = parseFloat(document.getElementById("hm-cfg-cellsize").value) || 1.0;
    const label = document.getElementById("hm-cfg-label").value || "Room";
    if (!Number.isFinite(rows) || !Number.isFinite(cols) || rows < 1 || cols < 1 || rows > 50 || cols > 50) {
        alert("Rows and cols must be 1–50.");
        return;
    }
    await fetch("/api/heatmap/grid", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({ rows, cols, cell_size_m, label }),
    });
    document.getElementById("hm-grid-modal").classList.remove("open");
    _hmFocusCell = null;
    _hmHeat = null;   // force recreate so radius matches new cell size
    await _hmRefresh();
    _hmResize();
}

/* ════════════════════════════════════════════════════════════════════════════
   Mode switcher — Survey / Live Radar / Edit
   ════════════════════════════════════════════════════════════════════════════ */
function _hmSwitchMode(mode) {
    if (!["survey", "live", "edit"].includes(mode)) return;
    _hmMode = mode;
    document.querySelectorAll(".hm-mode-btn").forEach(b => b.classList.toggle("active", b.dataset.mode === mode));
    document.getElementById("hm-edit-tools").hidden = mode !== "edit";
    document.getElementById("hm-live-status").hidden = mode !== "live";
    document.getElementById("hm-pins-panel").style.display = mode === "live" ? "" : "none";
    const note = document.getElementById("hm-mode-note");
    if (note) note.textContent = _hmModeNotes[mode] || "";
    // Cursor hints per mode
    if (_hmCanvas) {
        _hmCanvas.style.cursor = mode === "edit" ? "crosshair" : (mode === "live" ? "default" : "crosshair");
    }
    // Live radar lifecycle
    if (mode === "live") {
        _hmStartLive();
    } else {
        _hmStopLive();
    }
    _hmDrawOverlay();
}

function _hmPickEditTool(tool) {
    if (tool === "clear-walls") {
        if (!confirm("Wipe all walls?")) return;
        _hmGrid.walls = [];
        _hmPersistGeometry();
        _hmDrawOverlay();
        return;
    }
    if (tool === "clear-rooms") {
        if (!confirm("Wipe all rooms?")) return;
        _hmGrid.rooms = [];
        _hmPersistGeometry();
        _hmDrawOverlay();
        return;
    }
    _hmEditTool = tool;
    document.querySelectorAll(".hm-edit-btn").forEach(b => {
        if (b.dataset.tool === "clear-walls" || b.dataset.tool === "clear-rooms") return;
        b.classList.toggle("active", b.dataset.tool === tool);
    });
}

async function _hmPersistGeometry() {
    try {
        await fetch("/api/heatmap/geometry", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ walls: _hmGrid.walls || [], rooms: _hmGrid.rooms || [] }),
        });
    } catch (e) {
        console.error("[heatmap] persist geometry failed", e);
    }
}

/* ── Edit-mode drag handlers ─────────────────────────────────────────────────
   In Edit mode, the operator drags on the canvas to draw a wall (line) or
   room (rectangle). Coordinates are stored in cell-fractions so the geometry
   survives grid resizes proportionally. */
function _hmCellFraction(clientX, clientY) {
    if (!_hmCanvas || !_hmGrid) return null;
    const rect = _hmCanvas.getBoundingClientRect();
    const x = (clientX - rect.left) / rect.width  * _hmGrid.cols;
    const y = (clientY - rect.top)  / rect.height * _hmGrid.rows;
    return [x, y];
}

function _hmOnEditDown(e) {
    if (_hmMode !== "edit") return;
    e.preventDefault?.();
    const t = e.touches ? e.touches[0] : e;
    const pt = _hmCellFraction(t.clientX, t.clientY);
    if (!pt) return;

    if (_hmEditTool === "erase") {
        _hmEraseAt(pt[0], pt[1]);
        return;
    }
    _hmDragStart = pt;
    _hmDragEnd = pt;
    _hmDrawOverlay();
}

function _hmOnEditMove(e) {
    if (_hmMode !== "edit" || !_hmDragStart) return;
    const t = e.touches ? e.touches[0] : e;
    if (!t) return;
    const pt = _hmCellFraction(t.clientX, t.clientY);
    if (!pt) return;
    _hmDragEnd = pt;
    _hmDrawOverlay();
}

async function _hmOnEditUp(e) {
    if (_hmMode !== "edit" || !_hmDragStart) return;
    const t = (e.changedTouches && e.changedTouches[0]) || e;
    const end = _hmCellFraction(t.clientX, t.clientY) || _hmDragEnd || _hmDragStart;
    const [x1, y1] = _hmDragStart;
    const [x2, y2] = end;
    _hmDragStart = null;
    _hmDragEnd = null;
    const dist = Math.hypot(x2 - x1, y2 - y1);
    if (dist < 0.15) {                    // ignore taps that produced no drag
        _hmDrawOverlay();
        return;
    }
    if (_hmEditTool === "wall") {
        _hmGrid.walls = _hmGrid.walls || [];
        _hmGrid.walls.push({
            id: "w" + Date.now(),
            x1, y1, x2, y2,
        });
    } else if (_hmEditTool === "room") {
        const x = Math.min(x1, x2), y = Math.min(y1, y2);
        const w = Math.abs(x2 - x1), h = Math.abs(y2 - y1);
        if (w < 0.5 || h < 0.5) { _hmDrawOverlay(); return; }   // ignore tiny rooms
        const label = prompt("Room label?", "Room") || "";
        _hmGrid.rooms = _hmGrid.rooms || [];
        _hmGrid.rooms.push({
            id: "r" + Date.now(),
            x, y, w, h, label,
        });
    }
    _hmDrawOverlay();
    _hmPersistGeometry();
}

function _hmEraseAt(x, y) {
    // Erase: remove the wall whose midpoint is closest, OR the room whose
    // rectangle contains the click. Prefer rooms (they're bigger targets).
    let removedSomething = false;
    if (_hmGrid.rooms && _hmGrid.rooms.length) {
        for (let i = _hmGrid.rooms.length - 1; i >= 0; i--) {
            const r = _hmGrid.rooms[i];
            if (x >= r.x && x <= r.x + r.w && y >= r.y && y <= r.y + r.h) {
                _hmGrid.rooms.splice(i, 1);
                removedSomething = true;
                break;
            }
        }
    }
    if (!removedSomething && _hmGrid.walls && _hmGrid.walls.length) {
        // Distance from point to wall segment
        let bestIdx = -1, bestDist = Infinity;
        for (let i = 0; i < _hmGrid.walls.length; i++) {
            const w = _hmGrid.walls[i];
            const d = _segDist(x, y, w.x1, w.y1, w.x2, w.y2);
            if (d < bestDist) { bestDist = d; bestIdx = i; }
        }
        if (bestIdx >= 0 && bestDist < 0.4) {
            _hmGrid.walls.splice(bestIdx, 1);
            removedSomething = true;
        }
    }
    if (removedSomething) {
        _hmDrawOverlay();
        _hmPersistGeometry();
    }
}

function _segDist(px, py, x1, y1, x2, y2) {
    const dx = x2 - x1, dy = y2 - y1;
    const len2 = dx * dx + dy * dy;
    if (len2 < 1e-6) return Math.hypot(px - x1, py - y1);
    let t = ((px - x1) * dx + (py - y1) * dy) / len2;
    t = Math.max(0, Math.min(1, t));
    return Math.hypot(px - (x1 + t * dx), py - (y1 + t * dy));
}

/* ════════════════════════════════════════════════════════════════════════════
   Live radar — pulsing pins per visible device, refreshed each scan
   ════════════════════════════════════════════════════════════════════════════ */
function _hmStartLive() {
    _hmStopLive();
    _hmFetchLivePins();
    _hmLiveTimer = setInterval(_hmFetchLivePins, 3500);
    if (!_hmLiveFrame) {
        const tick = () => { if (_hmMode === "live") _hmDrawOverlay(); _hmLiveFrame = requestAnimationFrame(tick); };
        _hmLiveFrame = requestAnimationFrame(tick);
    }
}

function _hmStopLive() {
    if (_hmLiveTimer) { clearInterval(_hmLiveTimer); _hmLiveTimer = null; }
    if (_hmLiveFrame) { cancelAnimationFrame(_hmLiveFrame); _hmLiveFrame = null; }
}

async function _hmFetchLivePins() {
    try {
        const res = await fetch("/api/heatmap/live");
        if (!res.ok) return;
        const data = await res.json();
        _hmLivePins = (data.pins || []).filter(p => p && p.cell);   // need a survey-cell match to plot
        const placeable = _hmLivePins.length;
        const total = (data.pins || []).length;
        document.getElementById("hm-live-text").textContent =
            `Live radar — ${placeable} placed / ${total - placeable} unplaced (no survey)`;
        _hmRenderPinsList(data.pins || []);
        _hmDrawOverlay();
    } catch (e) {
        console.error("[heatmap] live fetch failed", e);
    }
}

function _hmRenderPinsList(pins) {
    const el = document.getElementById("hm-pins-list");
    if (!el) return;
    if (!pins.length) {
        el.innerHTML = '<div style="color:var(--tx-3);font-size:.74rem">No devices visible.</div>';
        return;
    }
    const sorted = pins.slice().sort((a, b) => (b.confidence || 0) - (a.confidence || 0));
    el.innerHTML = sorted.slice(0, 20).map(p => {
        const dot = `<span class="hm-pin-dot hm-pin-cat-${escHtml(p.category || "unknown")}"></span>`;
        const cellTxt = p.cell ? `(${p.cell.row},${p.cell.col}) ${p.confidence}%` : "no survey";
        const knownTag = p.is_known ? '<span class="tag tag-ok" style="font-size:.55rem">trusted</span>' : "";
        const trackerTag = p.is_tracker ? '<span class="tag tag-bad" style="font-size:.55rem">tracker</span>' : "";
        return `<div class="hm-pin-row" onclick="(()=>{const s=document.getElementById('hm-device-picker');s.value='${escHtml(p.fingerprint_id)}';s.dispatchEvent(new Event('change'));})()">
            ${dot}<span class="hm-pin-name">${escHtml(p.best_name || "Unknown")}</span>
            <span class="hm-pin-meta">${escHtml(p.live_rssi)} dBm · ${escHtml(cellTxt)}</span>
            ${knownTag}${trackerTag}
        </div>`;
    }).join("");
}

function _hmCategoryColor(cat) {
    // Mapped to dashboard's existing eco-badge / category palette so the radar
    // pin color matches the icon you see in the Devices tab. Includes the
    // Apple-Continuity buckets ("apple") and a few extras that appear in the
    // resolver output (audio, hid_*, smart_*, fmd_tag, etc.).
    const map = {
        phone:    "#58A6FF",  tablet:   "#58A6FF",
        computer: "#A78BFA",  laptop:   "#A78BFA",
        apple:    "#FF6B6B",  // Apple ecosystem (red — distinct from tracker)
        watch:    "#FF7B00",  smartwatch: "#FF7B00",
        audio:    "#FFB000",  earbuds:  "#FFB000",  smart_speaker: "#FFB000",
        input:    "#3FB950",  hid_input: "#3FB950", hid_keyboard:  "#3FB950",
        hid_mouse:"#3FB950",  hid_apple:"#3FB950",  hid_logitech:  "#3FB950",
        tracker:  "#F85149",  tracker_tag: "#F85149", airtag: "#F85149", smarttag: "#F85149",
        medical:  "#26C6DA",  cgm: "#26C6DA",       hearing_aid: "#26C6DA", insulin_pump: "#26C6DA",
        iot:      "#8B00FF",  smart_light: "#8B00FF", smart_lock: "#8B00FF",
        fitness:  "#22D3A5",  fitness_tracker: "#22D3A5", heart_rate_strap: "#22D3A5",
        camera:   "#FF9F43",  proximity: "#A1A1AA",
        gaming:   "#D29922",  controller: "#D29922",
        tv:       "#5C6BC0",  smart_tv: "#5C6BC0",   streaming_device: "#5C6BC0",
        vehicle:  "#E91E63",  car: "#E91E63",
        generic:  "#888",     unknown: "#999",
    };
    return map[cat] || map.unknown;
}

/* ── Walls / rooms render (cell-fraction → backing pixels) ──────────────────*/
function _hmFracToPx(fx, fy, w, h) {
    return [
        (fx / _hmGrid.cols) * w,
        (fy / _hmGrid.rows) * h,
    ];
}

function _hmDrawRooms(ctx, w, h) {
    const rooms = _hmGrid.rooms || [];
    for (const r of rooms) {
        const [x, y] = _hmFracToPx(r.x, r.y, w, h);
        const [x2, y2] = _hmFracToPx(r.x + r.w, r.y + r.h, w, h);
        const rw = x2 - x, rh = y2 - y;
        ctx.save();
        // Subtle filled rect with a thin tinted border
        ctx.fillStyle = "rgba(255,176,0,0.05)";
        ctx.fillRect(x, y, rw, rh);
        ctx.strokeStyle = "rgba(255,176,0,0.55)";
        ctx.setLineDash([8 * _hmDpr, 6 * _hmDpr]);
        ctx.lineWidth = 1.5 * _hmDpr;
        ctx.strokeRect(x + 1, y + 1, rw - 2, rh - 2);
        ctx.setLineDash([]);
        // Label
        if (r.label) {
            ctx.fillStyle = "rgba(255,176,0,0.92)";
            ctx.font = `bold ${Math.round(11 * _hmDpr)}px JetBrains Mono, monospace`;
            ctx.textAlign = "left";
            ctx.textBaseline = "top";
            const padX = 6 * _hmDpr, padY = 4 * _hmDpr;
            const text = r.label.toUpperCase();
            const m = ctx.measureText(text);
            ctx.fillStyle = "rgba(10,14,22,0.85)";
            ctx.fillRect(x + 4, y + 4, m.width + padX * 2, 16 * _hmDpr);
            ctx.fillStyle = "rgba(255,176,0,0.92)";
            ctx.fillText(text, x + 4 + padX, y + 4 + padY);
        }
        ctx.restore();
    }
}

function _hmDrawWalls(ctx, w, h) {
    const walls = _hmGrid.walls || [];
    if (!walls.length) return;
    ctx.save();
    ctx.lineCap = "round";
    ctx.shadowColor = "rgba(255,255,255,0.18)";
    ctx.shadowBlur = 4 * _hmDpr;
    for (const wall of walls) {
        const [x1, y1] = _hmFracToPx(wall.x1, wall.y1, w, h);
        const [x2, y2] = _hmFracToPx(wall.x2, wall.y2, w, h);
        ctx.strokeStyle = "rgba(255,255,255,0.92)";
        ctx.lineWidth = 4 * _hmDpr;
        ctx.beginPath();
        ctx.moveTo(x1, y1);
        ctx.lineTo(x2, y2);
        ctx.stroke();
        ctx.strokeStyle = "rgba(0,0,0,0.45)";
        ctx.lineWidth = 1.2 * _hmDpr;
        ctx.shadowBlur = 0;
        ctx.beginPath();
        ctx.moveTo(x1, y1);
        ctx.lineTo(x2, y2);
        ctx.stroke();
        ctx.shadowColor = "rgba(255,255,255,0.18)";
        ctx.shadowBlur = 4 * _hmDpr;
    }
    ctx.restore();
}

function _hmDrawDragPreview(ctx, w, h) {
    if (!_hmDragStart || !_hmDragEnd) return;
    const [x1, y1] = _hmFracToPx(_hmDragStart[0], _hmDragStart[1], w, h);
    const [x2, y2] = _hmFracToPx(_hmDragEnd[0],   _hmDragEnd[1],   w, h);
    ctx.save();
    if (_hmEditTool === "wall") {
        ctx.strokeStyle = "rgba(255,176,0,0.95)";
        ctx.lineWidth = 4 * _hmDpr;
        ctx.lineCap = "round";
        ctx.beginPath();
        ctx.moveTo(x1, y1);
        ctx.lineTo(x2, y2);
        ctx.stroke();
    } else if (_hmEditTool === "room") {
        const x = Math.min(x1, x2), y = Math.min(y1, y2);
        const rw = Math.abs(x2 - x1), rh = Math.abs(y2 - y1);
        ctx.strokeStyle = "rgba(255,176,0,0.95)";
        ctx.fillStyle = "rgba(255,176,0,0.10)";
        ctx.lineWidth = 2 * _hmDpr;
        ctx.setLineDash([6 * _hmDpr, 4 * _hmDpr]);
        ctx.fillRect(x, y, rw, rh);
        ctx.strokeRect(x, y, rw, rh);
        ctx.setLineDash([]);
    }
    ctx.restore();
}

/* ── Live radar pins — pulsing dots at survey-derived positions ─────────────*/
function _hmDrawLivePins(ctx, w, h) {
    if (!_hmLivePins.length) return;
    const cw = w / _hmGrid.cols;
    const ch = h / _hmGrid.rows;
    const t = (Date.now() / 600) % 1;

    // --- Group pins by cell so we can fan them out instead of stacking ---
    const cellGroups = new Map();
    for (const pin of _hmLivePins) {
        if (!pin.cell) continue;
        const key = `${pin.cell.row},${pin.cell.col}`;
        if (!cellGroups.has(key)) cellGroups.set(key, []);
        cellGroups.get(key).push(pin);
    }

    // Pin sizing — bigger and more readable than before.
    // Use cell minimum so pins remain proportional but never tiny.
    const cellMin = Math.min(cw, ch);
    const baseR = Math.max(9 * _hmDpr, cellMin * 0.13);
    const ringMaxAdd = Math.max(cw, ch) * 0.42;

    for (const [, group] of cellGroups) {
        const cellCx = group[0].cell.col * cw + cw / 2;
        const cellCy = group[0].cell.row * ch + ch / 2;
        // Fan-out radius for stacked pins. Stays inside cell bounds.
        const fanR = group.length > 1
            ? Math.min(cellMin * 0.30, baseR * 1.6 + group.length * 1.5)
            : 0;

        group.forEach((pin, i) => {
            // Distribute around the cell center on a circle.
            let cx, cy;
            if (group.length === 1) {
                cx = cellCx;
                cy = cellCy;
            } else {
                const angle = (i / group.length) * Math.PI * 2 - Math.PI / 2;
                cx = cellCx + Math.cos(angle) * fanR;
                cy = cellCy + Math.sin(angle) * fanR;
            }

            const colorRaw = _hmCategoryColor(pin.category);
            const conf = Math.max(0, Math.min(1, (pin.confidence || 0) / 100));
            // Selected pin gets a slight size boost.
            const isSel = pin.fingerprint_id === _hmSelectedFp;
            const r = baseR * (isSel ? 1.25 : 1);
            const ringR = r + ringMaxAdd * t;

            ctx.save();

            // Outer pulse ring — fades out as it expands
            ctx.strokeStyle = colorRaw;
            ctx.globalAlpha = (1 - t) * (0.55 + 0.45 * conf);
            ctx.lineWidth = 2.8 * _hmDpr;
            ctx.beginPath();
            ctx.arc(cx, cy, ringR, 0, 2 * Math.PI);
            ctx.stroke();

            // Soft glow halo around dot for visibility on bright heatmap
            ctx.globalAlpha = 0.35;
            ctx.fillStyle = colorRaw;
            ctx.beginPath();
            ctx.arc(cx, cy, r * 1.7, 0, 2 * Math.PI);
            ctx.fill();

            // Solid dot core
            ctx.globalAlpha = 1.0;
            ctx.fillStyle = colorRaw;
            ctx.beginPath();
            ctx.arc(cx, cy, r, 0, 2 * Math.PI);
            ctx.fill();

            // White inner ring for contrast against any background
            ctx.strokeStyle = "rgba(255,255,255,0.92)";
            ctx.lineWidth = 1.6 * _hmDpr;
            ctx.stroke();

            // Dark outer outline keeps it readable on light theme too
            ctx.strokeStyle = "rgba(0,0,0,0.7)";
            ctx.lineWidth = 1.0 * _hmDpr;
            ctx.beginPath();
            ctx.arc(cx, cy, r + 1.6 * _hmDpr, 0, 2 * Math.PI);
            ctx.stroke();

            // Selected device gets an extra amber glow ring
            if (isSel) {
                ctx.strokeStyle = "rgba(255,176,0,0.98)";
                ctx.lineWidth = 3 * _hmDpr;
                ctx.beginPath();
                ctx.arc(cx, cy, r + 5 * _hmDpr, 0, 2 * Math.PI);
                ctx.stroke();
            }

            // Label — pill behind text, only show first ~6 chars per pin if cell is crowded
            const maxLabelLen = group.length >= 5 ? 10 : 22;
            const txt = (pin.best_name || pin.category || "Unknown").slice(0, maxLabelLen);
            ctx.font = `${Math.round(10 * _hmDpr)}px JetBrains Mono, monospace`;
            ctx.textAlign = "left";
            ctx.textBaseline = "middle";
            const m = ctx.measureText(txt);
            const lx = cx + r + 6 * _hmDpr;
            const ly = cy;
            ctx.globalAlpha = 0.88;
            ctx.fillStyle = "rgba(10,14,22,0.85)";
            ctx.fillRect(lx - 3 * _hmDpr, ly - 8 * _hmDpr, m.width + 8 * _hmDpr, 14 * _hmDpr);
            ctx.globalAlpha = 1.0;
            ctx.fillStyle = "rgba(240,240,245,0.98)";
            ctx.fillText(txt, lx + 1 * _hmDpr, ly);
            ctx.restore();
        });

        // Optional: small stack-count badge in cell corner if 4+ pins clustered
        if (group.length >= 4) {
            ctx.save();
            ctx.fillStyle = "rgba(255,176,0,0.92)";
            ctx.beginPath();
            ctx.arc(cellCx + cw * 0.32, cellCy - ch * 0.32, 9 * _hmDpr, 0, 2 * Math.PI);
            ctx.fill();
            ctx.strokeStyle = "rgba(0,0,0,0.7)";
            ctx.lineWidth = 1.2 * _hmDpr;
            ctx.stroke();
            ctx.font = `bold ${Math.round(10 * _hmDpr)}px JetBrains Mono, monospace`;
            ctx.textAlign = "center";
            ctx.textBaseline = "middle";
            ctx.fillStyle = "#0a0e16";
            ctx.fillText(String(group.length), cellCx + cw * 0.32, cellCy - ch * 0.32);
            ctx.restore();
        }
    }
}
