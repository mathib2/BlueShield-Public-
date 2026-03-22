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
    updateAll();
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
    if (tab === "analytics") renderAnalytics();
    if (tab === "graph") renderConversationGraph();
    if (tab === "following") renderFollowingGrid();
    if (tab === "shadows") renderShadowGrid();
    if (tab === "live") { renderLiveDemo(); fetchTimeTravel(); }
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
    if (confirm("⚠ GHOST MODE: This will immediately shut down the system.\nAre you sure?")) {
        if (confirm("FINAL WARNING: The Raspberry Pi will power off NOW.\nContinue?")) {
            fetch("/api/ghost", { method: "POST" });
        }
    }
}
$("btn-ghost").addEventListener("click", ghostMode);
if ($("btn-ghost-cfg")) $("btn-ghost-cfg").addEventListener("click", ghostMode);

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

    const riskBadge = `<span class="risk-badge risk-${d.risk_level || 'low'}">${d.risk_score || 0} ${(d.risk_level || 'low').toUpperCase()}</span>`;

    const motionArrows = { approaching: "↑ Nearing", leaving: "↓ Leaving", stationary: "— Idle" };
    const motionCls = `movement-${d.rssi_trend || "stationary"}`;
    const motion = `<span class="movement-ind ${motionCls}">${motionArrows[d.rssi_trend] || "— Idle"}</span>`;

    const action = d.is_known
        ? `<button class="btn-untrust" onclick="untrustDevice('${id}');event.stopPropagation()">Untrust</button>`
        : `<button class="btn-trust" onclick="trustFingerprint('${id}');event.stopPropagation()">Trust</button>`;

    const eco = d.ecosystem ? `<span class="eco-badge eco-${d.ecosystem || 'other'}">${d.ecosystem}</span>` : "";

    return `<tr class="${rowCls} ${sel} ${followCls}" onclick="selectDevice('${id}')">
        <td>${d.category_icon || "❓"}</td>
        <td><strong>${escHtml(d.best_name || "Unknown")}</strong> ${eco}<br><span class="mono" style="font-size:.62rem;color:var(--tx-3)">${id}</span></td>
        <td><span class="cat-pill">${d.category_icon || "?"} ${d.category || "?"}</span></td>
        <td>${riskBadge}</td>
        <td>${motion}</td>
        <td><span class="mono">${rssi}</span> <div class="rssi-bar"><div class="rssi-fill" style="width:${pct}%;background:${rssiColor}"></div></div></td>
        <td><span class="mac-chip">${d.mac_count || 0}</span></td>
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
        <td>${d.category_icon || "❓"}</td>
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
        html += `<div class="detail-section"><div class="detail-section-title">🧠 AI Classification</div>`;
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
        html += `<div class="detail-section"><div class="detail-section-title" style="color:var(--red)">⚠ Tracker Suspect</div>`;
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
    html += `<button class="qa-btn qa-track" onclick="switchTab('radar')">📡 Radar</button>`;
    html += `<button class="qa-btn qa-alert" onclick="watchDevice('${fpId}')">🔔 Watch</button>`;
    html += `<button class="qa-btn qa-export" onclick="exportPackets('${fpId}')">📦 Packets</button>`;
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
    const icons = { phone:"📱", audio:"🎧", input:"🖱️", watch:"⌚", computer:"💻", tv:"📺", tracker:"📍", health:"❤️", gaming:"🎮", iot:"💡", apple:"🍎", nearby:"📶", unknown:"❓" };
    el.innerHTML = Object.entries(cats).sort((a,b) => b[1]-a[1]).map(([cat, cnt]) =>
        `<div class="cat-row"><span class="cat-icon">${icons[cat] || "❓"}</span><span class="cat-name">${cat}</span><span class="cat-count">${cnt}</span></div>`
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

/* ── Channel Grid ──────────────────────────────────────────── */
function simulateChannelActivity(devCount) {
    for (let i = 0; i < 40; i++) {
        if ([37, 38, 39].includes(i)) channelStats[i] += Math.floor(Math.random() * devCount * 3) + devCount;
        else channelStats[i] += Math.floor(Math.random() * devCount);
    }
}
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
        statusCard.innerHTML = `<div class="tracker-status-card"><div class="tsc-icon">🛡️</div><div class="tsc-info"><div class="tsc-title">Environment Clear</div><div class="tsc-desc">No suspected trackers detected nearby.</div></div></div>`;
        return;
    }

    badge.style.display = "";
    badge.textContent = trackerSuspects.length;
    topBadge.textContent = trackerSuspects.length;

    statusCard.innerHTML = `<div class="tracker-status-card alert"><div class="tsc-icon">⚠️</div><div class="tsc-info"><div class="tsc-title">${trackerSuspects.length} Suspected Tracker(s)</div><div class="tsc-desc">Potential tracking devices detected in your vicinity.</div></div></div>`;

    grid.innerHTML = trackerSuspects.map(t => {
        const cls = t.confidence > 0.7 ? "tracker-high" : "tracker-med";
        const icon = t.tracker_type.includes("airtag") ? "🍎📍" : t.tracker_type.includes("smarttag") ? "📱📍" : "📍";
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
        if (overview) overview.innerHTML = `<div class="follow-status-card"><div class="fsc-icon">🛡️</div><div class="fsc-info"><div class="fsc-title">All Clear</div><div class="fsc-desc">No devices appear to be following you.</div></div></div>`;
        return;
    }

    badge.style.display = "";
    badge.textContent = followingAlerts.length;
    if (topBadge) topBadge.textContent = followingAlerts.length;

    const threat = followingAlerts.some(f => f.threat_level === "following");
    if (overview) overview.innerHTML = `<div class="follow-status-card${threat ? " alert" : ""}"><div class="fsc-icon">${threat ? "⚠️" : "👁️"}</div><div class="fsc-info"><div class="fsc-title">${followingAlerts.length} Device(s) of Interest</div><div class="fsc-desc">${threat ? "One or more devices may be following you!" : "Monitoring suspicious patterns."}</div></div></div>`;

    grid.innerHTML = followingAlerts.map(f => {
        const threatCls = f.threat_level === "following" ? "threat-following" : f.threat_level === "suspicious" ? "threat-suspicious" : "threat-monitoring";
        const icon = f.threat_level === "following" ? "🚨" : f.threat_level === "suspicious" ? "👁️" : "📡";
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
        if (overview) overview.innerHTML = `<div class="shadow-status-card"><div class="shsc-icon">🌙</div><div class="shsc-info"><div class="shsc-title">No Shadows Detected</div><div class="shsc-desc">No devices exhibiting stealth behavior.</div></div></div>`;
        return;
    }

    badge.style.display = "";
    badge.textContent = shadowDevices.length;
    if (topBadge) topBadge.textContent = shadowDevices.length;

    const high = shadowDevices.filter(s => (s.stealth_score || 0) > 0.7).length;
    if (overview) overview.innerHTML = `<div class="shadow-status-card${high ? " alert" : ""}"><div class="shsc-icon">${high ? "👻" : "🌙"}</div><div class="shsc-info"><div class="shsc-title">${shadowDevices.length} Shadow Device(s)</div><div class="shsc-desc">${high ? high + " high-stealth device(s) detected!" : "Monitoring devices with intermittent visibility."}</div></div></div>`;

    grid.innerHTML = shadowDevices.map(s => {
        const score = Math.round((s.stealth_score || 0) * 100);
        const cls = score > 70 ? "shadow-high" : "shadow-med";
        return `<div class="shadow-card ${cls}">
            <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
                <span style="font-size:1.4rem">👻</span>
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
            icon: d.category_icon || "📡",
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
        ctx.fillText(n.icon || "📡", n.x, n.y);

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
        <div class="detail-section-title" style="color:var(--cyan);font-weight:600;font-size:.78rem">📖 Device Life Story</div>
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
    const cw = canvas.clientWidth || 700;
    canvas.width = cw * dpr;
    canvas.height = 150 * dpr;
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
$("j-mode").addEventListener("change", e => {
    const needsTarget = ["targeted", "deauth"].includes(e.target.value);
    $("j-target-grp").style.display = needsTarget ? "" : "none";
});
$("btn-jam").addEventListener("click", async () => {
    if (jammerActive) {
        await fetch("/api/jammer/stop", { method: "POST" });
        addTimelineEvent("jam", "Jammer stopped");
    } else {
        await fetch("/api/jammer/start", { method: "POST", headers:{"Content-Type":"application/json"},
            body: JSON.stringify({ mode: $("j-mode").value, channel: parseInt($("j-channel").value), target: $("j-target")?.value || "" })
        });
        addTimelineEvent("jam", `Jammer started: ${$("j-mode").value} mode`);
    }
});

function updateJammer(status) {
    jammerActive = status.is_jamming || false;
    const sess = status.active_session || {};
    const btn = $("btn-jam");
    btn.textContent = jammerActive ? "Stop Jammer" : "Start Jammer";
    btn.classList.toggle("active", jammerActive);
    $("jam-ind").classList.toggle("on", jammerActive);
    $("jam-ind-txt").textContent = jammerActive ? "ACTIVE" : "Inactive";
    $("jl-pkts").textContent = sess.packets_sent || 0;
    $("jl-mode").textContent = sess.mode || "--";
    $("jl-ch").textContent = sess.channel || "--";
    $("jl-be").textContent = status.backend || "--";
    $("nav-jam-badge").style.display = jammerActive ? "" : "none";
    $("pill-scan").classList.toggle("jamming", jammerActive);

    document.querySelectorAll(".ch-bar").forEach(bar => {
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
    if ($("lw-density-icon")) $("lw-density-icon").textContent = w.density_icon || "☀️";
    if ($("lw-turb")) $("lw-turb").textContent = w.turbulence || "Calm";
    if ($("lw-turb-icon")) $("lw-turb-icon").textContent = w.turbulence_icon || "🌊";
    if ($("lw-wind")) $("lw-wind").textContent = w.wind || "Stable";
    if ($("lw-wind-icon")) $("lw-wind-icon").textContent = w.wind_icon || "🧘";
    if ($("lw-forecast")) $("lw-forecast").textContent = w.forecast || "Quiet";
    if ($("lw-forecast-icon")) $("lw-forecast-icon").textContent = w.forecast_icon || "📉";
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
            $("tt-live-btn").textContent = "🔴 LIVE";
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
        $("tt-live-btn").textContent = "🔴 LIVE";
        $("tt-live-btn").style.color = "";
        $("tt-info").textContent = "Live mode — showing real-time data";
        renderLiveDemo();
    });
}

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
})();
