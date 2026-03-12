/* ═══════════════════════════════════════════════════════════════════════
   BlueShield v3.0 — Kismet/Ellisys-style Bluetooth Analyzer Dashboard
   Tab-based navigation, split-pane device detail, signal heatmap,
   event timeline, BLE channel grid, separate jammer tab.
   ═══════════════════════════════════════════════════════════════════════ */

const socket = io();

// ── State ─────────────────────────────────────────────────────────
let autoScan = true;
let isJamming = false;
let viewMode = "clustered";
let currentDevices = [];
let currentClustered = [];
let currentClusterSummary = {};
let selectedDeviceId = null;
let scanCount = 0;
let startTime = Date.now();
let timeline = [];
let channelStats = new Array(40).fill(0);
let alertList = [];
let searchFilter = "";
let sortCol = null;
let sortDir = 1;

// ── Refs (cached DOM) ─────────────────────────────────────────────
const $ = id => document.getElementById(id);

// ── Theme ─────────────────────────────────────────────────────────
function getTheme() { return localStorage.getItem("bs-theme") || "dark"; }
function setTheme(t) {
    document.documentElement.setAttribute("data-theme", t);
    localStorage.setItem("bs-theme", t);
    $("ico-sun").style.display  = t === "dark" ? "block" : "none";
    $("ico-moon").style.display = t === "light" ? "block" : "none";
}
setTheme(getTheme());
$("btn-theme").addEventListener("click", () => setTheme(getTheme() === "dark" ? "light" : "dark"));

// ── Clock ─────────────────────────────────────────────────────────
setInterval(() => {
    $("clock").textContent = new Date().toLocaleTimeString("en-US", { hour12: false });
}, 1000);

// ── Uptime ────────────────────────────────────────────────────────
setInterval(() => {
    const s = Math.floor((Date.now() - startTime) / 1000);
    const m = Math.floor(s / 60), h = Math.floor(m / 60);
    $("sf-uptime").textContent = h > 0 ? `${h}:${String(m % 60).padStart(2,"0")}` : `${m}:${String(s % 60).padStart(2,"0")}`;
}, 1000);

// ── Tab Navigation ────────────────────────────────────────────────
const navItems = document.querySelectorAll(".nav-item[data-tab]");
const tabPanes = document.querySelectorAll(".tab-pane");

function switchTab(tabId) {
    navItems.forEach(n => n.classList.toggle("active", n.dataset.tab === tabId));
    tabPanes.forEach(p => p.classList.toggle("active", p.id === `tab-${tabId}`));
}
navItems.forEach(n => n.addEventListener("click", () => switchTab(n.dataset.tab)));

// Sidebar collapse
$("sidebar-toggle").addEventListener("click", () => $("sidebar").classList.toggle("collapsed"));

// ── Socket.IO Events ──────────────────────────────────────────────
socket.on("connect", () => {
    const pill = $("pill-conn");
    pill.classList.add("on");
    $("conn-text").textContent = "Connected";
    fetchStatus();
});

socket.on("disconnect", () => {
    $("pill-conn").classList.remove("on");
    $("conn-text").textContent = "Disconnected";
});

socket.on("status", data => updateAll(data));

socket.on("scan_result", data => {
    const pill = $("pill-scan");
    pill.classList.add("scanning");
    $("scan-text").textContent = "Scanning";
    setTimeout(() => { pill.classList.remove("scanning"); $("scan-text").textContent = "Idle"; }, 2000);
    scanCount++;
    $("sf-scans").textContent = scanCount;
    $("ss-scans").textContent = scanCount;

    // Add timeline event
    const devCount = (data.devices_found || []).length;
    const unknowns = data.unknown_devices || 0;
    addTimelineEvent("scan", `Scan #${scanCount}: found ${devCount} device(s), ${unknowns} unknown`);

    // Simulate channel activity (randomize since BLE advertisement channels are 37-39)
    [37, 38, 39].forEach(ch => { channelStats[ch] += Math.floor(Math.random() * devCount) + 1; });
    // Data channels get occasional hits
    for (let i = 0; i < 37; i++) {
        if (Math.random() < 0.15) channelStats[i] += Math.floor(Math.random() * 3);
    }
    renderChannelGrid();
});

socket.on("device_update", data => {
    if (data.summary) updateStats(data.summary, data.cluster_summary);
    if (data.devices) currentDevices = data.devices;
    if (data.clustered_devices) currentClustered = data.clustered_devices;
    if (data.cluster_summary) currentClusterSummary = data.cluster_summary;
    renderDeviceTable();
    renderSignalPanels();
    updateStatusBar();
    if (selectedDeviceId) renderDetailPanel();
});

socket.on("alert", data => {
    const entry = { timestamp: data.timestamp, level: data.data?.level || "info", message: data.data?.message || "Alert" };
    alertList.unshift(entry);
    if (alertList.length > 200) alertList.length = 200;
    renderAlertList();
    addTimelineEvent("alert", entry.message);
    const cnt = alertList.length;
    $("nav-alert-badge").textContent = cnt;
    $("alert-top").textContent = cnt;
});

socket.on("jammer_update", data => updateJammerPanel(data));
socket.on("autoscan_changed", data => { autoScan = data.enabled; updateAutoScanBtn(); });
socket.on("range_changed", data => { if (data.preset) $("range-select").value = data.preset; });

// ── Fetch ─────────────────────────────────────────────────────────
async function fetchStatus() {
    try {
        const r = await fetch("/api/status");
        const d = await r.json();
        updateAll(d);
    } catch (e) { console.error("[BlueShield] fetch failed:", e); }
}

function updateAll(d) {
    if (d.summary) updateStats(d.summary, d.cluster_summary);
    if (d.devices) currentDevices = d.devices;
    if (d.clustered_devices) currentClustered = d.clustered_devices;
    if (d.cluster_summary) currentClusterSummary = d.cluster_summary;
    if (d.jammer) updateJammerPanel(d.jammer);
    if (d.alerts) { alertList = (d.alerts || []).map(a => ({ timestamp: a.timestamp, level: a.data?.level||"info", message: a.data?.message||"" })); renderAlertList(); }
    if (d.platform) updatePlatform(d.platform);
    if (d.auto_scan !== undefined) { autoScan = d.auto_scan; updateAutoScanBtn(); }
    if (d.scan_interval) { $("scan-interval").value = d.scan_interval; $("interval-display").textContent = d.scan_interval + "s"; }
    if (d.total_scans) { scanCount = d.total_scans; $("sf-scans").textContent = scanCount; $("ss-scans").textContent = scanCount; }
    renderDeviceTable();
    renderSignalPanels();
    updateStatusBar();
}

// ── Stats Strip ───────────────────────────────────────────────────
function updateStats(summary, cs) {
    cs = cs || {};
    $("ss-physical").textContent  = cs.total_physical_devices || summary.total_devices || 0;
    $("ss-macs").textContent      = cs.total_mac_addresses || summary.total_devices || 0;
    $("ss-trusted").textContent   = cs.known_devices || summary.known_devices || 0;
    $("ss-unknown").textContent   = cs.unknown_devices || summary.unknown_devices || 0;
    $("ss-clustered").textContent = cs.mac_reduction || 0;
    $("ss-scans").textContent     = summary.total_scans || scanCount;
    $("nav-dev-count").textContent = cs.total_physical_devices || summary.total_devices || 0;
}

// ── Device Table ──────────────────────────────────────────────────
const CLUSTERED_COLS = [
    { key:"fp",      label:"Device" },
    { key:"name",    label:"Name" },
    { key:"cat",     label:"Category" },
    { key:"mfr",     label:"Manufacturer" },
    { key:"rssi",    label:"RSSI" },
    { key:"signal",  label:"Signal" },
    { key:"macs",    label:"MACs" },
    { key:"dur",     label:"Seen" },
    { key:"status",  label:"Status" },
    { key:"action",  label:"Action" },
];
const RAW_COLS = [
    { key:"addr",   label:"Address" },
    { key:"name",   label:"Name" },
    { key:"cat",    label:"Category" },
    { key:"mfr",    label:"Manufacturer" },
    { key:"type",   label:"Type" },
    { key:"rssi",   label:"RSSI" },
    { key:"signal", label:"Signal" },
    { key:"status", label:"Alert" },
    { key:"seen",   label:"Seen" },
    { key:"action", label:"Action" },
];

function renderDeviceTable() {
    const cols = viewMode === "clustered" ? CLUSTERED_COLS : RAW_COLS;
    const thead = $("dev-thead");
    thead.innerHTML = cols.map(c => `<th data-col="${c.key}">${c.label}</th>`).join("");

    // Attach sort handlers
    thead.querySelectorAll("th").forEach(th => {
        th.addEventListener("click", () => {
            const col = th.dataset.col;
            if (sortCol === col) sortDir *= -1;
            else { sortCol = col; sortDir = 1; }
            renderDeviceTable();
        });
    });

    const tbody = $("dev-tbody");
    let devices = viewMode === "clustered" ? [...currentClustered] : [...currentDevices];

    // Apply search filter
    if (searchFilter) {
        const q = searchFilter.toLowerCase();
        devices = devices.filter(d => {
            const name = (viewMode === "clustered" ? d.best_name : d.name) || "";
            const addr = (viewMode === "clustered" ? d.fingerprint_id : d.address) || "";
            const mfr = (viewMode === "clustered" ? d.manufacturer_name : d.manufacturer) || "";
            const cat = d.category || "";
            return name.toLowerCase().includes(q) || addr.toLowerCase().includes(q) ||
                   mfr.toLowerCase().includes(q) || cat.toLowerCase().includes(q);
        });
    }

    // Sort
    if (sortCol) {
        devices.sort((a, b) => {
            let va, vb;
            if (viewMode === "clustered") {
                switch(sortCol) {
                    case "name": va = a.best_name||""; vb = b.best_name||""; break;
                    case "rssi": va = a.avg_rssi||-100; vb = b.avg_rssi||-100; break;
                    case "macs": va = a.mac_count||1; vb = b.mac_count||1; break;
                    case "cat":  va = a.category||""; vb = b.category||""; break;
                    default: va = ""; vb = "";
                }
            } else {
                switch(sortCol) {
                    case "name": va = a.name||""; vb = b.name||""; break;
                    case "rssi": va = a.rssi||-100; vb = b.rssi||-100; break;
                    case "addr": va = a.address||""; vb = b.address||""; break;
                    case "seen": va = a.seen_count||0; vb = b.seen_count||0; break;
                    default: va = ""; vb = "";
                }
            }
            if (typeof va === "string") return va.localeCompare(vb) * sortDir;
            return (va - vb) * sortDir;
        });
    }

    if (devices.length === 0) {
        tbody.innerHTML = `<tr class="empty-row"><td colspan="${cols.length}">Waiting for first scan...</td></tr>`;
        return;
    }

    if (viewMode === "clustered") {
        tbody.innerHTML = devices.map(d => renderClusteredRow(d)).join("");
    } else {
        tbody.innerHTML = devices.map(d => renderRawRow(d)).join("");
    }

    // Row click -> select + detail
    tbody.querySelectorAll("tr").forEach(tr => {
        tr.addEventListener("click", e => {
            if (e.target.closest(".btn-trust")) return;
            const id = tr.dataset.id;
            if (!id) return;
            tbody.querySelectorAll("tr").forEach(r => r.classList.remove("selected"));
            tr.classList.add("selected");
            selectedDeviceId = id;
            renderDetailPanel();
        });
    });
}

function renderClusteredRow(d) {
    const rssi = Math.round(d.avg_rssi || -100);
    const pct = clamp(((rssi + 100) / 60) * 100, 0, 100);
    const color = rssi > -50 ? "var(--green)" : rssi > -70 ? "var(--orange)" : "var(--red)";
    const alert = d.alert_level || "none";
    const rowCls = alert === "critical" ? "row-crit" : alert === "warning" ? "row-warn" : d.is_known ? "row-ok" : "";
    const tag = d.is_known ? '<span class="tag tag-ok">TRUSTED</span>' :
                alert === "critical" ? '<span class="tag tag-crit">CRITICAL</span>' :
                '<span class="tag tag-warn">UNKNOWN</span>';
    const action = !d.is_known
        ? `<button class="btn-trust" onclick="trustFingerprint('${d.fingerprint_id}');event.stopPropagation()">Trust</button>`
        : '<span style="color:var(--green);font-size:.65rem">✓ Trusted</span>';
    const cat = (d.category || "unknown");
    const catUp = cat.charAt(0).toUpperCase() + cat.slice(1);
    const icon = d.category_icon || "";
    const mfr = d.manufacturer_name || "Unknown";
    const mfrS = mfr.length > 18 ? mfr.substring(0, 16) + "…" : mfr;
    const macCount = d.mac_count || d.mac_addresses?.length || 1;
    const fpS = (d.fingerprint_id || "").substring(0, 10);
    const dur = d.duration_display || "--";

    return `<tr class="${rowCls}" data-id="${d.fingerprint_id}">
        <td><span class="mono" title="${d.fingerprint_id}">${fpS}</span></td>
        <td style="font-weight:500">${d.best_name || "Unknown"}</td>
        <td><span class="cat-pill">${icon} ${catUp}</span></td>
        <td><span style="color:var(--tx-2);font-size:.72rem" title="${mfr}">${mfrS}</span></td>
        <td class="mono">${rssi} dBm</td>
        <td><div class="rssi-bar"><div class="rssi-fill" style="width:${pct}%;background:${color}"></div></div></td>
        <td><span class="mac-chip">${macCount} MAC${macCount>1?"s":""}</span></td>
        <td><span style="font-size:.72rem;color:var(--tx-3)">${dur}</span></td>
        <td>${tag}</td>
        <td>${action}</td>
    </tr>`;
}

function renderRawRow(d) {
    const rssi = d.rssi || -100;
    const pct = clamp(((rssi + 100) / 60) * 100, 0, 100);
    const color = rssi > -50 ? "var(--green)" : rssi > -70 ? "var(--orange)" : "var(--red)";
    const alert = d.alert_level || "none";
    const rowCls = alert === "critical" ? "row-crit" : alert === "warning" ? "row-warn" : d.is_known ? "row-ok" : "";
    const tag = alert === "critical" ? '<span class="tag tag-crit">CRITICAL</span>' :
                alert === "warning" ? '<span class="tag tag-warn">WARNING</span>' :
                '<span class="tag tag-ok">OK</span>';
    const action = !d.is_known
        ? `<button class="btn-trust" onclick="whitelistDevice('${d.address}');event.stopPropagation()">Trust</button>`
        : '<span style="color:var(--green);font-size:.65rem">✓ Trusted</span>';
    const cat = (d.category || "unknown");
    const catUp = cat.charAt(0).toUpperCase() + cat.slice(1);
    const icon = d.category_icon || "";
    const mfr = d.manufacturer || "Unknown";
    const mfrS = mfr.length > 18 ? mfr.substring(0, 16) + "…" : mfr;

    return `<tr class="${rowCls}" data-id="${d.address}">
        <td><span class="mono">${d.address}</span></td>
        <td style="font-weight:500">${d.name || "Unknown"}</td>
        <td><span class="cat-pill">${icon} ${catUp}</span></td>
        <td><span style="color:var(--tx-2);font-size:.72rem" title="${mfr}">${mfrS}</span></td>
        <td><span style="color:var(--accent)">${d.device_type || "?"}</span></td>
        <td class="mono">${rssi} dBm</td>
        <td><div class="rssi-bar"><div class="rssi-fill" style="width:${pct}%;background:${color}"></div></div></td>
        <td>${tag}</td>
        <td>${d.seen_count || 0}</td>
        <td>${action}</td>
    </tr>`;
}

// ── Detail Panel ──────────────────────────────────────────────────
function renderDetailPanel() {
    const panel = $("device-detail");
    const body = $("detail-body");
    if (!selectedDeviceId) { panel.classList.remove("open"); return; }
    panel.classList.add("open");

    let dev = null;
    if (viewMode === "clustered") {
        dev = currentClustered.find(d => d.fingerprint_id === selectedDeviceId);
    } else {
        dev = currentDevices.find(d => d.address === selectedDeviceId);
    }

    if (!dev) {
        body.innerHTML = '<div class="empty-msg">Device not found</div>';
        return;
    }

    if (viewMode === "clustered") {
        const macList = (dev.mac_addresses || []).map(m => `<span class="mono" style="display:block;font-size:.7rem;color:var(--tx-2)">${m}</span>`).join("");
        body.innerHTML = `
            <div class="detail-row"><span class="dr-label">Fingerprint ID</span><span class="dr-val">${dev.fingerprint_id || "--"}</span></div>
            <div class="detail-row"><span class="dr-label">Best Name</span><span class="dr-val">${dev.best_name || "Unknown"}</span></div>
            <div class="detail-row"><span class="dr-label">Category</span><span class="dr-val">${(dev.category_icon||"")} ${(dev.category||"unknown")}</span></div>
            <div class="detail-row"><span class="dr-label">Manufacturer</span><span class="dr-val">${dev.manufacturer_name || "Unknown"}</span></div>
            <div class="detail-row"><span class="dr-label">Avg RSSI</span><span class="dr-val">${Math.round(dev.avg_rssi||-100)} dBm</span></div>
            <div class="detail-row"><span class="dr-label">MAC Count</span><span class="dr-val">${dev.mac_count || 1}</span></div>
            <div class="detail-row"><span class="dr-label">First Seen</span><span class="dr-val">${fmtTime(dev.first_seen)}</span></div>
            <div class="detail-row"><span class="dr-label">Duration</span><span class="dr-val">${dev.duration_display || "--"}</span></div>
            <div class="detail-row"><span class="dr-label">Status</span><span class="dr-val">${dev.is_known ? "✓ Trusted" : "⚠ Unknown"}</span></div>
            <div style="margin-top:8px"><span class="dr-label">MAC Addresses</span>${macList}</div>
        `;
    } else {
        body.innerHTML = `
            <div class="detail-row"><span class="dr-label">Address</span><span class="dr-val">${dev.address}</span></div>
            <div class="detail-row"><span class="dr-label">Name</span><span class="dr-val">${dev.name || "Unknown"}</span></div>
            <div class="detail-row"><span class="dr-label">Category</span><span class="dr-val">${(dev.category_icon||"")} ${(dev.category||"unknown")}</span></div>
            <div class="detail-row"><span class="dr-label">Manufacturer</span><span class="dr-val">${dev.manufacturer || "Unknown"}</span></div>
            <div class="detail-row"><span class="dr-label">Type</span><span class="dr-val">${dev.device_type || "?"}</span></div>
            <div class="detail-row"><span class="dr-label">RSSI</span><span class="dr-val">${dev.rssi || -100} dBm</span></div>
            <div class="detail-row"><span class="dr-label">TX Power</span><span class="dr-val">${dev.tx_power || "?"}</span></div>
            <div class="detail-row"><span class="dr-label">Times Seen</span><span class="dr-val">${dev.seen_count || 0}</span></div>
            <div class="detail-row"><span class="dr-label">Alert Level</span><span class="dr-val">${dev.alert_level || "none"}</span></div>
            <div class="detail-row"><span class="dr-label">Known</span><span class="dr-val">${dev.is_known ? "✓ Yes" : "✗ No"}</span></div>
        `;
    }
}

$("close-detail").addEventListener("click", () => {
    $("device-detail").classList.remove("open");
    selectedDeviceId = null;
    $("dev-tbody").querySelectorAll("tr.selected").forEach(r => r.classList.remove("selected"));
});

// ── Signal Panels ─────────────────────────────────────────────────
const CAT_ICONS = {
    phone:"📱", tablet:"📱", computer:"💻", input:"🖱️", audio:"🎧",
    watch:"⌚", health:"❤️", fitness:"🏃", tv:"📺", tracker:"📍",
    gaming:"🎮", iot:"💡", apple:"🍎", nearby:"📶", generic:"📡", unknown:"❓"
};

function renderSignalPanels() {
    renderRSSIPanel();
    renderCategoryPanel();
    renderHeatmap();
}

function renderRSSIPanel() {
    const container = $("rssi-full");
    const devs = viewMode === "clustered" ? currentClustered : currentDevices;
    if (!devs || devs.length === 0) { container.innerHTML = '<div class="empty-msg">No signal data</div>'; return; }

    const sorted = [...devs]
        .filter(d => { const r = viewMode === "clustered" ? d.avg_rssi : d.rssi; return r && r !== 0 && r > -100; })
        .sort((a, b) => (viewMode === "clustered" ? (b.avg_rssi||-100) : (b.rssi||-100)) - (viewMode === "clustered" ? (a.avg_rssi||-100) : (a.rssi||-100)))
        .slice(0, 10);

    if (sorted.length === 0) { container.innerHTML = '<div class="empty-msg">No RSSI data</div>'; return; }

    container.innerHTML = sorted.map(d => {
        const rssi = Math.round(viewMode === "clustered" ? (d.avg_rssi||-100) : (d.rssi||-100));
        const pct = clamp(((rssi + 100) / 60) * 100, 0, 100);
        const color = rssi > -50 ? "var(--green)" : rssi > -70 ? "var(--orange)" : "var(--red)";
        const name = ((viewMode === "clustered" ? d.best_name : d.name) || "Unknown").substring(0, 14);
        return `<div class="rssi-row"><span class="rssi-name">${name}</span><div class="rssi-bar-o"><div class="rssi-bar-i" style="width:${pct}%;background:${color}"></div></div><span class="rssi-v">${rssi} dBm</span></div>`;
    }).join("");
}

function renderCategoryPanel() {
    const container = $("cat-full");
    const cats = currentClusterSummary.categories || {};
    if (Object.keys(cats).length === 0) { container.innerHTML = '<div class="empty-msg">No data yet</div>'; return; }

    container.innerHTML = Object.entries(cats).sort((a,b) => b[1]-a[1]).map(([c, n]) => {
        const icon = CAT_ICONS[c] || "❓";
        return `<div class="cat-row"><span class="cat-icon">${icon}</span><span class="cat-name">${c}</span><span class="cat-count">${n}</span></div>`;
    }).join("");
}

function renderHeatmap() {
    const container = $("heatmap");
    const devs = viewMode === "clustered" ? currentClustered : currentDevices;
    if (!devs || devs.length === 0) { container.innerHTML = '<div class="empty-msg">Waiting for data...</div>'; return; }

    // Generate a time-bucket heatmap: rows = devices, cols = time buckets
    const top = [...devs]
        .filter(d => { const r = viewMode === "clustered" ? d.avg_rssi : d.rssi; return r && r > -100; })
        .slice(0, 8);

    if (top.length === 0) { container.innerHTML = '<div class="empty-msg">No heatmap data</div>'; return; }

    const buckets = 12;
    container.innerHTML = top.map(d => {
        const name = ((viewMode === "clustered" ? d.best_name : d.name) || "?").substring(0, 12);
        const rssi = viewMode === "clustered" ? (d.avg_rssi||-100) : (d.rssi||-100);
        // Simulated historical data based on RSSI + noise
        const cells = Array.from({length: buckets}, (_, i) => {
            const val = clamp(rssi + Math.floor(Math.random() * 15 - 7), -100, -20);
            const intensity = clamp(((val + 100) / 60), 0, 1);
            const g = Math.floor(intensity * 185 + 40);
            const r = Math.floor((1 - intensity) * 180 + 40);
            return `<div class="hm-cell" style="background:rgba(${r},${g},80,${0.3+intensity*0.7})" title="${val} dBm"></div>`;
        }).join("");
        return `<div class="hm-row"><span class="hm-name">${name}</span><div class="hm-cells">${cells}</div></div>`;
    }).join("");
}

// ── Timeline ──────────────────────────────────────────────────────
function addTimelineEvent(type, msg) {
    timeline.unshift({ time: new Date(), type, msg });
    if (timeline.length > 300) timeline.length = 300;
    renderTimeline();
}

function renderTimeline() {
    const container = $("tl-list");
    if (timeline.length === 0) {
        container.innerHTML = '<div class="empty-msg">Events appear as scans run...</div>';
        return;
    }
    container.innerHTML = timeline.slice(0, 100).map(e => {
        const ts = e.time.toLocaleTimeString("en-US", { hour12: false, hour:"2-digit", minute:"2-digit", second:"2-digit" });
        const cls = e.type === "scan" ? "tl-scan" : e.type === "alert" ? "tl-alert" : "tl-jam";
        return `<div class="tl-entry"><span class="tl-time">${ts}</span><span class="tl-type ${cls}">${e.type}</span><span class="tl-msg">${e.msg}</span></div>`;
    }).join("");
}

$("btn-clear-tl").addEventListener("click", () => {
    timeline = [];
    renderTimeline();
});

// ── Channel Grid ──────────────────────────────────────────────────
function renderChannelGrid() {
    const container = $("ch-grid");
    const maxCount = Math.max(1, ...channelStats);

    container.innerHTML = Array.from({length: 40}, (_, i) => {
        const count = channelStats[i];
        const isAdv = i >= 37;
        const freq = 2402 + (i * 2);
        const intensity = count / maxCount;
        const borderC = isAdv ? "var(--orange)" : intensity > 0.5 ? "var(--accent)" : "var(--border)";
        const bgStyle = count > 0 ? `background:rgba(${isAdv?"210,153,34":"88,166,255"},${0.05+intensity*0.2})` : "";
        return `<div class="ch-cell" style="border-color:${borderC};${bgStyle}"><div class="ch-num">${i}</div><div class="ch-freq">${freq} MHz</div><div class="ch-count">${count}</div></div>`;
    }).join("");
}

// ── Jammer Panel ──────────────────────────────────────────────────
function updateJammerPanel(status) {
    if (!status) return;
    isJamming = status.is_jamming;

    const btn = $("btn-jam");
    const ind = $("jam-ind");
    const badge = $("nav-jam-badge");
    const sbJam = $("sb-jam");

    if (isJamming) {
        btn.textContent = "Stop Jammer";
        btn.classList.add("active");
        ind.classList.add("on");
        $("jam-ind-txt").textContent = "ACTIVE";
        badge.style.display = "";
        sbJam.textContent = "Jammer: ON";

        if (status.active_session) {
            $("jl-pkts").textContent = status.active_session.packets_sent || 0;
            $("jl-mode").textContent = status.active_session.mode || "--";
            $("jl-ch").textContent = status.active_session.channel || "--";

            // Highlight active channel bars
            document.querySelectorAll(".ch-bar").forEach(bar => {
                const ch = bar.dataset.ch;
                const mode = status.active_session.mode;
                if (mode === "sweep" || ch == status.active_session.channel) {
                    bar.classList.add("active");
                } else {
                    bar.classList.remove("active");
                }
            });
        }
    } else {
        btn.textContent = "Start Jammer";
        btn.classList.remove("active");
        ind.classList.remove("on");
        $("jam-ind-txt").textContent = "Inactive";
        badge.style.display = "none";
        sbJam.textContent = "Jammer: Off";
        document.querySelectorAll(".ch-bar").forEach(b => b.classList.remove("active"));
    }

    if (status.backend) {
        $("jl-be").textContent = status.backend === "raw_hci" ? "Raw HCI" : status.backend === "hcitool" ? "hcitool" : "Simulated";
    }
}

// ── Alerts Tab ────────────────────────────────────────────────────
function renderAlertList() {
    const container = $("alert-full");
    const cnt = alertList.length;
    $("nav-alert-badge").textContent = cnt;
    $("alert-top").textContent = cnt;

    if (cnt === 0) {
        container.innerHTML = '<div class="empty-msg">No alerts. System clean.</div>';
        return;
    }

    container.innerHTML = alertList.slice(0, 100).map(a => {
        const ts = fmtTime(a.timestamp);
        const cls = a.level === "critical" ? "al-crit" : a.level === "warning" ? "al-warn" : "al-info";
        return `<div class="alert-entry"><span class="al-time">${ts}</span><span class="al-lvl ${cls}">${a.level}</span><span class="al-msg">${a.message}</span></div>`;
    }).join("");
}

// ── Platform ──────────────────────────────────────────────────────
function updatePlatform(info) {
    const pill = $("pill-plat");
    if (info.os === "Linux" && info.has_hcitool) pill.textContent = "RPi FULL";
    else if (info.os === "Linux") pill.textContent = "LINUX BLE";
    else if (info.os === "Windows") pill.textContent = "WIN BLE";
    else pill.textContent = info.os;

    // Config tab platform info
    const cfgPlat = $("cfg-plat");
    if (cfgPlat) {
        cfgPlat.innerHTML = `
            <div>OS: ${info.os || "--"}</div>
            <div>Host: ${info.hostname || "--"}</div>
            <div>Bleak: ${info.has_bleak ? "✓" : "✗"}</div>
            <div>hcitool: ${info.has_hcitool ? "✓" : "✗"}</div>
            <div>hcidump: ${info.has_hcidump ? "✓" : "✗"}</div>
        `;
    }
}

// ── Status Bar ────────────────────────────────────────────────────
function updateStatusBar() {
    const devCount = viewMode === "clustered" ? currentClustered.length : currentDevices.length;
    $("sb-dev").textContent = `${devCount} device${devCount!==1?"s":""}`;
    $("sb-scans").textContent = `${scanCount} scans`;
    const rangeLabel = $("range-select").selectedOptions[0]?.text || "All";
    $("sb-range").textContent = `Range: ${rangeLabel}`;
}

function updateAutoScanBtn() {
    const btn = $("btn-autoscan");
    btn.textContent = autoScan ? "Auto: ON" : "Auto: OFF";
    btn.classList.toggle("active", autoScan);
}

// ── User Actions ──────────────────────────────────────────────────

// Scan button
$("btn-scan").addEventListener("click", async () => {
    const btn = $("btn-scan");
    btn.innerHTML = '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/></svg> Scanning...';
    btn.disabled = true;
    try { await fetch("/api/scan", { method: "POST" }); } catch(e) { console.error(e); }
    setTimeout(() => {
        btn.innerHTML = '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/></svg> Scan';
        btn.disabled = false;
    }, 2000);
});

// Auto-scan toggle
$("btn-autoscan").addEventListener("click", () => {
    autoScan = !autoScan;
    socket.emit("toggle_autoscan", { enabled: autoScan });
    updateAutoScanBtn();
});

// Scan interval slider
$("scan-interval").addEventListener("input", e => {
    const val = parseInt(e.target.value);
    $("interval-display").textContent = val + "s";
    socket.emit("set_scan_interval", { interval: val });
});

// Range selector
$("range-select").addEventListener("change", async e => {
    await fetch("/api/range", { method: "POST", headers: {"Content-Type":"application/json"}, body: JSON.stringify({ preset: e.target.value }) });
});

// View toggle (Devices / Raw MACs)
$("vt-clustered").addEventListener("click", () => {
    viewMode = "clustered";
    $("vt-clustered").classList.add("active");
    $("vt-raw").classList.remove("active");
    selectedDeviceId = null;
    $("device-detail").classList.remove("open");
    renderDeviceTable();
    renderSignalPanels();
});
$("vt-raw").addEventListener("click", () => {
    viewMode = "raw";
    $("vt-raw").classList.add("active");
    $("vt-clustered").classList.remove("active");
    selectedDeviceId = null;
    $("device-detail").classList.remove("open");
    renderDeviceTable();
    renderSignalPanels();
});

// Search filter
$("device-search").addEventListener("input", e => {
    searchFilter = e.target.value;
    renderDeviceTable();
});

// Jammer controls
$("btn-jam").addEventListener("click", async () => {
    if (isJamming) {
        await fetch("/api/jammer/stop", { method: "POST" });
        addTimelineEvent("jam", "Jammer stopped");
    } else {
        const mode = $("j-mode").value;
        const channel = $("j-channel").value;
        const target = $("j-target")?.value?.trim() || "";
        await fetch("/api/jammer/start", {
            method: "POST",
            headers: {"Content-Type":"application/json"},
            body: JSON.stringify({ mode, channel: parseInt(channel), target })
        });
        addTimelineEvent("jam", `Jammer started: ${mode} on ch ${channel}`);
    }
});

$("j-mode").addEventListener("change", () => {
    const tg = $("j-target-grp");
    if (tg) tg.style.display = $("j-mode").value === "targeted" ? "" : "none";
});

// Export alerts
$("btn-export").addEventListener("click", async () => {
    const btn = $("btn-export");
    btn.textContent = "Exporting...";
    try {
        const res = await fetch("/api/export", { method: "POST" });
        if (res.ok) {
            const blob = await res.blob();
            const url = URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = `blueshield_report_${new Date().toISOString().slice(0,10)}.json`;
            a.click();
            URL.revokeObjectURL(url);
        }
    } catch(e) { console.error(e); }
    setTimeout(() => { btn.textContent = "Export"; }, 1500);
});

// Config save
$("btn-save-cfg").addEventListener("click", async () => {
    const data = {
        scan_interval: parseInt($("cfg-interval").value) || 5,
        scan_duration: parseInt($("cfg-duration").value) || 10,
        alert_threshold: parseInt($("cfg-threshold").value) || 3,
    };
    await fetch("/api/config", { method: "POST", headers: {"Content-Type":"application/json"}, body: JSON.stringify(data) });
    $("scan-interval").value = data.scan_interval;
    $("interval-display").textContent = data.scan_interval + "s";
    $("btn-save-cfg").textContent = "Saved!";
    setTimeout(() => { $("btn-save-cfg").textContent = "Save"; }, 1500);
});

// Reset
$("btn-reset").addEventListener("click", async () => {
    if (confirm("Reset all discovered devices, scan history, and alerts?")) {
        await fetch("/api/reset", { method: "POST" });
        scanCount = 0;
        alertList = [];
        timeline = [];
        channelStats = new Array(40).fill(0);
        selectedDeviceId = null;
        $("device-detail").classList.remove("open");
        renderAlertList();
        renderTimeline();
        renderChannelGrid();
    }
});

// Trust actions (global so onclick works)
window.trustFingerprint = async function(fpId) {
    await fetch("/api/whitelist", { method: "POST", headers: {"Content-Type":"application/json"}, body: JSON.stringify({ fingerprint_id: fpId }) });
};
window.whitelistDevice = async function(addr) {
    await fetch("/api/whitelist", { method: "POST", headers: {"Content-Type":"application/json"}, body: JSON.stringify({ address: addr }) });
};

// ── Jammer stats refresh ──────────────────────────────────────────
setInterval(async () => {
    if (isJamming) {
        try { const r = await fetch("/api/jammer"); const d = await r.json(); updateJammerPanel(d); } catch {}
    }
}, 1000);

// Fallback poll
setInterval(fetchStatus, 15000);

// ── Utilities ─────────────────────────────────────────────────────
function clamp(v, min, max) { return Math.max(min, Math.min(max, v)); }

function fmtTime(iso) {
    if (!iso) return "--:--";
    try { return new Date(iso).toLocaleTimeString("en-US", { hour12:false, hour:"2-digit", minute:"2-digit", second:"2-digit" }); }
    catch { return typeof iso === "string" ? iso.substring(11, 19) : "--:--"; }
}

// ── Initial render ────────────────────────────────────────────────
renderChannelGrid();
renderTimeline();
renderAlertList();
