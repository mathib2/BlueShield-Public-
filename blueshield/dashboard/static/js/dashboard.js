/* ═══════════════════════════════════════════════════════════════════
   BlueShield Dashboard v2.0 — Client-Side Logic
   Features: fingerprint clustering, range filter, light/dark mode
   ═══════════════════════════════════════════════════════════════════ */

const socket = io();

// ── State ───────────────────────────────────────────────────────

let autoScan = true;
let isJamming = false;
let alertCount = 0;
let viewMode = "clustered"; // "clustered" or "raw"
let currentDevices = [];
let currentClustered = [];
let currentClusterSummary = {};

// ── Theme ───────────────────────────────────────────────────────

function getTheme() {
    return localStorage.getItem("bs-theme") || "dark";
}

function setTheme(theme) {
    document.documentElement.setAttribute("data-theme", theme);
    localStorage.setItem("bs-theme", theme);
    document.getElementById("icon-sun").style.display = theme === "dark" ? "block" : "none";
    document.getElementById("icon-moon").style.display = theme === "light" ? "block" : "none";
}

setTheme(getTheme());

document.getElementById("btn-theme").addEventListener("click", () => {
    setTheme(getTheme() === "dark" ? "light" : "dark");
});

// ── Socket.IO Events ────────────────────────────────────────────

socket.on("connect", () => {
    const pill = document.getElementById("pill-status");
    document.getElementById("scanner-status-text").textContent = "Connected";
    pill.classList.add("active");
    fetchStatus();
});

socket.on("disconnect", () => {
    document.getElementById("scanner-status-text").textContent = "Disconnected";
    document.getElementById("pill-status").classList.remove("active", "scanning");
});

socket.on("status", (data) => {
    updateAll(data);
});

socket.on("scan_result", (data) => {
    const pill = document.getElementById("pill-status");
    document.getElementById("scanner-status-text").textContent = "Scanning...";
    pill.classList.add("scanning");
    setTimeout(() => {
        document.getElementById("scanner-status-text").textContent = "Connected";
        pill.classList.remove("scanning");
    }, 2000);
});

socket.on("device_update", (data) => {
    if (data.summary) updateSummaryCards(data.summary, data.cluster_summary);
    if (data.devices) { currentDevices = data.devices; }
    if (data.clustered_devices) { currentClustered = data.clustered_devices; }
    if (data.cluster_summary) { currentClusterSummary = data.cluster_summary; }
    renderDeviceTable();
    updateRSSIChart();
    updateCategoryChart();
});

socket.on("alert", (data) => {
    addAlertEntry(data);
    alertCount++;
    document.getElementById("alert-count").textContent = alertCount;
});

socket.on("jammer_update", (data) => updateJammerPanel(data));
socket.on("autoscan_changed", (data) => { autoScan = data.enabled; updateAutoScanBtn(); });
socket.on("range_changed", (data) => {
    const sel = document.getElementById("range-select");
    if (data.preset && sel) sel.value = data.preset;
});

// ── Fetch ───────────────────────────────────────────────────────

async function fetchStatus() {
    try {
        const res = await fetch("/api/status");
        const data = await res.json();
        updateAll(data);
    } catch (e) {
        console.error("[BlueShield] Status fetch failed:", e);
    }
}

function updateAll(data) {
    if (data.summary) updateSummaryCards(data.summary, data.cluster_summary);
    if (data.devices) currentDevices = data.devices;
    if (data.clustered_devices) currentClustered = data.clustered_devices;
    if (data.cluster_summary) currentClusterSummary = data.cluster_summary;
    renderDeviceTable();
    updateRSSIChart();
    updateCategoryChart();
    if (data.jammer) updateJammerPanel(data.jammer);
    if (data.alerts) updateAlertFeed(data.alerts);
    if (data.platform) updatePlatform(data.platform);
    if (data.auto_scan !== undefined) { autoScan = data.auto_scan; updateAutoScanBtn(); }
    if (data.scan_interval) {
        document.getElementById("scan-interval").value = data.scan_interval;
        document.getElementById("interval-value").textContent = data.scan_interval;
    }
    if (data.total_scans) document.getElementById("val-scans").textContent = data.total_scans;
}

// ── Summary Cards ───────────────────────────────────────────────

function updateSummaryCards(summary, clusterSummary) {
    if (!summary) return;
    const cs = clusterSummary || {};

    document.getElementById("val-physical").textContent = cs.total_physical_devices || summary.total_devices || 0;
    document.getElementById("val-macs").textContent = cs.total_mac_addresses || summary.total_devices || 0;
    document.getElementById("val-known").textContent = cs.known_devices || summary.known_devices || 0;
    document.getElementById("val-unknown").textContent = cs.unknown_devices || summary.unknown_devices || 0;
    document.getElementById("val-reduced").textContent = cs.mac_reduction || 0;
    document.getElementById("val-scans").textContent = summary.total_scans || 0;
}

// ── Device Table ────────────────────────────────────────────────

function renderDeviceTable() {
    if (viewMode === "clustered") {
        renderClusteredTable();
    } else {
        renderRawTable();
    }
}

function renderClusteredTable() {
    const headerRow = document.getElementById("table-header-row");
    headerRow.innerHTML = `
        <th>Device</th>
        <th>Name</th>
        <th>Category</th>
        <th>Manufacturer</th>
        <th>RSSI</th>
        <th>Signal</th>
        <th>MACs</th>
        <th>Seen For</th>
        <th>Status</th>
        <th>Action</th>
    `;

    const tbody = document.getElementById("device-table-body");
    const devices = currentClustered;
    document.getElementById("device-count").textContent = `${devices.length} device${devices.length !== 1 ? "s" : ""}`;
    document.getElementById("table-title").textContent = "Physical Devices (Fingerprinted)";

    if (!devices || devices.length === 0) {
        tbody.innerHTML = '<tr class="empty-row"><td colspan="10">No devices detected yet...</td></tr>';
        return;
    }

    tbody.innerHTML = devices.map(dev => {
        const alert = dev.alert_level || "none";
        const rowCls = alert === "critical" ? "row-critical" : alert === "warning" ? "row-warning" : dev.is_known ? "row-ok" : "";

        const rssi = Math.round(dev.avg_rssi || -100);
        const rssiPct = Math.max(0, Math.min(100, ((rssi + 100) / 60) * 100));
        const rssiColor = rssi > -50 ? "var(--green)" : rssi > -70 ? "var(--orange)" : "var(--red)";

        const alertTag = alert === "critical" ? '<span class="alert-tag critical">CRITICAL</span>'
            : alert === "warning" ? '<span class="alert-tag warning">UNKNOWN</span>'
            : '<span class="alert-tag ok">TRUSTED</span>';

        const action = !dev.is_known
            ? `<button class="btn-trust" onclick="trustFingerprint('${dev.fingerprint_id}')">Trust</button>`
            : '<span style="color:var(--green);font-size:0.7rem;">Trusted</span>';

        const icon = dev.category_icon || "";
        const cat = (dev.category || "unknown");
        const catDisplay = cat.charAt(0).toUpperCase() + cat.slice(1);

        const mfr = dev.manufacturer_name || "Unknown";
        const mfrShort = mfr.length > 18 ? mfr.substring(0, 16) + "\u2026" : mfr;

        const macCount = dev.mac_count || dev.mac_addresses?.length || 1;
        const fpShort = (dev.fingerprint_id || "").substring(0, 10);

        const dur = dev.duration_display || "--";

        return `<tr class="${rowCls}">
            <td><span class="mono" title="${dev.fingerprint_id}">${fpShort}</span></td>
            <td style="font-weight:500">${dev.best_name || "Unknown"}</td>
            <td><span class="cat-pill">${icon} ${catDisplay}</span></td>
            <td><span style="color:var(--text-secondary);font-size:0.75rem" title="${mfr}">${mfrShort}</span></td>
            <td class="mono">${rssi} dBm</td>
            <td><div class="rssi-bar"><div class="rssi-fill" style="width:${rssiPct}%;background:${rssiColor}"></div></div></td>
            <td><span class="mac-chip">${macCount} MAC${macCount > 1 ? "s" : ""}</span></td>
            <td><span class="dur-text">${dur}</span></td>
            <td>${alertTag}</td>
            <td>${action}</td>
        </tr>`;
    }).join("");
}

function renderRawTable() {
    const headerRow = document.getElementById("table-header-row");
    headerRow.innerHTML = `
        <th>Address</th>
        <th>Name</th>
        <th>Category</th>
        <th>Manufacturer</th>
        <th>Type</th>
        <th>RSSI</th>
        <th>Signal</th>
        <th>Alert</th>
        <th>Seen</th>
        <th>Action</th>
    `;

    const tbody = document.getElementById("device-table-body");
    const devices = currentDevices;
    document.getElementById("device-count").textContent = `${devices.length} MAC${devices.length !== 1 ? "s" : ""}`;
    document.getElementById("table-title").textContent = "Raw MAC Addresses";

    if (!devices || devices.length === 0) {
        tbody.innerHTML = '<tr class="empty-row"><td colspan="10">No devices detected yet...</td></tr>';
        return;
    }

    tbody.innerHTML = devices.map(dev => {
        const alert = dev.alert_level || "none";
        const rowCls = alert === "critical" ? "row-critical" : alert === "warning" ? "row-warning" : dev.is_known ? "row-ok" : "";

        const rssi = dev.rssi || -100;
        const rssiPct = Math.max(0, Math.min(100, ((rssi + 100) / 60) * 100));
        const rssiColor = rssi > -50 ? "var(--green)" : rssi > -70 ? "var(--orange)" : "var(--red)";

        const alertTag = alert === "critical" ? '<span class="alert-tag critical">CRITICAL</span>'
            : alert === "warning" ? '<span class="alert-tag warning">WARNING</span>'
            : '<span class="alert-tag ok">OK</span>';

        const action = !dev.is_known
            ? `<button class="btn-trust" onclick="whitelistDevice('${dev.address}')">Trust</button>`
            : '<span style="color:var(--green);font-size:0.7rem;">Trusted</span>';

        const icon = dev.category_icon || "";
        const cat = (dev.category || "unknown");
        const catDisplay = cat.charAt(0).toUpperCase() + cat.slice(1);

        const mfr = dev.manufacturer || "Unknown";
        const mfrShort = mfr.length > 18 ? mfr.substring(0, 16) + "\u2026" : mfr;

        return `<tr class="${rowCls}">
            <td><span class="mono">${dev.address}</span></td>
            <td style="font-weight:500">${dev.name || "Unknown"}</td>
            <td><span class="cat-pill">${icon} ${catDisplay}</span></td>
            <td><span style="color:var(--text-secondary);font-size:0.75rem" title="${mfr}">${mfrShort}</span></td>
            <td><span style="color:var(--blue)">${dev.device_type || "?"}</span></td>
            <td class="mono">${rssi} dBm</td>
            <td><div class="rssi-bar"><div class="rssi-fill" style="width:${rssiPct}%;background:${rssiColor}"></div></div></td>
            <td>${alertTag}</td>
            <td>${dev.seen_count || 0}</td>
            <td>${action}</td>
        </tr>`;
    }).join("");
}

// ── RSSI Chart ──────────────────────────────────────────────────

function updateRSSIChart() {
    const container = document.getElementById("rssi-chart");
    const devices = viewMode === "clustered" ? currentClustered : currentDevices;

    if (!devices || devices.length === 0) {
        container.innerHTML = '<div class="empty-msg">No devices detected</div>';
        return;
    }

    const sorted = [...devices]
        .filter(d => {
            const r = viewMode === "clustered" ? d.avg_rssi : d.rssi;
            return r && r !== 0 && r > -100;
        })
        .sort((a, b) => {
            const ra = viewMode === "clustered" ? (b.avg_rssi || -100) : (b.rssi || -100);
            const rb = viewMode === "clustered" ? (a.avg_rssi || -100) : (a.rssi || -100);
            return ra - rb;
        })
        .slice(0, 8);

    if (sorted.length === 0) {
        container.innerHTML = '<div class="empty-msg">No RSSI data</div>';
        return;
    }

    container.innerHTML = sorted.map(dev => {
        const rssi = Math.round(viewMode === "clustered" ? (dev.avg_rssi || -100) : (dev.rssi || -100));
        const pct = Math.max(0, Math.min(100, ((rssi + 100) / 60) * 100));
        const color = rssi > -50 ? "var(--green)" : rssi > -70 ? "var(--orange)" : "var(--red)";
        const icon = dev.category_icon || "";
        const name = (viewMode === "clustered" ? dev.best_name : dev.name) || "Unknown";
        const nameShort = name.substring(0, 14);

        return `<div class="rssi-row">
            <span class="rssi-name">${icon} ${nameShort}</span>
            <div class="rssi-bar-outer">
                <div class="rssi-bar-inner" style="width:${pct}%;background:${color}"></div>
            </div>
            <span class="rssi-val">${rssi} dBm</span>
        </div>`;
    }).join("");
}

// ── Category Chart ──────────────────────────────────────────────

const CAT_ICONS = {
    phone: "\ud83d\udcf1", tablet: "\ud83d\udcf1", computer: "\ud83d\udcbb",
    input: "\ud83d\uddb1\ufe0f", audio: "\ud83c\udfa7", watch: "\u231a",
    health: "\u2764\ufe0f", fitness: "\ud83c\udfc3", tv: "\ud83d\udcfa",
    tracker: "\ud83d\udccd", gaming: "\ud83c\udfae", iot: "\ud83d\udca1",
    apple: "\ud83c\udf4e", nearby: "\ud83d\udcf6", generic: "\ud83d\udce1",
    unknown: "\u2753",
};

function updateCategoryChart() {
    const container = document.getElementById("category-chart");
    const cats = currentClusterSummary.categories || {};

    if (Object.keys(cats).length === 0) {
        container.innerHTML = '<div class="empty-msg">No data yet</div>';
        return;
    }

    const sorted = Object.entries(cats).sort((a, b) => b[1] - a[1]);
    container.innerHTML = sorted.map(([cat, count]) => {
        const icon = CAT_ICONS[cat] || "\u2753";
        return `<div class="cat-row">
            <span class="cat-icon">${icon}</span>
            <span class="cat-name">${cat}</span>
            <span class="cat-count">${count}</span>
        </div>`;
    }).join("");
}

// ── Jammer Panel ────────────────────────────────────────────────

function updateJammerPanel(status) {
    if (!status) return;
    isJamming = status.is_jamming;

    const btn = document.getElementById("btn-jam-toggle");
    const stats = document.getElementById("jammer-stats");
    const pill = document.getElementById("pill-jammer");

    if (isJamming) {
        btn.textContent = "Stop Jammer";
        btn.classList.add("active");
        pill.classList.add("jamming");
        document.getElementById("jammer-status-text").textContent = "Jamming";
        stats.style.display = "block";

        if (status.active_session) {
            document.getElementById("jam-packets").textContent = status.active_session.packets_sent || 0;
            document.getElementById("jam-mode-display").textContent = status.active_session.mode || "--";
            document.getElementById("jam-channel-display").textContent = status.active_session.channel || "--";
        }
    } else {
        btn.textContent = "Start Jammer";
        btn.classList.remove("active");
        pill.classList.remove("jamming");
        document.getElementById("jammer-status-text").textContent = "Jammer Off";
        stats.style.display = "none";
    }

    const backendEl = document.getElementById("jam-backend-display");
    if (backendEl && status.backend) {
        backendEl.textContent = status.backend === "raw_hci" ? "Raw HCI" : "hcitool";
    }
}

// ── Alerts ───────────────────────────────────────────────────────

function updateAlertFeed(alerts) {
    const feed = document.getElementById("alert-feed");
    if (!alerts || alerts.length === 0) {
        feed.innerHTML = '<div class="empty-msg">No alerts. System clean.</div>';
        alertCount = 0;
        document.getElementById("alert-count").textContent = "0";
        return;
    }

    alertCount = alerts.length;
    document.getElementById("alert-count").textContent = alertCount;

    feed.innerHTML = [...alerts].reverse().map(alert => {
        const data = alert.data || {};
        const level = data.level || "info";
        const msg = data.message || "Unknown alert";
        const ts = fmtTime(alert.timestamp);
        return `<div class="alert-entry">
            <span class="alert-time">${ts}</span>
            <span class="alert-lvl ${level}">${level}</span>
            <span class="alert-msg">${msg}</span>
        </div>`;
    }).join("");

    feed.scrollTop = 0;
}

function addAlertEntry(alert) {
    const feed = document.getElementById("alert-feed");
    const empty = feed.querySelector(".empty-msg");
    if (empty) empty.remove();

    const data = alert.data || {};
    const level = data.level || "info";
    const msg = data.message || "Unknown alert";
    const ts = fmtTime(alert.timestamp);

    const entry = document.createElement("div");
    entry.className = "alert-entry";
    entry.innerHTML = `<span class="alert-time">${ts}</span><span class="alert-lvl ${level}">${level}</span><span class="alert-msg">${msg}</span>`;
    feed.insertBefore(entry, feed.firstChild);
    while (feed.children.length > 50) feed.removeChild(feed.lastChild);
}

function updatePlatform(info) {
    const pill = document.getElementById("pill-platform");
    if (info.os === "Linux" && info.has_hcitool) pill.textContent = "RPi FULL";
    else if (info.os === "Linux") pill.textContent = "LINUX BLE";
    else if (info.os === "Windows") pill.textContent = "WIN BLE";
    else pill.textContent = info.os;
}

function updateAutoScanBtn() {
    const btn = document.getElementById("btn-autoscan");
    btn.textContent = autoScan ? "Auto: ON" : "Auto: OFF";
    btn.classList.toggle("active", autoScan);
}

// ── User Actions ────────────────────────────────────────────────

document.getElementById("btn-scan").addEventListener("click", async () => {
    const btn = document.getElementById("btn-scan");
    btn.innerHTML = '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg> Scanning...';
    btn.disabled = true;
    try { await fetch("/api/scan", { method: "POST" }); } catch (e) { console.error(e); }
    setTimeout(() => {
        btn.innerHTML = '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg> Scan Now';
        btn.disabled = false;
    }, 2000);
});

document.getElementById("btn-autoscan").addEventListener("click", () => {
    autoScan = !autoScan;
    socket.emit("toggle_autoscan", { enabled: autoScan });
    updateAutoScanBtn();
});

document.getElementById("scan-interval").addEventListener("input", (e) => {
    const val = parseInt(e.target.value);
    document.getElementById("interval-value").textContent = val;
    socket.emit("set_scan_interval", { interval: val });
});

// Range selector
document.getElementById("range-select").addEventListener("change", async (e) => {
    const preset = e.target.value;
    await fetch("/api/range", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ preset }),
    });
});

// View toggle
document.getElementById("btn-view-clustered").addEventListener("click", () => {
    viewMode = "clustered";
    document.getElementById("btn-view-clustered").classList.add("active");
    document.getElementById("btn-view-raw").classList.remove("active");
    renderDeviceTable();
    updateRSSIChart();
});

document.getElementById("btn-view-raw").addEventListener("click", () => {
    viewMode = "raw";
    document.getElementById("btn-view-raw").classList.add("active");
    document.getElementById("btn-view-clustered").classList.remove("active");
    renderDeviceTable();
    updateRSSIChart();
});

// Jammer
document.getElementById("btn-jam-toggle").addEventListener("click", async () => {
    if (isJamming) {
        await fetch("/api/jammer/stop", { method: "POST" });
    } else {
        const mode = document.getElementById("jammer-mode").value;
        const channel = document.getElementById("jammer-channel").value;
        const target = document.getElementById("jammer-target")?.value?.trim() || "";
        await fetch("/api/jammer/start", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ mode, channel: parseInt(channel), target }),
        });
    }
});

const jammerMode = document.getElementById("jammer-mode");
if (jammerMode) {
    jammerMode.addEventListener("change", () => {
        const tg = document.getElementById("target-group");
        if (tg) tg.style.display = jammerMode.value === "targeted" ? "block" : "none";
    });
}

// Export & Reset
document.getElementById("btn-export").addEventListener("click", async () => {
    const btn = document.getElementById("btn-export");
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
    } catch (e) { console.error(e); }
    setTimeout(() => { btn.textContent = "Export Report"; }, 1500);
});

document.getElementById("btn-reset").addEventListener("click", async () => {
    if (confirm("Reset all discovered devices and scan history?")) {
        await fetch("/api/reset", { method: "POST" });
        alertCount = 0;
        document.getElementById("alert-count").textContent = "0";
        document.getElementById("alert-feed").innerHTML = '<div class="empty-msg">No alerts. System clean.</div>';
    }
});

// Trust actions
async function trustFingerprint(fpId) {
    await fetch("/api/whitelist", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ fingerprint_id: fpId }),
    });
}

async function whitelistDevice(address) {
    await fetch("/api/whitelist", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ address }),
    });
}

// ── Utilities ───────────────────────────────────────────────────

function fmtTime(iso) {
    if (!iso) return "--:--";
    try {
        return new Date(iso).toLocaleTimeString("en-US", { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" });
    } catch { return iso.substring(11, 19); }
}

// Clock
setInterval(() => {
    document.getElementById("clock").textContent = new Date().toLocaleTimeString("en-US", { hour12: false });
}, 1000);

// Jammer stats refresh
setInterval(async () => {
    if (isJamming) {
        try {
            const res = await fetch("/api/jammer");
            const data = await res.json();
            updateJammerPanel(data);
        } catch {}
    }
}, 1000);

// Fallback poll
setInterval(fetchStatus, 15000);
