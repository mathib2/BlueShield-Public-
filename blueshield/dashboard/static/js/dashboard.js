/* ═══════════════════════════════════════════════════════════════════
   BlueShield Dashboard — Client-Side Logic
   ═══════════════════════════════════════════════════════════════════ */

const socket = io();

// ── State ───────────────────────────────────────────────────────

let autoScan = true;
let isJamming = false;
let alertCount = 0;

// ── Socket.IO Events ────────────────────────────────────────────

socket.on("connect", () => {
    console.log("[BlueShield] Connected to server");
    document.getElementById("scanner-status").textContent = "CONNECTED";
    document.getElementById("scanner-status").classList.add("scanning");
    fetchStatus();
});

socket.on("disconnect", () => {
    document.getElementById("scanner-status").textContent = "DISCONNECTED";
    document.getElementById("scanner-status").classList.remove("scanning");
});

socket.on("status", (data) => {
    updateSummaryCards(data.summary);
    updateDeviceTable(data.devices);
    updateJammerPanel(data.jammer);
    updateAlertFeed(data.alerts);
    if (data.platform) updatePlatform(data.platform);
    autoScan = data.auto_scan;
    updateAutoScanButton();
});

socket.on("scan_result", (data) => {
    document.getElementById("scanner-status").textContent = "SCANNING";
    document.getElementById("scanner-status").classList.add("scanning");
    setTimeout(() => {
        document.getElementById("scanner-status").textContent = "IDLE";
        document.getElementById("scanner-status").classList.remove("scanning");
    }, 2000);
});

socket.on("device_update", (data) => {
    updateSummaryCards(data.summary);
    updateDeviceTable(data.devices);
    updateRSSIChart(data.devices);
});

socket.on("alert", (data) => {
    addAlertEntry(data);
    alertCount++;
    document.getElementById("alert-count").textContent = alertCount;
});

socket.on("jammer_update", (data) => {
    updateJammerPanel(data);
});

socket.on("autoscan_changed", (data) => {
    autoScan = data.enabled;
    updateAutoScanButton();
});

// ── Fetch Helpers ───────────────────────────────────────────────

async function fetchStatus() {
    try {
        const res = await fetch("/api/status");
        const data = await res.json();
        updateSummaryCards(data.summary);
        updateDeviceTable(data.devices);
        updateRSSIChart(data.devices);
        updateJammerPanel(data.jammer);
        updateAlertFeed(data.alerts);
        if (data.platform) updatePlatform(data.platform);
        document.getElementById("card-scans").querySelector(".card-value").textContent = data.total_scans || 0;
    } catch (e) {
        console.error("[BlueShield] Status fetch failed:", e);
    }
}

// ── UI Update Functions ─────────────────────────────────────────

function updateSummaryCards(summary) {
    if (!summary) return;
    const set = (id, val) => {
        const el = document.getElementById(id);
        if (el) el.querySelector(".card-value").textContent = val;
    };
    set("card-total", summary.total_devices || 0);
    set("card-known", summary.known_devices || 0);
    set("card-unknown", summary.unknown_devices || 0);
    set("card-scans", summary.total_scans || 0);

    const critVal = (summary.critical_alerts || 0) + (summary.warning_alerts || 0);
    set("card-alerts", critVal);
    const alertEl = document.getElementById("card-alerts").querySelector(".card-value");
    if (critVal > 0) {
        alertEl.classList.add("danger");
    } else {
        alertEl.classList.remove("danger");
    }
}

function updateDeviceTable(devices) {
    const tbody = document.getElementById("device-table-body");
    if (!devices || devices.length === 0) {
        tbody.innerHTML = '<tr class="empty-row"><td colspan="10">No devices detected yet...</td></tr>';
        return;
    }

    tbody.innerHTML = devices.map(dev => {
        const alert = dev.alert_level || "none";
        const rowClass = alert === "critical" ? "alert-critical"
            : alert === "warning" ? "alert-warning"
            : dev.is_known ? "alert-ok" : "";

        const rssi = dev.rssi || -100;
        const rssiPct = Math.max(0, Math.min(100, ((rssi + 100) / 70) * 100));
        const rssiColor = rssi > -50 ? "var(--green)"
            : rssi > -70 ? "var(--orange)" : "var(--red)";

        const alertBadge = alert === "critical"
            ? '<span class="alert-badge critical">CRITICAL</span>'
            : alert === "warning"
            ? '<span class="alert-badge warning">WARNING</span>'
            : '<span class="alert-badge ok">OK</span>';

        const actionBtn = !dev.is_known
            ? `<button class="btn-whitelist" onclick="whitelistDevice('${dev.address}')">Trust</button>`
            : '<span style="color:var(--green);font-size:0.7rem;">Trusted</span>';

        // Category with icon
        const catIcon = dev.category_icon || "&#10067;";
        const catName = (dev.category || "unknown");
        const catDisplay = catName.charAt(0).toUpperCase() + catName.slice(1);

        // Manufacturer (truncate if long)
        const mfr = dev.manufacturer || "Unknown";
        const mfrShort = mfr.length > 18 ? mfr.substring(0, 16) + "\u2026" : mfr;

        return `<tr class="${rowClass}">
            <td><span class="mono">${dev.address}</span></td>
            <td style="color:var(--text-primary)">${dev.name || "Unknown"}</td>
            <td><span class="cat-badge">${catIcon} ${catDisplay}</span></td>
            <td><span style="color:var(--text-secondary);font-size:0.75rem;" title="${mfr}">${mfrShort}</span></td>
            <td><span style="color:var(--cyan)">${dev.device_type || "?"}</span></td>
            <td>${rssi} dBm</td>
            <td>
                <div class="rssi-bar-container">
                    <div class="rssi-bar-fill" style="width:${rssiPct}%;background:${rssiColor}"></div>
                </div>
            </td>
            <td>${alertBadge}</td>
            <td>${dev.seen_count || 0}</td>
            <td>${actionBtn}</td>
        </tr>`;
    }).join("");
}

function updateRSSIChart(devices) {
    const container = document.getElementById("rssi-chart");
    if (!devices || devices.length === 0) {
        container.innerHTML = '<div class="empty-state">No devices detected</div>';
        return;
    }

    // Sort by RSSI (strongest first), take top 8
    const sorted = [...devices]
        .filter(d => d.rssi && d.rssi !== 0)
        .sort((a, b) => (b.rssi || -100) - (a.rssi || -100))
        .slice(0, 8);

    if (sorted.length === 0) {
        container.innerHTML = '<div class="empty-state">No RSSI data</div>';
        return;
    }

    container.innerHTML = sorted.map(dev => {
        const rssi = dev.rssi || -100;
        const pct = Math.max(0, Math.min(100, ((rssi + 100) / 70) * 100));
        const icon = dev.category_icon || "";
        const name = (dev.name || dev.address).substring(0, 14);
        const bgPos = `${100 - pct}%`;

        return `<div class="rssi-row">
            <span class="rssi-name">${icon} ${name}</span>
            <div class="rssi-bar-outer">
                <div class="rssi-bar-inner" style="width:${pct}%;background-position:${bgPos} 0"></div>
            </div>
            <span class="rssi-value">${rssi} dBm</span>
        </div>`;
    }).join("");
}

function updateJammerPanel(status) {
    if (!status) return;
    isJamming = status.is_jamming;

    const btn = document.getElementById("btn-jam-toggle");
    const stats = document.getElementById("jammer-stats");
    const badge = document.getElementById("jammer-status-badge");

    if (isJamming) {
        btn.textContent = "Stop Jammer";
        btn.classList.add("active");
        badge.textContent = "JAMMING";
        badge.classList.add("jamming");
        stats.style.display = "block";

        if (status.active_session) {
            document.getElementById("jam-packets").textContent = status.active_session.packets_sent || 0;
            document.getElementById("jam-mode-display").textContent = status.active_session.mode || "--";
            document.getElementById("jam-channel-display").textContent = status.active_session.channel || "--";
        }
    } else {
        btn.textContent = "Start Jammer";
        btn.classList.remove("active");
        badge.textContent = "JAMMER OFF";
        badge.classList.remove("jamming");
        stats.style.display = "none";
    }

    // Show backend type
    const backendEl = document.getElementById("jam-backend-display");
    if (backendEl && status.backend) {
        backendEl.textContent = status.backend === "raw_hci" ? "Raw HCI (Fast)" : "hcitool";
    }
}

function updateAlertFeed(alerts) {
    const feed = document.getElementById("alert-feed");
    if (!alerts || alerts.length === 0) {
        feed.innerHTML = '<div class="empty-state">No alerts. System clean.</div>';
        alertCount = 0;
        document.getElementById("alert-count").textContent = "0";
        return;
    }

    alertCount = alerts.length;
    document.getElementById("alert-count").textContent = alertCount;

    feed.innerHTML = alerts.reverse().map(alert => {
        const data = alert.data || {};
        const level = data.level || "info";
        const msg = data.message || "Unknown alert";
        const ts = formatTime(alert.timestamp);

        return `<div class="alert-entry">
            <span class="alert-time">${ts}</span>
            <span class="alert-level ${level}">${level}</span>
            <span class="alert-msg">${msg}</span>
        </div>`;
    }).join("");

    feed.scrollTop = 0;
}

function addAlertEntry(alert) {
    const feed = document.getElementById("alert-feed");
    const empty = feed.querySelector(".empty-state");
    if (empty) empty.remove();

    const data = alert.data || {};
    const level = data.level || "info";
    const msg = data.message || "Unknown alert";
    const ts = formatTime(alert.timestamp);

    const entry = document.createElement("div");
    entry.className = "alert-entry";
    entry.innerHTML = `
        <span class="alert-time">${ts}</span>
        <span class="alert-level ${level}">${level}</span>
        <span class="alert-msg">${msg}</span>
    `;
    feed.insertBefore(entry, feed.firstChild);

    while (feed.children.length > 50) {
        feed.removeChild(feed.lastChild);
    }
}

function updatePlatform(info) {
    const badge = document.getElementById("platform-badge");
    if (info.os === "Linux" && info.has_hcitool) {
        badge.textContent = "RPi FULL";
    } else if (info.os === "Linux") {
        badge.textContent = "LINUX BLE";
    } else if (info.os === "Windows") {
        badge.textContent = "WIN BLE";
    } else {
        badge.textContent = info.os;
    }
}

function updateAutoScanButton() {
    const btn = document.getElementById("btn-autoscan");
    if (autoScan) {
        btn.textContent = "Auto: ON";
        btn.classList.add("active");
    } else {
        btn.textContent = "Auto: OFF";
        btn.classList.remove("active");
    }
}

// ── User Actions ────────────────────────────────────────────────

document.getElementById("btn-scan").addEventListener("click", async () => {
    const btn = document.getElementById("btn-scan");
    btn.textContent = "Scanning...";
    btn.disabled = true;
    try {
        await fetch("/api/scan", { method: "POST" });
    } catch (e) {
        console.error("Scan failed:", e);
    }
    setTimeout(() => {
        btn.textContent = "Scan Now";
        btn.disabled = false;
    }, 2000);
});

document.getElementById("btn-autoscan").addEventListener("click", () => {
    autoScan = !autoScan;
    socket.emit("toggle_autoscan", { enabled: autoScan });
    updateAutoScanButton();
});

document.getElementById("scan-interval").addEventListener("input", (e) => {
    const val = parseInt(e.target.value);
    document.getElementById("interval-value").textContent = val;
    socket.emit("set_scan_interval", { interval: val });
});

document.getElementById("btn-jam-toggle").addEventListener("click", async () => {
    if (isJamming) {
        await fetch("/api/jammer/stop", { method: "POST" });
    } else {
        const mode = document.getElementById("jammer-mode").value;
        const channel = document.getElementById("jammer-channel").value;
        const targetInput = document.getElementById("jammer-target");
        const target = targetInput ? targetInput.value.trim() : "";
        await fetch("/api/jammer/start", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ mode, channel: parseInt(channel), target }),
        });
    }
});

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
    } catch (e) {
        console.error("Export failed:", e);
    }
    setTimeout(() => { btn.textContent = "Export Report"; }, 1500);
});

document.getElementById("btn-reset").addEventListener("click", async () => {
    if (confirm("Reset all discovered devices and scan history?")) {
        await fetch("/api/reset", { method: "POST" });
        alertCount = 0;
        document.getElementById("alert-count").textContent = "0";
        document.getElementById("alert-feed").innerHTML = '<div class="empty-state">No alerts. System clean.</div>';
    }
});

async function whitelistDevice(address) {
    await fetch("/api/whitelist", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ address }),
    });
}

// ── Jammer mode toggle for target input ─────────────────────────

const jammerModeSelect = document.getElementById("jammer-mode");
if (jammerModeSelect) {
    jammerModeSelect.addEventListener("change", () => {
        const targetGroup = document.getElementById("target-group");
        if (targetGroup) {
            targetGroup.style.display = jammerModeSelect.value === "targeted" ? "block" : "none";
        }
    });
}

// ── Utilities ───────────────────────────────────────────────────

function formatTime(iso) {
    if (!iso) return "--:--";
    try {
        const d = new Date(iso);
        return d.toLocaleTimeString("en-US", { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" });
    } catch {
        return iso.substring(11, 19);
    }
}

// Clock
setInterval(() => {
    document.getElementById("clock").textContent = new Date().toLocaleTimeString("en-US", { hour12: false });
}, 1000);

// Periodic jammer stats refresh
setInterval(async () => {
    if (isJamming) {
        try {
            const res = await fetch("/api/jammer");
            const data = await res.json();
            updateJammerPanel(data);
        } catch {}
    }
}, 1000);

// Fallback status poll
setInterval(fetchStatus, 15000);
