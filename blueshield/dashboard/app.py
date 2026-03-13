"""
BlueShield Web Dashboard v4.0

Flask + Socket.IO backend for the BlueShield Bluetooth security monitor.
Serves a real-time web dashboard with BLE fingerprinting, risk scoring,
tracker detection, proximity radar, and exposes REST/WebSocket APIs.

Run: python -m blueshield [--sim] [--port 8080]
"""

import asyncio
import argparse
import platform
import shutil
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, jsonify, request, send_file
from flask_socketio import SocketIO

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from blueshield.config.settings import load_config, save_config, LOG_DIR
from blueshield.scanner.bt_scanner import BluetoothScanner, SimulatedScanner
from blueshield.scanner.fingerprint import BLEFingerprintEngine
from blueshield.scanner.risk_engine import calculate_risk, calculate_rssi_trend
from blueshield.scanner.tracker_detector import TrackerDetector
from blueshield.scanner.ai_classifier import AIDeviceClassifier, estimate_people, calculate_safety_score, get_bluetooth_weather
from blueshield.jammer.bt_jammer import BluetoothJammer, SimulatedJammer
from blueshield.logs.logger import BlueShieldLogger


# ── App Setup ────────────────────────────────────────────────────────────────

STATIC_DIR = Path(__file__).parent / "static"

app = Flask(__name__, static_folder=str(STATIC_DIR), static_url_path="/static")
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# Global state
scanner = None
jammer = None
logger = None
config = None
fingerprint_engine = None
tracker_detector = None
ai_classifier = None
auto_scan = True
scan_interval = 5
rssi_filter = -100  # default: all devices
platform_info = {}
_scan_lock = threading.Lock()

# Configurable alert rules
alert_rules = [
    {"id": "unknown_close", "enabled": True, "name": "Unknown Close Proximity",
     "condition": "rssi > -50 AND unknown", "message": "Unknown device in close proximity"},
    {"id": "long_presence", "enabled": True, "name": "Long Presence",
     "condition": "duration > 1800 AND unknown", "message": "Device present for >30 minutes"},
    {"id": "mac_rotation", "enabled": True, "name": "MAC Rotation",
     "condition": "mac_count > 3", "message": "Rapid MAC rotation detected"},
    {"id": "tracker_detected", "enabled": True, "name": "Tracker Detected",
     "condition": "tracker_suspect", "message": "Possible tracker detected"},
    {"id": "approaching", "enabled": True, "name": "Approaching Device",
     "condition": "approaching AND unknown", "message": "Unknown device approaching"},
    {"id": "critical_risk", "enabled": True, "name": "Critical Risk",
     "condition": "risk_level == critical", "message": "Critical risk device detected"},
]

# Device watch list (alert when device re-appears)
watch_list = set()

# Time-travel snapshot history (stores last N scan snapshots)
scan_snapshots = []
MAX_SNAPSHOTS = 120  # ~10 minutes at 5s interval

# Range presets: name -> RSSI threshold
RANGE_PRESETS = {
    "all":    -100,  # Everything
    "far":    -90,   # Up to ~30m
    "mid":    -75,   # Up to ~10m
    "close":  -60,   # Up to ~3m
    "immediate": -45, # Within ~1m
}


def detect_platform():
    """Detect available Bluetooth capabilities."""
    info = {
        "os": platform.system(),
        "hostname": platform.node(),
        "has_bleak": False,
        "has_hcitool": False,
        "has_hcidump": False,
    }
    try:
        import bleak
        info["has_bleak"] = True
    except ImportError:
        pass
    if platform.system() == "Linux":
        info["has_hcitool"] = shutil.which("hcitool") is not None
        info["has_hcidump"] = shutil.which("hcidump") is not None
    return info


def run_async(coro):
    """Run an async coroutine in a dedicated thread with its own event loop."""
    result = [None]
    exception = [None]

    def _run():
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                result[0] = loop.run_until_complete(coro)
            finally:
                loop.close()
        except Exception as e:
            exception[0] = e

    t = threading.Thread(target=_run)
    t.start()
    t.join(timeout=60)
    if exception[0]:
        raise exception[0]
    return result[0]


def evaluate_alert_rules(device_fp):
    """Check if a device triggers any alert rules."""
    triggered = []
    for rule in alert_rules:
        if not rule["enabled"]:
            continue

        hit = False
        rid = rule["id"]

        if rid == "unknown_close":
            if not device_fp.is_known and device_fp.avg_rssi > -50:
                hit = True
        elif rid == "long_presence":
            duration = device_fp.last_seen - device_fp.first_seen
            if not device_fp.is_known and duration > 1800:
                hit = True
        elif rid == "mac_rotation":
            if len(device_fp.mac_addresses) > 3:
                hit = True
        elif rid == "tracker_detected":
            if device_fp.tracker_suspect:
                hit = True
        elif rid == "approaching":
            if device_fp.rssi_trend == "approaching" and not device_fp.is_known:
                hit = True
        elif rid == "critical_risk":
            if device_fp.risk_level == "critical":
                hit = True

        if hit:
            triggered.append({
                "rule_id": rid,
                "rule_name": rule["name"],
                "message": rule["message"],
                "device_id": device_fp.fingerprint_id,
                "device_name": device_fp.best_name,
            })

    # Check watch list
    if device_fp.fingerprint_id in watch_list:
        triggered.append({
            "rule_id": "watch_return",
            "rule_name": "Watch List Return",
            "message": f"Watched device returned: {device_fp.best_name}",
            "device_id": device_fp.fingerprint_id,
            "device_name": device_fp.best_name,
        })

    return triggered


def do_scan_and_emit():
    """Execute a scan, feed fingerprint engine, run risk/tracker analysis, emit results."""
    global fingerprint_engine
    with _scan_lock:
        try:
            result = run_async(scanner.run_scan(rssi_filter=rssi_filter))
            logger.log_scan(result)

            # Feed advertisement data into fingerprint engine
            for dev_dict in result.get("devices_found", []):
                addr = dev_dict.get("address", "")
                rssi = dev_dict.get("rssi", 0)
                name = dev_dict.get("name", "Unknown")
                manufacturer = dev_dict.get("manufacturer", "Unknown")
                category = dev_dict.get("category", "unknown")
                category_icon = dev_dict.get("category_icon", "")
                svc_uuids = dev_dict.get("service_uuids", [])
                tx_power = dev_dict.get("tx_power", 0)

                # Get fingerprint data from scanner if available
                mfr_id = 0
                payload_len = 0
                mfr_data_bytes = b""
                raw_adv_data = {}
                dev_obj = scanner.devices.get(addr.upper())
                if dev_obj and hasattr(dev_obj, '_fingerprint_data'):
                    fp_data = dev_obj._fingerprint_data
                    mfr_id = fp_data.get("manufacturer_id", 0)
                    payload_len = fp_data.get("payload_len", 0)
                    mfr_data_bytes = fp_data.get("mfr_data_bytes", b"")
                    raw_adv_data = fp_data.get("raw_adv_data", {})

                fingerprint_engine.record_advertisement(
                    mac=addr,
                    rssi=rssi,
                    payload_len=payload_len,
                    manufacturer_id=mfr_id,
                    service_uuids=svc_uuids,
                    name=name,
                    tx_power=tx_power,
                    category=category,
                    category_icon=category_icon,
                    manufacturer_name=manufacturer,
                    mfr_data_bytes=mfr_data_bytes,
                    raw_adv_data=raw_adv_data,
                )

            # Run clustering
            fingerprint_engine.run_clustering()

            # ── Run risk scoring and tracker detection on each cluster ──
            tracker_suspects = []
            rule_alerts = []

            for fp_id, fp in fingerprint_engine.clusters.items():
                rssi_hist = fingerprint_engine.get_rssi_history(fp_id)

                # Risk assessment
                risk = calculate_risk(
                    fingerprint_id=fp_id,
                    name=fp.best_name,
                    manufacturer_id=fp.manufacturer_id,
                    manufacturer_name=fp.manufacturer_name,
                    is_known=fp.is_known,
                    mac_count=len(fp.mac_addresses),
                    rssi_history=rssi_hist,
                    first_seen=fp.first_seen,
                    last_seen=fp.last_seen,
                    observation_count=fp.observation_count,
                    avg_rssi=fp.avg_rssi,
                    service_uuids=fp.service_uuids,
                    tracker_suspect=fp.tracker_suspect,
                    category=fp.category,
                )
                fp.risk_score = risk.score
                fp.risk_level = risk.level
                fp.risk_factors = risk.factors
                fp.rssi_trend = risk.rssi_trend
                fp.movement_indicator = risk.rssi_trend

                # Tracker detection
                suspect = tracker_detector.evaluate_device(
                    device_id=fp_id,
                    name=fp.best_name,
                    manufacturer_id=fp.manufacturer_id,
                    service_uuids=fp.service_uuids,
                    payload_len=int(fp.avg_payload_len),
                    rssi_history=rssi_hist,
                    first_seen=fp.first_seen,
                    last_seen=fp.last_seen,
                    mfr_data_bytes=b"",  # Already evaluated from raw
                    category=fp.category,
                )
                if suspect:
                    fp.tracker_suspect = True
                    fp.tracker_type = suspect.tracker_type
                    fp.tracker_confidence = suspect.confidence
                    # Re-evaluate risk with tracker flag
                    risk = calculate_risk(
                        fingerprint_id=fp_id,
                        name=fp.best_name,
                        manufacturer_id=fp.manufacturer_id,
                        manufacturer_name=fp.manufacturer_name,
                        is_known=fp.is_known,
                        mac_count=len(fp.mac_addresses),
                        rssi_history=rssi_hist,
                        first_seen=fp.first_seen,
                        last_seen=fp.last_seen,
                        observation_count=fp.observation_count,
                        avg_rssi=fp.avg_rssi,
                        service_uuids=fp.service_uuids,
                        tracker_suspect=True,
                        category=fp.category,
                    )
                    fp.risk_score = risk.score
                    fp.risk_level = risk.level
                    fp.risk_factors = risk.factors
                    tracker_suspects.append(suspect.to_dict())
                else:
                    fp.tracker_suspect = False

                # Evaluate alert rules
                alerts = evaluate_alert_rules(fp)
                rule_alerts.extend(alerts)

            # Feed analytics tracker
            fp_ids = list(fingerprint_engine.clusters.keys())
            device_count = len(fp_ids)
            logger.analytics.record_scan(fp_ids, device_count)

            # Emit basic alerts
            if result.get("unknown_devices", 0) > 0:
                alert_data = {
                    "level": result["alert_status"],
                    "message": f"{result['unknown_devices']} unknown device(s) detected",
                    "devices": [d for d in result["devices_found"] if not d.get("is_known")],
                }
                logger.log_alert(result["alert_status"], alert_data["message"], alert_data["devices"])
                socketio.emit("alert", {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "data": alert_data,
                })

            # Emit rule-based alerts
            for ra in rule_alerts:
                socketio.emit("alert", {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "data": {
                        "level": "warning" if "critical" not in ra["rule_id"] else "critical",
                        "message": ra["message"],
                        "rule_id": ra["rule_id"],
                        "device_id": ra["device_id"],
                        "device_name": ra["device_name"],
                    },
                })

            socketio.emit("scan_result", result)

            # Emit comprehensive device update
            clustered = fingerprint_engine.get_clustered_devices()
            cluster_summary = fingerprint_engine.get_cluster_summary()
            analytics_summary = logger.analytics.get_summary()

            # ── AI Classification, People Detection, Safety, Weather ──
            classifications = {}
            for fp_id, fp in fingerprint_engine.clusters.items():
                cr = ai_classifier.classify(
                    device_id=fp_id, name=fp.best_name, category=fp.category,
                    ecosystem=fp.ecosystem or "", manufacturer_id=fp.manufacturer_id,
                    manufacturer_name=fp.manufacturer_name,
                    service_uuids=fp.service_uuids, payload_len=int(fp.avg_payload_len),
                    avg_rssi=fp.avg_rssi, is_known=fp.is_known,
                    tracker_suspect=fp.tracker_suspect,
                    mac_count=len(fp.mac_addresses),
                )
                classifications[fp_id] = cr.to_dict()

            people = estimate_people(clustered)
            safety = calculate_safety_score(clustered, len(tracker_suspects))
            weather = get_bluetooth_weather(clustered, analytics_summary)

            # ── Time travel snapshot ──
            snapshot = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "devices": [{
                    "fingerprint_id": d.get("fingerprint_id"),
                    "best_name": d.get("best_name"),
                    "category": d.get("category"),
                    "category_icon": d.get("category_icon"),
                    "avg_rssi": d.get("avg_rssi"),
                    "risk_level": d.get("risk_level"),
                    "risk_score": d.get("risk_score"),
                    "rssi_trend": d.get("rssi_trend"),
                    "ecosystem": d.get("ecosystem"),
                    "is_known": d.get("is_known"),
                    "tracker_suspect": d.get("tracker_suspect"),
                } for d in clustered],
                "people_count": people["estimated_people"],
                "safety_score": safety["score"],
                "device_count": len(clustered),
            }
            scan_snapshots.append(snapshot)
            if len(scan_snapshots) > MAX_SNAPSHOTS:
                scan_snapshots.pop(0)

            socketio.emit("device_update", {
                "summary": scanner.get_device_summary(),
                "devices": scanner.get_all_devices(),
                "clustered_devices": clustered,
                "cluster_summary": cluster_summary,
                "tracker_suspects": tracker_suspects,
                "analytics": analytics_summary,
                "classifications": classifications,
                "people": people,
                "safety": safety,
                "weather": weather,
            })
            return result
        except Exception as e:
            print(f"[BlueShield] Scan error: {e}")
            import traceback
            traceback.print_exc()
            return {"error": str(e)}


# ── Routes ───────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return send_file(str(STATIC_DIR / "index.html"))


@app.route("/api/status")
def api_status():
    clustered = fingerprint_engine.get_clustered_devices() if fingerprint_engine else []
    cluster_summary = fingerprint_engine.get_cluster_summary() if fingerprint_engine else {}
    return jsonify({
        "summary": scanner.get_device_summary(),
        "devices": scanner.get_all_devices(),
        "clustered_devices": clustered,
        "cluster_summary": cluster_summary,
        "jammer": jammer.get_status(),
        "alerts": logger.get_alerts(count=30),
        "auto_scan": auto_scan,
        "scan_interval": scan_interval,
        "rssi_filter": rssi_filter,
        "range_presets": RANGE_PRESETS,
        "platform": platform_info,
        "total_scans": scanner.total_scans,
        "tracker_suspects": tracker_detector.get_all_suspects() if tracker_detector else [],
        "analytics": logger.analytics.get_summary() if logger else {},
        "people": estimate_people(clustered) if clustered else {},
        "safety": calculate_safety_score(clustered, len(tracker_detector.get_all_suspects()) if tracker_detector else 0),
        "weather": get_bluetooth_weather(clustered, logger.analytics.get_summary() if logger else {}),
    })


@app.route("/api/devices")
def api_devices():
    return jsonify(scanner.get_all_devices())


@app.route("/api/devices/clustered")
def api_devices_clustered():
    """Get fingerprint-clustered devices (physical devices, not MACs)."""
    clustered = fingerprint_engine.get_clustered_devices() if fingerprint_engine else []
    return jsonify(clustered)


@app.route("/api/summary")
def api_summary():
    return jsonify(scanner.get_device_summary())


@app.route("/api/cluster-summary")
def api_cluster_summary():
    """Get fingerprint cluster summary."""
    return jsonify(fingerprint_engine.get_cluster_summary() if fingerprint_engine else {})


@app.route("/api/scan", methods=["POST"])
def api_scan():
    try:
        result = do_scan_and_emit()
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/range", methods=["POST"])
def api_set_range():
    """Set the scan range filter."""
    global rssi_filter
    data = request.get_json(force=True, silent=True) or {}
    preset = data.get("preset", "all")
    custom_rssi = data.get("rssi")

    if custom_rssi is not None:
        rssi_filter = int(custom_rssi)
    elif preset in RANGE_PRESETS:
        rssi_filter = RANGE_PRESETS[preset]
    else:
        return jsonify({"error": f"Unknown preset: {preset}"}), 400

    socketio.emit("range_changed", {"rssi_filter": rssi_filter, "preset": preset})
    return jsonify({"rssi_filter": rssi_filter, "preset": preset})


@app.route("/api/range", methods=["GET"])
def api_get_range():
    """Get current range settings."""
    current_preset = "custom"
    for name, val in RANGE_PRESETS.items():
        if val == rssi_filter:
            current_preset = name
            break
    return jsonify({
        "rssi_filter": rssi_filter,
        "preset": current_preset,
        "presets": RANGE_PRESETS,
    })


@app.route("/api/jammer", methods=["GET"])
def api_jammer_status():
    return jsonify(jammer.get_status())


@app.route("/api/jammer/start", methods=["POST"])
def api_jammer_start():
    data = request.get_json(force=True, silent=True) or {}
    mode = data.get("mode", "sweep")
    channel = int(data.get("channel", 39))
    target = data.get("target", "")
    try:
        config["jam_enabled"] = True
        jammer.config = config
        session = jammer.start_jam(mode=mode, channel=channel, target=target)
        status = jammer.get_status()
        socketio.emit("jammer_update", status)
        return jsonify(status)
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/jammer/stop", methods=["POST"])
def api_jammer_stop():
    session = jammer.stop_jam()
    if session:
        logger.log_jam_session({
            "session_id": session.session_id,
            "mode": session.mode,
            "channel": session.channel,
            "packets_sent": session.packets_sent,
            "start_time": session.start_time,
            "end_time": session.end_time,
        })
    status = jammer.get_status()
    socketio.emit("jammer_update", status)
    return jsonify(status)


@app.route("/api/whitelist", methods=["POST"])
def api_whitelist_add():
    """Trust a device — works with both MAC and fingerprint ID."""
    data = request.get_json(force=True, silent=True) or {}
    address = data.get("address", "").upper()
    fp_id = data.get("fingerprint_id", "")

    if fp_id and fingerprint_engine:
        fingerprint_engine.trust_fingerprint(fp_id)
        logger.log_event("whitelist_add", {"fingerprint_id": fp_id})
    elif address:
        scanner.add_known_device(address)
        if fingerprint_engine:
            cluster_id = fingerprint_engine.get_fingerprint_for_mac(address)
            if cluster_id:
                fingerprint_engine.trust_fingerprint(cluster_id)
        logger.log_event("whitelist_add", {"address": address})
    else:
        return jsonify({"error": "address or fingerprint_id required"}), 400

    clustered = fingerprint_engine.get_clustered_devices() if fingerprint_engine else []
    socketio.emit("device_update", {
        "summary": scanner.get_device_summary(),
        "devices": scanner.get_all_devices(),
        "clustered_devices": clustered,
        "cluster_summary": fingerprint_engine.get_cluster_summary() if fingerprint_engine else {},
    })
    return jsonify({"status": "ok"})


@app.route("/api/whitelist", methods=["DELETE"])
def api_whitelist_remove():
    """Untrust a device — works with both MAC and fingerprint ID."""
    data = request.get_json(force=True, silent=True) or {}
    address = data.get("address", "").upper()
    fp_id = data.get("fingerprint_id", "")

    if fp_id and fingerprint_engine:
        fingerprint_engine.untrust_fingerprint(fp_id)
    elif address:
        scanner.known_devices.discard(address)
        if address in scanner.devices:
            scanner.devices[address].is_known = False
            scanner.devices[address].alert_level = "warning"
        scanner.save_known_devices()

    logger.log_event("whitelist_remove", {"address": address, "fingerprint_id": fp_id})
    clustered = fingerprint_engine.get_clustered_devices() if fingerprint_engine else []
    socketio.emit("device_update", {
        "summary": scanner.get_device_summary(),
        "devices": scanner.get_all_devices(),
        "clustered_devices": clustered,
        "cluster_summary": fingerprint_engine.get_cluster_summary() if fingerprint_engine else {},
    })
    return jsonify({"status": "ok"})


@app.route("/api/export", methods=["POST"])
def api_export():
    filepath = logger.export_report()
    logger.log_event("export", {"file": filepath})
    return send_file(filepath, as_attachment=True, download_name=Path(filepath).name)


@app.route("/api/reset", methods=["POST"])
def api_reset():
    global fingerprint_engine, tracker_detector, scan_snapshots
    scanner.devices.clear()
    scanner.scan_history.clear()
    scanner.total_scans = 0
    fingerprint_engine = BLEFingerprintEngine()
    tracker_detector = TrackerDetector()
    scan_snapshots = []
    socketio.emit("device_update", {
        "summary": scanner.get_device_summary(),
        "devices": [],
        "clustered_devices": [],
        "cluster_summary": fingerprint_engine.get_cluster_summary(),
        "tracker_suspects": [],
        "analytics": logger.analytics.get_summary(),
    })
    return jsonify({"status": "reset"})


@app.route("/api/config", methods=["GET"])
def api_config_get():
    return jsonify(config)


@app.route("/api/config", methods=["POST"])
def api_config_set():
    global scan_interval, auto_scan
    data = request.get_json(force=True, silent=True) or {}
    for key, val in data.items():
        config[key] = val
    scan_interval = config.get("scan_interval", 5)
    save_config(config)
    return jsonify(config)


@app.route("/api/platform")
def api_platform():
    return jsonify(platform_info)


# ── New v4 API endpoints ─────────────────────────────────────────────────────

@app.route("/api/ghost", methods=["POST"])
def api_ghost():
    """Emergency shutdown (Ghost Mode) — only works on Linux/RPi."""
    if platform_info.get("os") == "Linux":
        socketio.emit("ghost_mode", {"status": "shutting_down"})
        logger.log_event("ghost_mode", {"status": "activated"})
        time.sleep(0.5)
        try:
            subprocess.Popen(["sudo", "shutdown", "now"])
        except Exception as e:
            return jsonify({"error": str(e)}), 500
        return jsonify({"status": "shutting_down"})
    else:
        # Simulated on non-Linux
        socketio.emit("ghost_mode", {"status": "simulated"})
        return jsonify({"status": "simulated", "message": "Ghost mode only available on Linux/RPi"})


@app.route("/api/analytics")
def api_analytics():
    """Get historical device analytics."""
    return jsonify(logger.analytics.get_summary() if logger else {})


@app.route("/api/trackers")
def api_trackers():
    """Get all suspected trackers."""
    return jsonify(tracker_detector.get_all_suspects() if tracker_detector else [])


@app.route("/api/device/<device_id>/rssi-history")
def api_device_rssi_history(device_id):
    """Get RSSI history for a specific fingerprint."""
    history = fingerprint_engine.get_rssi_history(device_id) if fingerprint_engine else []
    return jsonify({"device_id": device_id, "rssi_history": history})


@app.route("/api/device/<device_id>/packets")
def api_device_packets(device_id):
    """Get raw advertisement data for a specific fingerprint."""
    if fingerprint_engine and device_id in fingerprint_engine.clusters:
        fp = fingerprint_engine.clusters[device_id]
        return jsonify({
            "device_id": device_id,
            "device_name": fp.best_name,
            "manufacturer_id": fp.manufacturer_id,
            "manufacturer_name": fp.manufacturer_name,
            "service_uuids": fp.service_uuids,
            "packet_data": fp.raw_adv_data,
            "mac_addresses": fp.mac_addresses,
            "category": fp.category,
            "ecosystem": fp.ecosystem,
        })
    return jsonify({"error": "device not found"}), 404


@app.route("/api/alerts/rules", methods=["GET"])
def api_get_alert_rules():
    """Get configurable alert rules."""
    return jsonify(alert_rules)


@app.route("/api/alerts/rules", methods=["POST"])
def api_set_alert_rules():
    """Update alert rules (toggle enabled/disabled)."""
    global alert_rules
    data = request.get_json(force=True, silent=True) or {}
    rule_id = data.get("id")
    enabled = data.get("enabled")
    if rule_id is not None and enabled is not None:
        for rule in alert_rules:
            if rule["id"] == rule_id:
                rule["enabled"] = bool(enabled)
                break
    return jsonify(alert_rules)


@app.route("/api/alerts/watch", methods=["POST"])
def api_watch_device():
    """Add a device to the watch list (alert when it re-appears)."""
    data = request.get_json(force=True, silent=True) or {}
    fp_id = data.get("fingerprint_id", "")
    if fp_id:
        watch_list.add(fp_id)
        return jsonify({"status": "watching", "fingerprint_id": fp_id})
    return jsonify({"error": "fingerprint_id required"}), 400


@app.route("/api/alerts/watch", methods=["DELETE"])
def api_unwatch_device():
    """Remove a device from the watch list."""
    data = request.get_json(force=True, silent=True) or {}
    fp_id = data.get("fingerprint_id", "")
    watch_list.discard(fp_id)
    return jsonify({"status": "unwatched", "fingerprint_id": fp_id})


@app.route("/api/classify/<device_id>")
def api_classify_device(device_id):
    """AI classification for a single device."""
    if fingerprint_engine and device_id in fingerprint_engine.clusters:
        fp = fingerprint_engine.clusters[device_id]
        cr = ai_classifier.classify(
            device_id=device_id, name=fp.best_name, category=fp.category,
            ecosystem=fp.ecosystem or "", manufacturer_id=fp.manufacturer_id,
            manufacturer_name=fp.manufacturer_name,
            service_uuids=fp.service_uuids, payload_len=int(fp.avg_payload_len),
            avg_rssi=fp.avg_rssi, is_known=fp.is_known,
            tracker_suspect=fp.tracker_suspect,
            mac_count=len(fp.mac_addresses),
        )
        return jsonify(cr.to_dict())
    return jsonify({"error": "device not found"}), 404


@app.route("/api/people")
def api_people():
    """Human presence estimation."""
    clustered = fingerprint_engine.get_clustered_devices() if fingerprint_engine else []
    return jsonify(estimate_people(clustered))


@app.route("/api/safety")
def api_safety():
    """Environment safety score."""
    clustered = fingerprint_engine.get_clustered_devices() if fingerprint_engine else []
    tc = len(tracker_detector.get_all_suspects()) if tracker_detector else 0
    return jsonify(calculate_safety_score(clustered, tc))


@app.route("/api/weather")
def api_weather():
    """Bluetooth weather report."""
    clustered = fingerprint_engine.get_clustered_devices() if fingerprint_engine else []
    analytics = logger.analytics.get_summary() if logger else {}
    return jsonify(get_bluetooth_weather(clustered, analytics))


@app.route("/api/time-travel")
def api_time_travel():
    """Return scan snapshots for time travel playback."""
    return jsonify({"snapshots": scan_snapshots})


# ── Socket.IO Events ────────────────────────────────────────────────────────

@socketio.on("connect")
def on_connect():
    clustered = fingerprint_engine.get_clustered_devices() if fingerprint_engine else []
    cluster_summary = fingerprint_engine.get_cluster_summary() if fingerprint_engine else {}
    socketio.emit("status", {
        "summary": scanner.get_device_summary(),
        "devices": scanner.get_all_devices(),
        "clustered_devices": clustered,
        "cluster_summary": cluster_summary,
        "jammer": jammer.get_status(),
        "alerts": logger.get_alerts(count=30),
        "auto_scan": auto_scan,
        "scan_interval": scan_interval,
        "rssi_filter": rssi_filter,
        "range_presets": RANGE_PRESETS,
        "platform": platform_info,
        "tracker_suspects": tracker_detector.get_all_suspects() if tracker_detector else [],
        "analytics": logger.analytics.get_summary() if logger else {},
        "alert_rules": alert_rules,
        "people": estimate_people(clustered) if clustered else {},
        "safety": calculate_safety_score(clustered, len(tracker_detector.get_all_suspects()) if tracker_detector else 0),
        "weather": get_bluetooth_weather(clustered, logger.analytics.get_summary() if logger else {}),
    })


@socketio.on("toggle_autoscan")
def on_toggle_autoscan(data):
    global auto_scan
    auto_scan = data.get("enabled", True)
    socketio.emit("autoscan_changed", {"enabled": auto_scan})


@socketio.on("set_scan_interval")
def on_set_interval(data):
    global scan_interval
    scan_interval = max(1, min(60, int(data.get("interval", 5))))
    config["scan_interval"] = scan_interval


@socketio.on("set_range")
def on_set_range(data):
    global rssi_filter
    preset = data.get("preset", "all")
    if preset in RANGE_PRESETS:
        rssi_filter = RANGE_PRESETS[preset]
    elif "rssi" in data:
        rssi_filter = int(data["rssi"])
    socketio.emit("range_changed", {"rssi_filter": rssi_filter, "preset": preset})


# ── Background Scan Loop ────────────────────────────────────────────────────

def background_scan_loop():
    """Periodically scan and push results to connected clients."""
    while True:
        if auto_scan:
            do_scan_and_emit()
        time.sleep(scan_interval)


# ── Entry Point ──────────────────────────────────────────────────────────────

def main():
    global scanner, jammer, logger, config, scan_interval, platform_info
    global auto_scan, fingerprint_engine, tracker_detector, ai_classifier

    parser = argparse.ArgumentParser(description="BlueShield Web Dashboard")
    parser.add_argument("--sim", action="store_true", help="Use simulated scanner (no hardware)")
    parser.add_argument("--port", type=int, default=8080, help="Web server port")
    parser.add_argument("--host", default="0.0.0.0", help="Web server host")
    args = parser.parse_args()

    config = load_config()
    scan_interval = config.get("scan_interval", 5)
    platform_info = detect_platform()

    print(f"[BlueShield] Platform: {platform_info['os']}")
    print(f"[BlueShield] Bleak available: {platform_info['has_bleak']}")
    print(f"[BlueShield] hcitool available: {platform_info['has_hcitool']}")

    # Initialize engines
    fingerprint_engine = BLEFingerprintEngine()
    tracker_detector = TrackerDetector()
    ai_classifier = AIDeviceClassifier()
    print("[BlueShield] BLE Fingerprinting engine v4.0 initialized")
    print("[BlueShield] Tracker detection engine initialized")
    print("[BlueShield] Risk scoring engine initialized")
    print("[BlueShield] AI device classifier initialized")
    print("[BlueShield] People detection & safety scoring active")

    if args.sim:
        print("[BlueShield] Using SIMULATED scanner and jammer")
        scanner = SimulatedScanner(config)
        jammer = SimulatedJammer(config)
    else:
        print("[BlueShield] Using REAL hardware scanner")
        scanner = BluetoothScanner(config)
        if platform_info["os"] == "Linux" and platform_info["has_hcitool"]:
            jammer = BluetoothJammer(config)
        else:
            print("[BlueShield] Jammer: simulated (requires Linux + hcitool)")
            jammer = SimulatedJammer(config)

    logger = BlueShieldLogger(config)

    # Start background scanning in a daemon thread
    scan_thread = threading.Thread(target=background_scan_loop, daemon=True)
    scan_thread.start()

    print(f"[BlueShield] Dashboard v4.0 starting at http://localhost:{args.port}")
    socketio.run(app, host=args.host, port=args.port, debug=False, allow_unsafe_werkzeug=True)


if __name__ == "__main__":
    main()
