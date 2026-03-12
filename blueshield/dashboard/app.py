"""
BlueShield Web Dashboard

Flask + Socket.IO backend for the BlueShield Bluetooth security monitor.
Serves a real-time web dashboard with BLE fingerprinting, range filtering,
and exposes REST/WebSocket APIs.

Run: python -m blueshield [--sim] [--port 8080]
"""

import asyncio
import argparse
import platform
import shutil
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
auto_scan = True
scan_interval = 5
rssi_filter = -100  # default: all devices
platform_info = {}
_scan_lock = threading.Lock()

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


def do_scan_and_emit():
    """Execute a scan, feed fingerprint engine, and emit results via Socket.IO."""
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
                dev_obj = scanner.devices.get(addr.upper())
                if dev_obj and hasattr(dev_obj, '_fingerprint_data'):
                    mfr_id = dev_obj._fingerprint_data.get("manufacturer_id", 0)
                    payload_len = dev_obj._fingerprint_data.get("payload_len", 0)

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
                )

            # Run clustering
            fingerprint_engine.run_clustering()

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

            socketio.emit("scan_result", result)

            # Emit both raw devices and clustered view
            clustered = fingerprint_engine.get_clustered_devices()
            cluster_summary = fingerprint_engine.get_cluster_summary()

            socketio.emit("device_update", {
                "summary": scanner.get_device_summary(),
                "devices": scanner.get_all_devices(),
                "clustered_devices": clustered,
                "cluster_summary": cluster_summary,
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
    # Find which preset matches
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
        # Also trust the fingerprint cluster this MAC belongs to
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
    global fingerprint_engine
    scanner.devices.clear()
    scanner.scan_history.clear()
    scanner.total_scans = 0
    fingerprint_engine = BLEFingerprintEngine()
    socketio.emit("device_update", {
        "summary": scanner.get_device_summary(),
        "devices": [],
        "clustered_devices": [],
        "cluster_summary": fingerprint_engine.get_cluster_summary(),
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
    global scanner, jammer, logger, config, scan_interval, platform_info, auto_scan, fingerprint_engine

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

    # Initialize fingerprint engine
    fingerprint_engine = BLEFingerprintEngine()
    print("[BlueShield] BLE Fingerprinting engine initialized")

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

    print(f"[BlueShield] Dashboard starting at http://localhost:{args.port}")
    socketio.run(app, host=args.host, port=args.port, debug=False, allow_unsafe_werkzeug=True)


if __name__ == "__main__":
    main()
