"""
BlueShield Web Dashboard

Flask + Socket.IO backend for the BlueShield Bluetooth security monitor.
Serves a real-time web dashboard and exposes REST/WebSocket APIs.

Run: python -m blueshield [--sim] [--port 5000]
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
auto_scan = True
scan_interval = 5
platform_info = {}
_scan_lock = threading.Lock()


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
    """Run an async coroutine in a dedicated thread with its own event loop.

    Bleak requires a real asyncio event loop (not monkey-patched).
    We run it in a native thread to avoid conflicts.
    """
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
    t.join(timeout=60)  # max 60s for a scan
    if exception[0]:
        raise exception[0]
    return result[0]


def do_scan_and_emit():
    """Execute a scan and emit results via Socket.IO."""
    with _scan_lock:
        try:
            result = run_async(scanner.run_scan())
            logger.log_scan(result)

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
            socketio.emit("device_update", {
                "summary": scanner.get_device_summary(),
                "devices": scanner.get_all_devices(),
            })
            return result
        except Exception as e:
            print(f"[BlueShield] Scan error: {e}")
            return {"error": str(e)}


# ── Routes ───────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return send_file(str(STATIC_DIR / "index.html"))


@app.route("/api/status")
def api_status():
    return jsonify({
        "summary": scanner.get_device_summary(),
        "devices": scanner.get_all_devices(),
        "jammer": jammer.get_status(),
        "alerts": logger.get_alerts(count=30),
        "auto_scan": auto_scan,
        "scan_interval": scan_interval,
        "platform": platform_info,
        "total_scans": scanner.total_scans,
    })


@app.route("/api/devices")
def api_devices():
    return jsonify(scanner.get_all_devices())


@app.route("/api/summary")
def api_summary():
    return jsonify(scanner.get_device_summary())


@app.route("/api/scan", methods=["POST"])
def api_scan():
    try:
        result = do_scan_and_emit()
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


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
    data = request.get_json(force=True, silent=True) or {}
    address = data.get("address", "").upper()
    if not address:
        return jsonify({"error": "address required"}), 400
    scanner.add_known_device(address)
    logger.log_event("whitelist_add", {"address": address})
    socketio.emit("device_update", {
        "summary": scanner.get_device_summary(),
        "devices": scanner.get_all_devices(),
    })
    return jsonify({"status": "ok", "address": address})


@app.route("/api/whitelist", methods=["DELETE"])
def api_whitelist_remove():
    data = request.get_json(force=True, silent=True) or {}
    address = data.get("address", "").upper()
    if not address:
        return jsonify({"error": "address required"}), 400
    scanner.known_devices.discard(address)
    if address in scanner.devices:
        scanner.devices[address].is_known = False
        scanner.devices[address].alert_level = "warning"
    scanner.save_known_devices()
    logger.log_event("whitelist_remove", {"address": address})
    socketio.emit("device_update", {
        "summary": scanner.get_device_summary(),
        "devices": scanner.get_all_devices(),
    })
    return jsonify({"status": "ok", "address": address})


@app.route("/api/export", methods=["POST"])
def api_export():
    filepath = logger.export_report()
    logger.log_event("export", {"file": filepath})
    return send_file(filepath, as_attachment=True, download_name=Path(filepath).name)


@app.route("/api/reset", methods=["POST"])
def api_reset():
    scanner.devices.clear()
    scanner.scan_history.clear()
    scanner.total_scans = 0
    socketio.emit("device_update", {
        "summary": scanner.get_device_summary(),
        "devices": [],
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
    socketio.emit("status", {
        "summary": scanner.get_device_summary(),
        "devices": scanner.get_all_devices(),
        "jammer": jammer.get_status(),
        "alerts": logger.get_alerts(count=30),
        "auto_scan": auto_scan,
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


# ── Background Scan Loop ────────────────────────────────────────────────────

def background_scan_loop():
    """Periodically scan and push results to connected clients."""
    while True:
        if auto_scan:
            do_scan_and_emit()
        time.sleep(scan_interval)


# ── Entry Point ──────────────────────────────────────────────────────────────

def main():
    global scanner, jammer, logger, config, scan_interval, platform_info, auto_scan

    parser = argparse.ArgumentParser(description="BlueShield Web Dashboard")
    parser.add_argument("--sim", action="store_true", help="Use simulated scanner (no hardware)")
    parser.add_argument("--port", type=int, default=5000, help="Web server port")
    parser.add_argument("--host", default="0.0.0.0", help="Web server host")
    args = parser.parse_args()

    config = load_config()
    scan_interval = config.get("scan_interval", 5)
    platform_info = detect_platform()

    print(f"[BlueShield] Platform: {platform_info['os']}")
    print(f"[BlueShield] Bleak available: {platform_info['has_bleak']}")
    print(f"[BlueShield] hcitool available: {platform_info['has_hcitool']}")

    if args.sim:
        print("[BlueShield] Using SIMULATED scanner and jammer")
        scanner = SimulatedScanner(config)
        jammer = SimulatedJammer(config)
    else:
        print("[BlueShield] Using REAL hardware scanner")
        scanner = BluetoothScanner(config)
        # Jammer only works on Linux with hcitool
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
