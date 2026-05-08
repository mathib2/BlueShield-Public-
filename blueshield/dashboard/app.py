"""
BlueShield Web Dashboard v4.0

Flask + Socket.IO backend for the BlueShield Bluetooth security monitor.
Serves a real-time web dashboard with BLE fingerprinting, risk scoring,
tracker detection, proximity radar, and exposes REST/WebSocket APIs.

Run: python -m blueshield [--port 8080]
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

from functools import wraps
from flask import Flask, jsonify, request, send_file, session, redirect, url_for, make_response
from flask_socketio import SocketIO

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from blueshield.config.settings import load_config, save_config, LOG_DIR
from blueshield.scanner.bt_scanner import BluetoothScanner
from blueshield.scanner.fingerprint import BLEFingerprintEngine
from blueshield.scanner.heatmap import HeatmapStore, Sample as HeatmapSample
from typing import Optional
from blueshield.scanner.risk_engine import calculate_risk, calculate_rssi_trend
from blueshield.scanner.tracker_detector import TrackerDetector
from blueshield.scanner.ai_classifier import AIDeviceClassifier, estimate_people, calculate_safety_score, get_bluetooth_weather
from blueshield.scanner.advanced_analysis import (
    FollowingDetector, ShadowDeviceDetector, EnvironmentFingerprint,
    DeviceLifeStory, ConversationGraph, MovementTrailTracker,
)
from blueshield.jammer.bt_jammer import BluetoothJammer
from blueshield.logs.logger import BlueShieldLogger
# v7.5: evidence-integrity module (Ed25519 signatures + hash-chained event log)
try:
    from blueshield.logs.integrity import (
        SessionSigner, ChainedEventLog, write_session_manifest,
    )
    HAS_INTEGRITY = True
except ImportError:
    HAS_INTEGRITY = False
    SessionSigner = None
    ChainedEventLog = None
    write_session_manifest = None
from blueshield.sniffer.sniffle_engine import make_sniffer, BLEPacket, ConnectionRecord
from blueshield.sniffer.gatt_inspector import make_gatt_inspector
from blueshield.sniffer.crackle_runner import CrackleRunner
from blueshield.sniffer.pairing_detector import PairingEvent
from blueshield.sniffer.nrf_sniffer import make_nrf_sniffer
from blueshield.core.device_correlator import DeviceCorrelator


# ── App Setup ────────────────────────────────────────────────────────────────

STATIC_DIR = Path(__file__).parent / "static"

app = Flask(__name__, static_folder=str(STATIC_DIR), static_url_path="/static")

# Aggressive no-cache for static assets — operators iterate on JS/CSS
# constantly and stale cache is the #1 source of "I don't see your update"
# bug reports. Production deployments still get gzip via the WSGI layer;
# the cost is one re-download per visit, which is fine for an operator
# console that's <300 KB total.
@app.after_request
def _no_static_cache(response):
    try:
        if request.path.startswith("/static/"):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"
    except Exception:
        pass
    return response
# v7.5: secret key loaded from env or generated per-boot (never hardcoded in prod)
import secrets as _secrets_mod
_sk_path = Path(__file__).parent.parent / "keys" / "flask_secret.bin"
if _sk_path.exists():
    app.secret_key = _sk_path.read_bytes()
else:
    app.secret_key = _secrets_mod.token_bytes(32)
    try:
        _sk_path.parent.mkdir(parents=True, exist_ok=True)
        _sk_path.write_bytes(app.secret_key)
        os.chmod(_sk_path, 0o600)
    except Exception:
        pass
# Session cookies: HttpOnly + SameSite, 30-minute idle timeout
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=1800,
)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# ── Authentication (v7.5: bcrypt hashes, no hardcoded plaintext) ─────────────
# User store: {username: bcrypt_hash}. Loaded from keys/users.json if present,
# otherwise seeded with admin/admin123 → prompts user to change via /api/auth/change-password.
import json as _json_mod
_USERS_PATH = Path(__file__).parent.parent / "keys" / "users.json"

def _hash_password(pw: str) -> str:
    try:
        import bcrypt
        return bcrypt.hashpw(pw.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("ascii")
    except ImportError:
        # Fallback: SHA-256 + fixed-per-install salt. Not ideal but avoids plaintext.
        import hashlib
        salt = app.secret_key[:16]
        return "sha256:" + hashlib.sha256(salt + pw.encode("utf-8")).hexdigest()

def _verify_password(pw: str, stored_hash: str) -> bool:
    try:
        if stored_hash.startswith("sha256:"):
            import hashlib
            salt = app.secret_key[:16]
            return stored_hash == "sha256:" + hashlib.sha256(salt + pw.encode("utf-8")).hexdigest()
        import bcrypt
        return bcrypt.checkpw(pw.encode("utf-8"), stored_hash.encode("ascii"))
    except Exception:
        return False

def _load_users():
    if _USERS_PATH.exists():
        try:
            return _json_mod.loads(_USERS_PATH.read_text())
        except Exception:
            pass
    # Seed with default admin — hash, not plaintext. User is warned on login.
    default = {"admin": _hash_password("admin123"), "_seeded_default": True}
    try:
        _USERS_PATH.parent.mkdir(parents=True, exist_ok=True)
        _USERS_PATH.write_text(_json_mod.dumps(default, indent=2))
        os.chmod(_USERS_PATH, 0o600)
    except Exception:
        pass
    return default

def _save_users(users: dict):
    try:
        _USERS_PATH.write_text(_json_mod.dumps(users, indent=2))
        os.chmod(_USERS_PATH, 0o600)
    except Exception:
        pass

USERS = _load_users()

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            if request.is_json or request.path.startswith("/api/") or request.path.startswith("/socket.io"):
                return jsonify({"error": "Unauthorized"}), 401
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated

@app.before_request
def check_auth():
    """Protect all routes except login, static files, and socket.io."""
    allowed = ("/login", "/static/")
    if any(request.path.startswith(p) for p in allowed):
        return None
    if request.path.startswith("/socket.io"):
        return None  # socket.io handles its own auth
    # v7.7: public-URL + local-URLs endpoints must be reachable on the
    # login page so the audience can see the demo URL + QR codes before
    # they authenticate.
    if request.path in ("/api/system/public-url", "/api/system/local-urls"):
        return None
    if not session.get("logged_in"):
        if request.is_json or request.path.startswith("/api/"):
            return jsonify({"error": "Unauthorized"}), 401
        return redirect("/login")

# Global state
scanner = None
jammer = None
logger = None
config = None
fingerprint_engine = None
tracker_detector = None
ai_classifier = None
following_detector = None
shadow_detector = None
env_fingerprint = None
life_story = None
conversation_graph = None
trail_tracker = None
advanced_mode = False
auto_scan = True
device_correlator = DeviceCorrelator()
# v7.5: evidence integrity (assigned in startup)
signer = None
chained_log = None
scan_interval = 15  # must be > scan_duration (default 5s) to avoid InProgress errors
_advanced_scan_counter = 0  # throttle heavy analysis — only run every 3rd scan on Pi 3
rssi_filter = -100  # default: all devices
platform_info = {}
_scan_lock = threading.Lock()

# ── Sniffer global state ─────────────────────────────────────────────────────
sniffer_engine   = None
gatt_inspector   = None
crackle_runner   = None
nrf_sniffer      = None          # nRF52840 BLE sniffer instance #1 (/dev/ttyACM0)
nrf_sniffer_2    = None          # nRF52840 BLE sniffer instance #2 (/dev/ttyACM1)
_nrf_bridge_running = False      # controls the nRF→socketio bridge thread

# ── Heatmap global state ─────────────────────────────────────────────────────
heatmap_store: Optional[HeatmapStore] = None  # initialized in main() with the captures dir

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
MAX_SNAPSHOTS = 60   # ~15 minutes at 15s interval (keep low to save Pi 3 RAM)

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
    global fingerprint_engine, _advanced_scan_counter
    if not _scan_lock.acquire(blocking=False):
        return  # Previous scan still running — skip this cycle
    try:
        try:
            # Skip scan if jammer is active (they share the HCI adapter)
            if jammer and jammer.is_jamming:
                return

            result = run_async(scanner.run_scan(rssi_filter=rssi_filter))
            if result is None:
                return
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
                apple_info = None
                resolved = None
                dev_obj = scanner.devices.get(addr.upper())
                if dev_obj and hasattr(dev_obj, '_fingerprint_data'):
                    fp_data = dev_obj._fingerprint_data
                    mfr_id = fp_data.get("manufacturer_id", 0)
                    payload_len = fp_data.get("payload_len", 0)
                    mfr_data_bytes = fp_data.get("mfr_data_bytes", b"")
                    raw_adv_data = fp_data.get("raw_adv_data", {})
                    apple_info = fp_data.get("apple_info")
                    resolved = fp_data.get("resolved")

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
                    apple_info=apple_info,
                    resolved=resolved,
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
                    apple_info=getattr(fp, 'apple_info', None) or None,
                )
                classifications[fp_id] = cr.to_dict()

            people = estimate_people(clustered)
            safety = calculate_safety_score(clustered, len(tracker_suspects))
            weather = get_bluetooth_weather(clustered, analytics_summary)

            # ── Advanced Analysis: Following, Shadows, Environment, Life Story, Graph ──
            # Only run every 3rd scan to reduce CPU load on Pi 3
            _advanced_scan_counter += 1
            run_advanced = (_advanced_scan_counter % 3 == 0)

            following_alerts = []
            shadow_devices = []
            env_anomalies = {}
            trail_data = {}

            if following_detector and run_advanced:
                following_detector.record_scan()
                for fp_id, fp in fingerprint_engine.clusters.items():
                    rssi_hist = fingerprint_engine.get_rssi_history(fp_id)
                    latest_rssi = rssi_hist[-1][1] if rssi_hist and isinstance(rssi_hist[-1], (list, tuple)) else (rssi_hist[-1] if rssi_hist else -100)
                    following_detector.record_observation(fp_id, latest_rssi)
                following_alerts = following_detector.get_all_alerts(clustered)

            if shadow_detector and run_advanced:
                # Record visibility for all known fingerprints
                current_ids = set(d.get("fingerprint_id", "") for d in clustered)
                for fp_id in set(list(shadow_detector.visibility_log.keys()) + list(current_ids)):
                    visible = fp_id in current_ids
                    name = ""
                    fp = fingerprint_engine.clusters.get(fp_id)
                    if fp:
                        name = fp.best_name
                    shadow_detector.record_visibility(fp_id, visible, name)
                shadow_devices = shadow_detector.get_all_shadows(clustered)

            if env_fingerprint and run_advanced:
                env_fingerprint.record_scan(clustered)
                env_anomalies = env_fingerprint.get_anomalies(clustered)

            if life_story and run_advanced:
                for d in clustered:
                    fid = d.get("fingerprint_id", "")
                    life_story.record_state(fid, d)

            if conversation_graph and run_advanced:
                device_ids = [d.get("fingerprint_id", "") for d in clustered if d.get("fingerprint_id")]
                conversation_graph.record_scan(device_ids)

            if trail_tracker:
                for d in clustered:
                    fid = d.get("fingerprint_id", "")
                    rssi = d.get("avg_rssi", -100)
                    # Use hash-based angle (same as radar)
                    h = 0
                    for ch in fid:
                        h = ((h << 5) - h + ord(ch)) & 0xFFFFFFFF
                    angle = (h % 628) / 100.0
                    trail_tracker.record_position(fid, rssi, angle)
                trail_data = trail_tracker.get_all_trails()

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

            # ── AI Device Correlation: deduplicate + track across MAC changes ──
            try:
                raw_devices = scanner.get_all_devices()
                device_correlator.ingest_scan_results(raw_devices)
                correlated_devices = device_correlator.get_unified_devices()
                correlator_stats = device_correlator.get_stats()
                following_correlated = device_correlator.get_following_devices()
            except Exception as corr_exc:
                print(f"[BlueShield] Correlator error: {corr_exc}")
                correlated_devices = []
                correlator_stats = {}
                following_correlated = []

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
                "following": following_alerts,
                "shadows": shadow_devices,
                "environment": env_anomalies,
                "trails": trail_data,
                "correlated_devices": correlated_devices,
                "correlator_stats": correlator_stats,
                "following_correlated": following_correlated,
            })
            return result
        except Exception as e:
            print(f"[BlueShield] Scan error: {e}")
            import traceback
            traceback.print_exc()
            return {"error": str(e)}
    finally:
        _scan_lock.release()


# ── Routes ───────────────────────────────────────────────────────────────────

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        data = request.get_json() if request.is_json else request.form
        username = (data.get("username", "") or "").strip()
        password = data.get("password", "") or ""
        stored = USERS.get(username)
        # stored may be bcrypt hash (string) or, on very old configs, plaintext
        ok = False
        if stored and isinstance(stored, str):
            ok = _verify_password(password, stored)
        if ok:
            session.permanent = True
            session["logged_in"] = True
            session["username"] = username
            # v7.5: audit trail for successful auth
            try: log_event_chained("login_success", {"username": username})
            except: pass
            if request.is_json:
                return jsonify({
                    "success": True,
                    "using_default_password": USERS.get("_seeded_default") and username == "admin" and password == "admin123",
                })
            return redirect("/")
        # Log failed attempts
        try: log_event_chained("login_failure", {"username": username})
        except: pass
        if request.is_json:
            return jsonify({"error": "Invalid credentials"}), 401
        return send_file(str(STATIC_DIR / "login.html"))
    if session.get("logged_in"):
        return redirect("/")
    return send_file(str(STATIC_DIR / "login.html"))

@app.route("/logout")
def logout():
    try: log_event_chained("logout", {"username": session.get("username", "unknown")})
    except: pass
    session.clear()
    return redirect("/login")

@app.route("/api/auth/change-password", methods=["POST"])
@login_required
def api_change_password():
    """Allow logged-in users to change their password. v7.5 hardening."""
    data = request.get_json(force=True, silent=True) or {}
    old_pw = data.get("old", "")
    new_pw = data.get("new", "")
    if len(new_pw) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400
    u = session.get("username", "")
    if not u or u not in USERS:
        return jsonify({"error": "Session user invalid"}), 401
    if not _verify_password(old_pw, USERS[u]):
        return jsonify({"error": "Current password incorrect"}), 401
    USERS[u] = _hash_password(new_pw)
    USERS.pop("_seeded_default", None)
    _save_users(USERS)
    try: log_event_chained("password_changed", {"username": u})
    except: pass
    return jsonify({"success": True})

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
        "jammer": jammer.get_status() if jammer else JAMMER_UNAVAILABLE_STATUS,
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


# ── BLE-Map (room heatmap) ────────────────────────────────────────────────────
@app.route("/api/heatmap")
@login_required
def api_heatmap_get():
    """Return the full grid + samples + device picker index."""
    if heatmap_store is None:
        return jsonify({"error": "heatmap not initialized"}), 503
    return jsonify(heatmap_store.snapshot())


@app.route("/api/heatmap/grid", methods=["POST"])
@login_required
def api_heatmap_reshape():
    """Set grid dimensions. Body: { rows, cols, label?, cell_size_m? }.
    Drops samples that fall outside the new dimensions."""
    if heatmap_store is None:
        return jsonify({"error": "heatmap not initialized"}), 503
    data = request.get_json(silent=True) or {}
    try:
        rows = int(data.get("rows", heatmap_store.grid.rows))
        cols = int(data.get("cols", heatmap_store.grid.cols))
    except (TypeError, ValueError):
        return jsonify({"error": "rows and cols must be integers"}), 400
    label = str(data.get("label", "") or "")
    try:
        cell_size_m = float(data.get("cell_size_m", heatmap_store.grid.cell_size_m))
    except (TypeError, ValueError):
        cell_size_m = heatmap_store.grid.cell_size_m
    heatmap_store.reshape(rows=rows, cols=cols, label=label, cell_size_m=cell_size_m)
    return jsonify(heatmap_store.snapshot())


@app.route("/api/heatmap/sample", methods=["POST"])
@login_required
def api_heatmap_sample():
    """Record a sample for a single cell. Body: { row, col }.

    Snapshots all currently-visible clustered devices' avg_rssi at this moment
    into the chosen cell, with a single timestamp shared across all devices
    so the time-travel slider can replay the survey.
    """
    if heatmap_store is None:
        return jsonify({"error": "heatmap not initialized"}), 503
    data = request.get_json(silent=True) or {}
    try:
        row = int(data["row"])
        col = int(data["col"])
    except (KeyError, TypeError, ValueError):
        return jsonify({"error": "row and col required"}), 400

    grid = heatmap_store.grid
    if not (0 <= row < grid.rows and 0 <= col < grid.cols):
        return jsonify({"error": f"cell ({row},{col}) outside {grid.rows}x{grid.cols} grid"}), 400

    if fingerprint_engine is None:
        return jsonify({"error": "fingerprint engine not ready"}), 503

    now = time.time()
    samples: list[HeatmapSample] = []
    # Allow ~2 scan windows of staleness so a walking operator who lingers
    # between scans still gets all currently-clustered devices in the cell.
    stale_cutoff = max(60, int((scan_interval or 15) * 2 + 10))
    for fp_id, fp in fingerprint_engine.clusters.items():
        if (now - (fp.last_seen or 0)) > stale_cutoff:
            continue
        samples.append(HeatmapSample(
            fingerprint_id=fp_id,
            rssi=float(fp.avg_rssi or -100),
            timestamp=now,
            best_name=fp.best_name or "Unknown",
            category=fp.category or "unknown",
        ))

    n = heatmap_store.add_samples(row=row, col=col, samples=samples)
    return jsonify({
        "ok": True,
        "row": row, "col": col,
        "device_count": n,
        "timestamp": round(now, 1),
    })


@app.route("/api/heatmap/cell/<int:row>/<int:col>", methods=["DELETE"])
@login_required
def api_heatmap_clear_cell(row, col):
    """Delete all samples in a single cell."""
    if heatmap_store is None:
        return jsonify({"error": "heatmap not initialized"}), 503
    n = heatmap_store.clear_cell(row, col)
    return jsonify({"ok": True, "removed": n})


@app.route("/api/heatmap/clear", methods=["POST"])
@login_required
def api_heatmap_clear():
    """Wipe all heatmap samples (keeps grid dimensions)."""
    if heatmap_store is None:
        return jsonify({"error": "heatmap not initialized"}), 503
    heatmap_store.clear_all()
    return jsonify({"ok": True})


@app.route("/api/heatmap/geometry", methods=["POST"])
@login_required
def api_heatmap_geometry():
    """Replace walls and/or rooms in one call.

    Body: { walls: [{x1,y1,x2,y2[,id]}, ...], rooms: [{x,y,w,h,label[,id]}, ...] }
    Coordinates are in *cell-fractions* (0..cols on x, 0..rows on y), so the
    geometry survives grid-resizes proportionally.
    """
    if heatmap_store is None:
        return jsonify({"error": "heatmap not initialized"}), 503
    data = request.get_json(silent=True) or {}
    if "walls" in data:
        heatmap_store.set_walls(data.get("walls") or [])
    if "rooms" in data:
        heatmap_store.set_rooms(data.get("rooms") or [])
    return jsonify(heatmap_store.snapshot())


@app.route("/api/heatmap/live")
@login_required
def api_heatmap_live():
    """Per-device best-match-cell estimates for the live radar view.

    For every fingerprint cluster currently visible to the scanner, find the
    surveyed cell whose stored RSSI for that device is closest to the live
    avg_rssi reading. That's the operator-walkable approximation of "where
    this device is right now in the room" without trilateration hardware.
    """
    if heatmap_store is None or fingerprint_engine is None:
        return jsonify({"error": "heatmap or fingerprint not initialized"}), 503

    grid = heatmap_store.grid
    snapshot = grid.to_dict()
    samples = grid.samples or {}
    now = time.time()
    fresh_window = max(60, int((scan_interval or 15) * 2 + 10))

    pins = []
    for fp_id, fp in fingerprint_engine.clusters.items():
        last_seen = fp.last_seen or 0
        # Skip devices that haven't been seen recently — stale RSSI is noise
        if (now - last_seen) > fresh_window:
            continue
        live_rssi = float(fp.avg_rssi or -100)
        # Search the survey for the closest-RSSI cell for this device
        best = None
        best_diff = float("inf")
        for key, cell_samples in samples.items():
            for s in cell_samples:
                if s.fingerprint_id != fp_id:
                    continue
                diff = abs(s.rssi - live_rssi)
                if diff < best_diff:
                    best_diff = diff
                    r, c = (int(x) for x in key.split(","))
                    best = {"row": r, "col": c, "cell_rssi": s.rssi}
        # Confidence: 100% at 0 dBm difference, drops linearly, floor 0%
        confidence = max(0, min(100, int(100 - best_diff * 8))) if best else 0
        category = fp.category or "unknown"
        pins.append({
            "fingerprint_id": fp_id,
            "best_name": fp.best_name or "Unknown",
            "category": category,
            "ecosystem": fp.ecosystem or "",
            "live_rssi": round(live_rssi, 1),
            "age_sec": round(now - last_seen, 1),
            "cell": best,            # None if no survey samples for this device
            "confidence": confidence,
            "is_known": bool(fp.is_known),
            "is_tracker": bool(getattr(fp, "tracker_suspect", False)),
        })

    return jsonify({
        "rows": grid.rows,
        "cols": grid.cols,
        "walls": snapshot["walls"],
        "rooms": snapshot["rooms"],
        "pins": pins,
        "timestamp": round(now, 1),
        "fresh_window_sec": fresh_window,
    })


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


JAMMER_UNAVAILABLE_STATUS = {
    "is_jamming": False, "jam_enabled": False, "backend": "offline",
    "total_sessions": 0, "active_session": None, "adapters": [],
    "adapters_active": [], "packets_per_second": 0,
    "ota_packets_per_second_est": 0,
    "offline_reason": "jammer hardware not available (requires Linux + hcitool)",
}


@app.route("/api/jammer", methods=["GET"])
def api_jammer_status():
    if jammer is None:
        return jsonify(JAMMER_UNAVAILABLE_STATUS)
    return jsonify(jammer.get_status())


@app.route("/api/jammer/start", methods=["POST"])
def api_jammer_start():
    if jammer is None:
        return jsonify({"error": "Jammer offline — hardware unavailable"}), 503
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
        # v7.5: audit trail for offensive action (hash-chained, tamper-evident)
        log_event_chained("jam_start", {
            "mode": mode, "channel": channel, "target": target,
            "session_id": session.session_id if session else None,
        })
        return jsonify(status)
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/jammer/stop", methods=["POST"])
def api_jammer_stop():
    if jammer is None:
        return jsonify(JAMMER_UNAVAILABLE_STATUS)
    session = jammer.stop_jam()
    if session:
        # v7.5: audit trail for offensive action (hash-chained)
        log_event_chained("jam_stop", {
            "session_id": session.session_id,
            "mode": session.mode,
            "packets_sent": session.packets_sent,
            "end_time": session.end_time,
        })
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
    global following_detector, shadow_detector, env_fingerprint, life_story, conversation_graph, trail_tracker
    scanner.devices.clear()
    scanner.scan_history.clear()
    scanner.total_scans = 0
    fingerprint_engine = BLEFingerprintEngine()
    tracker_detector = TrackerDetector()
    scan_snapshots = []
    following_detector = FollowingDetector()
    shadow_detector = ShadowDeviceDetector()
    env_fingerprint = EnvironmentFingerprint()
    life_story = DeviceLifeStory()
    conversation_graph = ConversationGraph()
    trail_tracker = MovementTrailTracker()
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
    scan_interval = config.get("scan_interval", 15)
    save_config(config)
    return jsonify(config)


@app.route("/api/platform")
def api_platform():
    return jsonify(platform_info)


@app.route("/api/system/public-url")
def api_public_url():
    """Return the live public URL set by the remote-access tunnel
    (Tailscale Funnel or Cloudflare Quick Tunnel). The setup script
    writes this file. The dashboard reads it to display a QR code so
    the audience can scan it on their phone during the demo. Public —
    no auth required so the URL can render on the login page."""
    url_file = Path("/etc/blueshield/public-url")
    if not url_file.exists():
        return jsonify({"url": None, "available": False,
                        "hint": "run tools/setup_remote_access.sh"})
    try:
        url = url_file.read_text().strip()
    except Exception as e:
        return jsonify({"url": None, "available": False, "error": str(e)})
    if not url or not url.startswith("http"):
        return jsonify({"url": None, "available": False})
    return jsonify({"url": url, "available": True})


@app.route("/api/system/local-urls")
def api_local_urls():
    """Return every URL the dashboard is reachable at right now from
    the local network. Used by the login page to render QR codes for
    the audience. Public — no auth, by design.

    Order of preference (best first for demo day):
      1. AP IP (10.42.0.1) when BlueShield-AP profile is active
      2. mDNS hostname (blueshield.local)
      3. Live LAN IP (whatever DHCP handed us)
    """
    import socket as _sock
    urls = []
    seen = set()

    def add(url, label):
        if url and url not in seen:
            urls.append({"url": url, "label": label})
            seen.add(url)

    # 1. AP IP — known fixed when BlueShield-AP is up
    try:
        out = subprocess.run(
            ["ip", "-4", "addr", "show", "wlan0"],
            capture_output=True, text=True, timeout=2,
        ).stdout
        if "10.42.0.1" in out:
            add("http://10.42.0.1:8080", "BlueShield WiFi (AP)")
    except Exception:
        pass

    # 2. mDNS hostname (avahi)
    try:
        host = _sock.gethostname()
        if host:
            add(f"http://{host}.local:8080", "mDNS (any device)")
    except Exception:
        pass

    # 3. Whatever IPv4 LAN IP we currently hold (excluding the AP IP we
    # already added, link-local 169.254.x.x, and any IPv6).
    try:
        out = subprocess.run(
            ["hostname", "-I"], capture_output=True, text=True, timeout=2,
        ).stdout
        import re as _re
        v4 = _re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
        for ip in out.split():
            if not v4.match(ip):
                continue
            if ip == "10.42.0.1" or ip.startswith("169.254.") or ip == "127.0.0.1":
                continue
            add(f"http://{ip}:8080", f"LAN ({ip})")
    except Exception:
        pass

    return jsonify({"urls": urls, "count": len(urls)})


# ── New v4 API endpoints ─────────────────────────────────────────────────────

@app.route("/api/system")
def api_system():
    """Raspberry Pi system health — CPU temp, RAM, voltage, uptime."""
    info = {
        "cpu_temp": None,
        "cpu_percent": None,
        "ram_used_mb": None,
        "ram_total_mb": None,
        "ram_percent": None,
        "undervoltage": False,
        "throttled": False,
        "uptime_seconds": None,
        "disk_used_gb": None,
        "disk_total_gb": None,
        "ip_address": None,
    }
    try:
        # CPU temperature (Linux/RPi)
        temp_file = Path("/sys/class/thermal/thermal_zone0/temp")
        if temp_file.exists():
            info["cpu_temp"] = round(int(temp_file.read_text().strip()) / 1000, 1)
    except Exception:
        pass
    try:
        # RAM from /proc/meminfo
        meminfo = Path("/proc/meminfo").read_text()
        mem = {}
        for line in meminfo.splitlines():
            parts = line.split()
            if parts[0] in ("MemTotal:", "MemAvailable:"):
                mem[parts[0]] = int(parts[1])
        total = mem.get("MemTotal:", 0)
        avail = mem.get("MemAvailable:", 0)
        used = total - avail
        info["ram_total_mb"] = round(total / 1024, 1)
        info["ram_used_mb"] = round(used / 1024, 1)
        info["ram_percent"] = round(used / total * 100, 1) if total else 0
    except Exception:
        pass
    try:
        # CPU usage from /proc/stat (two samples 200ms apart)
        def read_cpu():
            line = Path("/proc/stat").read_text().splitlines()[0].split()
            vals = [int(x) for x in line[1:]]
            idle = vals[3]
            total = sum(vals)
            return idle, total
        i1, t1 = read_cpu()
        time.sleep(0.2)
        i2, t2 = read_cpu()
        dt = t2 - t1
        info["cpu_percent"] = round((1 - (i2 - i1) / dt) * 100, 1) if dt else 0
    except Exception:
        pass
    try:
        # Uptime
        uptime_sec = float(Path("/proc/uptime").read_text().split()[0])
        info["uptime_seconds"] = int(uptime_sec)
    except Exception:
        pass
    try:
        # Throttle/undervoltage via vcgencmd (RPi only)
        result = subprocess.run(
            ["vcgencmd", "get_throttled"],
            capture_output=True, text=True, timeout=2
        )
        if result.returncode == 0:
            val = int(result.stdout.strip().split("=")[1], 16)
            info["undervoltage"] = bool(val & 0x1)       # bit 0: currently undervolted
            info["throttled"] = bool(val & 0x4)          # bit 2: currently throttled
            info["throttle_raw"] = hex(val)
    except Exception:
        pass
    try:
        # Disk usage
        stat = subprocess.run(["df", "-BG", "/"], capture_output=True, text=True, timeout=2)
        if stat.returncode == 0:
            parts = stat.stdout.splitlines()[1].split()
            info["disk_total_gb"] = int(parts[1].rstrip("G"))
            info["disk_used_gb"] = int(parts[2].rstrip("G"))
    except Exception:
        pass
    try:
        # IP address
        import socket as _sock
        s = _sock.socket(_sock.AF_INET, _sock.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        info["ip_address"] = s.getsockname()[0]
        s.close()
    except Exception:
        pass
    # BLE adapter inventory
    try:
        hci_out = subprocess.run(
            ["hciconfig", "-a"], capture_output=True, text=True, timeout=3
        )
        if hci_out.returncode == 0:
            adapters = []
            current = None
            for line in hci_out.stdout.splitlines():
                if line and not line[0].isspace() and ":" in line:
                    if current:
                        adapters.append(current)
                    name = line.split(":")[0].strip()
                    current = {"name": name, "address": "", "type": "", "up": "UP" in line}
                elif current and "BD Address:" in line:
                    parts = line.strip().split()
                    idx = parts.index("Address:") + 1 if "Address:" in parts else -1
                    if idx > 0 and idx < len(parts):
                        current["address"] = parts[idx]
                elif current and "Name:" in line:
                    current["type"] = line.split("Name:")[1].strip().strip("'")
            if current:
                adapters.append(current)
            info["bt_adapters"] = adapters
    except Exception:
        pass
    # nRF sniffer status (both dongles)
    if nrf_sniffer:
        info["nrf_sniffer"] = {
            "port": nrf_sniffer.port,
            "running": getattr(nrf_sniffer, '_running', False),
            "simulated": False,
        }
    if nrf_sniffer_2:
        info["nrf_sniffer_2"] = {
            "port": nrf_sniffer_2.port,
            "running": getattr(nrf_sniffer_2, '_running', False),
            "simulated": False,
        }
    return jsonify(info)


@app.route("/api/usb-reset", methods=["POST"])
@login_required
def api_usb_reset():
    """Reset the USB hub to recover crashed adapters, then re-detect and remap."""
    global jammer
    if platform_info.get("os") != "Linux":
        return jsonify({"error": "USB reset only works on Linux"}), 400

    import subprocess as sp

    # Step 1: Stop jammer if running
    if jammer and jammer.is_jamming:
        try:
            jammer.stop_jam()
        except Exception:
            pass

    # Step 2: Reset USB hub
    try:
        sp.run(["bash", "-c", "echo 0 > /sys/bus/usb/devices/1-1/authorized"], timeout=5)
        time.sleep(2)
        sp.run(["bash", "-c", "echo 1 > /sys/bus/usb/devices/1-1/authorized"], timeout=5)
        time.sleep(4)
    except Exception as e:
        return jsonify({"error": f"USB reset failed: {e}"}), 500

    # Step 3: Bring all adapters UP
    for i in range(4):
        sp.run(["hciconfig", f"hci{i}", "up"], capture_output=True, timeout=5)
    time.sleep(1)

    # Step 4: Detect adapters by vendor
    result = sp.run(["hciconfig", "-a"], capture_output=True, text=True, timeout=5)
    detected = {}
    current_name = None
    for line in result.stdout.split("\n"):
        if line and not line[0] in ("\t", " "):
            current_name = line.split(":")[0]
            detected[current_name] = {"up": False, "bus": "", "vendor": ""}
        elif current_name:
            if "UP RUNNING" in line:
                detected[current_name]["up"] = True
            if "Bus:" in line:
                parts = line.strip().split()
                if "Bus:" in parts:
                    detected[current_name]["bus"] = parts[parts.index("Bus:") + 1]
            if "Manufacturer:" in line:
                detected[current_name]["vendor"] = line.split("Manufacturer:")[-1].strip()

    # Step 5: Auto-map roles based on bus type
    # UART = Pi's built-in Broadcom (scanner), USB = Realtek (jammers)
    scanner_iface = None
    jammer_ifaces = []
    for name, info in sorted(detected.items()):
        if not info["up"]:
            continue
        if info["bus"] == "UART":
            scanner_iface = name
        elif info["bus"] == "USB":
            jammer_ifaces.append(name)

    mapping = {
        "scanner": scanner_iface or config.get("interface", "hci2"),
        "jammer_primary": jammer_ifaces[0] if len(jammer_ifaces) >= 1 else config.get("jammer_interface", "hci0"),
        "jammer_secondary": jammer_ifaces[1] if len(jammer_ifaces) >= 2 else None,
        "adapters": detected,
    }

    # Step 6: Update config in memory
    if scanner_iface:
        config["interface"] = scanner_iface
    if len(jammer_ifaces) >= 1:
        config["jammer_interface"] = jammer_ifaces[0]
    if len(jammer_ifaces) >= 2:
        config["jammer_secondary_interface"] = jammer_ifaces[1]

    # Step 7: Reinitialize jammer with new adapters
    try:
        jammer_cfg = {**config, "interface": config.get("jammer_interface", "hci0")}
        jammer = BluetoothJammer(jammer_cfg)
    except Exception as e:
        mapping["jammer_reinit_error"] = str(e)

    # Step 8: Check nRF dongles
    import os
    nrf_status = []
    for port in ["/dev/ttyACM0", "/dev/ttyACM1"]:
        nrf_status.append({"port": port, "available": os.path.exists(port)})
    mapping["nrf_dongles"] = nrf_status

    print(f"[BlueShield] USB Reset: scanner={mapping['scanner']}, "
          f"jammer1={mapping['jammer_primary']}, jammer2={mapping['jammer_secondary']}")

    return jsonify({"status": "ok", "mapping": mapping})


@app.route("/api/correlator/devices")
@login_required
def api_correlator_devices():
    """Get AI-correlated deduplicated device list."""
    return jsonify({
        "devices": device_correlator.get_unified_devices(),
        "stats": device_correlator.get_stats(),
    })


@app.route("/api/correlator/device/<mac>")
@login_required
def api_correlator_device(mac):
    """Look up the cluster a specific MAC belongs to."""
    cluster = device_correlator.get_cluster_for_mac(mac)
    if cluster:
        return jsonify(cluster)
    return jsonify({"error": "MAC not found"}), 404


@app.route("/api/correlator/following")
@login_required
def api_correlator_following():
    """Get devices flagged as persistently following."""
    return jsonify(device_correlator.get_following_devices())


@app.route("/api/correlator/stats")
@login_required
def api_correlator_stats():
    """Get AI model statistics."""
    return jsonify(device_correlator.get_stats())


# ── v7.5 evidence integrity API ──
@app.route("/api/integrity/status")
@login_required
def api_integrity_status():
    """Return signer fingerprint + chained-log verification result."""
    if not HAS_INTEGRITY or signer is None or not signer.available:
        return jsonify({
            "available": False,
            "reason": "cryptography library not installed",
        })
    result = chained_log.verify() if chained_log else {"valid": False}
    return jsonify({
        "available": True,
        "signer_fingerprint": signer.fingerprint,
        "public_key_pem": signer.public_key_pem(),
        "chain": result,
        "algorithm": "Ed25519",
        "hash": "SHA-256",
    })


@app.route("/api/integrity/verify-chain")
@login_required
def api_integrity_verify():
    """Walk the entire hash chain and report any tampering."""
    if not chained_log:
        return jsonify({"valid": False, "reason": "chain log unavailable"}), 503
    return jsonify(chained_log.verify())


@app.route("/api/integrity/pubkey", methods=["GET"])
@login_required
def api_integrity_pubkey():
    """Serve the public key so external auditors can verify signatures."""
    if not signer or not signer.available:
        return jsonify({"error": "signer unavailable"}), 503
    return signer.public_key_pem(), 200, {"Content-Type": "application/x-pem-file"}


def log_event_chained(event_type: str, data: dict):
    """Helper — append an event to the hash-chained log if available."""
    if chained_log:
        try:
            chained_log.append({"event": event_type, **data})
        except Exception as e:
            print(f"[BlueShield] chained log append failed: {e}")


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
        # Ghost mode requires Linux/RPi for the underlying shutdown path.
        socketio.emit("ghost_mode", {"status": "unavailable"})
        return jsonify({"status": "unavailable", "message": "Ghost mode only available on Linux/RPi"})


@app.route("/api/adapters")
@login_required
def api_adapters():
    """Detect and return status of all HCI Bluetooth adapters."""
    adapters = []
    if platform_info.get("os") != "Linux":
        return jsonify({"adapters": [], "note": "Adapter detection requires Linux"})
    try:
        result = subprocess.run(
            ["hciconfig", "-a"],
            capture_output=True, text=True, timeout=5
        )
        current = None
        roles = {
            config.get("interface", "hci2"): "Scanner (Broadcom BT4.1)",
            config.get("jammer_interface", "hci0"): "Primary Jammer (Realtek BT5.4)",
            config.get("jammer_secondary_interface", "hci3"): "Secondary Jammer (Realtek BT5.3)",
        }
        for line in result.stdout.splitlines():
            if line and not line.startswith("\t") and not line.startswith(" "):
                if current:
                    adapters.append(current)
                name = line.split(":")[0].strip()
                current = {
                    "name": name,
                    "role": roles.get(name, "Unassigned"),
                    "up": False,
                    "details": line.strip(),
                }
            elif current and line.strip():
                # hciconfig prints "UP RUNNING" on an indented continuation line,
                # not on the header — flag must be set while we're inside the block
                if "UP RUNNING" in line:
                    current["up"] = True
                if "BD Address" in line:
                    current["address"] = line.split("BD Address:")[1].split()[0]
                if "Name:" in line:
                    current["hw_name"] = line.split("Name:")[1].strip().strip("'")
        if current:
            adapters.append(current)
    except Exception as e:
        return jsonify({"error": str(e), "adapters": []})
    return jsonify({"adapters": adapters})


@app.route("/api/long_range/scan", methods=["POST"])
@login_required
def api_long_range_scan():
    """Trigger a BLE scan on hci2 (nRF52840 Coded PHY — up to 1,300m)."""
    if not config:
        return jsonify({"error": "Not initialized"}), 500
    lr_interface = config.get("long_range_interface", "hci2")

    # Verify hci2 exists before attempting scan
    if platform_info.get("os") == "Linux":
        check = subprocess.run(
            ["hciconfig", lr_interface],
            capture_output=True, text=True, timeout=3
        )
        if check.returncode != 0:
            return jsonify({
                "error": f"{lr_interface} not found — is the nRF52840 (Zephyr HCI) plugged in?",
                "devices": []
            }), 404

    lr_config = {**config, "interface": lr_interface, "scan_duration": 8}
    from blueshield.scanner.bt_scanner import BluetoothScanner as _BS
    lr_scanner = _BS(lr_config)
    try:
        devices = run_async(lr_scanner.scan_ble())
        result = [d.to_dict() for d in devices]
        # Tag every device as long-range
        for d in result:
            d["source"] = "long_range"
        return jsonify({"devices": result, "adapter": lr_interface, "count": len(result)})
    except Exception as e:
        return jsonify({"error": str(e), "devices": []}), 500


@app.route("/api/sniffle/status")
@login_required
def api_sniffle_status():
    """Return Sniffle (nRF52840 #1) configuration and status."""
    port = config.get("sniffle_port", "/dev/ttyACM0") if config else "/dev/ttyACM0"
    enabled = config.get("sniffle_enabled", False) if config else False
    port_exists = False
    if platform_info.get("os") == "Linux":
        from pathlib import Path as _P
        port_exists = _P(port).exists()
    return jsonify({
        "enabled": enabled,
        "port": port,
        "port_exists": port_exists,
        "note": "Sniffle capture: run 'python -m sniffle.sniff_receiver -s <port>' on the Pi",
    })


# ── Sniffer API ──────────────────────────────────────────────────────────────

@app.route("/api/sniffer/status")
@login_required
def api_sniffer_status():
    """Current sniffer engine status, packet stats, and connection list."""
    if sniffer_engine is None:
        return jsonify({"running": False, "error": "Sniffer not initialised"})
    stats = sniffer_engine.get_stats()
    stats["simulated"]   = False
    stats["connections"] = sniffer_engine.get_connections()
    stats["pairing_sessions"] = (
        sniffer_engine.pairing_detector.get_active_sessions()
        + sniffer_engine.pairing_detector.get_history()
    )
    stats["crackle_available"] = crackle_runner.binary_available() if crackle_runner else False
    return jsonify(stats)


@app.route("/api/sniffer/start", methods=["POST"])
@login_required
def api_sniffer_start():
    """Start BLE packet capture."""
    if sniffer_engine is None:
        return jsonify({"error": "Sniffer not initialised"}), 503
    if sniffer_engine._running:
        return jsonify({"status": "already_running"})
    data       = request.get_json(force=True, silent=True) or {}
    target_mac = data.get("target_mac") or None
    rssi_min   = int(data.get("rssi_min", -100))
    coded_phy  = bool(data.get("coded_phy", False))
    sniffer_engine.start(target_mac=target_mac, rssi_min=rssi_min, coded_phy=coded_phy)
    socketio.emit("sniffer_state", {"state": "SCANNING", "simulated": False})
    return jsonify({"status": "started", "simulated": False})


@app.route("/api/sniffer/stop", methods=["POST"])
@login_required
def api_sniffer_stop():
    """Stop BLE packet capture."""
    if sniffer_engine is None:
        return jsonify({"error": "Sniffer not initialised"}), 503
    sniffer_engine.stop()
    socketio.emit("sniffer_state", {"state": "IDLE"})
    return jsonify({"status": "stopped"})


@app.route("/api/sniffer/packets")
@login_required
def api_sniffer_packets():
    """Return the most recent N captured packets."""
    count = min(int(request.args.get("count", 200)), 500)
    if sniffer_engine is None:
        return jsonify({"packets": []})
    return jsonify({"packets": sniffer_engine.get_recent_packets(count)})


@app.route("/api/sniffer/connections")
@login_required
def api_sniffer_connections():
    """Return all captured connections."""
    if sniffer_engine is None:
        return jsonify({"connections": []})
    return jsonify({"connections": sniffer_engine.get_connections()})


@app.route("/api/sniffer/pairing")
@login_required
def api_sniffer_pairing():
    """Return pairing sessions (active + history)."""
    if sniffer_engine is None:
        return jsonify({"sessions": []})
    sessions = (
        sniffer_engine.pairing_detector.get_active_sessions()
        + sniffer_engine.pairing_detector.get_history()
    )
    return jsonify({"sessions": sessions})


@app.route("/api/sniffer/pcap/export")
@login_required
def api_sniffer_pcap_export():
    """Download the current PCAP capture file."""
    if sniffer_engine is None or not hasattr(sniffer_engine, "_current_pcap_path"):
        return jsonify({"error": "No PCAP available"}), 404
    path = sniffer_engine._current_pcap_path
    if not path or not Path(path).exists():
        return jsonify({"error": "PCAP file not found"}), 404
    return send_file(path, as_attachment=True,
                     download_name=Path(path).name,
                     mimetype="application/vnd.tcpdump.pcap")


@app.route("/api/sniffer/gatt", methods=["POST"])
@login_required
def api_sniffer_gatt():
    """Start a GATT inspection for the given MAC address."""
    if gatt_inspector is None:
        return jsonify({"error": "GATT inspector not initialised"}), 503
    data = request.get_json(force=True, silent=True) or {}
    mac  = (data.get("mac") or "").strip().upper()
    if not mac:
        return jsonify({"error": "mac required"}), 400
    if gatt_inspector.is_busy(mac):
        return jsonify({"status": "already_inspecting", "mac": mac})

    def on_gatt_done(result: dict):
        socketio.emit("gatt_result", result)

    gatt_inspector.inspect(mac, on_result=on_gatt_done,
                           read_values=bool(data.get("read_values", True)))
    return jsonify({"status": "started", "mac": mac})


@app.route("/api/sniffer/gatt/<mac>")
@login_required
def api_sniffer_gatt_cached(mac):
    """Return the most recent GATT inspection result for a MAC."""
    if gatt_inspector is None:
        return jsonify({"error": "GATT inspector not initialised"}), 503
    result = gatt_inspector.get_cached_result(mac.upper())
    if result is None:
        return jsonify({"error": "No cached result — start inspection first"}), 404
    return jsonify(result)


@app.route("/api/sniffer/crackle", methods=["POST"])
@login_required
def api_sniffer_crackle():
    """Run crackle against a legacy pairing PCAP."""
    if crackle_runner is None:
        return jsonify({"error": "Crackle runner not initialised"}), 503
    data = request.get_json(force=True, silent=True) or {}
    session_id = data.get("session_id", "manual")

    # Determine PCAP source: explicit path or current capture
    pcap_path = data.get("pcap_path")
    if not pcap_path and sniffer_engine and hasattr(sniffer_engine, "_current_pcap_path"):
        pcap_path = sniffer_engine._current_pcap_path

    if not pcap_path:
        return jsonify({"error": "No PCAP path available — start a capture first"}), 400

    passkey_max = int(data.get("passkey_max", 0))

    def on_crackle_done(result):
        socketio.emit("crackle_result", result.to_dict())

    crackle_runner.crack(
        pcap_path=pcap_path,
        session_id=session_id,
        on_result=on_crackle_done,
        passkey_max=passkey_max,
    )
    return jsonify({"status": "started", "pcap_path": pcap_path})


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
            apple_info=getattr(fp, 'apple_info', None) or None,
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


@app.route("/api/following")
def api_following():
    """Get following detection alerts."""
    clustered = fingerprint_engine.get_clustered_devices() if fingerprint_engine else []
    return jsonify(following_detector.get_all_alerts(clustered) if following_detector else [])


@app.route("/api/shadows")
def api_shadows():
    """Get shadow/stealth device detections."""
    clustered = fingerprint_engine.get_clustered_devices() if fingerprint_engine else []
    return jsonify(shadow_detector.get_all_shadows(clustered) if shadow_detector else [])


@app.route("/api/environment")
def api_environment():
    """Get environment fingerprint and anomalies."""
    clustered = fingerprint_engine.get_clustered_devices() if fingerprint_engine else []
    return jsonify(env_fingerprint.get_anomalies(clustered) if env_fingerprint else {})


@app.route("/api/device/<device_id>/life-story")
def api_life_story(device_id):
    """Get the life story for a device."""
    return jsonify(life_story.get_story(device_id) if life_story else {"events": []})


@app.route("/api/graph")
def api_graph():
    """Get the BLE conversation graph."""
    clustered = fingerprint_engine.get_clustered_devices() if fingerprint_engine else []
    return jsonify(conversation_graph.build_graph(clustered) if conversation_graph else {"nodes": [], "edges": []})


@app.route("/api/trails")
def api_trails():
    """Get movement trail data for radar."""
    return jsonify(trail_tracker.get_all_trails() if trail_tracker else {})


@app.route("/api/advanced-mode", methods=["POST"])
def api_toggle_advanced():
    """Toggle advanced mode."""
    global advanced_mode
    data = request.get_json(force=True, silent=True) or {}
    advanced_mode = data.get("enabled", not advanced_mode)
    socketio.emit("advanced_mode", {"enabled": advanced_mode})
    return jsonify({"enabled": advanced_mode})


# ── Sniffer Socket.IO event emitters (called from sniffer callbacks) ─────────

def _on_sniffer_packet(pkt: BLEPacket):
    """Push a captured BLE packet to all connected clients."""
    socketio.emit("sniffer_packet", pkt.to_dict())


def _on_sniffer_connection(conn: ConnectionRecord):
    """Push a CONNECT_IND event to all connected clients."""
    socketio.emit("sniffer_connection", conn.to_dict())


def _on_sniffer_pairing(session: PairingEvent):
    """Push an SMP pairing event to all connected clients."""
    socketio.emit("sniffer_pairing", session.to_dict())


def _on_sniffer_state(state: str):
    socketio.emit("sniffer_state", {"state": state, "simulated": False})


def _on_sniffer_error(msg: str):
    socketio.emit("sniffer_error", {"message": msg})


# ── nRF Sniffer → Socket.IO bridge ──────────────────────────────────────────

def _nrf_to_blepacket(pkt: dict) -> dict:
    """Convert an nRF sniffer packet dict to the BLEPacket.to_dict() format
    that the frontend sniffer UI expects."""
    aa_str = pkt.get("access_address") or "0x8E89BED6"
    try:
        aa_int = int(aa_str, 16) if isinstance(aa_str, str) else (aa_str or 0x8E89BED6)
    except (ValueError, TypeError):
        aa_int = 0x8E89BED6

    pdu_hex = pkt.get("pdu", "")
    pdu_bytes = bytes.fromhex(pdu_hex) if pdu_hex else b""

    pkt_type = pkt.get("type", "adv")
    if pkt_type == "connect":
        pkt_type = "connect_ind"

    return {
        "ts":              pkt.get("timestamp_us", 0) / 1_000_000,
        "pkt_type":        pkt_type,
        "channel":         pkt.get("channel", 0),
        "rssi":            pkt.get("rssi", 0),
        "access_address":  aa_str,
        "adv_address":     pkt.get("adv_address"),
        "adv_type":        pkt.get("adv_type"),
        "adv_type_name":   pkt.get("adv_type_name"),
        "payload_hex":     pdu_hex,
        "payload_len":     len(pdu_bytes),
        "conn_aa":         aa_str if pkt_type == "connect_ind" else None,
        "hop_increment":   None,
        "crc_init":        None,
        "llid":            None,
        "data_length":     len(pdu_bytes) if pkt_type == "data" else None,
        "adv_name":        pkt.get("adv_name"),
        "manufacturer":    None,
        "source":          "nrf",
    }


def _nrf_bridge_loop():
    """Poll both nRF sniffers for new packets and emit them as socketio events."""
    global _nrf_bridge_running
    while _nrf_bridge_running and nrf_sniffer:
        try:
            # Collect packets from both sniffers
            all_packets = []
            for sniffer_inst, label in [(nrf_sniffer, "nrf1"), (nrf_sniffer_2, "nrf2")]:
                if sniffer_inst is None:
                    continue
                try:
                    pkts = sniffer_inst.get_packets(clear=True)
                    for p in pkts:
                        p["_sniffer_source"] = label
                    all_packets.extend(pkts)
                except Exception:
                    pass

            for pkt in all_packets:
                converted = _nrf_to_blepacket(pkt)
                converted["sniffer_source"] = pkt.get("_sniffer_source", "nrf1")
                socketio.emit("sniffer_packet", converted)

                # Emit connection events
                if pkt.get("type") == "connect":
                    source = pkt.get("_sniffer_source", "nrf1")
                    conn_dict = {
                        "session_id":     f"{source}-{pkt.get('pkt_counter', 0)}",
                        "access_address": pkt.get("access_address"),
                        "central_mac":    pkt.get("central_mac", "??:??:??:??:??:??"),
                        "peripheral_mac": pkt.get("peripheral_mac", "??:??:??:??:??:??"),
                        "start_ts":       time.time(),
                        "end_ts":         None,
                        "duration_s":     None,
                        "hop_increment":  0,
                        "crc_init":       "0x000000",
                        "packet_count":   0,
                        "data_bytes":     0,
                    }
                    socketio.emit("sniffer_connection", conn_dict)

        except Exception as exc:
            print(f"[nRF Bridge] Error: {exc}")

        time.sleep(0.3)


@app.route("/api/nrf-sniffer/status")
@login_required
def api_nrf_sniffer_status():
    """Return the nRF52840 sniffer hardware status and stats."""
    if nrf_sniffer is None:
        return jsonify({"available": False, "reason": "nRF sniffer not initialized"})

    devices = nrf_sniffer.get_devices()
    connections = nrf_sniffer.get_connections()

    return jsonify({
        "available": True,
        "simulated": False,
        "running": getattr(nrf_sniffer, '_running', False),
        "port": nrf_sniffer.port,
        "device_count": len(devices),
        "connection_count": len(connections),
        "devices": devices,
        "connections": connections,
        "bridge_active": _nrf_bridge_running,
    })


@app.route("/api/nrf-sniffer/start", methods=["POST"])
@login_required
def api_nrf_sniffer_start():
    """Start the nRF52840 sniffer and the bridge to dashboard."""
    global _nrf_bridge_running
    if nrf_sniffer is None:
        return jsonify({"error": "nRF sniffer not initialized"}), 400

    if getattr(nrf_sniffer, '_running', False):
        return jsonify({"status": "already_running"})

    try:
        nrf_sniffer.open()
        nrf_sniffer.start_scan()
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500

    # Also start second sniffer if available
    if nrf_sniffer_2:
        try:
            nrf_sniffer_2.open()
            nrf_sniffer_2.start_scan()
        except Exception as exc:
            print(f"[BlueShield] nRF sniffer #2 start failed: {exc}")

    # Start the bridge thread
    if not _nrf_bridge_running:
        _nrf_bridge_running = True
        bridge_t = threading.Thread(target=_nrf_bridge_loop, daemon=True, name="NrfBridge")
        bridge_t.start()

    socketio.emit("sniffer_state", {"state": "SCANNING", "source": "nrf"})
    return jsonify({"status": "started", "simulated": False})


@app.route("/api/nrf-sniffer/stop", methods=["POST"])
@login_required
def api_nrf_sniffer_stop():
    """Stop the nRF52840 sniffer."""
    global _nrf_bridge_running
    if nrf_sniffer is None:
        return jsonify({"error": "nRF sniffer not initialized"}), 400

    _nrf_bridge_running = False
    try:
        nrf_sniffer.stop_scan()
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500

    # Also stop second sniffer
    if nrf_sniffer_2:
        try:
            nrf_sniffer_2.stop_scan()
        except Exception:
            pass

    socketio.emit("sniffer_state", {"state": "IDLE", "source": "nrf"})
    return jsonify({"status": "stopped"})


@app.route("/api/nrf-sniffer/follow", methods=["POST"])
@login_required
def api_nrf_sniffer_follow():
    """Follow a specific BLE device by MAC address."""
    if nrf_sniffer is None:
        return jsonify({"error": "nRF sniffer not initialized"}), 400

    data = request.get_json(force=True, silent=True) or {}
    mac = data.get("mac", "").strip().upper()
    if not mac:
        return jsonify({"error": "MAC address required"}), 400

    try:
        nrf_sniffer.follow_device(mac)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500

    return jsonify({"status": "following", "target": mac})


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
        "jammer": jammer.get_status() if jammer else JAMMER_UNAVAILABLE_STATUS,
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
        "following": following_detector.get_all_alerts(clustered) if following_detector and clustered else [],
        "shadows": shadow_detector.get_all_shadows(clustered) if shadow_detector and clustered else [],
        "environment": env_fingerprint.get_anomalies(clustered) if env_fingerprint and clustered else {},
        "trails": trail_tracker.get_all_trails() if trail_tracker else {},
        "advanced_mode": advanced_mode,
    })


@socketio.on("toggle_autoscan")
def on_toggle_autoscan(data):
    global auto_scan
    auto_scan = data.get("enabled", True)
    socketio.emit("autoscan_changed", {"enabled": auto_scan})


@socketio.on("set_scan_interval")
def on_set_interval(data):
    global scan_interval
    scan_interval = max(10, min(120, int(data.get("interval", 15))))
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

def _reset_adapter_for_scan():
    """Reset the BLE scan adapter so BlueZ releases stale state."""
    try:
        iface = config.get("interface", "hci2") if config else "hci2"
        subprocess.run(["hciconfig", iface, "down"], capture_output=True, timeout=5)
        time.sleep(0.5)
        subprocess.run(["hciconfig", iface, "up"], capture_output=True, timeout=5)
        time.sleep(0.5)
        print(f"[BlueShield] Adapter {iface} reset for clean scan state")
    except Exception as e:
        print(f"[BlueShield] Adapter reset warning: {e}")


def background_scan_loop():
    """Periodically scan and push results to connected clients."""
    last_scan_time = 0
    last_nrf_merge_time = 0
    scan_failures = 0

    # ── Startup settling: give BlueZ/DBus time to initialize after boot ──
    print("[BlueShield] Background scan loop started — waiting 12s for BlueZ to settle...")
    time.sleep(12)

    # Reset the scan adapter to clear any stale state from previous runs
    _reset_adapter_for_scan()
    time.sleep(2)
    print("[BlueShield] Adapter ready — starting scan cycle")

    while True:
        try:
            now = time.monotonic()

            # Run BLE scan on interval
            if auto_scan and (now - last_scan_time) >= scan_interval:
                try:
                    result = do_scan_and_emit()
                    if result and "error" not in (result or {}):
                        scan_failures = 0
                    else:
                        scan_failures += 1
                        if scan_failures <= 3:
                            print(f"[BlueShield] Scan returned no data (attempt {scan_failures})")
                        # After 3 consecutive failures, reset adapter and retry
                        if scan_failures == 3:
                            print("[BlueShield] 3 scan failures — resetting adapter...")
                            _reset_adapter_for_scan()
                except Exception as scan_exc:
                    scan_failures += 1
                    print(f"[BlueShield] Scan loop error #{scan_failures}: {scan_exc}")
                    import traceback
                    traceback.print_exc()
                    if scan_failures >= 3:
                        print("[BlueShield] Persistent scan errors — resetting adapter...")
                        _reset_adapter_for_scan()
                        scan_failures = 0  # Reset counter after recovery
                last_scan_time = time.monotonic()

            # Merge nRF sniffer devices into dashboard every 5 seconds
            if nrf_sniffer and (now - last_nrf_merge_time) >= 5:
                try:
                    _merge_nrf_devices_to_scanner()
                except Exception:
                    pass
                last_nrf_merge_time = now

            # Broadcast jammer status every 2s so packet counter stays live
            if jammer is not None and jammer.is_jamming:
                socketio.emit("jammer_update", jammer.get_status())
        except Exception as loop_exc:
            print(f"[BlueShield] Background loop error: {loop_exc}")
        time.sleep(2)


def _merge_nrf_devices_to_scanner():
    """Feed nRF sniffer discovered devices into the scanner's device table."""
    for sniffer_inst in [nrf_sniffer, nrf_sniffer_2]:
        if not sniffer_inst or not getattr(sniffer_inst, '_running', False):
            continue
        try:
            nrf_devs = sniffer_inst.get_devices()
        except Exception:
            continue
        for nd in nrf_devs:
            addr = nd.get("address", "").upper()
            if not addr or addr == "00:00:00:00:00:00":
                continue
            # Create a lightweight device dict if scanner doesn't know about it
            if hasattr(scanner, 'devices') and addr not in scanner.devices:
                from blueshield.scanner.bt_scanner import BluetoothDevice
                dev = BluetoothDevice(
                    address=addr,
                    name=nd.get("name") or "Unknown",
                    rssi=nd.get("rssi", -100),
                    source="nrf_sniffer",
                )
                dev.manufacturer = nd.get("manufacturer_name", "Unknown")
                dev.service_uuids = nd.get("service_uuids", [])
                dev.tx_power = nd.get("tx_power")
                scanner.devices[addr] = dev
            elif hasattr(scanner, 'devices') and addr in scanner.devices:
                # Update RSSI from sniffer (usually more accurate)
                existing = scanner.devices[addr]
                if nd.get("rssi", -100) > -100:
                    existing.rssi = nd["rssi"]


# ── Entry Point ──────────────────────────────────────────────────────────────

# ── HCI helpers (v7.7) ──
# hci numbers re-enumerate across boots, so banner labels can't be hard-coded.
# Resolve a runtime label from `hciconfig -a` + manufacturer info.
_HCI_CACHE: dict = {}

def _describe_hci(name: str) -> str:
    """Return a human label like 'Realtek BT5.4 USB' for an hciX adapter.
    Cached for the life of the process; falls back to 'unknown' on error."""
    if not name:
        return "unknown"
    if name in _HCI_CACHE:
        return _HCI_CACHE[name]
    try:
        import subprocess as _sp
        out = _sp.run(["hciconfig", name, "version"],
                      capture_output=True, text=True, timeout=2).stdout
        ver = ""
        manu = ""
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("HCI Version:"):
                ver = line.split(":", 1)[1].strip().split()[0]
            if line.startswith("Manufacturer:"):
                manu = line.split(":", 1)[1].strip()
                # "Realtek Semiconductor Corporation (93)" -> "Realtek"
                if "(" in manu: manu = manu.split("(")[0].strip()
                manu = manu.replace("Semiconductor Corporation", "").strip()
        bus = "USB"
        try:
            base = _sp.run(["hciconfig", name], capture_output=True,
                           text=True, timeout=2).stdout
            if "Bus: UART" in base: bus = "UART"
        except Exception:
            pass
        if not manu and bus == "UART":
            manu = "Broadcom"  # Pi onboard chip
        label_parts = [p for p in [manu, f"BT{ver}" if ver else "", bus] if p]
        label = " ".join(label_parts) or "unknown"
    except Exception:
        label = "unknown"
    _HCI_CACHE[name] = label
    return label


def main():
    global scanner, jammer, logger, config, scan_interval, platform_info
    global auto_scan, fingerprint_engine, tracker_detector, ai_classifier
    global following_detector, shadow_detector, env_fingerprint, life_story, conversation_graph, trail_tracker
    global sniffer_engine, gatt_inspector, crackle_runner, nrf_sniffer, nrf_sniffer_2, _nrf_bridge_running, heatmap_store

    parser = argparse.ArgumentParser(description="BlueShield Web Dashboard")
    parser.add_argument("--port", type=int, default=8080, help="Web server port")
    parser.add_argument("--host", default="0.0.0.0", help="Web server host")
    args = parser.parse_args()

    config = load_config()
    scan_interval = config.get("scan_interval", 15)
    platform_info = detect_platform()

    print(f"[BlueShield] Platform: {platform_info['os']}")
    print(f"[BlueShield] Bleak available: {platform_info['has_bleak']}")
    print(f"[BlueShield] hcitool available: {platform_info['has_hcitool']}")

    # Initialize engines
    fingerprint_engine = BLEFingerprintEngine()
    tracker_detector = TrackerDetector()
    ai_classifier = AIDeviceClassifier()
    following_detector = FollowingDetector()
    shadow_detector = ShadowDeviceDetector()
    env_fingerprint = EnvironmentFingerprint()
    life_story = DeviceLifeStory()
    conversation_graph = ConversationGraph()
    trail_tracker = MovementTrailTracker()
    print("[BlueShield] BLE Fingerprinting engine v5.0 initialized")
    print("[BlueShield] Tracker detection engine initialized")
    print("[BlueShield] Risk scoring engine initialized")
    print("[BlueShield] AI device classifier initialized")
    print("[BlueShield] People detection & safety scoring active")
    print("[BlueShield] Following detector active (>=70% confidence)")
    print("[BlueShield] Shadow device detector active")
    print("[BlueShield] Environment fingerprinting active")
    print("[BlueShield] Device life story tracker active")
    print("[BlueShield] Conversation graph engine active")
    print("[BlueShield] Movement trail tracker active")

    print("[BlueShield] Using REAL hardware scanner")
    scanner = BluetoothScanner(config)
    scan_iface = config.get('interface', 'hci2')
    print(f"[BlueShield] Scanner    -> {scan_iface} ({_describe_hci(scan_iface)})")
    if platform_info["os"] == "Linux" and platform_info["has_hcitool"]:
        jammer_cfg = {**config, "interface": config.get("jammer_interface", "hci0")}
        jammer = BluetoothJammer(jammer_cfg)
        sec = config.get("jammer_secondary_interface", "hci3")
        print(f"[BlueShield] Jammer     -> {jammer_cfg['interface']} ({_describe_hci(jammer_cfg['interface'])})")
        print(f"[BlueShield] Jammer 2   -> {sec} ({_describe_hci(sec)})")
    else:
        # Real jammer requires Linux + hcitool. The dashboard surfaces this as
        # offline rather than emitting fake packet-per-second counts.
        print("[BlueShield] *** JAMMER UNAVAILABLE *** requires Linux + hcitool")
        print("[BlueShield] Dashboard will show jammer as 'offline'. No jam commands will run.")
        jammer = None

    logger = BlueShieldLogger(config)

    # v7.5: evidence-integrity init (Ed25519 + chained JSONL event log)
    global signer, chained_log
    signer = None
    chained_log = None
    if HAS_INTEGRITY:
        try:
            keydir = str(Path(__file__).parent.parent / "keys")
            signer = SessionSigner(keydir=keydir)
            chained_log_path = str(Path(__file__).parent.parent / "logs" / "events_chain.jsonl")
            chained_log = ChainedEventLog(chained_log_path, signer=signer)
            if signer.available:
                print(f"[BlueShield] Evidence integrity: Ed25519 signer ready "
                      f"(fingerprint: {signer.fingerprint})")
                print(f"[BlueShield] Chained event log: {chained_log_path}")
                chained_log.append({
                    "event": "session_start",
                    "operator": "admin",
                    "blueshield_version": "7.7",
                })
            else:
                print("[BlueShield] Evidence integrity: cryptography not available")
        except Exception as e:
            print(f"[BlueShield] Evidence integrity init failed: {e}")

    # ── Initialise sniffer subsystem ─────────────────────────────────────────
    pcap_dir = str(Path(__file__).parent.parent.parent / "captures")

    # ── BLE-Map heatmap store ────────────────────────────────────────────────
    heatmap_path = str(Path(pcap_dir) / "heatmap.json")
    heatmap_store = HeatmapStore(heatmap_path)
    cell_count = sum(len(v) for v in heatmap_store.grid.samples.values())
    print(f"[BlueShield] Heatmap store    : {heatmap_store.grid.rows}x{heatmap_store.grid.cols} grid, {cell_count} samples")

    sniffer_engine = make_sniffer(
        serial_port=config.get("sniffle_port", "/dev/ttyACM0"),
        pcap_dir=pcap_dir,
    )
    sniffer_engine.on_packet     = _on_sniffer_packet
    sniffer_engine.on_connection = _on_sniffer_connection
    sniffer_engine.on_pairing    = _on_sniffer_pairing
    sniffer_engine.on_state      = _on_sniffer_state
    sniffer_engine.on_error      = _on_sniffer_error

    gatt_inspector = make_gatt_inspector()
    crackle_runner = CrackleRunner(output_dir=str(Path(pcap_dir) / "crackle"))

    # Be explicit about which sniffer backend is actually live
    backend_name = type(sniffer_engine).__name__  # SniffleEngine / WhadSniffleEngine
    backend_label = {
        "SniffleEngine": "Sniffle / TI CC1352 BLE PDU capture",
        "WhadSniffleEngine": "WHAD / nRF52840 ButteRFly BLE adv-channel sniff",
    }.get(backend_name, backend_name)
    sniffer_status = "HARDWARE" if sniffer_engine.hardware_available else "UNAVAILABLE (no compatible sniffer on serial port)"
    print(f"[BlueShield] Sniffer engine  : {sniffer_status} ({backend_label})")
    print(f"[BlueShield] GATT inspector  : bleak")
    print(f"[BlueShield] Crackle runner  : {'binary: ' + crackle_runner._binary if crackle_runner.binary_available() else 'Python fallback'}")

    # ── Initialise nRF52840 BLE sniffers (dual-dongle) ─────────────────────
    nrf_port   = config.get("nrf_sniffer_port",   "/dev/ttyACM0")
    nrf_port_2 = config.get("nrf_sniffer_port_2", "/dev/ttyACM1")
    nrf_enabled = config.get("nrf_sniffer_enabled", False)
    if nrf_enabled:
        nrf_sniffer = make_nrf_sniffer(port=nrf_port)
        print(f"[BlueShield] nRF52 sniffer #1: HARDWARE -> {nrf_port}")

        try:
            import os
            if os.path.exists(nrf_port_2):
                nrf_sniffer_2 = make_nrf_sniffer(port=nrf_port_2)
                print(f"[BlueShield] nRF52 sniffer #2: HARDWARE -> {nrf_port_2}")
            else:
                print(f"[BlueShield] nRF52 sniffer #2: NOT FOUND ({nrf_port_2})")
        except Exception as e:
            print(f"[BlueShield] nRF52 sniffer #2: FAILED ({e})")
    else:
        print(f"[BlueShield] nRF52 sniffer  : DISABLED (set nrf_sniffer_enabled=true in config)")

    # Start background scanning in a daemon thread
    scan_thread = threading.Thread(target=background_scan_loop, daemon=True)
    scan_thread.start()

    print(f"[BlueShield] Dashboard v7.7 starting at http://localhost:{args.port}")
    socketio.run(app, host=args.host, port=args.port, debug=False, allow_unsafe_werkzeug=True)


if __name__ == "__main__":
    main()
