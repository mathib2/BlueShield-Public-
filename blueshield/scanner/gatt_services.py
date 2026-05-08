"""
Bluetooth SIG GATT service-UUID registry.

Identifies device class from advertised service UUIDs. This is the most
reliable single fingerprinting layer for "what is this device" because the
Bluetooth SIG service UUID is officially assigned and unique per function.

A device that advertises 0x180D (Heart Rate) is *definitely* a heart-rate
sensor — there is no ambiguity. Same for HID (0x1812, keyboards/mice),
Glucose Service (0x1808, diabetes), CGM (0x183A), Insulin Delivery (0x183B),
Hearing Access (0x1854), Pulse Oximeter (0x1822), and so on.

Sources:
  - Bluetooth SIG "Assigned Numbers" document (services + service-specific
    characteristics; updated ~quarterly)
  - https://www.bluetooth.com/specifications/assigned-numbers/
  - GATT Specification Supplement (medical device profiles)
"""
from __future__ import annotations
from typing import Optional


# (label, category, device_class, confidence, hint)
# - category: maps to dashboard group (medical / input / audio / fitness / iot / phone / proximity)
# - device_class: more specific — heart_rate / glucose / insulin / hid_keyboard / hid_mouse / etc.
# - confidence: 0..1, higher when the UUID is uniquely identifying.
# - hint: one-line note shown in tooltip / detail panel.
SERVICE_UUIDS: dict[int, tuple[str, str, str, float, str]] = {
    # ── Standard GATT services (16-bit) ────────────────────────────────────────
    0x1800: ("Generic Access",   "generic", "ble_device",     0.05, ""),
    0x1801: ("Generic Attribute","generic", "ble_device",     0.05, ""),
    0x1802: ("Immediate Alert",  "generic", "alert",          0.30, ""),
    0x1803: ("Link Loss",        "generic", "tracker_alert",  0.40, "Tag/finder may use this for separation alerts"),
    0x1804: ("Tx Power",         "generic", "ble_device",     0.05, ""),

    # ── Medical (high accuracy — these UUIDs only appear on real medical hardware) ─
    0x1808: ("Glucose",                       "medical", "glucose_meter",      0.99, "Blood glucose meter"),
    0x183A: ("Continuous Glucose Monitoring", "medical", "cgm",                0.99, "CGM sensor (Dexcom/Libre/Medtronic)"),
    0x183B: ("Insulin Delivery",              "medical", "insulin_pump",       0.99, "Insulin pump"),
    0x1810: ("Blood Pressure",                "medical", "blood_pressure",     0.99, ""),
    0x1822: ("Pulse Oximeter",                "medical", "pulse_oximeter",     0.99, ""),
    0x1809: ("Health Thermometer",            "medical", "thermometer",        0.95, ""),
    0x181D: ("Weight Scale",                  "medical", "weight_scale",       0.95, ""),
    0x181B: ("Body Composition",              "medical", "body_composition",   0.90, ""),
    0x181C: ("User Data",                     "medical", "user_data",          0.40, "Often paired with weight/composition"),
    0x183C: ("Bond Management",               "medical", "ble_device",         0.10, ""),
    0x1854: ("Hearing Access Service (HAS)",  "medical", "hearing_aid",        0.99, "LE Audio hearing aid"),
    0x1850: ("Published Audio Capabilities",  "audio",   "le_audio",           0.85, "LE Audio sink"),
    0x1851: ("Audio Stream Control (ASCS)",   "audio",   "le_audio",           0.85, "LE Audio stream"),
    0x1852: ("Broadcast Audio Scan (BASS)",   "audio",   "le_audio_broadcast", 0.85, "LE Audio Auracast"),
    0x1853: ("Common Audio Service",          "audio",   "le_audio",           0.85, ""),
    0x1855: ("Telephone Bearer Service",      "phone",   "phone_call",         0.80, ""),
    0x1856: ("Generic Telephone Bearer",      "phone",   "phone_call",         0.75, ""),
    0x1857: ("Microphone Control Service",    "audio",   "le_audio",           0.80, ""),
    0x1844: ("Volume Control",                "audio",   "le_audio",           0.70, ""),
    0x1845: ("Volume Offset Control",         "audio",   "le_audio",           0.50, ""),
    0x1843: ("Audio Input Control",           "audio",   "le_audio",           0.70, ""),

    # ── Input (HID — keyboards, mice, controllers) ─────────────────────────────
    0x1812: ("Human Interface Device", "input", "hid_device",     0.97, "Keyboard / mouse / trackpad / controller"),
    0x180F: ("Battery",                "generic", "ble_device",  0.10, ""),

    # ── Fitness / activity ─────────────────────────────────────────────────────
    0x180D: ("Heart Rate",             "fitness", "heart_rate_strap", 0.97, "Chest strap / fitness watch"),
    0x1814: ("Running Speed Cadence",  "fitness", "running_pod",      0.95, ""),
    0x1816: ("Cycling Speed Cadence",  "fitness", "cycling_sensor",   0.95, ""),
    0x1818: ("Cycling Power",          "fitness", "cycling_power",    0.95, ""),
    0x181E: ("Bond Management",        "fitness", "ble_device",       0.10, ""),
    0x183E: ("Physical Activity Monitor","fitness", "fitness_tracker", 0.85, ""),
    0x1826: ("Fitness Machine",        "fitness", "fitness_machine",  0.95, "Treadmill / bike / rower"),

    # ── Sensors / IoT ──────────────────────────────────────────────────────────
    0x181A: ("Environmental Sensing",  "iot",    "env_sensor",        0.88, "Temperature/humidity/pressure sensor"),
    0x1827: ("Mesh Provisioning",      "iot",    "mesh_node",         0.55, ""),
    0x1828: ("Mesh Proxy",             "iot",    "mesh_node",         0.55, ""),
    0x1846: ("Reconnection Configuration","iot", "ble_device",        0.10, ""),

    # ── Common vendor services (16-bit assigned namespace 0xFExx) ──────────────
    0xFE2C: ("Google Fast Pair",       "audio",  "fastpair_audio",    0.85, "Google Fast Pair (audio device)"),
    0xFE9F: ("Google Generic",         "phone",  "google_device",     0.40, ""),
    0xFEAA: ("Eddystone",              "iot",    "beacon",            0.90, "Google Eddystone beacon"),
    0xFE61: ("Logitech (Unifying)",    "input",  "logitech_input",    0.90, "Logitech keyboard/mouse"),
    0xFEFF: ("GN Netcom (Jabra)",      "audio",  "jabra_audio",       0.90, "Jabra headset"),
    0xFEED: ("Tile",                   "tracker","tile_tag",          0.95, "Tile tracker"),
    0xFEEC: ("Tile",                   "tracker","tile_tag",          0.95, "Tile tracker"),
    0xFE0F: ("Philips Hue",            "iot",    "smart_light",       0.90, "Philips Hue bulb"),
    0xFE2D: ("IKEA TRÅDFRI",          "iot",    "smart_light",       0.85, ""),
    0xFE26: ("Google Wi-Fi setup",     "iot",    "google_device",     0.50, ""),
    0xFE2A: ("DIRECTV",                "tv",     "smart_tv",          0.85, ""),
    0xFE2E: ("Ericsson",               "iot",    "ble_device",        0.20, ""),
    0xFE53: ("3M Scott Safety",        "iot",    "industrial",        0.80, ""),
    0xFE59: ("Nordic Semiconductor",   "iot",    "ble_device",        0.15, "Nordic SoC dev kit"),
    0xFE03: ("Amazon",                 "iot",    "amazon_device",     0.65, ""),
    0xFE9D: ("Pebble Technology",      "watch",  "pebble_watch",      0.95, ""),
    0xFEC9: ("Apple iBeacon (legacy)", "proximity", "beacon",         0.80, ""),
    0xFE6F: ("LINE Beacon",            "proximity","beacon",          0.80, ""),
    0xFCF1: ("Google",                 "phone",  "google_device",     0.40, ""),
    0xFD6F: ("Exposure Notifications", "phone",  "phone",             0.85, "iPhone or Android with Exposure Notifications"),
    0xFD3D: ("Govee",                  "iot",    "govee_sensor",      0.85, "Govee/WALTR sensor or light"),
    0xFD79: ("Hask Technology",        "iot",    "iot_device",        0.40, ""),
    0xFD90: ("Guangzhou SuperSound",   "iot",    "iot_device",        0.40, ""),
    0xFE9A: ("Estimote",               "proximity","beacon",          0.85, ""),
    0xFEAB: ("Nest Labs",              "iot",    "nest_device",       0.85, "Google Nest"),
    0xFEAC: ("Nest Labs",              "iot",    "nest_device",       0.85, "Google Nest"),
    0xFD5A: ("Samsung",                "phone",  "samsung_device",    0.80, ""),
    0xFD43: ("Samsung",                "phone",  "samsung_device",    0.80, ""),
    0xFD3F: ("Sonos",                  "audio",  "sonos_speaker",     0.95, ""),
    0xFE07: ("Sonos",                  "audio",  "sonos_speaker",     0.95, ""),
    0xFD18: ("Spotify",                "audio",  "spotify_connect",   0.70, ""),
    0xFE0C: ("Garmin",                 "fitness","garmin_device",     0.90, "Garmin watch / cycling"),
    0xFE7F: ("Garmin",                 "fitness","garmin_device",     0.90, ""),
    0xFC8E: ("Yale",                   "iot",    "smart_lock",        0.95, "Yale smart lock"),
    0xFD5C: ("August Home",            "iot",    "smart_lock",        0.95, "August smart lock"),
    0xFE56: ("Google Find My Device",  "tracker","fmd_tag",           0.90, "Google Find My Device"),

    # ── BTHome v2 (open-source IoT sensor protocol) ────────────────────────────
    0xFCD2: ("BTHome v2",              "iot",    "bthome_sensor",     0.95, "Open-source BLE sensor (Shelly/Xiaomi/etc.)"),

    # ── Diabetes-specific known UUIDs (proprietary services from real devices) ─
    0xFE5C: ("Dexcom (legacy)",        "medical","cgm",               0.95, "Dexcom CGM"),
    0xF8A2: ("Freestyle Libre 3",      "medical","cgm",               0.92, "Abbott FreeStyle Libre 3"),
    0xFE76: ("Tandem Diabetes",        "medical","insulin_pump",      0.92, "Tandem t:slim X2 / Mobi"),

    # ── Pacemakers / Implantable cardiac devices (proprietary) ─────────────────
    # These show up on patients' Bluetooth-enabled implants when in pairing mode.
    0xFE36: ("Medtronic",              "medical","pacemaker",         0.85, "Medtronic implantable device"),
    0xFE3F: ("Medtronic",              "medical","pacemaker",         0.85, ""),
    0xFCBE: ("Abbott (St. Jude)",      "medical","pacemaker",         0.85, "Abbott Confirm Rx ICM"),

    # ── Hearing aids (proprietary) ─────────────────────────────────────────────
    0xFDF0: ("Android ASHA",           "medical","hearing_aid",       0.97, "Android Streaming for Hearing Aids"),
    0xFDFE: ("ReSound (GN)",           "medical","hearing_aid",       0.92, "GN ReSound hearing aid"),
    0xFDD0: ("Sonova / Phonak",        "medical","hearing_aid",       0.90, "Phonak hearing aid"),
    0xFDD7: ("Oticon",                 "medical","hearing_aid",       0.90, "Oticon / Bernafon"),
}


# Same registry but indexed by 4-char hex (the form bleak gives us)
SERVICE_BY_HEX: dict[str, tuple[str, str, str, float, str]] = {
    f"{k:04x}": v for k, v in SERVICE_UUIDS.items()
}


def resolve_uuid(uuid_str: str) -> Optional[tuple[str, str, str, float, str]]:
    """Resolve a service UUID (any form) to (label, category, class, conf, hint).

    Accepts:
      - 16-bit short form: "180d", "0x180d", "180D"
      - Full 128-bit form: "0000180d-0000-1000-8000-00805f9b34fb"
      - Vendor 128-bit form (returns None — caller can match against
        VENDOR_SERVICE_UUIDS_128 if needed).
    """
    if not uuid_str:
        return None
    s = uuid_str.lower().replace("-", "").replace("0x", "")
    # Long form — extract the short part if it's a SIG-base UUID
    if len(s) == 32 and s.endswith("00001000800000805f9b34fb"):
        s = s[4:8]
    if len(s) == 4:
        return SERVICE_BY_HEX.get(s)
    return None


def classify_by_services(uuids: list[str]) -> Optional[dict]:
    """Pick the highest-confidence service from a device's advertised UUID list."""
    best: Optional[tuple[str, tuple]] = None
    for u in (uuids or []):
        m = resolve_uuid(u)
        if m and (best is None or m[3] > best[1][3]):
            best = (u, m)
    if best is None:
        return None
    label, category, dclass, conf, hint = best[1]
    return {
        "service_label": label,
        "category":     category,
        "device_class": dclass,
        "confidence":   conf,
        "hint":         hint,
        "matched_uuid": best[0],
    }
