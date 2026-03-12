"""
BlueShield Bluetooth Scanner/Sniffer Module

Scans for Classic Bluetooth and BLE devices using the system's HCI interface.
Designed for Raspberry Pi with built-in or USB Bluetooth adapter.

Requires: bluez, pybluez2 (classic), bleak (BLE), bluetooth-numbers (device ID)
Run as root for full scanning capabilities.
"""

import asyncio
import json
import time
import struct
import subprocess
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import Optional
from pathlib import Path


# ── Bluetooth SIG Company IDs (built-in fallback) ─────────────────────────
# Used when bluetooth-numbers is not installed
COMPANY_IDS = {
    6: "Microsoft",
    76: "Apple, Inc.",
    89: "Nordic Semiconductor",
    117: "Samsung Electronics",
    224: "Google",
    301: "Bose Corporation",
    343: "Texas Instruments",
    397: "Laird Connectivity",
    741: "Xiaomi",
    919: "Amazfit",
    1177: "Fitbit",
    1370: "JBL",
    1452: "Logitech",
    2558: "Meta Platforms",
}

# ── Apple Continuity Device Types ──────────────────────────────────────────
# Byte at offset 1 of Apple manufacturer data (company ID 76)
APPLE_DEVICE_TYPES = {
    0x01: "AirPods",
    0x02: "iPhone",
    0x03: "iPad",
    0x04: "MacBook",
    0x05: "Apple Watch",
    0x06: "iPod touch",
    0x07: "iPhone",
    0x09: "MacBook",
    0x0A: "Apple Watch",
    0x0B: "MacBook",
    0x0C: "HomePod",
    0x0E: "AirPods Pro",
    0x0F: "AirPods Max",
    0x10: "AirPods Pro 2",
    0x12: "HomePod mini",
    0x14: "AirTag",
    0x19: "Apple Vision Pro",
}

# ── BLE Service UUID → Category Mapping ────────────────────────────────────
SERVICE_CATEGORIES = {
    "180d": ("Heart Rate", "health"),
    "180f": ("Battery", "accessory"),
    "1812": ("HID", "input"),         # Keyboards, mice, game controllers
    "180a": ("Device Info", "generic"),
    "1800": ("Generic Access", "generic"),
    "1801": ("Generic Attribute", "generic"),
    "1802": ("Immediate Alert", "alert"),
    "1803": ("Link Loss", "alert"),
    "1804": ("Tx Power", "generic"),
    "1805": ("Current Time", "time"),
    "1810": ("Blood Pressure", "health"),
    "1816": ("Cycling Speed", "fitness"),
    "1818": ("Cycling Power", "fitness"),
    "181c": ("User Data", "generic"),
    "fe9f": ("Google Fast Pair", "audio"),
    "febe": ("Bose", "audio"),
    "fd5a": ("Samsung", "phone"),
}


def resolve_company(company_id: int) -> str:
    """Resolve Bluetooth SIG company ID to manufacturer name."""
    try:
        from bluetooth_numbers import company
        name = company.get(company_id)
        if name:
            return name
    except ImportError:
        pass
    return COMPANY_IDS.get(company_id, f"Unknown ({company_id})")


def decode_apple_device(mfr_data: bytes) -> str:
    """Decode Apple continuity protocol to identify device type."""
    if len(mfr_data) < 2:
        return "Apple Device"
    # Apple continuity message type is at byte 0
    msg_type = mfr_data[0]
    if msg_type in APPLE_DEVICE_TYPES:
        return APPLE_DEVICE_TYPES[msg_type]
    # Fallback: check for common subtypes
    if msg_type == 0x10:  # Nearby Info
        if len(mfr_data) >= 3:
            device_byte = mfr_data[2] >> 4
            device_map = {
                1: "iPhone", 2: "iPhone", 3: "iPad", 4: "MacBook",
                5: "Apple Watch", 6: "iPod touch", 7: "iPhone",
                9: "MacBook", 10: "Apple Watch", 14: "AirPods",
            }
            return device_map.get(device_byte, "Apple Device")
    return "Apple Device"


def classify_device(name: str, manufacturer: str, service_uuids: list, rssi: int) -> str:
    """Infer device category from available data."""
    name_lower = (name or "").lower()
    mfr_lower = (manufacturer or "").lower()

    # Name-based classification
    name_keywords = {
        "input": ["keyboard", "mouse", "mx keys", "mx master", "k380", "trackpad", "logitech m"],
        "audio": ["airpods", "buds", "headphone", "speaker", "bose", "jbl", "beats",
                   "sony wh", "sony wf", "jabra", "soundcore", "earbuds", "qc45", "qc35"],
        "phone": ["iphone", "galaxy", "pixel", "oneplus", "huawei", "xiaomi", "samsung sm"],
        "tablet": ["ipad", "galaxy tab", "fire hd"],
        "watch": ["apple watch", "galaxy watch", "fitbit", "amazfit", "garmin", "band"],
        "computer": ["macbook", "thinkpad", "surface", "imac", "mac mini", "laptop"],
        "tv": ["fire tv", "chromecast", "roku", "appletv", "smart tv", "lg tv", "samsung tv"],
        "tracker": ["airtag", "tile", "smarttag", "chipolo"],
        "health": ["blood pressure", "thermometer", "scale", "oximeter"],
        "gaming": ["controller", "xbox", "playstation", "dualsense", "joy-con", "switch pro"],
        "iot": ["bulb", "sensor", "switch", "plug", "thermostat", "lock", "doorbell",
                "ring", "nest", "hue", "tuya", "tapo", "govee", "elk-bledom"],
    }
    for category, keywords in name_keywords.items():
        if any(kw in name_lower for kw in keywords):
            return category

    # Service UUID classification
    for uuid_str in service_uuids:
        short = uuid_str.replace("-", "")[:4].lower()
        if short in SERVICE_CATEGORIES:
            return SERVICE_CATEGORIES[short][1]

    # Manufacturer-based fallback
    if "apple" in mfr_lower:
        return "apple"
    if "samsung" in mfr_lower:
        return "phone"
    if "logitech" in mfr_lower:
        return "input"
    if "bose" in mfr_lower or "jbl" in mfr_lower:
        return "audio"

    # RSSI-based hint (very close = likely personal device)
    if rssi > -40:
        return "nearby"

    return "unknown"


# ── Device Category Icons (for dashboard) ──────────────────────────────────
CATEGORY_ICONS = {
    "phone": "📱", "tablet": "📱", "computer": "💻", "input": "🖱️",
    "audio": "🎧", "watch": "⌚", "health": "❤️", "fitness": "🏃",
    "tv": "📺", "tracker": "📍", "gaming": "🎮", "iot": "💡",
    "apple": "🍎", "nearby": "📶", "generic": "📡", "unknown": "❓",
}


@dataclass
class BluetoothDevice:
    """Represents a discovered Bluetooth device."""
    address: str
    name: str = "Unknown"
    rssi: int = 0
    device_class: str = "Unknown"
    device_type: str = "Unknown"  # "classic", "ble", "dual"
    manufacturer: str = "Unknown"
    category: str = "unknown"     # phone, audio, input, watch, etc.
    category_icon: str = "❓"
    services: list = field(default_factory=list)
    service_uuids: list = field(default_factory=list)
    tx_power: int = 0
    first_seen: str = ""
    last_seen: str = ""
    seen_count: int = 0
    is_known: bool = False
    alert_level: str = "none"  # "none", "info", "warning", "critical"

    def to_dict(self):
        return asdict(self)

    def update_seen(self):
        now = datetime.now(timezone.utc).isoformat()
        if not self.first_seen:
            self.first_seen = now
        self.last_seen = now
        self.seen_count += 1


class BluetoothScanner:
    """Main Bluetooth scanner that combines Classic BT and BLE scanning."""

    def __init__(self, config: dict):
        self.config = config
        self.interface = config.get("interface", "hci0")
        self.scan_duration = config.get("scan_duration", 10)
        self.devices: dict[str, BluetoothDevice] = {}
        self.scan_history: list[dict] = []
        self.known_devices: set[str] = set()
        self.is_scanning = False
        self.total_scans = 0
        self._load_known_devices()

    def _load_known_devices(self):
        """Load known/whitelisted device addresses."""
        known_file = self.config.get("known_devices_file", "")
        if known_file and Path(known_file).exists():
            with open(known_file, "r") as f:
                data = json.load(f)
                self.known_devices = set(data.get("devices", []))

    def save_known_devices(self):
        """Save known devices list."""
        known_file = self.config.get("known_devices_file", "")
        if known_file:
            Path(known_file).parent.mkdir(parents=True, exist_ok=True)
            with open(known_file, "w") as f:
                json.dump({"devices": list(self.known_devices)}, f, indent=2)

    def add_known_device(self, address: str):
        """Add a device to the known/whitelist."""
        self.known_devices.add(address.upper())
        if address.upper() in self.devices:
            self.devices[address.upper()].is_known = True
            self.devices[address.upper()].alert_level = "none"
        self.save_known_devices()

    def scan_classic_hcitool(self) -> list[BluetoothDevice]:
        """Scan for Classic Bluetooth devices using hcitool (Linux/RPi)."""
        devices = []
        try:
            result = subprocess.run(
                ["hcitool", "-i", self.interface, "scan", "--flush"],
                capture_output=True, text=True, timeout=self.scan_duration + 5
            )
            for line in result.stdout.strip().split("\n")[1:]:  # skip header
                parts = line.strip().split("\t")
                if len(parts) >= 2:
                    addr = parts[0].strip()
                    name = parts[1].strip() if len(parts) > 1 else "Unknown"
                    cat = classify_device(name, "", [], -70)
                    dev = BluetoothDevice(
                        address=addr, name=name, device_type="classic",
                        category=cat, category_icon=CATEGORY_ICONS.get(cat, "❓"),
                    )
                    devices.append(dev)
        except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError):
            pass

        # Try to get RSSI via hcitool inq
        try:
            result = subprocess.run(
                ["hcitool", "-i", self.interface, "inq", "--flush"],
                capture_output=True, text=True, timeout=self.scan_duration + 5
            )
            for line in result.stdout.strip().split("\n")[1:]:
                parts = line.strip().split()
                if len(parts) >= 1:
                    addr = parts[0]
                    for dev in devices:
                        if dev.address == addr and len(parts) >= 6:
                            try:
                                dev.rssi = int(parts[-1])
                            except ValueError:
                                pass
        except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError):
            pass

        return devices

    async def scan_ble_bleak(self) -> list[BluetoothDevice]:
        """Scan for BLE devices using bleak with full advertisement parsing."""
        devices = []
        try:
            from bleak import BleakScanner

            found_devices = {}

            def detection_callback(device, advertisement_data):
                rssi = advertisement_data.rssi if advertisement_data else 0
                name = device.name or (
                    advertisement_data.local_name if advertisement_data else None
                ) or "Unknown"

                # ── Manufacturer resolution ──
                manufacturer = "Unknown"
                apple_type = ""
                mfr_ids = []
                if advertisement_data and advertisement_data.manufacturer_data:
                    for mfr_id, mfr_bytes in advertisement_data.manufacturer_data.items():
                        mfr_ids.append(mfr_id)
                        manufacturer = resolve_company(mfr_id)
                        # Decode Apple continuity data
                        if mfr_id == 76 and len(mfr_bytes) >= 2:
                            apple_type = decode_apple_device(mfr_bytes)

                # ── Service UUIDs ──
                svc_uuids = []
                if advertisement_data and advertisement_data.service_uuids:
                    svc_uuids = list(advertisement_data.service_uuids)

                # ── TX Power ──
                tx_power = 0
                if advertisement_data and advertisement_data.tx_power is not None:
                    tx_power = advertisement_data.tx_power

                # Use Apple type as name if device name is unknown
                display_name = name
                if display_name == "Unknown" and apple_type:
                    display_name = apple_type

                # ── Device categorization ──
                category = classify_device(display_name, manufacturer, svc_uuids, rssi)
                icon = CATEGORY_ICONS.get(category, "❓")

                found_devices[device.address] = {
                    "address": device.address,
                    "name": display_name,
                    "rssi": rssi,
                    "manufacturer": manufacturer,
                    "category": category,
                    "category_icon": icon,
                    "service_uuids": svc_uuids,
                    "tx_power": tx_power,
                }

            scanner = BleakScanner(detection_callback=detection_callback)
            await scanner.start()
            await asyncio.sleep(self.scan_duration)
            await scanner.stop()

            for addr, info in found_devices.items():
                dev = BluetoothDevice(
                    address=info["address"],
                    name=info["name"],
                    rssi=info["rssi"],
                    device_type="ble",
                    manufacturer=info["manufacturer"],
                    category=info["category"],
                    category_icon=info["category_icon"],
                    service_uuids=info["service_uuids"],
                    tx_power=info["tx_power"],
                )
                devices.append(dev)
        except ImportError:
            pass  # bleak not installed
        except Exception as e:
            print(f"[BlueShield] BLE scan error: {e}")
        return devices

    def scan_hcidump_passive(self, duration: int = 5) -> list[dict]:
        """Passive sniffing using hcidump — captures raw HCI packets."""
        packets = []
        try:
            subprocess.run(
                ["hciconfig", self.interface, "up"],
                capture_output=True, timeout=5
            )
            subprocess.run(
                ["hcitool", "-i", self.interface, "lescan", "--duplicates"],
                capture_output=True, timeout=2,
            )

            proc = subprocess.Popen(
                ["hcidump", "-i", self.interface, "-X"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )
            time.sleep(duration)
            proc.terminate()
            output = proc.stdout.read()

            current_packet = []
            for line in output.split("\n"):
                if line.startswith(">") or line.startswith("<"):
                    if current_packet:
                        packets.append({
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "direction": "rx" if current_packet[0].startswith(">") else "tx",
                            "raw": "\n".join(current_packet),
                        })
                    current_packet = [line]
                elif line.strip():
                    current_packet.append(line)
            if current_packet:
                packets.append({
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "direction": "rx" if current_packet[0].startswith(">") else "tx",
                    "raw": "\n".join(current_packet),
                })
        except (FileNotFoundError, PermissionError, subprocess.TimeoutExpired):
            pass
        return packets

    async def run_scan(self) -> dict:
        """Execute a full scan cycle (classic + BLE) and return results."""
        self.is_scanning = True
        self.total_scans += 1
        scan_start = datetime.now(timezone.utc).isoformat()
        new_devices = []
        unknown_devices = []

        ble_devices = await self.scan_ble_bleak()
        classic_devices = self.scan_classic_hcitool()
        all_found = ble_devices + classic_devices

        for dev in all_found:
            addr = dev.address.upper()
            if addr in self.devices:
                existing = self.devices[addr]
                existing.update_seen()
                existing.rssi = dev.rssi or existing.rssi
                if dev.name != "Unknown":
                    existing.name = dev.name
                if dev.manufacturer != "Unknown":
                    existing.manufacturer = dev.manufacturer
                if dev.category != "unknown":
                    existing.category = dev.category
                    existing.category_icon = dev.category_icon
                if dev.service_uuids:
                    existing.service_uuids = list(set(existing.service_uuids + dev.service_uuids))
                if dev.tx_power:
                    existing.tx_power = dev.tx_power
                if dev.services:
                    existing.services = list(set(existing.services + dev.services))
            else:
                dev.update_seen()
                dev.is_known = addr in self.known_devices
                if not dev.is_known:
                    dev.alert_level = "warning"
                    unknown_devices.append(dev)
                new_devices.append(dev)
                self.devices[addr] = dev

        alert_count = len(unknown_devices)
        threshold = self.config.get("alert_threshold", 3)
        alert_status = "normal"
        if alert_count >= threshold:
            alert_status = "critical"
            for dev in unknown_devices:
                dev.alert_level = "critical"
        elif alert_count > 0:
            alert_status = "warning"

        scan_result = {
            "scan_id": self.total_scans,
            "timestamp": scan_start,
            "duration": self.scan_duration,
            "total_devices": len(all_found),
            "new_devices": len(new_devices),
            "unknown_devices": alert_count,
            "alert_status": alert_status,
            "devices_found": [d.to_dict() for d in all_found],
        }
        self.scan_history.append(scan_result)
        self.is_scanning = False
        return scan_result

    def get_device_summary(self) -> dict:
        """Get a summary of all discovered devices."""
        total = len(self.devices)
        known = sum(1 for d in self.devices.values() if d.is_known)
        unknown = total - known
        critical = sum(1 for d in self.devices.values() if d.alert_level == "critical")
        warning = sum(1 for d in self.devices.values() if d.alert_level == "warning")

        # Category breakdown
        categories = {}
        for d in self.devices.values():
            cat = d.category or "unknown"
            categories[cat] = categories.get(cat, 0) + 1

        return {
            "total_devices": total,
            "known_devices": known,
            "unknown_devices": unknown,
            "critical_alerts": critical,
            "warning_alerts": warning,
            "total_scans": self.total_scans,
            "categories": categories,
        }

    def get_all_devices(self) -> list[dict]:
        """Return all devices sorted by last_seen."""
        devs = sorted(
            self.devices.values(),
            key=lambda d: d.last_seen or "",
            reverse=True
        )
        return [d.to_dict() for d in devs]


# --- Simulated scanner for development/demo without hardware ---

class SimulatedScanner(BluetoothScanner):
    """Simulated scanner for testing the dashboard without Bluetooth hardware."""

    import random

    FAKE_DEVICES = [
        ("AA:BB:CC:DD:EE:01", "iPhone 14 Pro", "ble", -45, "Apple, Inc.", "phone", "📱"),
        ("AA:BB:CC:DD:EE:02", "AirPods Pro", "ble", -30, "Apple, Inc.", "audio", "🎧"),
        ("AA:BB:CC:DD:EE:03", "Galaxy Buds2", "ble", -55, "Samsung Electronics", "audio", "🎧"),
        ("AA:BB:CC:DD:EE:04", "JBL Flip 6", "classic", -60, "JBL", "audio", "🎧"),
        ("AA:BB:CC:DD:EE:05", "Unknown Device", "ble", -70, "Unknown", "unknown", "❓"),
        ("AA:BB:CC:DD:EE:06", "Logitech MX Keys", "ble", -35, "Logitech", "input", "🖱️"),
        ("AA:BB:CC:DD:EE:07", "Fitbit Sense", "ble", -50, "Fitbit", "watch", "⌚"),
        ("AA:BB:CC:DD:EE:08", "SUSPICIOUS_DEVICE", "ble", -80, "Unknown", "unknown", "❓"),
        ("AA:BB:CC:DD:EE:09", "RPi-Attacker", "classic", -90, "Unknown", "unknown", "❓"),
        ("AA:BB:CC:DD:EE:0A", "Apple Watch S9", "ble", -42, "Apple, Inc.", "watch", "⌚"),
        ("AA:BB:CC:DD:EE:0B", "MacBook Pro", "ble", -40, "Apple, Inc.", "computer", "💻"),
        ("AA:BB:CC:DD:EE:0C", "Bose QC45", "classic", -38, "Bose Corporation", "audio", "🎧"),
    ]

    async def run_scan(self) -> dict:
        import random
        self.is_scanning = True
        self.total_scans += 1
        scan_start = datetime.now(timezone.utc).isoformat()
        new_devices = []
        unknown_devices = []

        num_found = random.randint(3, len(self.FAKE_DEVICES))
        found = random.sample(self.FAKE_DEVICES, num_found)

        all_devs = []
        for addr, name, dtype, base_rssi, mfr, cat, icon in found:
            rssi = base_rssi + random.randint(-10, 10)
            dev = BluetoothDevice(
                address=addr, name=name, device_type=dtype, rssi=rssi,
                manufacturer=mfr, category=cat, category_icon=icon,
            )
            all_devs.append(dev)

            if addr in self.devices:
                existing = self.devices[addr]
                existing.update_seen()
                existing.rssi = rssi
            else:
                dev.update_seen()
                dev.is_known = addr in self.known_devices
                if not dev.is_known:
                    dev.alert_level = "warning"
                    unknown_devices.append(dev)
                new_devices.append(dev)
                self.devices[addr] = dev

        alert_count = len(unknown_devices)
        threshold = self.config.get("alert_threshold", 3)
        alert_status = "normal"
        if alert_count >= threshold:
            alert_status = "critical"
            for dev in unknown_devices:
                dev.alert_level = "critical"
        elif alert_count > 0:
            alert_status = "warning"

        scan_result = {
            "scan_id": self.total_scans,
            "timestamp": scan_start,
            "duration": self.scan_duration,
            "total_devices": len(all_devs),
            "new_devices": len(new_devices),
            "unknown_devices": alert_count,
            "alert_status": alert_status,
            "devices_found": [d.to_dict() for d in all_devs],
        }
        self.scan_history.append(scan_result)
        self.is_scanning = False
        return scan_result
