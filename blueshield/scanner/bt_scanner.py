"""
BlueShield Bluetooth Scanner/Sniffer Module

Scans for Classic Bluetooth and BLE devices using the system's HCI interface.
Designed for Raspberry Pi with built-in or USB Bluetooth adapter.

Requires: bluez, pybluez2 (classic), bleak (BLE)
Run as root for full scanning capabilities.
"""

import asyncio
import json
import time
import subprocess
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import Optional
from pathlib import Path


@dataclass
class BluetoothDevice:
    """Represents a discovered Bluetooth device."""
    address: str
    name: str = "Unknown"
    rssi: int = 0
    device_class: str = "Unknown"
    device_type: str = "Unknown"  # "classic", "ble", "dual"
    manufacturer: str = "Unknown"
    services: list = field(default_factory=list)
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
                    dev = BluetoothDevice(
                        address=addr, name=name, device_type="classic"
                    )
                    devices.append(dev)
        except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError) as e:
            pass  # hcitool not available or scan failed

        # Also try to get RSSI via hcitool rssi for connected devices
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
        """Scan for BLE devices using bleak (cross-platform)."""
        devices = []
        try:
            from bleak import BleakScanner

            # Use callback-based scanning for better RSSI capture
            found_devices = {}

            def detection_callback(device, advertisement_data):
                rssi = advertisement_data.rssi if advertisement_data else 0
                name = device.name or (advertisement_data.local_name if advertisement_data else None) or "Unknown"
                mfr = ""
                if advertisement_data and advertisement_data.manufacturer_data:
                    mfr_id = list(advertisement_data.manufacturer_data.keys())[0]
                    mfr = f"MFR-ID:{mfr_id}"
                found_devices[device.address] = {
                    "address": device.address,
                    "name": name,
                    "rssi": rssi,
                    "manufacturer": mfr,
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
                    manufacturer=info["manufacturer"] or "Unknown",
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
            # Enable LE scan first
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

            # Parse raw HCI dump output
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

        # Run BLE scan (primary, cross-platform)
        ble_devices = await self.scan_ble_bleak()

        # Run classic scan (Linux/RPi only)
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

        # Determine alert level
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

        return {
            "total_devices": total,
            "known_devices": known,
            "unknown_devices": unknown,
            "critical_alerts": critical,
            "warning_alerts": warning,
            "total_scans": self.total_scans,
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
        ("AA:BB:CC:DD:EE:01", "iPhone 14 Pro", "ble", -45),
        ("AA:BB:CC:DD:EE:02", "AirPods Pro", "ble", -30),
        ("AA:BB:CC:DD:EE:03", "Galaxy Buds2", "ble", -55),
        ("AA:BB:CC:DD:EE:04", "JBL Flip 6", "classic", -60),
        ("AA:BB:CC:DD:EE:05", "Unknown Device", "ble", -70),
        ("AA:BB:CC:DD:EE:06", "Logitech MX Keys", "ble", -35),
        ("AA:BB:CC:DD:EE:07", "Fitbit Sense", "ble", -50),
        ("AA:BB:CC:DD:EE:08", "SUSPICIOUS_DEVICE", "ble", -80),
        ("AA:BB:CC:DD:EE:09", "RPi-Attacker", "classic", -90),
        ("AA:BB:CC:DD:EE:0A", "Unknown", "ble", -75),
        ("AA:BB:CC:DD:EE:0B", "MacBook Pro", "ble", -40),
        ("AA:BB:CC:DD:EE:0C", "Bose QC45", "classic", -38),
    ]

    async def run_scan(self) -> dict:
        import random
        self.is_scanning = True
        self.total_scans += 1
        scan_start = datetime.now(timezone.utc).isoformat()
        new_devices = []
        unknown_devices = []

        # Randomly select a subset of devices each scan
        num_found = random.randint(3, len(self.FAKE_DEVICES))
        found = random.sample(self.FAKE_DEVICES, num_found)

        all_devs = []
        for addr, name, dtype, base_rssi in found:
            rssi = base_rssi + random.randint(-10, 10)
            dev = BluetoothDevice(
                address=addr, name=name, device_type=dtype, rssi=rssi
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
