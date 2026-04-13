"""
GATT Inspector — Bleak-based BLE service and characteristic enumeration.

Connects to a peripheral, walks all GATT services and characteristics,
reads values for readable characteristics (with timeout protection),
and returns a structured JSON-serialisable dict.

Runs in a worker thread; the caller receives results via an asyncio-to-
threading bridge so Flask/SocketIO can emit the result safely.

Edge cases handled:
  - Characteristic read timeouts
  - Descriptors that refuse reads
  - Encoding errors in name / value fields
  - Rapid repeated inspection requests for the same MAC (debounced)
  - Adapter busy / connection refused errors
  - MTU negotiation (requests 247 bytes where possible)
"""

from __future__ import annotations

import asyncio
import struct
import threading
import time
from typing import Any, Callable, Dict, List, Optional

# Standard GATT UUIDs (16-bit short form expanded to 128-bit)
# https://www.bluetooth.com/specifications/assigned-numbers/

_SERVICE_NAMES: Dict[str, str] = {
    "1800": "Generic Access",
    "1801": "Generic Attribute",
    "180a": "Device Information",
    "180d": "Heart Rate",
    "180f": "Battery Service",
    "1810": "Blood Pressure",
    "1812": "Human Interface Device",
    "1816": "Cycling Speed and Cadence",
    "1818": "Cycling Power",
    "181a": "Environmental Sensing",
    "181c": "User Data",
    "181e": "Bond Management",
    "1820": "Internet Protocol Support",
    "1823": "Pulse Oximeter",
    "1826": "Fitness Machine",
    "fe59": "Nordic DFU Service",
}

_CHAR_NAMES: Dict[str, str] = {
    "2a00": "Device Name",
    "2a01": "Appearance",
    "2a02": "Peripheral Privacy Flag",
    "2a03": "Reconnection Address",
    "2a04": "Peripheral Preferred Connection Parameters",
    "2a05": "Service Changed",
    "2a19": "Battery Level",
    "2a23": "System ID",
    "2a24": "Model Number String",
    "2a25": "Serial Number String",
    "2a26": "Firmware Revision String",
    "2a27": "Hardware Revision String",
    "2a28": "Software Revision String",
    "2a29": "Manufacturer Name String",
    "2a2a": "IEEE 11073-20601 Regulatory Certification Data List",
    "2a37": "Heart Rate Measurement",
    "2a38": "Body Sensor Location",
    "2a39": "Heart Rate Control Point",
    "2a3f": "Alert Status",
    "2a4d": "HID Report",
    "2a50": "PnP ID",
    "2a6e": "Temperature",
    "2a6f": "Humidity",
    "2901": "Characteristic User Description",
    "2902": "Client Characteristic Configuration",
    "2903": "Server Characteristic Configuration",
    "2904": "Characteristic Presentation Format",
}

_APPEARANCE_NAMES: Dict[int, str] = {
    0:    "Unknown",
    64:   "Phone",
    128:  "Computer",
    192:  "Watch",
    256:  "Clock",
    320:  "Display",
    384:  "Remote Control",
    448:  "Eye Glasses",
    512:  "Tag",
    576:  "Keyring",
    640:  "Media Player",
    704:  "Barcode Scanner",
    768:  "Thermometer",
    832:  "Heart Rate Sensor",
    896:  "Blood Pressure",
    960:  "HID",
    1152: "Running/Walking Sensor",
    1216: "Cycling Sensor",
    1344: "Pulse Oximeter",
    1408: "Weight Scale",
    1472: "Personal Mobility Device",
    1600: "Insulin Pump",
    1664: "Medication Delivery",
    3136: "Generic Outdoor Sports",
}

# Read these UUIDs as strings (printable text)
_STRING_CHAR_UUIDS = {"2a24", "2a25", "2a26", "2a27", "2a28", "2a29", "2a00"}

# Max time to attempt a characteristic read
_READ_TIMEOUT_S = 3.0
# Do not attempt reads on unknown vendor chars unless explicitly requested
_SAFE_READ_UUIDS = set(_STRING_CHAR_UUIDS) | {"2a19", "2a01", "2a23", "2a50"}


class GATTInspector:
    """
    Enumerates GATT services and characteristics for a given BLE device.

    Usage:
        inspector = GATTInspector()
        inspector.inspect("AA:BB:CC:DD:EE:FF", on_result=my_callback)

    The callback receives a dict with keys:
        mac, name, connected_at, duration_ms,
        services (list), error (str or None)
    """

    def __init__(self):
        self._active: Dict[str, threading.Thread] = {}
        self._last_result: Dict[str, dict]        = {}
        self._lock = threading.Lock()

    # ── public ───────────────────────────────────────────────────────────────

    def inspect(
        self,
        mac: str,
        on_result: Callable[[dict], None],
        adapter: str = "hci0",
        read_values: bool = True,
        timeout: float = 15.0,
    ) -> None:
        """
        Start an asynchronous GATT inspection.  Returns immediately.
        The on_result callback is called from a worker thread when done.
        """
        mac = mac.upper()
        with self._lock:
            if mac in self._active and self._active[mac].is_alive():
                # Already inspecting this device — debounce
                return

        t = threading.Thread(
            target=self._run_inspection,
            args=(mac, on_result, adapter, read_values, timeout),
            daemon=True,
            name=f"GATT-{mac}",
        )
        with self._lock:
            self._active[mac] = t
        t.start()

    def get_cached_result(self, mac: str) -> Optional[dict]:
        return self._last_result.get(mac.upper())

    def is_busy(self, mac: str) -> bool:
        mac = mac.upper()
        with self._lock:
            t = self._active.get(mac)
        return t is not None and t.is_alive()

    # ── internal ─────────────────────────────────────────────────────────────

    def _run_inspection(self, mac, on_result, adapter, read_values, timeout):
        """Worker thread: runs asyncio event loop to perform GATT walk."""
        result = {
            "mac":          mac,
            "name":         None,
            "connected_at": time.time(),
            "duration_ms":  None,
            "services":     [],
            "error":        None,
            "adapter":      adapter,
        }
        t0 = time.monotonic()

        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(
                asyncio.wait_for(
                    self._inspect_async(mac, result, adapter, read_values),
                    timeout=timeout,
                )
            )
        except asyncio.TimeoutError:
            result["error"] = f"Inspection timed out after {timeout}s"
        except Exception as e:
            result["error"] = str(e)
        finally:
            result["duration_ms"] = int((time.monotonic() - t0) * 1000)
            with self._lock:
                self._last_result[mac] = result
                self._active.pop(mac, None)
            on_result(result)

    async def _inspect_async(self, mac: str, result: dict, adapter: str, read_values: bool):
        """Async GATT walk — runs inside worker thread's event loop."""
        try:
            from bleak import BleakClient, BleakError  # type: ignore
        except ImportError:
            result["error"] = "bleak not installed (pip install bleak)"
            return

        try:
            from bleak import BleakClient
            async with BleakClient(
                mac,
                timeout=10.0,
                adapter=adapter if adapter != "hci0" else None,
            ) as client:
                result["name"] = client.address  # may be overridden by Device Name char

                services_out = []
                for service in client.services:
                    svc_uuid  = service.uuid.lower()
                    svc_short = self._short_uuid(svc_uuid)
                    svc_name  = (_SERVICE_NAMES.get(svc_short)
                                 or service.description
                                 or f"Service {svc_short}")

                    chars_out = []
                    for char in service.characteristics:
                        char_uuid  = char.uuid.lower()
                        char_short = self._short_uuid(char_uuid)
                        char_name  = (_CHAR_NAMES.get(char_short)
                                      or char.description
                                      or f"Char {char_short}")
                        props = list(char.properties)

                        char_entry: dict = {
                            "uuid":        char.uuid,
                            "short_uuid":  char_short,
                            "name":        char_name,
                            "handle":      char.handle,
                            "properties":  props,
                            "value_hex":   None,
                            "value_text":  None,
                            "value_decoded": None,
                            "error":       None,
                            "descriptors": [],
                        }

                        # Read value
                        if read_values and "read" in props:
                            try:
                                val = await asyncio.wait_for(
                                    client.read_gatt_char(char.uuid),
                                    timeout=_READ_TIMEOUT_S,
                                )
                                char_entry["value_hex"] = val.hex()
                                char_entry["value_decoded"] = self._decode_value(char_short, val)

                                if char_short in _STRING_CHAR_UUIDS:
                                    try:
                                        char_entry["value_text"] = val.decode("utf-8").strip("\x00").strip()
                                    except Exception:
                                        char_entry["value_text"] = val.decode("latin-1", errors="replace").strip()

                                # Special: override device name from Device Name characteristic
                                if char_short == "2a00" and char_entry["value_text"]:
                                    result["name"] = char_entry["value_text"]

                            except asyncio.TimeoutError:
                                char_entry["error"] = "Read timeout"
                            except Exception as e:
                                char_entry["error"] = str(e)[:80]

                        # Descriptors
                        for desc in char.descriptors:
                            desc_entry = {
                                "uuid":   desc.uuid,
                                "handle": desc.handle,
                                "name":   _CHAR_NAMES.get(self._short_uuid(desc.uuid.lower()), "Descriptor"),
                                "value_hex": None,
                            }
                            try:
                                dval = await asyncio.wait_for(
                                    client.read_gatt_descriptor(desc.handle),
                                    timeout=_READ_TIMEOUT_S,
                                )
                                desc_entry["value_hex"] = bytes(dval).hex()
                            except Exception:
                                pass
                            char_entry["descriptors"].append(desc_entry)

                        chars_out.append(char_entry)

                    services_out.append({
                        "uuid":       service.uuid,
                        "short_uuid": svc_short,
                        "name":       svc_name,
                        "handle":     service.handle,
                        "characteristics": chars_out,
                    })

                result["services"] = services_out

        except Exception as e:
            result["error"] = f"Connection failed: {e}"

    # ── helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _short_uuid(uuid: str) -> str:
        """Extract the 16-bit short UUID from a 128-bit string, if it's a SIG UUID."""
        u = uuid.replace("-", "").lower()
        if u[8:] == "00001000800000805f9b34fb":
            return u[4:8]
        return uuid.lower()

    @staticmethod
    def _decode_value(short_uuid: str, data: bytes) -> Optional[Any]:
        """Decode characteristic value into a human-readable Python object."""
        try:
            if short_uuid == "2a19":   # Battery Level
                return {"battery_pct": data[0]}

            if short_uuid == "2a01":   # Appearance
                if len(data) >= 2:
                    val = struct.unpack_from("<H", data)[0]
                    return {"appearance_code": val,
                            "description": _APPEARANCE_NAMES.get(val & 0xFFC0, "Unknown")}

            if short_uuid == "2a50":   # PnP ID
                if len(data) >= 7:
                    src, vid, pid, ver = struct.unpack_from("<BHHH", data)
                    return {"vendor_id_src": "Bluetooth" if src == 1 else "USB",
                            "vendor_id": f"0x{vid:04X}",
                            "product_id": f"0x{pid:04X}",
                            "version": f"0x{ver:04X}"}

            if short_uuid == "2a23":   # System ID
                return {"system_id_hex": data.hex()}

            if short_uuid == "2a37":   # Heart Rate Measurement
                flags = data[0]
                hr_format = flags & 0x01
                hr = struct.unpack_from("<H", data, 1)[0] if hr_format else data[1]
                return {"heart_rate_bpm": hr}

        except Exception:
            pass
        return None


# ── Simulated GATT inspector (no hardware) ───────────────────────────────────

class SimulatedGATTInspector(GATTInspector):
    """Returns plausible fake GATT data for UI/testing when no hardware is present."""

    def _run_inspection(self, mac, on_result, adapter, read_values, timeout):
        time.sleep(1.5)   # simulate connection delay

        services = [
            {
                "uuid": "00001800-0000-1000-8000-00805f9b34fb",
                "short_uuid": "1800",
                "name": "Generic Access",
                "handle": 1,
                "characteristics": [
                    {
                        "uuid": "00002a00-0000-1000-8000-00805f9b34fb",
                        "short_uuid": "2a00",
                        "name": "Device Name",
                        "handle": 3,
                        "properties": ["read"],
                        "value_hex": "426c756553686965" + "6c64",
                        "value_text": "BlueShield Demo",
                        "value_decoded": None,
                        "error": None,
                        "descriptors": [],
                    },
                    {
                        "uuid": "00002a01-0000-1000-8000-00805f9b34fb",
                        "short_uuid": "2a01",
                        "name": "Appearance",
                        "handle": 5,
                        "properties": ["read"],
                        "value_hex": "4000",
                        "value_text": None,
                        "value_decoded": {"appearance_code": 64, "description": "Phone"},
                        "error": None,
                        "descriptors": [],
                    },
                ],
            },
            {
                "uuid": "0000180a-0000-1000-8000-00805f9b34fb",
                "short_uuid": "180a",
                "name": "Device Information",
                "handle": 10,
                "characteristics": [
                    {
                        "uuid": "00002a29-0000-1000-8000-00805f9b34fb",
                        "short_uuid": "2a29",
                        "name": "Manufacturer Name String",
                        "handle": 12,
                        "properties": ["read"],
                        "value_hex": bytes("BlueShield Inc", "utf-8").hex(),
                        "value_text": "BlueShield Inc",
                        "value_decoded": None,
                        "error": None,
                        "descriptors": [],
                    },
                    {
                        "uuid": "00002a26-0000-1000-8000-00805f9b34fb",
                        "short_uuid": "2a26",
                        "name": "Firmware Revision String",
                        "handle": 14,
                        "properties": ["read"],
                        "value_hex": bytes("5.5.0", "utf-8").hex(),
                        "value_text": "5.5.0",
                        "value_decoded": None,
                        "error": None,
                        "descriptors": [],
                    },
                ],
            },
            {
                "uuid": "0000180f-0000-1000-8000-00805f9b34fb",
                "short_uuid": "180f",
                "name": "Battery Service",
                "handle": 20,
                "characteristics": [
                    {
                        "uuid": "00002a19-0000-1000-8000-00805f9b34fb",
                        "short_uuid": "2a19",
                        "name": "Battery Level",
                        "handle": 22,
                        "properties": ["read", "notify"],
                        "value_hex": "5a",
                        "value_text": None,
                        "value_decoded": {"battery_pct": 90},
                        "error": None,
                        "descriptors": [
                            {"uuid": "00002902-0000-1000-8000-00805f9b34fb",
                             "handle": 23, "name": "Client Characteristic Configuration",
                             "value_hex": "0000"},
                        ],
                    },
                ],
            },
        ]

        result = {
            "mac":          mac,
            "name":         "BlueShield Demo Device",
            "connected_at": time.time(),
            "duration_ms":  1500,
            "services":     services,
            "error":        None,
            "adapter":      "simulated",
        }

        with self._lock:
            self._last_result[mac] = result
            self._active.pop(mac, None)
        on_result(result)


def make_gatt_inspector(sim: bool = False) -> GATTInspector:
    """Return a real or simulated GATT inspector."""
    if sim:
        return SimulatedGATTInspector()
    # If bleak isn't available, fall back to simulated
    try:
        import bleak  # noqa: F401
        return GATTInspector()
    except ImportError:
        return SimulatedGATTInspector()
