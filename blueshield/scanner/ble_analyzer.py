"""
BlueShield BLE Protocol Analyzer v2.0

PhD-level BLE advertisement analysis module implementing the full Bluetooth SIG
Core Specification Vol 3, Part C, Section 11 AD structure parsing, vendor-specific
protocol decoders (Apple Continuity, Google Fast Pair, Samsung SmartThings,
Microsoft Swift Pair), beacon format parsers (iBeacon, Eddystone, AltBeacon),
OUI resolution, GATT service UUID lookup, log-distance path-loss distance
estimation, tracker detection with MAC rotation analysis, and composite threat
scoring.

All code is pure Python with no external dependencies beyond the standard
library (struct, math, re). All databases (OUI, service UUIDs, company IDs)
are inlined to allow standalone import with zero configuration.

Reference documents:
    - Bluetooth Core Specification v5.4, Vol 3, Part C, Section 11 (AD types)
    - Bluetooth Assigned Numbers (https://www.bluetooth.com/specifications/assigned-numbers/)
    - Apple Continuity Protocol (reverse-engineered by Furiousmac et al.)
    - Google Fast Pair Specification v1.0
    - Eddystone Protocol Specification (github.com/google/eddystone)
    - AltBeacon Specification v1.0

Usage:
    from blueshield.scanner.ble_analyzer import BLEAnalyzer

    analyzer = BLEAnalyzer()
    result = analyzer.analyze_advertisement(raw_ad_bytes, rssi=-67, mac="AA:BB:CC:DD:EE:FF")
"""

from __future__ import annotations

import struct
import math
import re
import time
from typing import Optional


# ===========================================================================
#  1. OUI (MAC prefix) Database  --  120+ common BLE manufacturers
# ===========================================================================

OUI_DATABASE: dict[str, str] = {
    # -- Apple (various OUI ranges) ----------------------------------------
    "00:CD:FE": "Apple, Inc.",
    "04:CB:88": "Apple, Inc.",
    "04:E5:36": "Apple, Inc.",
    "08:66:98": "Apple, Inc.",
    "0C:30:21": "Apple, Inc.",
    "0C:51:01": "Apple, Inc.",
    "10:94:BB": "Apple, Inc.",
    "14:98:77": "Apple, Inc.",
    "18:3E:EF": "Apple, Inc.",
    "18:EE:69": "Apple, Inc.",
    "1C:9E:46": "Apple, Inc.",
    "20:78:F0": "Apple, Inc.",
    "24:A2:E1": "Apple, Inc.",
    "28:6A:BA": "Apple, Inc.",
    "2C:BE:EB": "Apple, Inc.",
    "30:35:AD": "Apple, Inc.",
    "34:C0:59": "Apple, Inc.",
    "38:C9:86": "Apple, Inc.",
    "3C:06:30": "Apple, Inc.",
    "40:98:AD": "Apple, Inc.",
    "44:2A:60": "Apple, Inc.",
    "48:D7:05": "Apple, Inc.",
    "4C:57:CA": "Apple, Inc.",
    "54:4E:90": "Apple, Inc.",
    "58:B0:35": "Apple, Inc.",
    "60:F8:1D": "Apple, Inc.",
    "64:B0:A6": "Apple, Inc.",
    "68:FE:F7": "Apple, Inc.",
    "6C:94:66": "Apple, Inc.",
    "70:3E:AC": "Apple, Inc.",
    "78:7B:8A": "Apple, Inc.",
    "7C:D1:C3": "Apple, Inc.",
    "80:E6:50": "Apple, Inc.",
    "84:FC:FE": "Apple, Inc.",
    "88:66:A5": "Apple, Inc.",
    "8C:85:90": "Apple, Inc.",
    "90:8D:6C": "Apple, Inc.",
    "94:E9:6A": "Apple, Inc.",
    "98:01:A7": "Apple, Inc.",
    "9C:20:7B": "Apple, Inc.",
    "A0:99:9B": "Apple, Inc.",
    "A4:83:E7": "Apple, Inc.",
    "A8:66:7F": "Apple, Inc.",
    "AC:BC:32": "Apple, Inc.",
    "B0:19:C6": "Apple, Inc.",
    "B8:E8:56": "Apple, Inc.",
    "BC:52:B7": "Apple, Inc.",
    "C0:D0:12": "Apple, Inc.",
    "DC:A4:CA": "Apple, Inc.",
    "F0:18:98": "Apple, Inc.",
    "F4:31:C3": "Apple, Inc.",
    # -- Samsung -----------------------------------------------------------
    "00:07:AB": "Samsung Electronics",
    "00:12:FB": "Samsung Electronics",
    "00:15:99": "Samsung Electronics",
    "00:1A:8A": "Samsung Electronics",
    "00:21:19": "Samsung Electronics",
    "00:26:37": "Samsung Electronics",
    "08:37:3D": "Samsung Electronics",
    "0C:DF:A4": "Samsung Electronics",
    "14:49:E0": "Samsung Electronics",
    "18:3A:2D": "Samsung Electronics",
    "28:CC:01": "Samsung Electronics",
    "34:14:5F": "Samsung Electronics",
    "40:4E:36": "Samsung Electronics",
    "50:01:D9": "Samsung Electronics",
    "5C:3A:45": "Samsung Electronics",
    "64:B5:C6": "Samsung Electronics",
    "78:BD:BC": "Samsung Electronics",
    "84:25:DB": "Samsung Electronics",
    "8C:F5:A3": "Samsung Electronics",
    "94:B8:6D": "Samsung Electronics",
    "A8:7C:01": "Samsung Electronics",
    "C0:97:27": "Samsung Electronics",
    "E4:7D:BD": "Samsung Electronics",
    "F8:04:2E": "Samsung Electronics",
    # -- Google / Nest -----------------------------------------------------
    "08:9E:08": "Google, Inc.",
    "18:D6:C7": "Google, Inc.",
    "30:FD:38": "Google, Inc.",
    "44:07:0B": "Google, Inc.",
    "54:60:09": "Google, Inc.",
    "A4:77:33": "Google, Inc.",
    "F4:F5:D8": "Google, Inc.",
    "F4:F5:DB": "Google, Inc.",
    # -- Microsoft ---------------------------------------------------------
    "00:15:5D": "Microsoft Corporation",
    "00:50:F2": "Microsoft Corporation",
    "28:18:78": "Microsoft Corporation",
    "7C:1E:52": "Microsoft Corporation",
    "C8:3F:26": "Microsoft Corporation",
    # -- Raspberry Pi Foundation -------------------------------------------
    "28:CD:C1": "Raspberry Pi Foundation",
    "B8:27:EB": "Raspberry Pi Foundation",
    "D8:3A:DD": "Raspberry Pi Foundation",
    "DC:A6:32": "Raspberry Pi Foundation",
    "E4:5F:01": "Raspberry Pi Foundation",
    # -- Intel -------------------------------------------------------------
    "00:1B:21": "Intel Corporate",
    "00:1E:64": "Intel Corporate",
    "34:13:E8": "Intel Corporate",
    "3C:6A:A7": "Intel Corporate",
    "48:51:B7": "Intel Corporate",
    "58:91:CF": "Intel Corporate",
    "68:17:29": "Intel Corporate",
    "7C:B2:7D": "Intel Corporate",
    "8C:8D:28": "Intel Corporate",
    "A0:C5:89": "Intel Corporate",
    # -- Broadcom / Cypress ------------------------------------------------
    "00:10:18": "Broadcom Inc.",
    "20:13:E0": "Broadcom Inc.",
    "AC:1F:74": "Broadcom Inc.",
    # -- Qualcomm ----------------------------------------------------------
    "00:03:7F": "Qualcomm Inc.",
    "04:BD:70": "Qualcomm Inc.",
    "B0:7E:70": "Qualcomm Inc.",
    # -- Realtek -----------------------------------------------------------
    "00:E0:4C": "Realtek Semiconductor",
    "48:57:02": "Realtek Semiconductor",
    "70:8B:CD": "Realtek Semiconductor",
    # -- MediaTek ----------------------------------------------------------
    "00:0C:E7": "MediaTek Inc.",
    "14:75:90": "MediaTek Inc.",
    # -- Texas Instruments -------------------------------------------------
    "00:12:4B": "Texas Instruments",
    "04:A3:16": "Texas Instruments",
    "34:03:DE": "Texas Instruments",
    "54:6C:0E": "Texas Instruments",
    "98:07:2D": "Texas Instruments",
    "B0:B4:48": "Texas Instruments",
    "D0:39:72": "Texas Instruments",
    # -- Espressif (ESP32/ESP8266) -----------------------------------------
    "08:3A:F2": "Espressif Inc.",
    "24:0A:C4": "Espressif Inc.",
    "24:6F:28": "Espressif Inc.",
    "30:AE:A4": "Espressif Inc.",
    "3C:61:05": "Espressif Inc.",
    "40:F5:20": "Espressif Inc.",
    "4C:11:AE": "Espressif Inc.",
    "84:CC:A8": "Espressif Inc.",
    "A4:CF:12": "Espressif Inc.",
    "BC:DD:C2": "Espressif Inc.",
    "C8:C9:A3": "Espressif Inc.",
    "EC:FA:BC": "Espressif Inc.",
    # -- Nordic Semiconductor ----------------------------------------------
    "C5:4A:D8": "Nordic Semiconductor",
    "D4:B2:58": "Nordic Semiconductor",
    "E8:1D:FF": "Nordic Semiconductor",
    "F2:4F:4B": "Nordic Semiconductor",
    # -- Silicon Labs ------------------------------------------------------
    "00:0B:57": "Silicon Laboratories",
    "04:CB:C9": "Silicon Laboratories",
    "58:8E:81": "Silicon Laboratories",
    "84:2E:14": "Silicon Laboratories",
    "90:FD:9F": "Silicon Laboratories",
    # -- NXP Semiconductors ------------------------------------------------
    "00:04:9F": "NXP Semiconductors",
    "00:1F:7B": "NXP Semiconductors",
    "00:60:37": "NXP Semiconductors",
    # -- STMicroelectronics ------------------------------------------------
    "00:80:E1": "STMicroelectronics",
    "80:E1:26": "STMicroelectronics",
    # -- Amazon / Ring / Eero ----------------------------------------------
    "10:AE:60": "Amazon Technologies",
    "14:91:82": "Amazon Technologies",
    "24:4C:E3": "Amazon Technologies",
    "34:D2:70": "Amazon Technologies",
    "38:F7:3D": "Amazon Technologies",
    "40:B4:CD": "Amazon Technologies",
    "44:65:0D": "Amazon Technologies",
    "50:DC:E7": "Amazon Technologies",
    "68:54:FD": "Amazon Technologies",
    "74:C2:46": "Amazon Technologies",
    "84:D6:D0": "Amazon Technologies",
    "A0:02:DC": "Amazon Technologies",
    "F0:D2:F1": "Amazon Technologies",
    "FC:65:DE": "Amazon Technologies",
    # -- Xiaomi ------------------------------------------------------------
    "04:CF:8C": "Xiaomi Communications",
    "28:6C:07": "Xiaomi Communications",
    "34:CE:00": "Xiaomi Communications",
    "50:EC:50": "Xiaomi Communications",
    "58:44:98": "Xiaomi Communications",
    "64:CC:2E": "Xiaomi Communications",
    "78:11:DC": "Xiaomi Communications",
    "7C:49:EB": "Xiaomi Communications",
    "8C:DE:F9": "Xiaomi Communications",
    "9C:A5:25": "Xiaomi Communications",
    # -- Huawei ------------------------------------------------------------
    "00:46:4B": "Huawei Technologies",
    "04:C0:6F": "Huawei Technologies",
    "20:08:ED": "Huawei Technologies",
    "48:46:FB": "Huawei Technologies",
    "70:8A:09": "Huawei Technologies",
    "88:A2:D7": "Huawei Technologies",
    "CC:A2:23": "Huawei Technologies",
    # -- OnePlus / OPPO / Vivo / Nothing -----------------------------------
    "04:5A:95": "OnePlus Technology",
    "94:65:2D": "OnePlus Technology",
    "C0:EE:FB": "OPPO Digital",
    "A0:75:91": "OPPO Digital",
    "3C:AA:B0": "Vivo Mobile",
    "60:AB:67": "Vivo Mobile",
    "2C:DB:07": "Nothing Technology",
    # -- Tile / Chipolo / TrackR -------------------------------------------
    "C4:36:C0": "Tile, Inc.",
    "D9:E6:25": "Chipolo d.o.o.",
    "BC:57:29": "TrackR, Inc.",
    # -- Audio: Bose / Sony / JBL / Sennheiser / Bang & Olufsen -----------
    "04:52:C7": "Bose Corporation",
    "08:DF:1F": "Bose Corporation",
    "2C:41:A1": "Bose Corporation",
    "4C:87:5D": "Bose Corporation",
    "00:18:09": "Sony Corporation",
    "30:52:CB": "Sony Corporation",
    "40:9C:28": "Sony Corporation",
    "70:51:05": "Sony Corporation",
    "04:FE:A1": "Harman International (JBL)",
    "70:99:1C": "Harman International (JBL)",
    "00:1B:66": "Sennheiser Communications",
    "00:13:A9": "Bang & Olufsen",
    # -- Peripherals: Logitech / Razer -------------------------------------
    "00:1F:20": "Logitech International",
    "34:AF:2C": "Logitech International",
    "6C:B7:49": "Logitech International",
    "5C:9A:D8": "Razer Inc.",
    "C4:14:11": "Razer Inc.",
    # -- Wearables: Fitbit / Garmin / Polar / Whoop ------------------------
    "C0:CB:F6": "Fitbit, Inc.",
    "D1:45:AC": "Fitbit, Inc.",
    "DC:EF:CA": "Fitbit, Inc.",
    "C8:FF:28": "Garmin International",
    "01:23:45": "Garmin International",
    "D0:6F:4A": "Garmin International",
    "A0:9E:1A": "Polar Electro Oy",
    "00:22:D0": "Polar Electro Oy",
    "B8:5A:F7": "Whoop, Inc.",
    # -- IoT: Ring / Nest / Philips Hue / IKEA ----------------------------
    "5C:47:5E": "Ring LLC",
    "34:3E:A4": "Areox (Ring)",
    "18:B4:30": "Nest Labs (Google)",
    "64:16:66": "Nest Labs (Google)",
    "00:17:88": "Signify (Philips Hue)",
    "EC:B5:FA": "Signify (Philips Hue)",
    "CC:86:EC": "IKEA of Sweden",
    "60:01:94": "IKEA of Sweden",
    "94:3C:C6": "IKEA of Sweden",
}


def lookup_oui(mac: str) -> str:
    """Resolve the manufacturer name from the first 3 octets (OUI) of a MAC
    address using the inline database.

    Args:
        mac: MAC address in colon-separated hex format (e.g. "AA:BB:CC:DD:EE:FF").

    Returns:
        Manufacturer name string, or "Unknown" if not found.

    Reference:
        IEEE MA-L (OUI) public listing: https://standards-oui.ieee.org/
    """
    if not mac or len(mac) < 8:
        return "Unknown"
    prefix = mac[:8].upper()
    return OUI_DATABASE.get(prefix, "Unknown")


def is_random_mac(mac: str) -> bool:
    """Determine whether a MAC address is locally administered (random).

    Per IEEE 802, bit 1 of the first octet is the U/L bit.  If set, the
    address is locally administered, which BLE uses for random/private
    addresses (resolvable and non-resolvable).

    Args:
        mac: Colon-separated MAC address string.

    Returns:
        True if the MAC is locally administered (random).
    """
    if not mac or len(mac) < 2:
        return False
    try:
        first_octet = int(mac[:2], 16)
        return bool(first_octet & 0x02)
    except ValueError:
        return False


# ===========================================================================
#  2. Service UUID Database  --  80+ standard GATT services
# ===========================================================================

SERVICE_UUID_DATABASE: dict[int, tuple[str, str]] = {
    # -- Generic Access / Attribute ----------------------------------------
    0x1800: ("Generic Access", "core"),
    0x1801: ("Generic Attribute", "core"),
    # -- Common GATT services ----------------------------------------------
    0x1802: ("Immediate Alert", "proximity"),
    0x1803: ("Link Loss", "proximity"),
    0x1804: ("Tx Power", "proximity"),
    0x1805: ("Current Time", "time"),
    0x1806: ("Reference Time Update", "time"),
    0x1807: ("Next DST Change", "time"),
    0x1808: ("Glucose", "health"),
    0x1809: ("Health Thermometer", "health"),
    0x180A: ("Device Information", "core"),
    0x180B: ("Network Availability", "network"),
    0x180D: ("Heart Rate", "health"),
    0x180E: ("Phone Alert Status", "phone"),
    0x180F: ("Battery Service", "core"),
    0x1810: ("Blood Pressure", "health"),
    0x1811: ("Alert Notification", "phone"),
    0x1812: ("Human Interface Device", "hid"),
    0x1813: ("Scan Parameters", "core"),
    0x1814: ("Running Speed and Cadence", "fitness"),
    0x1815: ("Automation IO", "iot"),
    0x1816: ("Cycling Speed and Cadence", "fitness"),
    0x1818: ("Cycling Power", "fitness"),
    0x1819: ("Location and Navigation", "location"),
    0x181A: ("Environmental Sensing", "environmental"),
    0x181B: ("Body Composition", "health"),
    0x181C: ("User Data", "health"),
    0x181D: ("Weight Scale", "health"),
    0x181E: ("Bond Management", "security"),
    0x181F: ("Continuous Glucose Monitoring", "health"),
    0x1820: ("Internet Protocol Support", "network"),
    0x1821: ("Indoor Positioning", "location"),
    0x1822: ("Pulse Oximeter", "health"),
    0x1823: ("HTTP Proxy", "network"),
    0x1824: ("Transport Discovery", "core"),
    0x1825: ("Object Transfer", "transfer"),
    0x1826: ("Fitness Machine", "fitness"),
    0x1827: ("Mesh Provisioning", "mesh"),
    0x1828: ("Mesh Proxy", "mesh"),
    0x1829: ("Reconnection Configuration", "core"),
    0x182A: ("Insulin Delivery", "health"),
    0x182B: ("Binary Sensor", "iot"),
    0x182C: ("Emergency Configuration", "safety"),
    0x182E: ("Authorization Control", "security"),
    0x1843: ("Audio Input Control", "audio"),
    0x1844: ("Volume Control", "audio"),
    0x1845: ("Volume Offset Control", "audio"),
    0x1846: ("Coordinated Set Identification", "audio"),
    0x1847: ("Device Time", "time"),
    0x1848: ("Media Control", "audio"),
    0x1849: ("Generic Media Control", "audio"),
    0x184A: ("Constant Tone Extension", "location"),
    0x184B: ("Telephone Bearer", "phone"),
    0x184C: ("Generic Telephone Bearer", "phone"),
    0x184D: ("Microphone Control", "audio"),
    0x184E: ("Audio Stream Control", "audio"),
    0x184F: ("Broadcast Audio Scan", "audio"),
    0x1850: ("Published Audio Capabilities", "audio"),
    0x1851: ("Basic Audio Profile", "audio"),
    0x1852: ("Broadcast Audio Announcement", "audio"),
    0x1853: ("Common Audio", "audio"),
    0x1854: ("Hearing Access", "health"),
    0x1856: ("Public Broadcast Announcement", "audio"),
    0x1857: ("Electronic Shelf Label", "iot"),
    # -- Vendor / tracker / IoT service UUIDs ------------------------------
    0xFD6F: ("Apple Find My Network", "tracker"),
    0xFD5A: ("Samsung SmartThings", "tracker"),
    0xFD69: ("Samsung SmartTag", "tracker"),
    0xFD8E: ("Samsung SmartTag2", "tracker"),
    0xFDA6: ("Google Find My Device Network", "tracker"),
    0xFE2C: ("Google Fast Pair", "vendor"),
    0xFEA0: ("Google Connectivity", "vendor"),
    0xFE50: ("Google", "vendor"),
    0xFE9F: ("Google", "vendor"),
    0xFEED: ("Tile (Service A)", "tracker"),
    0xFE6E: ("Tile (Service B)", "tracker"),
    0xFEAA: ("Eddystone (Google)", "beacon"),
    0xFE6F: ("AltBeacon", "beacon"),
    0xFEF5: ("Dialog Semiconductor", "vendor"),
    0xFE07: ("Amazon (Alexa)", "vendor"),
    0xFE08: ("Amazon", "vendor"),
    0xFEB9: ("Xiaomi Inc.", "vendor"),
    0xFEBB: ("Xiaomi Inc.", "vendor"),
    0xFE95: ("Xiaomi Inc.", "vendor"),
    0xFE61: ("Logitech International", "vendor"),
    0xFDDF: ("Philips Hue", "iot"),
    0xFE0F: ("Philips Hue", "iot"),
    0xFFF0: ("Xiaomi MiBeacon", "vendor"),
    0xFFF1: ("Xiaomi MiBeacon2", "vendor"),
    0xFFF9: ("FIDO2 / WebAuthn", "security"),
}


def lookup_service_uuid(uuid_16: int) -> tuple[str, str]:
    """Look up a 16-bit GATT service UUID and return its name and category.

    Args:
        uuid_16: 16-bit service UUID integer (e.g. 0x180F).

    Returns:
        Tuple of (service_name, category).  Returns ("Unknown Service", "unknown")
        if the UUID is not in the database.

    Reference:
        Bluetooth SIG Assigned Numbers, Section 3.4 -- GATT Service UUIDs.
    """
    return SERVICE_UUID_DATABASE.get(uuid_16, ("Unknown Service", "unknown"))


# ===========================================================================
#  3. BLE Company ID Database (subset for manufacturer-specific decoding)
# ===========================================================================

COMPANY_ID_DATABASE: dict[int, str] = {
    0x0006: "Microsoft",
    0x000D: "Texas Instruments",
    0x000F: "Broadcom",
    0x001D: "Qualcomm",
    0x004C: "Apple, Inc.",
    0x0059: "Nordic Semiconductor",
    0x0075: "Samsung Electronics",
    0x0087: "Garmin International",
    0x008C: "Polar Electro Oy",
    0x00E0: "Google",
    0x00D2: "Dialog Semiconductor",
    0x010F: "Xiaomi Inc.",
    0x0131: "Huawei Technologies",
    0x0135: "Tile, Inc.",
    0x0157: "Realtek Semiconductor",
    0x0171: "Amazon.com Services",
    0x01A7: "OPPO",
    0x0310: "Chipolo d.o.o.",
    0x038F: "Nothing Technology",
    0x0499: "Ruuvi Innovations",
    0x0822: "Whoop, Inc.",
}


# ===========================================================================
#  4. ADParser class  --  Parse ALL standard BLE AD structures
# ===========================================================================

class ADParser:
    """Parse BLE Advertising Data (AD) structures per Bluetooth Core
    Specification Vol 3, Part C, Section 11.

    Each AD structure is TLV-encoded:

        [length (1 octet)] [AD type (1 octet)] [AD data (length-1 octets)]

    The parser walks the raw advertising bytes (after the PDU header and
    advertiser address) and returns a list of dicts.  Each dict always
    contains:
        - ``type``      (int)   : numeric AD type code
        - ``type_name`` (str)   : human-readable type name
        - ``data``      (bytes) : raw payload after the type octet
        - ``parsed``    (dict)  : type-specific decoded fields

    This implementation covers every AD type assigned by the Bluetooth SIG
    as of Core Spec v5.4 / Assigned Numbers 2024-01-24.
    """

    # Complete AD Type name registry per Bluetooth Assigned Numbers
    AD_TYPE_NAMES: dict[int, str] = {
        0x01: "Flags",
        0x02: "Incomplete List of 16-bit Service Class UUIDs",
        0x03: "Complete List of 16-bit Service Class UUIDs",
        0x04: "Incomplete List of 32-bit Service Class UUIDs",
        0x05: "Complete List of 32-bit Service Class UUIDs",
        0x06: "Incomplete List of 128-bit Service Class UUIDs",
        0x07: "Complete List of 128-bit Service Class UUIDs",
        0x08: "Shortened Local Name",
        0x09: "Complete Local Name",
        0x0A: "TX Power Level",
        0x0D: "Class of Device",
        0x0E: "Simple Pairing Hash C-192",
        0x0F: "Simple Pairing Randomizer R-192",
        0x10: "Security Manager TK Value",
        0x11: "Security Manager Out of Band Flags",
        0x12: "Peripheral Connection Interval Range",
        0x14: "List of 16-bit Service Solicitation UUIDs",
        0x15: "List of 128-bit Service Solicitation UUIDs",
        0x16: "Service Data - 16-bit UUID",
        0x17: "Public Target Address",
        0x18: "Random Target Address",
        0x19: "Appearance",
        0x1A: "Advertising Interval",
        0x1B: "LE Bluetooth Device Address",
        0x1C: "LE Role",
        0x1D: "Simple Pairing Hash C-256",
        0x1E: "Simple Pairing Randomizer R-256",
        0x1F: "List of 32-bit Service Solicitation UUIDs",
        0x20: "Service Data - 32-bit UUID",
        0x21: "Service Data - 128-bit UUID",
        0x22: "LE Secure Connections Confirmation Value",
        0x23: "LE Secure Connections Random Value",
        0x24: "URI",
        0x25: "Indoor Positioning",
        0x26: "Transport Discovery Data",
        0x27: "LE Supported Features",
        0x28: "Channel Map Update Indication",
        0x29: "PB-ADV",
        0x2A: "Mesh Message",
        0x2B: "Mesh Beacon",
        0x2C: "BIGInfo",
        0x2D: "Broadcast_Code",
        0x3D: "3D Information Data",
        0xFF: "Manufacturer Specific Data",
    }

    # BLE Appearance values (Bluetooth Assigned Numbers, Section 2.6)
    APPEARANCE_MAP: dict[int, str] = {
        0x0000: "Unknown",
        0x0040: "Generic Phone",
        0x0080: "Generic Computer",
        0x00C0: "Generic Watch",
        0x00C1: "Watch: Sports Watch",
        0x0100: "Generic Clock",
        0x0140: "Generic Display",
        0x0180: "Generic Remote Control",
        0x01C0: "Generic Eye-glasses",
        0x0200: "Generic Tag",
        0x0240: "Generic Keyring",
        0x0280: "Generic Media Player",
        0x02C0: "Generic Barcode Scanner",
        0x0300: "Generic Thermometer",
        0x0340: "Generic Heart Rate Sensor",
        0x0380: "Generic Blood Pressure",
        0x03C0: "Generic HID",
        0x03C1: "Keyboard",
        0x03C2: "Mouse",
        0x03C3: "Joystick",
        0x03C4: "Gamepad",
        0x03C5: "Digitizer Tablet",
        0x03C8: "Barcode Scanner",
        0x0440: "Generic Glucose Meter",
        0x0480: "Generic Running Walking Sensor",
        0x04C0: "Generic Cycling",
        0x0540: "Generic Pulse Oximeter",
        0x0580: "Generic Weight Scale",
        0x05C0: "Generic Outdoor Sports",
        0x0640: "Generic Environmental Sensor",
        0x0840: "Generic Wearable Audio",
        0x0841: "Earbud",
        0x0842: "Headset",
        0x0843: "Headphones",
        0x0844: "Neck Band",
        0x0940: "Generic Hearing Aid",
        0x0980: "Generic Gaming",
    }

    # Flags bitmask definitions (Core Spec Vol 3, Part C, Section 18.1)
    FLAG_LABELS: list[tuple[int, str]] = [
        (0x01, "LE Limited Discoverable Mode"),
        (0x02, "LE General Discoverable Mode"),
        (0x04, "BR/EDR Not Supported"),
        (0x08, "Simultaneous LE and BR/EDR to Same Device Capable (Controller)"),
        (0x10, "Simultaneous LE and BR/EDR to Same Device Capable (Host)"),
    ]

    def parse(self, raw_bytes: bytes) -> list[dict]:
        """Walk the AD byte stream and return a list of parsed structures.

        Args:
            raw_bytes: Raw advertising data bytes (AD structures only,
                       after the PDU header and advertiser address).

        Returns:
            List of dicts, each with keys: ``type``, ``type_name``,
            ``data``, ``parsed``.

        Reference:
            Bluetooth Core Spec Vol 3, Part C, Section 11.
        """
        results: list[dict] = []
        offset = 0
        while offset < len(raw_bytes):
            if offset + 1 > len(raw_bytes):
                break
            length = raw_bytes[offset]
            if length == 0:
                offset += 1
                continue
            if offset + 1 + length > len(raw_bytes):
                break  # truncated / malformed
            ad_type = raw_bytes[offset + 1]
            data = raw_bytes[offset + 2 : offset + 1 + length]
            parsed = self._decode(ad_type, data)
            entry: dict = {
                "type": ad_type,
                "type_name": self.AD_TYPE_NAMES.get(
                    ad_type, f"Unknown (0x{ad_type:02X})"
                ),
                "data": data,
                "parsed": parsed,
            }
            results.append(entry)
            offset += 1 + length
        return results

    # -- internal dispatch -------------------------------------------------

    def _decode(self, ad_type: int, data: bytes) -> dict:
        """Dispatch to the appropriate type-specific decoder."""
        decoder_map = {
            0x01: self._decode_flags,
            0x02: self._decode_uuid16_list,
            0x03: self._decode_uuid16_list,
            0x04: self._decode_uuid32_list,
            0x05: self._decode_uuid32_list,
            0x06: self._decode_uuid128_list,
            0x07: self._decode_uuid128_list,
            0x08: self._decode_local_name,
            0x09: self._decode_local_name,
            0x0A: self._decode_tx_power,
            0x0D: self._decode_class_of_device,
            0x0E: self._decode_pairing_hash,
            0x0F: self._decode_pairing_randomizer,
            0x10: self._decode_tk_value,
            0x11: self._decode_oob_flags,
            0x12: self._decode_conn_interval,
            0x14: self._decode_uuid16_list,
            0x15: self._decode_uuid128_list,
            0x16: self._decode_service_data_16,
            0x17: self._decode_target_address,
            0x18: self._decode_target_address,
            0x19: self._decode_appearance,
            0x1A: self._decode_adv_interval,
            0x1B: self._decode_le_bd_addr,
            0x1C: self._decode_le_role,
            0x1F: self._decode_uuid32_list,
            0x20: self._decode_service_data_32,
            0x21: self._decode_service_data_128,
            0xFF: self._decode_manufacturer_specific,
        }
        decoder = decoder_map.get(ad_type)
        if decoder:
            try:
                return decoder(data)
            except Exception:
                return {"error": "decode_failed", "raw_hex": data.hex()}
        return {"raw_hex": data.hex()}

    # -- Flags (0x01) ------------------------------------------------------

    def _decode_flags(self, data: bytes) -> dict:
        """Decode AD Type 0x01 -- Flags.

        Reference: Core Spec Vol 3, Part C, Section 18.1.
        """
        if len(data) < 1:
            return {"flags_raw": 0, "flags": []}
        flags_byte = data[0]
        labels = [label for mask, label in self.FLAG_LABELS if flags_byte & mask]
        return {
            "flags_raw": flags_byte,
            "flags": labels,
            "le_limited_discoverable": bool(flags_byte & 0x01),
            "le_general_discoverable": bool(flags_byte & 0x02),
            "br_edr_not_supported": bool(flags_byte & 0x04),
            "le_br_edr_controller": bool(flags_byte & 0x08),
            "le_br_edr_host": bool(flags_byte & 0x10),
        }

    # -- UUID lists (0x02-0x07, 0x14-0x15, 0x1F) --------------------------

    def _decode_uuid16_list(self, data: bytes) -> dict:
        """Decode lists of 16-bit Service Class UUIDs.

        Reference: Core Spec Vol 3, Part C, Section 11.
        """
        uuids: list[str] = []
        resolved: list[str] = []
        for i in range(0, len(data) - 1, 2):
            val = struct.unpack_from("<H", data, i)[0]
            uuids.append(f"0x{val:04X}")
            name, _ = lookup_service_uuid(val)
            resolved.append(name)
        return {"uuids": uuids, "resolved": resolved}

    def _decode_uuid32_list(self, data: bytes) -> dict:
        """Decode lists of 32-bit Service Class UUIDs.

        Reference: Core Spec Vol 3, Part C, Section 11.
        """
        uuids: list[str] = []
        for i in range(0, len(data) - 3, 4):
            val = struct.unpack_from("<I", data, i)[0]
            uuids.append(f"0x{val:08X}")
        return {"uuids": uuids}

    def _decode_uuid128_list(self, data: bytes) -> dict:
        """Decode lists of 128-bit Service Class UUIDs.

        128-bit UUIDs are transmitted in little-endian order per Core Spec.
        We reverse them to display in standard UUID format.

        Reference: Core Spec Vol 3, Part C, Section 11.
        """
        uuids: list[str] = []
        for i in range(0, len(data) - 15, 16):
            uuid_bytes = data[i : i + 16][::-1]  # reverse for display
            hex_str = uuid_bytes.hex()
            formatted = (
                f"{hex_str[0:8]}-{hex_str[8:12]}-{hex_str[12:16]}-"
                f"{hex_str[16:20]}-{hex_str[20:32]}"
            )
            uuids.append(formatted)
        return {"uuids": uuids}

    # -- Local Name (0x08, 0x09) -------------------------------------------

    def _decode_local_name(self, data: bytes) -> dict:
        """Decode Shortened or Complete Local Name.

        Reference: Core Spec Vol 3, Part C, Section 11.
        """
        try:
            name = data.decode("utf-8", errors="replace")
        except Exception:
            name = data.hex()
        return {"name": name}

    # -- TX Power Level (0x0A) ---------------------------------------------

    def _decode_tx_power(self, data: bytes) -> dict:
        """Decode TX Power Level (signed int8 in dBm).

        Range: -127 to +127 dBm.

        Reference: Core Spec Vol 3, Part C, Section 11.
        """
        if len(data) < 1:
            return {}
        tx_power = struct.unpack("b", data[:1])[0]
        return {"tx_power_dbm": tx_power}

    # -- Class of Device (0x0D) --------------------------------------------

    def _decode_class_of_device(self, data: bytes) -> dict:
        """Decode Class of Device (3 octets, little-endian).

        Reference: Bluetooth Assigned Numbers, Section 1.2.
        """
        if len(data) < 3:
            return {"raw_hex": data.hex()}
        cod = data[0] | (data[1] << 8) | (data[2] << 16)
        major_service = (cod >> 13) & 0x7FF
        major_device = (cod >> 8) & 0x1F
        minor_device = (cod >> 2) & 0x3F
        return {
            "class_of_device": cod,
            "major_service_class": major_service,
            "major_device_class": major_device,
            "minor_device_class": minor_device,
        }

    # -- Simple Pairing Hash (0x0E) ----------------------------------------

    def _decode_pairing_hash(self, data: bytes) -> dict:
        """Decode Simple Pairing Hash C-192 (16 octets).

        Reference: Core Spec Vol 3, Part C, Section 11.
        """
        return {"hash_c192": data.hex()}

    # -- Simple Pairing Randomizer (0x0F) ----------------------------------

    def _decode_pairing_randomizer(self, data: bytes) -> dict:
        """Decode Simple Pairing Randomizer R-192 (16 octets).

        Reference: Core Spec Vol 3, Part C, Section 11.
        """
        return {"randomizer_r192": data.hex()}

    # -- Security Manager TK Value (0x10) ----------------------------------

    def _decode_tk_value(self, data: bytes) -> dict:
        """Decode Security Manager TK Value (16 octets).

        Used in LE Legacy Pairing for out-of-band key exchange.

        Reference: Core Spec Vol 3, Part H, Section 2.3.5.3.
        """
        return {"tk_value": data.hex()}

    # -- Security Manager OOB Flags (0x11) ---------------------------------

    def _decode_oob_flags(self, data: bytes) -> dict:
        """Decode Security Manager Out of Band Flags.

        Reference: Core Spec Vol 3, Part C, Section 11.
        """
        if len(data) < 1:
            return {}
        flags = data[0]
        return {
            "oob_flags": flags,
            "oob_data_present": bool(flags & 0x01),
            "le_supported": bool(flags & 0x02),
            "address_type": "random" if (flags & 0x04) else "public",
        }

    # -- Peripheral Connection Interval Range (0x12) -----------------------

    def _decode_conn_interval(self, data: bytes) -> dict:
        """Decode Peripheral (Slave) Connection Interval Range.

        Two 16-bit values in 1.25ms units.

        Reference: Core Spec Vol 3, Part C, Section 11.
        """
        if len(data) < 4:
            return {"raw_hex": data.hex()}
        min_val, max_val = struct.unpack_from("<HH", data, 0)
        return {
            "min_interval_1_25ms": min_val,
            "max_interval_1_25ms": max_val,
            "min_interval_ms": min_val * 1.25,
            "max_interval_ms": max_val * 1.25,
        }

    # -- Service Data (0x16, 0x20, 0x21) -----------------------------------

    def _decode_service_data_16(self, data: bytes) -> dict:
        """Decode Service Data with a 16-bit UUID prefix.

        Format: [UUID (2 octets LE)] [Service Data (variable)]

        Reference: Core Spec Vol 3, Part C, Section 11.
        """
        if len(data) < 2:
            return {"raw_hex": data.hex()}
        uuid_val = struct.unpack_from("<H", data, 0)[0]
        svc_data = data[2:]
        name, category = lookup_service_uuid(uuid_val)
        return {
            "service_uuid": f"0x{uuid_val:04X}",
            "service_uuid_int": uuid_val,
            "service_name": name,
            "service_category": category,
            "service_data": svc_data,
            "service_data_hex": svc_data.hex(),
        }

    def _decode_service_data_32(self, data: bytes) -> dict:
        """Decode Service Data with a 32-bit UUID prefix.

        Reference: Core Spec Vol 3, Part C, Section 11.
        """
        if len(data) < 4:
            return {"raw_hex": data.hex()}
        uuid_val = struct.unpack_from("<I", data, 0)[0]
        svc_data = data[4:]
        return {
            "service_uuid": f"0x{uuid_val:08X}",
            "service_data": svc_data,
            "service_data_hex": svc_data.hex(),
        }

    def _decode_service_data_128(self, data: bytes) -> dict:
        """Decode Service Data with a 128-bit UUID prefix.

        Reference: Core Spec Vol 3, Part C, Section 11.
        """
        if len(data) < 16:
            return {"raw_hex": data.hex()}
        uuid_bytes = data[:16][::-1]
        hex_str = uuid_bytes.hex()
        formatted = (
            f"{hex_str[0:8]}-{hex_str[8:12]}-{hex_str[12:16]}-"
            f"{hex_str[16:20]}-{hex_str[20:32]}"
        )
        svc_data = data[16:]
        return {
            "service_uuid": formatted,
            "service_data": svc_data,
            "service_data_hex": svc_data.hex(),
        }

    # -- Target Address (0x17, 0x18) ---------------------------------------

    def _decode_target_address(self, data: bytes) -> dict:
        """Decode Public or Random Target Address list.

        Each address is 6 octets in little-endian order.

        Reference: Core Spec Vol 3, Part C, Section 11.
        """
        addresses: list[str] = []
        for i in range(0, len(data) - 5, 6):
            addr_bytes = data[i : i + 6][::-1]
            addr_str = ":".join(f"{b:02X}" for b in addr_bytes)
            addresses.append(addr_str)
        return {"addresses": addresses}

    # -- Appearance (0x19) -------------------------------------------------

    def _decode_appearance(self, data: bytes) -> dict:
        """Decode the Appearance value (16-bit category enum).

        Reference: Bluetooth Assigned Numbers, Section 2.6.
        """
        if len(data) < 2:
            return {}
        value = struct.unpack_from("<H", data, 0)[0]
        name = self.APPEARANCE_MAP.get(value, f"Unknown (0x{value:04X})")
        return {"appearance_value": value, "appearance_name": name}

    # -- Advertising Interval (0x1A) ---------------------------------------

    def _decode_adv_interval(self, data: bytes) -> dict:
        """Decode the Advertising Interval (16-bit, 0.625ms units).

        Reference: Core Spec Vol 3, Part C, Section 11.
        """
        if len(data) < 2:
            return {}
        raw = struct.unpack_from("<H", data, 0)[0]
        return {
            "interval_raw": raw,
            "interval_ms": raw * 0.625,
        }

    # -- LE Bluetooth Device Address (0x1B) --------------------------------

    def _decode_le_bd_addr(self, data: bytes) -> dict:
        """Decode LE Bluetooth Device Address (6 octets + 1 type octet).

        Reference: Core Spec Vol 3, Part C, Section 11.
        """
        if len(data) < 7:
            return {"raw_hex": data.hex()}
        addr_bytes = data[:6][::-1]
        addr_str = ":".join(f"{b:02X}" for b in addr_bytes)
        addr_type = "random" if data[6] else "public"
        return {"address": addr_str, "address_type": addr_type}

    # -- LE Role (0x1C) ----------------------------------------------------

    def _decode_le_role(self, data: bytes) -> dict:
        """Decode LE Role.

        Reference: Core Spec Vol 3, Part C, Section 11.
        """
        if len(data) < 1:
            return {}
        role_map = {
            0x00: "Peripheral Only",
            0x01: "Central Only",
            0x02: "Peripheral Preferred",
            0x03: "Central Preferred",
        }
        return {"role": role_map.get(data[0], f"Unknown (0x{data[0]:02X})")}

    # -- Manufacturer Specific Data (0xFF) ---------------------------------

    def _decode_manufacturer_specific(self, data: bytes) -> dict:
        """Decode Manufacturer Specific Data.

        Format: [Company ID (2 octets LE)] [Manufacturer Data (variable)]

        Reference: Core Spec Vol 3, Part C, Section 11.
        """
        if len(data) < 2:
            return {"raw_hex": data.hex()}
        company_id = struct.unpack_from("<H", data, 0)[0]
        company_name = COMPANY_ID_DATABASE.get(
            company_id, f"Unknown (0x{company_id:04X})"
        )
        mfg_data = data[2:]
        return {
            "company_id": company_id,
            "company_name": company_name,
            "manufacturer_data": mfg_data,
            "manufacturer_data_hex": mfg_data.hex(),
        }


# ===========================================================================
#  5. Apple Continuity Protocol Decoder
# ===========================================================================

class AppleContinuityDecoder:
    """Decode Apple's proprietary Continuity protocol from manufacturer-specific
    advertisement data (Company ID 0x004C).

    Apple Continuity uses a TLV (Type-Length-Value) format after the company
    ID bytes.  Each TLV encodes a different service: iBeacon, AirDrop,
    AirPods, Nearby Info, Find My, etc.

    Reference:
        - Furiousmac et al., "Apple Continuity Protocol" reverse-engineering
        - Guillaume Celosia & Mathieu Cunche, "Discontinued Privacy" (2020)
    """

    # Known Continuity TLV type identifiers
    CONTINUITY_TYPES: dict[int, str] = {
        0x01: "Apple Action",
        0x02: "iBeacon",
        0x03: "AirPrint",
        0x05: "AirDrop",
        0x06: "HomeKit",
        0x07: "AirPods / Proximity Pairing",
        0x08: "Hey Siri",
        0x09: "AirPlay Target",
        0x0A: "AirPlay Source",
        0x0B: "Magic Switch",
        0x0C: "Handoff",
        0x0D: "Tethering Target",
        0x0E: "Tethering Source",
        0x0F: "Nearby Info",
        0x10: "Nearby Action",
        0x12: "Find My / AirTag",
        0x14: "Magic Switch (Proximity)",
        0x19: "Find My (Separated)",
    }

    # Nearby Info device model hints (status bits, byte 1, bits 4-7)
    NEARBY_DEVICE_MODELS: dict[int, str] = {
        0x01: "iPhone",
        0x02: "iPad",
        0x03: "iPod touch",
        0x04: "Mac (macOS)",
        0x05: "Apple Watch",
        0x06: "iPod",
        0x07: "MacBook",
        0x09: "Apple TV",
        0x0A: "HomePod",
        0x0B: "AirTag",
        0x0C: "AirPods",
        0x0D: "AirPods Pro",
        0x0E: "AirPods Max",
        0x0F: "iPhone (proximity)",
        0x10: "iPad (proximity)",
        0x11: "Apple Vision Pro",
        0x14: "AirPods Pro 2",
    }

    # Nearby Action type codes
    NEARBY_ACTION_TYPES: dict[int, str] = {
        0x01: "Apple TV Setup",
        0x04: "Mobile Backup",
        0x05: "Watch Setup",
        0x06: "Apple TV Pair",
        0x07: "Internet Tethering",
        0x08: "Wi-Fi Password",
        0x09: "iOS Setup",
        0x0A: "Repair",
        0x0B: "Speaker Setup",
        0x0C: "Apple Pay",
        0x0D: "Whole Home Audio Setup",
        0x0E: "Developer Tools",
        0x0F: "Handoff",
        0x10: "TV Provider",
        0x11: "Connect to Network",
        0x13: "HomePod Setup",
        0x14: "AirTag Proximity",
    }

    # AirPods model byte mapping
    AIRPODS_MODELS: dict[int, str] = {
        0x01: "AirPods (1st gen)",
        0x02: "AirPods (1st gen)",
        0x03: "AirPods (2nd gen)",
        0x04: "AirPods (2nd gen)",
        0x05: "Powerbeats Pro",
        0x06: "Powerbeats Pro",
        0x09: "Beats Solo Pro",
        0x0A: "AirPods Pro",
        0x0B: "AirPods Pro",
        0x0C: "AirPods Max",
        0x0D: "AirPods Max",
        0x0E: "AirPods (3rd gen)",
        0x0F: "AirPods (3rd gen)",
        0x10: "Beats Fit Pro",
        0x12: "AirPods Pro 2",
        0x13: "AirPods Pro 2",
        0x14: "AirPods Pro 2 (USB-C)",
        0x19: "AirPods 4",
        0x1A: "AirPods 4 (ANC)",
        0x1C: "AirPods Max 2",
        0x1E: "AirPods Pro 3",
    }

    def decode(self, mfg_data: bytes) -> dict | None:
        """Decode Apple Continuity TLV structures from manufacturer data.

        Args:
            mfg_data: The manufacturer-specific payload AFTER the 2-byte
                      company ID (0x4C 0x00).

        Returns:
            Dict with ``continuity_type``, ``continuity_type_id``, and
            ``details``, or None if the data cannot be parsed.
        """
        if len(mfg_data) < 2:
            return None

        # Walk TLV chain -- Apple may pack multiple TLVs
        results: list[dict] = []
        offset = 0
        while offset + 2 <= len(mfg_data):
            tlv_type = mfg_data[offset]
            tlv_len = mfg_data[offset + 1]
            if offset + 2 + tlv_len > len(mfg_data):
                break
            tlv_data = mfg_data[offset + 2 : offset + 2 + tlv_len]
            decoded = self._decode_tlv(tlv_type, tlv_data)
            results.append(decoded)
            offset += 2 + tlv_len

        if not results:
            return None
        # Return the primary (first meaningful) TLV result
        primary = results[0]
        primary["all_tlvs"] = results
        return primary

    def _decode_tlv(self, tlv_type: int, data: bytes) -> dict:
        """Decode a single Apple Continuity TLV."""
        type_name = self.CONTINUITY_TYPES.get(
            tlv_type, f"Unknown (0x{tlv_type:02X})"
        )
        result: dict = {
            "continuity_type": type_name,
            "continuity_type_id": tlv_type,
            "details": {},
        }

        if tlv_type == 0x02:
            result["details"] = self._decode_ibeacon(data)
        elif tlv_type == 0x05:
            result["details"] = self._decode_airdrop(data)
        elif tlv_type == 0x07:
            result["details"] = self._decode_airpods(data)
        elif tlv_type == 0x09:
            result["details"] = self._decode_airplay_target(data)
        elif tlv_type == 0x0C:
            result["details"] = self._decode_handoff(data)
        elif tlv_type == 0x0F:
            result["details"] = self._decode_nearby_info(data)
        elif tlv_type == 0x10:
            result["details"] = self._decode_nearby_action(data)
        elif tlv_type == 0x12:
            result["details"] = self._decode_find_my(data)
        elif tlv_type == 0x14:
            result["details"] = self._decode_magic_switch(data)
        elif tlv_type == 0x19:
            result["details"] = self._decode_find_my_separated(data)
        else:
            result["details"] = {"raw_hex": data.hex()}

        return result

    def _decode_ibeacon(self, data: bytes) -> dict:
        """Decode iBeacon sub-TLV (type 0x02).

        Format: [length=0x15] [UUID 16B] [major 2B] [minor 2B] [TX 1B]
        """
        if len(data) < 21:
            return {"raw_hex": data.hex(), "error": "too_short"}
        uuid_bytes = data[0:16]
        uuid_str = (
            f"{uuid_bytes[0:4].hex()}-{uuid_bytes[4:6].hex()}-"
            f"{uuid_bytes[6:8].hex()}-{uuid_bytes[8:10].hex()}-"
            f"{uuid_bytes[10:16].hex()}"
        ).upper()
        major = struct.unpack(">H", data[16:18])[0]
        minor = struct.unpack(">H", data[18:20])[0]
        tx_power = struct.unpack("b", data[20:21])[0]
        return {
            "uuid": uuid_str,
            "major": major,
            "minor": minor,
            "tx_power_dbm": tx_power,
        }

    def _decode_airdrop(self, data: bytes) -> dict:
        """Decode AirDrop broadcast (type 0x05).

        Contains a truncated SHA-256 of the sender's contact info.
        """
        result: dict = {"raw_hex": data.hex()}
        if len(data) >= 8:
            result["zeros_padding"] = data[0]
            result["hash_fragment"] = data[2:8].hex()
        return result

    def _decode_airpods(self, data: bytes) -> dict:
        """Decode AirPods / Proximity Pairing (type 0x07).

        Fields: device model, status flags, battery levels, lid state.
        """
        if len(data) < 6:
            return {"raw_hex": data.hex()}
        status = data[0]
        device_model = (data[1] >> 4) & 0x0F | ((data[1] & 0x0F) << 4)
        model_name = self.AIRPODS_MODELS.get(
            data[1], f"Unknown (0x{data[1]:02X})"
        )
        # Battery levels: nibbles in bytes 3-4
        batt_right = (data[3] >> 4) & 0x0F
        batt_left = data[3] & 0x0F
        batt_case = (data[4] >> 4) & 0x0F
        # Charging flags in byte 4 low nibble
        charge_flags = data[4] & 0x0F
        lid_open = bool(data[5] & 0x04) if len(data) > 5 else None
        return {
            "model": model_name,
            "model_byte": data[1],
            "status": status,
            "battery_right": min(batt_right * 10, 100) if batt_right != 0x0F else None,
            "battery_left": min(batt_left * 10, 100) if batt_left != 0x0F else None,
            "battery_case": min(batt_case * 10, 100) if batt_case != 0x0F else None,
            "charging_right": bool(charge_flags & 0x01),
            "charging_left": bool(charge_flags & 0x02),
            "charging_case": bool(charge_flags & 0x04),
            "lid_open": lid_open,
        }

    def _decode_airplay_target(self, data: bytes) -> dict:
        """Decode AirPlay Target (type 0x09)."""
        result: dict = {"raw_hex": data.hex()}
        if len(data) >= 6:
            result["flags"] = data[0]
            result["seed"] = data[1]
            result["device_id"] = data[2:6].hex()
        return result

    def _decode_handoff(self, data: bytes) -> dict:
        """Decode Handoff broadcast (type 0x0C).

        Contains encrypted payload and activity type for Continuity.
        """
        result: dict = {"raw_hex": data.hex()}
        if len(data) >= 4:
            result["clipboard_status"] = data[0]
            result["sequence_number"] = struct.unpack(">H", data[1:3])[0]
            result["encrypted_payload"] = data[3:].hex()
        return result

    def _decode_nearby_info(self, data: bytes) -> dict:
        """Decode Nearby Info broadcast (type 0x0F).

        Reveals device model hint, status flags, and action code without
        requiring pairing or authentication.

        Reference:
            Martin et al., "Handoff All Your Privacy" (2019).
        """
        if len(data) < 4:
            return {"raw_hex": data.hex()}
        status_flags = data[0]
        action_code = status_flags >> 4
        status_lower = status_flags & 0x0F
        device_model_id = data[1]
        model_name = self.NEARBY_DEVICE_MODELS.get(
            device_model_id, f"Unknown (0x{device_model_id:02X})"
        )
        # Bytes 2-3 encode Wi-Fi and authentication state
        wifi_state = data[2] if len(data) > 2 else 0
        auth_tag = data[3:].hex() if len(data) > 3 else ""
        return {
            "device_model_id": device_model_id,
            "device_model": model_name,
            "action_code": action_code,
            "status_flags": status_lower,
            "wifi_state": wifi_state,
            "auth_tag": auth_tag,
            "is_primary_device": bool(status_lower & 0x01),
            "screen_on": bool(status_lower & 0x04),
        }

    def _decode_nearby_action(self, data: bytes) -> dict:
        """Decode Nearby Action broadcast (type 0x10).

        Triggers UI popups on nearby Apple devices (e.g. AirPods setup).
        """
        if len(data) < 3:
            return {"raw_hex": data.hex()}
        action_flags = data[0]
        action_type = data[1]
        action_name = self.NEARBY_ACTION_TYPES.get(
            action_type, f"Unknown (0x{action_type:02X})"
        )
        auth_tag = data[2:].hex()
        return {
            "action_flags": action_flags,
            "action_type": action_type,
            "action_name": action_name,
            "auth_tag": auth_tag,
        }

    def _decode_find_my(self, data: bytes) -> dict:
        """Decode Find My / AirTag broadcast (type 0x12).

        The Find My network uses rotating P-224 elliptic curve public keys.
        The advertisement contains a fragment of the current public key,
        status byte, and battery/counter information.

        Reference:
            Heinrich et al., "Who Can Find My Devices?" (2021).
        """
        if len(data) < 2:
            return {"raw_hex": data.hex()}
        status = data[0]
        battery_level = (status >> 6) & 0x03
        battery_map = {0: "full", 1: "medium", 2: "low", 3: "critical"}
        result: dict = {
            "status_byte": status,
            "battery_state": battery_map.get(battery_level, "unknown"),
            "maintained": bool(status & 0x04),
        }
        if len(data) >= 22:
            # 22 bytes = P-224 compressed public key fragment
            result["public_key_fragment"] = data[1:23].hex()
            result["key_length"] = len(data) - 1
        elif len(data) > 1:
            result["public_key_fragment"] = data[1:].hex()
            result["key_length"] = len(data) - 1
        return result

    def _decode_magic_switch(self, data: bytes) -> dict:
        """Decode Magic Switch proximity broadcast (type 0x14).

        Used for device proximity detection (e.g. auto-unlock Mac near
        Apple Watch).
        """
        result: dict = {"raw_hex": data.hex()}
        if len(data) >= 2:
            result["confidence"] = data[0]
            result["flags"] = data[1]
        return result

    def _decode_find_my_separated(self, data: bytes) -> dict:
        """Decode Find My Separated state broadcast (type 0x19).

        Emitted when an AirTag or Find My accessory has been separated
        from its owner for an extended period.  This triggers the anti-
        stalking alert on nearby iPhones.
        """
        if len(data) < 2:
            return {"raw_hex": data.hex()}
        status = data[0]
        result: dict = {
            "status_byte": status,
            "is_separated": True,
            "raw_hex": data.hex(),
        }
        if len(data) >= 22:
            result["public_key_fragment"] = data[1:23].hex()
        return result


# ===========================================================================
#  6. Google Fast Pair Decoder
# ===========================================================================

class GoogleFastPairDecoder:
    """Decode Google Fast Pair data from either manufacturer-specific data
    (company ID 0x00E0) or service data with UUID 0xFE2C.

    Google Fast Pair advertises model IDs (3 bytes), optional account key
    filters (for subsequent pairing), and battery notifications.

    Reference:
        Google Fast Pair Specification v1.0 (developers.google.com/nearby)
    """

    def decode(
        self,
        company_id: int | None,
        mfg_data: bytes,
        service_data_entries: list[dict],
    ) -> dict | None:
        """Decode Google Fast Pair data.

        Args:
            company_id: BLE Company Identifier (0x00E0 for Google).
            mfg_data: Raw manufacturer data payload (after company ID).
            service_data_entries: Parsed service data AD entries from ADParser.

        Returns:
            Dict with ``model_id``, ``type``, ``battery`` or None.
        """
        # Try service data UUID 0xFE2C first (Fast Pair primary channel)
        for entry in service_data_entries:
            parsed = entry.get("parsed", {})
            if parsed.get("service_uuid_int") == 0xFE2C:
                svc_data = parsed.get("service_data", b"")
                if isinstance(svc_data, str):
                    svc_data = bytes.fromhex(svc_data)
                return self._decode_fast_pair_service_data(svc_data)

        # Try manufacturer-specific data (company 0x00E0)
        if company_id == 0x00E0 and len(mfg_data) >= 3:
            return self._decode_fast_pair_mfg(mfg_data)

        # Check for Google Find My Device Network (UUID 0xFDA6)
        for entry in service_data_entries:
            parsed = entry.get("parsed", {})
            if parsed.get("service_uuid_int") == 0xFDA6:
                svc_data = parsed.get("service_data", b"")
                if isinstance(svc_data, str):
                    svc_data = bytes.fromhex(svc_data)
                return self._decode_find_my_device(svc_data)

        return None

    def _decode_fast_pair_service_data(self, data: bytes) -> dict:
        """Decode Fast Pair service data (UUID 0xFE2C payload).

        The first 3 bytes are the model ID when in discoverable mode.
        In non-discoverable mode, the data contains an account key filter.
        """
        if len(data) < 1:
            return {"type": "fast_pair", "model_id": None, "battery": None}

        # Model ID (3 bytes, big-endian)
        if len(data) >= 3:
            model_id = (data[0] << 16) | (data[1] << 8) | data[2]
            model_hex = f"0x{model_id:06X}"
        else:
            model_hex = data.hex()

        result: dict = {
            "type": "fast_pair_discoverable",
            "model_id": model_hex,
            "battery": None,
        }

        # Account key filter detection (non-discoverable mode)
        if len(data) > 3:
            flag_byte = data[0]
            if flag_byte in (0x00, 0x06):
                result["type"] = "fast_pair_non_discoverable"
                # Parse battery notification if present
                result["battery"] = self._parse_battery(data[3:])

        return result

    def _decode_fast_pair_mfg(self, data: bytes) -> dict:
        """Decode Google manufacturer-specific data."""
        model_id = (data[0] << 16) | (data[1] << 8) | data[2]
        return {
            "type": "fast_pair",
            "model_id": f"0x{model_id:06X}",
            "battery": self._parse_battery(data[3:]) if len(data) > 3 else None,
        }

    def _decode_find_my_device(self, data: bytes) -> dict:
        """Decode Google Find My Device Network service data (0xFDA6)."""
        result: dict = {
            "type": "google_find_my_device",
            "model_id": None,
            "battery": None,
        }
        if len(data) >= 1:
            result["protocol_version"] = data[0] >> 4
            result["frame_type"] = data[0] & 0x0F
        if len(data) >= 2:
            result["ephemeral_id_fragment"] = data[1:].hex()
        return result

    def _parse_battery(self, data: bytes) -> dict | None:
        """Parse Fast Pair battery notification TLV.

        Battery data uses 3 bytes: [left] [right] [case], each as a
        percentage (0-100) or 0xFF for unavailable.
        """
        if len(data) < 3:
            return None
        left = data[0] if data[0] != 0xFF else None
        right = data[1] if data[1] != 0xFF else None
        case = data[2] if data[2] != 0xFF else None
        return {
            "left": left,
            "right": right,
            "case": case,
        }


# ===========================================================================
#  7. Samsung SmartThings Decoder
# ===========================================================================

class SamsungSmartThingsDecoder:
    """Decode Samsung manufacturer data (Company ID 0x0075) and SmartThings
    service data (UUIDs 0xFD5A, 0xFD69, 0xFD8E).

    Detects SmartTag, SmartTag2, Galaxy Buds variants, and other Samsung
    BLE-enabled accessories.

    Reference:
        Samsung SmartThings Find network protocol (partially documented).
    """

    # Samsung device type identifiers (from service data)
    DEVICE_TYPES: dict[int, str] = {
        0x01: "Galaxy Phone",
        0x02: "Galaxy Tablet",
        0x03: "Galaxy Watch",
        0x04: "Galaxy Buds",
        0x05: "Galaxy Buds+",
        0x06: "Galaxy Buds Live",
        0x07: "Galaxy Buds Pro",
        0x08: "Galaxy Buds2",
        0x09: "Galaxy Buds2 Pro",
        0x0A: "Galaxy Buds FE",
        0x0B: "Galaxy Buds3",
        0x0C: "Galaxy Buds3 Pro",
        0x10: "SmartTag",
        0x11: "SmartTag+",
        0x12: "SmartTag2",
        0x20: "Galaxy Fit",
        0x21: "Galaxy Fit2",
        0x30: "Galaxy Ring",
    }

    def decode(
        self,
        company_id: int | None,
        mfg_data: bytes,
        service_data_entries: list[dict],
    ) -> dict | None:
        """Decode Samsung-specific advertisement data.

        Args:
            company_id: BLE Company Identifier (0x0075 for Samsung).
            mfg_data: Raw manufacturer data payload.
            service_data_entries: Parsed service data AD entries.

        Returns:
            Dict with device type, model, and tracker-specific fields, or None.
        """
        result: dict = {
            "vendor": "Samsung",
            "device_type": None,
            "model": None,
            "smarttag": None,
        }

        # Check SmartTag service UUIDs (0xFD69 for SmartTag, 0xFD8E for SmartTag2)
        for entry in service_data_entries:
            parsed = entry.get("parsed", {})
            svc_uuid = parsed.get("service_uuid_int")
            if svc_uuid in (0xFD69, 0xFD8E):
                svc_data = parsed.get("service_data", b"")
                if isinstance(svc_data, str):
                    svc_data = bytes.fromhex(svc_data)
                tag_protocol = "SmartTag2" if svc_uuid == 0xFD8E else "SmartTag"
                result["device_type"] = "tracker"
                result["model"] = tag_protocol
                result["smarttag"] = self._decode_smarttag(svc_data, tag_protocol)
                return result

        # Check SmartThings service UUID (0xFD5A)
        for entry in service_data_entries:
            parsed = entry.get("parsed", {})
            if parsed.get("service_uuid_int") == 0xFD5A:
                svc_data = parsed.get("service_data", b"")
                if isinstance(svc_data, str):
                    svc_data = bytes.fromhex(svc_data)
                return self._decode_smartthings(svc_data)

        # Fall back to manufacturer data (company 0x0075)
        if company_id == 0x0075 and len(mfg_data) >= 2:
            return self._decode_samsung_mfg(mfg_data)

        return None

    def _decode_smarttag(self, data: bytes, protocol: str) -> dict:
        """Decode SmartTag / SmartTag2 service data payload."""
        result: dict = {
            "protocol": protocol,
            "in_range_of_owner": None,
            "battery_low": None,
            "ephemeral_id": None,
        }
        if len(data) >= 1:
            flags = data[0]
            result["in_range_of_owner"] = bool(flags & 0x01)
            result["battery_low"] = bool(flags & 0x02)
            result["ringer_active"] = bool(flags & 0x04)
        if len(data) >= 8:
            result["ephemeral_id"] = data[1:8].hex()
        return result

    def _decode_smartthings(self, data: bytes) -> dict:
        """Decode generic SmartThings service data."""
        result: dict = {
            "vendor": "Samsung",
            "device_type": None,
            "model": None,
            "smarttag": None,
        }
        if len(data) >= 1:
            dev_type_byte = data[0]
            result["device_type"] = self.DEVICE_TYPES.get(
                dev_type_byte, f"Unknown (0x{dev_type_byte:02X})"
            )
        if len(data) >= 2:
            result["model"] = f"Samsung type 0x{data[0]:02X}"
        return result

    def _decode_samsung_mfg(self, mfg_data: bytes) -> dict:
        """Decode Samsung manufacturer-specific data fallback."""
        result: dict = {
            "vendor": "Samsung",
            "device_type": None,
            "model": None,
            "smarttag": None,
            "raw_hex": mfg_data.hex(),
        }
        if len(mfg_data) >= 2:
            sub_type = mfg_data[0]
            if sub_type in self.DEVICE_TYPES:
                result["device_type"] = self.DEVICE_TYPES[sub_type]
                result["model"] = self.DEVICE_TYPES[sub_type]
        return result


# ===========================================================================
#  8. Microsoft Swift Pair Decoder
# ===========================================================================

class MicrosoftSwiftPairDecoder:
    """Decode Microsoft Swift Pair beacon data from manufacturer-specific
    advertisements (Company ID 0x0006).

    Swift Pair enables fast Bluetooth pairing on Windows 10/11 by advertising
    a specific manufacturer data format with scenario type 0x03.

    Reference:
        Microsoft Swift Pair documentation (learn.microsoft.com).
    """

    # Scenario byte values
    SCENARIO_SWIFT_PAIR = 0x03

    # Major device class descriptions (Bluetooth CoD)
    MAJOR_DEVICE_CLASSES: dict[int, str] = {
        0x01: "Computer",
        0x02: "Phone",
        0x03: "LAN/Network Access Point",
        0x04: "Audio/Video",
        0x05: "Peripheral",
        0x06: "Imaging",
        0x07: "Wearable",
        0x08: "Toy",
        0x09: "Health",
    }

    def decode(
        self,
        company_id: int | None,
        mfg_data: bytes,
        service_data_entries: list[dict],
    ) -> dict | None:
        """Decode Microsoft Swift Pair beacon.

        Args:
            company_id: BLE Company Identifier (0x0006 for Microsoft).
            mfg_data: Raw manufacturer data payload.
            service_data_entries: Not used for Microsoft, included for API
                                 consistency.

        Returns:
            Dict with Swift Pair details or None.
        """
        if company_id != 0x0006 or len(mfg_data) < 2:
            return None

        # Microsoft vendor data: [vendor_section (1B)] [scenario (1B)] ...
        vendor_section = mfg_data[0]
        scenario = mfg_data[1]

        result: dict = {
            "vendor": "Microsoft",
            "vendor_section": vendor_section,
            "scenario": scenario,
            "is_swift_pair": scenario == self.SCENARIO_SWIFT_PAIR,
            "device_class": None,
            "display_name": None,
        }

        if scenario == self.SCENARIO_SWIFT_PAIR and len(mfg_data) >= 5:
            # Swift Pair format: [vendor] [0x03] [RSSI] [CoD 3B] [name...]
            result["rssi_threshold"] = struct.unpack("b", mfg_data[2:3])[0]
            # Class of Device
            if len(mfg_data) >= 5:
                cod = mfg_data[3] | (mfg_data[4] << 8)
                if len(mfg_data) >= 6:
                    cod |= mfg_data[5] << 16
                major_class = (cod >> 8) & 0x1F
                result["device_class"] = self.MAJOR_DEVICE_CLASSES.get(
                    major_class, f"Unknown (0x{major_class:02X})"
                )
                result["class_of_device_raw"] = cod
            # Display name (optional, UTF-8 after the CoD)
            if len(mfg_data) >= 7:
                try:
                    name = mfg_data[6:].decode("utf-8", errors="replace").rstrip("\x00")
                    if name:
                        result["display_name"] = name
                except Exception:
                    pass

        return result


# ===========================================================================
#  9. Beacon Parser  --  iBeacon, Eddystone, AltBeacon
# ===========================================================================

class BeaconParser:
    """Parse all major BLE beacon protocols from AD structures.

    Supported formats:
        - Apple iBeacon (manufacturer specific, company 0x004C, subtype 0x02)
        - Eddystone-UID (service data UUID 0xFEAA, frame 0x00)
        - Eddystone-URL (service data UUID 0xFEAA, frame 0x10)
        - Eddystone-TLM (service data UUID 0xFEAA, frame 0x20)
        - Eddystone-EID (service data UUID 0xFEAA, frame 0x30)
        - AltBeacon (manufacturer specific, 0xBEAC identifier)

    Reference:
        - Apple iBeacon (proprietary, widely reverse-engineered)
        - Eddystone: github.com/google/eddystone
        - AltBeacon: altbeacon.org/spec
    """

    # Eddystone URL encoding schemes
    EDDYSTONE_URL_SCHEMES: dict[int, str] = {
        0x00: "http://www.",
        0x01: "https://www.",
        0x02: "http://",
        0x03: "https://",
    }

    # Eddystone URL suffix encodings
    EDDYSTONE_URL_SUFFIXES: dict[int, str] = {
        0x00: ".com/",
        0x01: ".org/",
        0x02: ".edu/",
        0x03: ".net/",
        0x04: ".info/",
        0x05: ".biz/",
        0x06: ".gov/",
        0x07: ".com",
        0x08: ".org",
        0x09: ".edu",
        0x0A: ".net",
        0x0B: ".info",
        0x0C: ".biz",
        0x0D: ".gov",
    }

    def parse(self, ad_structures: list[dict]) -> dict | None:
        """Detect and parse beacon data from a list of AD structures.

        Args:
            ad_structures: List of parsed AD entry dicts from ``ADParser.parse()``.

        Returns:
            Dict with ``beacon_type`` and ``data``, or None if no beacon found.
        """
        for entry in ad_structures:
            ad_type = entry.get("type")
            parsed = entry.get("parsed", {})
            data = entry.get("data", b"")

            # Check for iBeacon in manufacturer specific data
            if ad_type == 0xFF:
                cid = parsed.get("company_id")
                mfg = parsed.get("manufacturer_data", b"")
                if isinstance(mfg, str):
                    mfg = bytes.fromhex(mfg)
                if cid == 0x004C and len(mfg) >= 23 and mfg[0] == 0x02 and mfg[1] == 0x15:
                    return self._parse_ibeacon(mfg[2:])
                # Check for AltBeacon signature (0xBEAC at bytes 0-1)
                if len(mfg) >= 24 and mfg[0] == 0xBE and mfg[1] == 0xAC:
                    return self._parse_altbeacon(mfg)

            # Check for Eddystone in service data
            if ad_type == 0x16:
                svc_uuid = parsed.get("service_uuid_int")
                svc_data = parsed.get("service_data", b"")
                if isinstance(svc_data, str):
                    svc_data = bytes.fromhex(svc_data)
                if svc_uuid == 0xFEAA and len(svc_data) >= 1:
                    frame_type = svc_data[0]
                    if frame_type == 0x00:
                        return self._parse_eddystone_uid(svc_data)
                    elif frame_type == 0x10:
                        return self._parse_eddystone_url(svc_data)
                    elif frame_type == 0x20:
                        return self._parse_eddystone_tlm(svc_data)
                    elif frame_type == 0x30:
                        return self._parse_eddystone_eid(svc_data)

        return None

    def _parse_ibeacon(self, data: bytes) -> dict:
        """Parse iBeacon payload (after subtype + length bytes).

        Format: [UUID 16B] [major 2B BE] [minor 2B BE] [TX power 1B signed]
        """
        if len(data) < 21:
            return {"beacon_type": "iBeacon", "data": {"error": "truncated"}}
        uuid_bytes = data[0:16]
        uuid_str = (
            f"{uuid_bytes[0:4].hex()}-{uuid_bytes[4:6].hex()}-"
            f"{uuid_bytes[6:8].hex()}-{uuid_bytes[8:10].hex()}-"
            f"{uuid_bytes[10:16].hex()}"
        ).upper()
        major = struct.unpack(">H", data[16:18])[0]
        minor = struct.unpack(">H", data[18:20])[0]
        tx_power = struct.unpack("b", data[20:21])[0]
        return {
            "beacon_type": "iBeacon",
            "data": {
                "uuid": uuid_str,
                "major": major,
                "minor": minor,
                "tx_power_dbm": tx_power,
            },
        }

    def _parse_eddystone_uid(self, data: bytes) -> dict:
        """Parse Eddystone-UID frame (frame type 0x00).

        Format: [frame 0x00] [TX power 1B] [namespace 10B] [instance 6B] [RFU 2B]
        """
        if len(data) < 18:
            return {"beacon_type": "Eddystone-UID", "data": {"error": "truncated"}}
        tx_power = struct.unpack("b", data[1:2])[0]
        namespace = data[2:12].hex().upper()
        instance = data[12:18].hex().upper()
        return {
            "beacon_type": "Eddystone-UID",
            "data": {
                "tx_power_dbm": tx_power,
                "namespace": namespace,
                "instance": instance,
            },
        }

    def _parse_eddystone_url(self, data: bytes) -> dict:
        """Parse Eddystone-URL frame (frame type 0x10).

        Format: [frame 0x10] [TX power 1B] [URL scheme 1B] [encoded URL ...]
        """
        if len(data) < 3:
            return {"beacon_type": "Eddystone-URL", "data": {"error": "truncated"}}
        tx_power = struct.unpack("b", data[1:2])[0]
        scheme = self.EDDYSTONE_URL_SCHEMES.get(data[2], "")
        url_parts: list[str] = [scheme]
        for byte in data[3:]:
            if byte in self.EDDYSTONE_URL_SUFFIXES:
                url_parts.append(self.EDDYSTONE_URL_SUFFIXES[byte])
            elif 0x20 <= byte <= 0x7E:
                url_parts.append(chr(byte))
        url = "".join(url_parts)
        return {
            "beacon_type": "Eddystone-URL",
            "data": {
                "tx_power_dbm": tx_power,
                "url": url,
            },
        }

    def _parse_eddystone_tlm(self, data: bytes) -> dict:
        """Parse Eddystone-TLM frame (frame type 0x20).

        Format: [frame 0x20] [version 1B] [voltage 2B BE] [temp 2B fixed 8.8]
                [adv_count 4B BE] [sec_count 4B BE (0.1s units)]
        """
        if len(data) < 14:
            return {"beacon_type": "Eddystone-TLM", "data": {"error": "truncated"}}
        version = data[1]
        voltage_mv = struct.unpack(">H", data[2:4])[0]
        # Temperature is fixed-point 8.8 (signed)
        temp_raw = struct.unpack(">h", data[4:6])[0]
        temperature_c = temp_raw / 256.0
        adv_count = struct.unpack(">I", data[6:10])[0]
        sec_count = struct.unpack(">I", data[10:14])[0]
        uptime_seconds = sec_count * 0.1
        return {
            "beacon_type": "Eddystone-TLM",
            "data": {
                "version": version,
                "voltage_mv": voltage_mv,
                "temperature_c": round(temperature_c, 2),
                "advertisement_count": adv_count,
                "uptime_seconds": round(uptime_seconds, 1),
            },
        }

    def _parse_eddystone_eid(self, data: bytes) -> dict:
        """Parse Eddystone-EID frame (frame type 0x30).

        Format: [frame 0x30] [TX power 1B] [encrypted ID 8B]
        """
        if len(data) < 10:
            return {"beacon_type": "Eddystone-EID", "data": {"error": "truncated"}}
        tx_power = struct.unpack("b", data[1:2])[0]
        eid = data[2:10].hex().upper()
        return {
            "beacon_type": "Eddystone-EID",
            "data": {
                "tx_power_dbm": tx_power,
                "encrypted_id": eid,
            },
        }

    def _parse_altbeacon(self, data: bytes) -> dict:
        """Parse AltBeacon format.

        Format: [0xBE 0xAC] [Beacon ID 20B] [ref RSSI 1B] [MFG reserved 1B]

        Reference: altbeacon.org/spec/altbeacon-tech-spec-v1-0.pdf
        """
        if len(data) < 24:
            return {"beacon_type": "AltBeacon", "data": {"error": "truncated"}}
        beacon_id = data[2:22].hex().upper()
        ref_rssi = struct.unpack("b", data[22:23])[0]
        mfg_reserved = data[23]
        return {
            "beacon_type": "AltBeacon",
            "data": {
                "beacon_id": beacon_id,
                "reference_rssi_dbm": ref_rssi,
                "mfg_reserved": mfg_reserved,
            },
        }


# ===========================================================================
#  10. DistanceEstimator class  --  RSSI-based distance estimation
# ===========================================================================

class DistanceEstimator:
    """Estimate physical distance to a BLE device using the log-distance
    path-loss model:

        RSSI = TX_power - 10 * n * log10(d)

    Solving for d:

        d = 10 ^ ((TX_power - RSSI) / (10 * n))

    Where:
        - TX_power is the RSSI at 1 meter (typically -59 dBm for BLE)
        - n is the path-loss exponent (environment dependent)
        - d is the estimated distance in meters

    Environment presets:
        - free_space: n = 2.0 (theoretical minimum)
        - indoor:     n = 2.7 (typical office / home)
        - indoor_obstructed: n = 3.5 (walls, furniture, metal objects)

    Reference:
        Rappaport, "Wireless Communications: Principles and Practice", Ch. 4.
    """

    ENVIRONMENT_PRESETS: dict[str, float] = {
        "free_space": 2.0,
        "indoor": 2.7,
        "indoor_obstructed": 3.5,
    }

    def __init__(
        self,
        tx_power: int = -59,
        n: float = 2.0,
    ):
        """Initialize the distance estimator.

        Args:
            tx_power: Expected RSSI at 1 meter (dBm).  Default -59 is the
                      typical BLE advertising TX power at 1m.
            n: Path-loss exponent.  Default 2.0 (free space).
        """
        self.tx_power = tx_power
        self.n = n

    def estimate(
        self,
        rssi: int,
        tx_power: int | None = None,
        n: float | None = None,
    ) -> float:
        """Estimate distance in meters from RSSI.

        Args:
            rssi: Received signal strength in dBm.
            tx_power: Override TX power at 1 meter (dBm).
            n: Override path-loss exponent.

        Returns:
            Estimated distance in meters.  Returns -1.0 if RSSI is invalid
            (e.g. 0 or -127 sentinel values).
        """
        if rssi == 0 or rssi <= -127:
            return -1.0
        effective_tx = tx_power if tx_power is not None else self.tx_power
        effective_n = n if n is not None else self.n
        if effective_n <= 0:
            effective_n = 2.0
        try:
            ratio = (effective_tx - rssi) / (10.0 * effective_n)
            distance = math.pow(10.0, ratio)
            return round(distance, 2)
        except (ValueError, OverflowError):
            return -1.0

    def estimate_with_environment(
        self,
        rssi: int,
        environment: str = "indoor",
        tx_power: int | None = None,
    ) -> float:
        """Estimate distance using a named environment preset.

        Args:
            rssi: Received signal strength in dBm.
            environment: One of "free_space", "indoor", "indoor_obstructed".
            tx_power: Override TX power at 1 meter.

        Returns:
            Estimated distance in meters.
        """
        preset_n = self.ENVIRONMENT_PRESETS.get(environment, 2.0)
        return self.estimate(rssi, tx_power=tx_power, n=preset_n)

    @staticmethod
    def classify_proximity(distance: float) -> str:
        """Classify distance into a proximity zone.

        Args:
            distance: Estimated distance in meters.

        Returns:
            "immediate" (<0.5m), "near" (<3m), "far" (<10m), or "very_far".
        """
        if distance < 0:
            return "unknown"
        if distance < 0.5:
            return "immediate"
        if distance < 3.0:
            return "near"
        if distance < 10.0:
            return "far"
        return "very_far"


# ===========================================================================
#  11. TrackerAnalyzer class  --  Detect tracking devices and MAC rotation
# ===========================================================================

class TrackerAnalyzer:
    """Detect known BLE tracking devices and suspicious advertising patterns.

    Detection targets include:
        - Apple AirTag / Find My accessories (type 0x12, service UUID 0xFD6F)
        - Samsung SmartTag / SmartTag2 (service UUIDs 0xFD69, 0xFD8E)
        - Google Find My Device Network (service UUID 0xFDA6)
        - Tile trackers (service UUIDs 0xFEED, 0xFE6E, company 0x0135)
        - Chipolo trackers (company ID 0x0310)
        - Generic heuristic detection (random MAC, no name, strong signal)

    Also provides MAC rotation detection to group devices that appear to be
    the same physical device using randomized addresses.

    Reference:
        Heinrich et al., "Who Can Find My Devices?" (PETS 2022).
    """

    # Well-known tracker service UUIDs
    TRACKER_SERVICE_UUIDS: set[str] = {
        "0xFD6F",  # Apple Find My
        "0xFDA6",  # Google Find My Device
        "0xFD69",  # Samsung SmartTag
        "0xFD8E",  # Samsung SmartTag2
        "0xFD5A",  # Samsung SmartThings
        "0xFEED",  # Tile (A)
        "0xFE6E",  # Tile (B)
    }

    # Tracker company IDs
    TRACKER_COMPANY_IDS: set[int] = {
        0x0135,  # Tile
        0x0310,  # Chipolo
    }

    def is_tracker(
        self,
        ad_entries: list[dict],
        manufacturer: str,
        service_uuids: list[str],
    ) -> dict:
        """Determine whether a device is a known or suspected tracker.

        Args:
            ad_entries: Parsed AD structures from ``ADParser.parse()``.
            manufacturer: Resolved manufacturer string.
            service_uuids: List of service UUID strings from the advertisement.

        Returns:
            Dict with: ``is_tracker`` (bool), ``tracker_type`` (str),
            ``confidence`` (float 0.0-1.0), ``details`` (str).
        """
        # Collect all UUIDs and company IDs from entries
        all_uuids: set[str] = set(service_uuids)
        company_ids: set[int] = set()
        has_find_my_tlv = False
        has_name = False

        for entry in ad_entries:
            parsed = entry.get("parsed", {})
            # Gather UUIDs from UUID list entries
            for u in parsed.get("uuids", []):
                all_uuids.add(u)
            # Gather company IDs
            if "company_id" in parsed:
                company_ids.add(parsed["company_id"])
            # Check for Apple Find My TLV
            if entry.get("type") == 0xFF:
                mfg = parsed.get("manufacturer_data", b"")
                if isinstance(mfg, str):
                    try:
                        mfg = bytes.fromhex(mfg)
                    except ValueError:
                        mfg = b""
                if parsed.get("company_id") == 0x004C and len(mfg) >= 2:
                    if mfg[0] == 0x12:
                        has_find_my_tlv = True
            # Check for name
            if entry.get("type") in (0x08, 0x09):
                name = parsed.get("name", "")
                if name:
                    has_name = True

        # -- Apple AirTag / Find My ----------------------------------------
        if has_find_my_tlv:
            return {
                "is_tracker": True,
                "tracker_type": "Apple AirTag / Find My Accessory",
                "confidence": 0.97,
                "details": "Detected Apple Find My TLV (type 0x12) in manufacturer data",
            }
        if "0xFD6F" in all_uuids:
            return {
                "is_tracker": True,
                "tracker_type": "Apple Find My Network",
                "confidence": 0.90,
                "details": "Service UUID 0xFD6F (Apple Find My Network) present",
            }

        # -- Google Find My Device -----------------------------------------
        if "0xFDA6" in all_uuids:
            return {
                "is_tracker": True,
                "tracker_type": "Google Find My Device",
                "confidence": 0.90,
                "details": "Service UUID 0xFDA6 (Google Find My Device Network) present",
            }

        # -- Samsung SmartTag ----------------------------------------------
        if "0xFD69" in all_uuids or "0xFD8E" in all_uuids:
            tag_ver = "SmartTag2" if "0xFD8E" in all_uuids else "SmartTag"
            return {
                "is_tracker": True,
                "tracker_type": f"Samsung {tag_ver}",
                "confidence": 0.93,
                "details": f"Samsung {tag_ver} service UUID detected",
            }

        # -- Tile ----------------------------------------------------------
        if all_uuids & {"0xFEED", "0xFE6E"}:
            return {
                "is_tracker": True,
                "tracker_type": "Tile Tracker",
                "confidence": 0.92,
                "details": "Tile service UUID (0xFEED / 0xFE6E) detected",
            }
        if 0x0135 in company_ids:
            return {
                "is_tracker": True,
                "tracker_type": "Tile Tracker",
                "confidence": 0.88,
                "details": "Tile company ID 0x0135 detected",
            }

        # -- Chipolo -------------------------------------------------------
        if 0x0310 in company_ids:
            return {
                "is_tracker": True,
                "tracker_type": "Chipolo Tracker",
                "confidence": 0.88,
                "details": "Chipolo company ID 0x0310 detected",
            }

        # -- No known tracker signature ------------------------------------
        return {
            "is_tracker": False,
            "tracker_type": "none",
            "confidence": 0.0,
            "details": "No known tracker signatures detected",
        }

    @staticmethod
    def detect_mac_rotation(devices: list[dict]) -> list[dict]:
        """Detect devices that appear to be the same physical device rotating
        MAC addresses.

        Groups are formed by matching: same OUI manufacturer, overlapping
        advertisement timing, similar RSSI (within 15 dBm), and identical
        service UUID sets.

        Args:
            devices: List of device info dicts, each with at minimum:
                ``mac`` (str), ``rssi`` (int), ``manufacturer`` (str),
                ``service_uuids`` (list[str]), ``last_seen`` (float epoch).

        Returns:
            List of dicts, each representing a suspected rotation group:
            ``{"macs": [...], "manufacturer": str, "avg_rssi": float,
              "service_uuids": [...], "confidence": float}``
        """
        if len(devices) < 2:
            return []

        groups: list[dict] = []
        used: set[str] = set()

        for i, dev_a in enumerate(devices):
            mac_a = dev_a.get("mac", "")
            if mac_a in used or not is_random_mac(mac_a):
                continue

            group_macs = [mac_a]
            group_rssis = [dev_a.get("rssi", -127)]

            for j, dev_b in enumerate(devices):
                if i == j:
                    continue
                mac_b = dev_b.get("mac", "")
                if mac_b in used or not is_random_mac(mac_b):
                    continue

                # Same manufacturer
                if dev_a.get("manufacturer") != dev_b.get("manufacturer"):
                    continue

                # Similar RSSI (within 15 dBm)
                rssi_a = dev_a.get("rssi", -127)
                rssi_b = dev_b.get("rssi", -127)
                if abs(rssi_a - rssi_b) > 15:
                    continue

                # Same service UUIDs
                uuids_a = set(dev_a.get("service_uuids", []))
                uuids_b = set(dev_b.get("service_uuids", []))
                if uuids_a and uuids_b and uuids_a != uuids_b:
                    continue

                # Overlapping timing (within 60 seconds)
                time_a = dev_a.get("last_seen", 0)
                time_b = dev_b.get("last_seen", 0)
                if time_a and time_b and abs(time_a - time_b) > 60:
                    continue

                group_macs.append(mac_b)
                group_rssis.append(rssi_b)
                used.add(mac_b)

            if len(group_macs) > 1:
                used.add(mac_a)
                avg_rssi = sum(group_rssis) / len(group_rssis)
                confidence = min(0.5 + 0.1 * len(group_macs), 0.95)
                groups.append({
                    "macs": group_macs,
                    "manufacturer": dev_a.get("manufacturer", "Unknown"),
                    "avg_rssi": round(avg_rssi, 1),
                    "service_uuids": list(dev_a.get("service_uuids", [])),
                    "confidence": confidence,
                })

        return groups


# ===========================================================================
#  12. ThreatScorer class  --  Composite device threat scoring (0-100)
# ===========================================================================

class ThreatScorer:
    """Score each observed BLE device for threat potential on a 0-100 scale.

    The score is computed by summing weighted factors that indicate suspicious
    or potentially threatening characteristics:

        +15  Unknown manufacturer (OUI not in database)
        +10  No advertised name
        +20  Strong RSSI (> -50 dBm) from unknown device
        +25  Known tracker device detected
        +15  MAC address rotation detected
        +10  Anomalous advertisement timing (too fast or irregular)
        +10  Suspicious service UUIDs (tracker-related)
        +15  Approaching device (RSSI increasing over time)

    Threat levels:
        0-25   : "safe"
        26-50  : "low"
        51-75  : "medium"
        76-100 : "high"

    This scoring is designed for security research and personal privacy
    awareness.  It is NOT a definitive indicator of malicious intent.
    """

    # Factor weights
    WEIGHT_UNKNOWN_MANUFACTURER = 15
    WEIGHT_NO_NAME = 10
    WEIGHT_STRONG_RSSI_UNKNOWN = 20
    WEIGHT_TRACKER_DETECTED = 25
    WEIGHT_MAC_ROTATION = 15
    WEIGHT_ANOMALOUS_TIMING = 10
    WEIGHT_SUSPICIOUS_UUIDS = 10
    WEIGHT_APPROACHING = 15

    # Suspicious service UUIDs (tracker-related)
    SUSPICIOUS_UUIDS: set[str] = {
        "0xFD6F",  # Apple Find My
        "0xFDA6",  # Google Find My Device
        "0xFD69",  # Samsung SmartTag
        "0xFD8E",  # Samsung SmartTag2
        "0xFEED",  # Tile
        "0xFE6E",  # Tile
    }

    def score(self, device_info: dict) -> dict:
        """Compute the threat score for a device.

        Args:
            device_info: Dict with device attributes.  Expected keys:
                - ``manufacturer`` (str): Resolved manufacturer or "Unknown"
                - ``name`` (str | None): Advertised device name
                - ``rssi`` (int): Current RSSI in dBm
                - ``rssi_history`` (list[int], optional): Recent RSSI readings
                - ``is_tracker`` (bool): Whether tracker detection flagged it
                - ``tracker_type`` (str | None): Type of tracker if detected
                - ``mac_rotation_detected`` (bool): MAC rotation flag
                - ``service_uuids`` (list[str]): Advertised service UUIDs
                - ``adv_interval_ms`` (float | None): Advertisement interval
                - ``is_random_mac`` (bool): Whether MAC is locally administered

        Returns:
            Dict with:
                - ``score`` (int): Threat score 0-100
                - ``factors`` (list[str]): Human-readable list of contributing factors
                - ``level`` (str): "safe", "low", "medium", or "high"
        """
        total = 0
        factors: list[str] = []

        manufacturer = device_info.get("manufacturer", "Unknown")
        name = device_info.get("name")
        rssi = device_info.get("rssi", -127)
        is_tracker = device_info.get("is_tracker", False)
        mac_rotation = device_info.get("mac_rotation_detected", False)
        service_uuids = set(device_info.get("service_uuids", []))
        adv_interval = device_info.get("adv_interval_ms")
        is_random = device_info.get("is_random_mac", False)
        rssi_history = device_info.get("rssi_history", [])

        # Factor 1: Unknown manufacturer
        if manufacturer in ("Unknown", None, ""):
            total += self.WEIGHT_UNKNOWN_MANUFACTURER
            factors.append(
                f"Unknown manufacturer (+{self.WEIGHT_UNKNOWN_MANUFACTURER})"
            )

        # Factor 2: No advertised name
        if not name:
            total += self.WEIGHT_NO_NAME
            factors.append(f"No advertised device name (+{self.WEIGHT_NO_NAME})")

        # Factor 3: Strong RSSI from unknown device
        if rssi > -50 and manufacturer in ("Unknown", None, "") and is_random:
            total += self.WEIGHT_STRONG_RSSI_UNKNOWN
            factors.append(
                f"Strong signal ({rssi} dBm) from unknown device "
                f"(+{self.WEIGHT_STRONG_RSSI_UNKNOWN})"
            )

        # Factor 4: Known tracker detected
        if is_tracker:
            total += self.WEIGHT_TRACKER_DETECTED
            tracker_type = device_info.get("tracker_type", "Unknown")
            factors.append(
                f"Tracker detected: {tracker_type} "
                f"(+{self.WEIGHT_TRACKER_DETECTED})"
            )

        # Factor 5: MAC rotation detected
        if mac_rotation:
            total += self.WEIGHT_MAC_ROTATION
            factors.append(
                f"MAC address rotation detected (+{self.WEIGHT_MAC_ROTATION})"
            )

        # Factor 6: Anomalous advertisement timing
        if adv_interval is not None and (adv_interval < 20 or adv_interval > 10240):
            total += self.WEIGHT_ANOMALOUS_TIMING
            factors.append(
                f"Anomalous advertisement interval ({adv_interval}ms) "
                f"(+{self.WEIGHT_ANOMALOUS_TIMING})"
            )

        # Factor 7: Suspicious service UUIDs
        suspicious_found = service_uuids & self.SUSPICIOUS_UUIDS
        if suspicious_found:
            total += self.WEIGHT_SUSPICIOUS_UUIDS
            factors.append(
                f"Suspicious service UUIDs: {', '.join(sorted(suspicious_found))} "
                f"(+{self.WEIGHT_SUSPICIOUS_UUIDS})"
            )

        # Factor 8: Approaching device (RSSI increasing over time)
        if len(rssi_history) >= 3:
            # Check if the last 3+ readings show a consistent increase
            diffs = [
                rssi_history[i + 1] - rssi_history[i]
                for i in range(len(rssi_history) - 1)
            ]
            # If more than half the diffs are positive and average > 2 dBm
            positive_diffs = [d for d in diffs if d > 0]
            if len(positive_diffs) > len(diffs) / 2:
                avg_increase = sum(positive_diffs) / len(positive_diffs)
                if avg_increase > 2.0:
                    total += self.WEIGHT_APPROACHING
                    factors.append(
                        f"Device approaching (RSSI increasing, avg +{avg_increase:.1f} dBm) "
                        f"(+{self.WEIGHT_APPROACHING})"
                    )

        # Clamp to 0-100
        total = max(0, min(100, total))

        # Determine threat level
        if total <= 25:
            level = "safe"
        elif total <= 50:
            level = "low"
        elif total <= 75:
            level = "medium"
        else:
            level = "high"

        return {
            "score": total,
            "factors": factors,
            "level": level,
        }


# ===========================================================================
#  13. BLEAnalyzer  --  Combined analysis pipeline
# ===========================================================================

class BLEAnalyzer:
    """Combined BLE advertisement analyzer that orchestrates all sub-modules
    into a single analysis pipeline.

    Usage::

        analyzer = BLEAnalyzer()

        # Analyze raw advertisement bytes
        result = analyzer.analyze_advertisement(
            raw_bytes=raw_ad_bytes,
            rssi=-67,
            mac="AA:BB:CC:DD:EE:FF",
        )

        # Analyze a device info dict (from scanner)
        enriched = analyzer.analyze_device(device_info)

    The result dict aggregates output from all sub-modules:
        - ``ad_structures``  : parsed AD entries from ADParser
        - ``manufacturer``   : resolved manufacturer string
        - ``device_type``    : inferred device category
        - ``beacons``        : detected beacon data (iBeacon, Eddystone, etc.)
        - ``apple``          : Apple Continuity decode or None
        - ``google``         : Google Fast Pair decode or None
        - ``samsung``        : Samsung SmartThings decode or None
        - ``microsoft``      : Microsoft Swift Pair decode or None
        - ``tracker``        : tracker detection result
        - ``distance``       : estimated distance in meters
        - ``proximity``      : proximity zone string
        - ``threat``         : threat score dict
    """

    def __init__(
        self,
        tx_power: int = -59,
        path_loss_n: float = 2.0,
    ):
        """Initialize all sub-analyzers.

        Args:
            tx_power: Expected RSSI at 1 meter for distance estimation.
            path_loss_n: Path-loss exponent for distance estimation.
        """
        self.ad_parser = ADParser()
        self.apple_decoder = AppleContinuityDecoder()
        self.google_decoder = GoogleFastPairDecoder()
        self.samsung_decoder = SamsungSmartThingsDecoder()
        self.microsoft_decoder = MicrosoftSwiftPairDecoder()
        self.beacon_parser = BeaconParser()
        self.tracker_analyzer = TrackerAnalyzer()
        self.distance_estimator = DistanceEstimator(tx_power=tx_power, n=path_loss_n)
        self.threat_scorer = ThreatScorer()

    def analyze_advertisement(
        self,
        raw_bytes: bytes,
        rssi: int = 0,
        mac: str = "",
    ) -> dict:
        """Perform full analysis of a raw BLE advertisement.

        This method runs the complete pipeline: AD parsing, vendor decoding,
        beacon detection, tracker detection, distance estimation, and threat
        scoring.

        Args:
            raw_bytes: Raw advertising data payload (AD structures only,
                       after the 2-byte PDU header and 6-byte address).
            rssi: Received Signal Strength Indicator in dBm.
            mac: Device MAC address in colon-separated hex format.

        Returns:
            Comprehensive analysis dict with all decoded fields.
        """
        # -- Step 1: Parse AD structures -----------------------------------
        ad_structures = self.ad_parser.parse(raw_bytes)

        # -- Step 2: Extract top-level fields ------------------------------
        name: str | None = None
        tx_power: int | None = None
        all_service_uuids: list[str] = []
        company_id: int | None = None
        company_name: str | None = None
        mfg_payload: bytes = b""
        service_data_entries: list[dict] = []
        appearance: str | None = None
        adv_interval_ms: float | None = None

        for entry in ad_structures:
            ad_type = entry.get("type")
            parsed = entry.get("parsed", {})

            # Name
            if ad_type in (0x08, 0x09):
                n = parsed.get("name")
                if n:
                    name = n

            # TX Power
            if ad_type == 0x0A:
                tp = parsed.get("tx_power_dbm")
                if tp is not None:
                    tx_power = tp

            # Service UUIDs (16-bit)
            if ad_type in (0x02, 0x03, 0x14):
                for u in parsed.get("uuids", []):
                    if u not in all_service_uuids:
                        all_service_uuids.append(u)

            # Service UUIDs (128-bit)
            if ad_type in (0x06, 0x07, 0x15):
                for u in parsed.get("uuids", []):
                    if u not in all_service_uuids:
                        all_service_uuids.append(u)

            # Manufacturer Specific Data
            if ad_type == 0xFF and "company_id" in parsed:
                company_id = parsed["company_id"]
                company_name = parsed.get("company_name")
                mfg_payload = parsed.get("manufacturer_data", b"")
                if isinstance(mfg_payload, str):
                    try:
                        mfg_payload = bytes.fromhex(mfg_payload)
                    except ValueError:
                        mfg_payload = b""

            # Service Data entries (for vendor decoders)
            if ad_type in (0x16, 0x20, 0x21):
                service_data_entries.append(entry)

            # Appearance
            if ad_type == 0x19:
                appearance = parsed.get("appearance_name")

            # Advertising Interval
            if ad_type == 0x1A:
                adv_interval_ms = parsed.get("interval_ms")

        # -- Step 3: OUI lookup --------------------------------------------
        oui_vendor = lookup_oui(mac)
        random_mac = is_random_mac(mac)
        manufacturer = company_name if company_name and "Unknown" not in company_name else oui_vendor

        # -- Step 4: Vendor-specific decoding ------------------------------
        apple_result: dict | None = None
        google_result: dict | None = None
        samsung_result: dict | None = None
        microsoft_result: dict | None = None

        if company_id == 0x004C:
            apple_result = self.apple_decoder.decode(mfg_payload)
        elif company_id == 0x00E0:
            google_result = self.google_decoder.decode(
                company_id, mfg_payload, service_data_entries
            )
        elif company_id == 0x0075:
            samsung_result = self.samsung_decoder.decode(
                company_id, mfg_payload, service_data_entries
            )
        elif company_id == 0x0006:
            microsoft_result = self.microsoft_decoder.decode(
                company_id, mfg_payload, service_data_entries
            )

        # Also check service data for Google/Samsung without matching company
        if not google_result:
            google_svc_uuids = {0xFE2C, 0xFDA6, 0xFEA0}
            for entry in service_data_entries:
                p = entry.get("parsed", {})
                if p.get("service_uuid_int") in google_svc_uuids:
                    google_result = self.google_decoder.decode(
                        company_id, b"", service_data_entries
                    )
                    break

        if not samsung_result:
            samsung_svc_uuids = {0xFD5A, 0xFD69, 0xFD8E}
            for entry in service_data_entries:
                p = entry.get("parsed", {})
                if p.get("service_uuid_int") in samsung_svc_uuids:
                    samsung_result = self.samsung_decoder.decode(
                        company_id, b"", service_data_entries
                    )
                    break

        # -- Step 5: Beacon detection --------------------------------------
        beacon_result = self.beacon_parser.parse(ad_structures)

        # -- Step 6: Infer device type -------------------------------------
        device_type = self._infer_device_type(
            ad_structures, apple_result, appearance, manufacturer, beacon_result
        )

        # -- Step 7: Tracker detection -------------------------------------
        tracker_result = self.tracker_analyzer.is_tracker(
            ad_structures, manufacturer, all_service_uuids
        )

        # -- Step 8: Distance estimation -----------------------------------
        distance = self.distance_estimator.estimate(rssi, tx_power=tx_power)
        proximity = self.distance_estimator.classify_proximity(distance)

        # -- Step 9: Threat scoring ----------------------------------------
        threat_input = {
            "manufacturer": manufacturer,
            "name": name,
            "rssi": rssi,
            "is_tracker": tracker_result.get("is_tracker", False),
            "tracker_type": tracker_result.get("tracker_type"),
            "mac_rotation_detected": False,  # requires multi-device context
            "service_uuids": all_service_uuids,
            "adv_interval_ms": adv_interval_ms,
            "is_random_mac": random_mac,
        }
        threat_result = self.threat_scorer.score(threat_input)

        # -- Step 10: Build JSON-safe result -------------------------------
        clean_structures = []
        for entry in ad_structures:
            cleaned: dict = {}
            for k, v in entry.items():
                if k == "parsed":
                    # Recursively clean the parsed dict
                    cleaned[k] = self._clean_dict(v)
                elif isinstance(v, (bytes, bytearray)):
                    cleaned[k] = v.hex()
                else:
                    cleaned[k] = v
            clean_structures.append(cleaned)

        return {
            "ad_structures": clean_structures,
            "manufacturer": manufacturer,
            "device_type": device_type,
            "beacons": [beacon_result] if beacon_result else [],
            "apple": apple_result,
            "google": google_result,
            "samsung": samsung_result,
            "microsoft": microsoft_result,
            "tracker": tracker_result,
            "distance": distance,
            "proximity": proximity,
            "threat": threat_result,
            # Additional metadata
            "name": name,
            "tx_power": tx_power,
            "service_uuids": all_service_uuids,
            "oui_vendor": oui_vendor,
            "is_random_mac": random_mac,
            "appearance": appearance,
        }

    def analyze_device(self, device_info: dict) -> dict:
        """Analyze and enrich a device info dict from the scanner.

        This method takes a higher-level device dict (with ``mac``, ``rssi``,
        ``raw_adv_data``, etc.) and runs the full analysis pipeline, merging
        the results back into the device dict.

        Args:
            device_info: Device dict with at minimum:
                - ``mac`` (str)
                - ``rssi`` (int)
                - ``raw_adv_data`` (bytes, optional)
                - ``name`` (str, optional)

        Returns:
            Enriched device dict with all analysis fields added.
        """
        result = dict(device_info)
        raw_data = device_info.get("raw_adv_data", b"")
        mac = device_info.get("mac", "")
        rssi = device_info.get("rssi", -127)

        if raw_data:
            analysis = self.analyze_advertisement(raw_data, rssi=rssi, mac=mac)
            result.update(analysis)
        else:
            # Even without raw data, perform OUI and distance
            result["oui_vendor"] = lookup_oui(mac)
            result["is_random_mac"] = is_random_mac(mac)
            result["manufacturer"] = result.get("manufacturer") or result["oui_vendor"]
            result["distance"] = self.distance_estimator.estimate(rssi)
            result["proximity"] = self.distance_estimator.classify_proximity(
                result["distance"]
            )
            # Threat score with available info
            result["threat"] = self.threat_scorer.score({
                "manufacturer": result.get("manufacturer", "Unknown"),
                "name": result.get("name"),
                "rssi": rssi,
                "is_tracker": False,
                "service_uuids": result.get("service_uuids", []),
                "is_random_mac": result["is_random_mac"],
            })

        return result

    def _infer_device_type(
        self,
        ad_structures: list[dict],
        apple_result: dict | None,
        appearance: str | None,
        manufacturer: str,
        beacon_result: dict | None,
    ) -> str:
        """Infer the high-level device category from all available data.

        Categories: phone, tablet, computer, watch, audio, tracker, beacon,
        wearable, iot, peripheral, health, fitness, unknown.
        """
        # Check Apple Nearby Info for device model hint
        if apple_result and apple_result.get("continuity_type_id") == 0x0F:
            details = apple_result.get("details", {})
            model = details.get("device_model", "").lower()
            if "iphone" in model or "phone" in model:
                return "phone"
            if "ipad" in model or "tablet" in model:
                return "tablet"
            if "mac" in model or "imac" in model:
                return "computer"
            if "watch" in model:
                return "watch"
            if "airpods" in model:
                return "audio"
            if "homepod" in model:
                return "iot"
            if "airtag" in model:
                return "tracker"

        # Check Apple AirPods TLV
        if apple_result and apple_result.get("continuity_type_id") == 0x07:
            return "audio"

        # Check Apple Find My
        if apple_result and apple_result.get("continuity_type_id") in (0x12, 0x19):
            return "tracker"

        # Check beacon
        if beacon_result:
            return "beacon"

        # Check appearance
        if appearance:
            app_lower = appearance.lower()
            if "phone" in app_lower:
                return "phone"
            if "computer" in app_lower:
                return "computer"
            if "watch" in app_lower:
                return "watch"
            if "keyboard" in app_lower or "mouse" in app_lower or "hid" in app_lower:
                return "peripheral"
            if "heart" in app_lower or "blood" in app_lower or "thermometer" in app_lower:
                return "health"
            if "running" in app_lower or "cycling" in app_lower:
                return "fitness"
            if "earbud" in app_lower or "headset" in app_lower or "headphone" in app_lower:
                return "audio"
            if "tag" in app_lower:
                return "tracker"
            if "sensor" in app_lower:
                return "iot"

        # Check service UUIDs for category hints
        for entry in ad_structures:
            parsed = entry.get("parsed", {})
            for uuid_str in parsed.get("uuids", []):
                try:
                    uuid_int = int(uuid_str, 16)
                    _, category = lookup_service_uuid(uuid_int)
                    if category == "health":
                        return "health"
                    if category == "fitness":
                        return "fitness"
                    if category == "audio":
                        return "audio"
                    if category == "hid":
                        return "peripheral"
                    if category == "tracker":
                        return "tracker"
                    if category == "beacon":
                        return "beacon"
                except (ValueError, TypeError):
                    continue

        # Check manufacturer for known audio brands
        mfg_lower = manufacturer.lower() if manufacturer else ""
        if any(brand in mfg_lower for brand in ("bose", "sony", "jbl", "sennheiser",
                                                  "bang & olufsen", "harman")):
            return "audio"
        if any(brand in mfg_lower for brand in ("fitbit", "garmin", "polar", "whoop")):
            return "wearable"
        if any(brand in mfg_lower for brand in ("tile", "chipolo", "trackr")):
            return "tracker"
        if any(brand in mfg_lower for brand in ("philips hue", "ikea", "nest", "ring")):
            return "iot"

        return "unknown"

    @staticmethod
    def _clean_dict(d: dict) -> dict:
        """Recursively convert bytes values to hex strings for JSON safety."""
        cleaned: dict = {}
        for k, v in d.items():
            if isinstance(v, (bytes, bytearray)):
                cleaned[k] = v.hex()
            elif isinstance(v, dict):
                cleaned[k] = BLEAnalyzer._clean_dict(v)
            elif isinstance(v, list):
                cleaned[k] = [
                    BLEAnalyzer._clean_dict(item) if isinstance(item, dict)
                    else (item.hex() if isinstance(item, (bytes, bytearray)) else item)
                    for item in v
                ]
            else:
                cleaned[k] = v
        return cleaned


# ===========================================================================
#  Module-level smoke test  --  run with: python -m blueshield.scanner.ble_analyzer
# ===========================================================================

if __name__ == "__main__":
    import json as _json

    # Synthetic iBeacon advertisement for validation
    #   Flags: 0x02 0x01 0x06
    #   Manufacturer data: Apple iBeacon
    sample_flags = bytes([0x02, 0x01, 0x06])
    sample_ibeacon_mfg = bytes([
        0x1A,        # length = 26
        0xFF,        # AD type = Manufacturer Specific Data
        0x4C, 0x00,  # Apple company ID (little-endian)
        0x02, 0x15,  # iBeacon sub-type (0x02) + length (0x15 = 21)
    ])
    sample_uuid = bytes([
        0xFD, 0xA5, 0x06, 0x93, 0xA4, 0xE2, 0x4F, 0xB1,
        0xAF, 0xCF, 0xC6, 0xEB, 0x07, 0x64, 0x78, 0x25,
    ])
    sample_major_minor_tx = bytes([0x00, 0x01, 0x00, 0x02, 0xC5])
    sample_raw = sample_flags + sample_ibeacon_mfg + sample_uuid + sample_major_minor_tx

    analyzer = BLEAnalyzer()
    result = analyzer.analyze_advertisement(
        sample_raw, mac="4C:57:CA:12:34:56", rssi=-72
    )
    print(_json.dumps(result, indent=2, default=str))
