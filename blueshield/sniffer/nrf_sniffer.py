"""
nRF Sniffer Engine — BLE packet capture using nRF52840 dongle.

Implements the Nordic Semiconductor nRF Sniffer for Bluetooth LE serial
protocol (SLIP-framed, protocol version 3).  Works alongside the existing
Sniffle-based engine in sniffle_engine.py — this module targets the
nRF52840 dongle flashed with Nordic's sniffer firmware instead of the
TI CC1352/CC26x2.

Hardware: nRF52840 Dongle (PCA10059) on /dev/ttyACM0
Firmware: nRF Sniffer for Bluetooth LE v4.x (protocol v3)
Serial:   1 000 000 baud, 8N1, RTS/CTS hardware flow control

Packet types emitted:
  "adv"          — advertising PDU (ADV_IND, ADV_NONCONN_IND, etc.)
  "data"         — LL data PDU on a connection
  "connect"      — CONNECT_IND observed
  "disconnect"   — link-layer disconnect detected by firmware
"""

from __future__ import annotations

import logging
import os
import random
import struct
import threading
import time
from collections import deque
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# -- SLIP framing constants (Nordic variant, NOT RFC 1055) --------------------

SLIP_START     = 0xAB
SLIP_END       = 0xBC
SLIP_ESC       = 0xCD
SLIP_ESC_START = 0xAC
SLIP_ESC_END   = 0xBD
SLIP_ESC_ESC   = 0xCE


# -- Protocol v3 command / event IDs ------------------------------------------

CMD_REQ_FOLLOW     = 0x00
CMD_REQ_SCAN_CONT  = 0x07
CMD_GO_IDLE        = 0xFE
CMD_PING_REQ       = 0x0D

EVT_FOLLOW             = 0x01
EVT_PACKET_ADV_PDU     = 0x02
EVT_CONNECT            = 0x05
EVT_PACKET_DATA_PDU    = 0x06
EVT_DISCONNECT         = 0x09
EVT_PING_RESP          = 0x0E


# -- Protocol v3 header sizes ------------------------------------------------

PROTO_HDR_LEN   = 6    # payload_len(2) + proto_ver(1) + pkt_counter(2) + pkt_type(1)
BLE_HDR_LEN     = 10   # hdr_len(1) + flags(1) + channel(1) + rssi(1) + evt_counter(2) + timestamp(4)

PROTO_VERSION   = 3
BOARD_ID        = 0     # default board ID for commands


# -- ADV PDU type names -------------------------------------------------------

ADV_PDU_TYPES = {
    0x00: "ADV_IND",
    0x01: "ADV_DIRECT_IND",
    0x02: "ADV_NONCONN_IND",
    0x03: "SCAN_REQ",
    0x04: "SCAN_RSP",
    0x05: "CONNECT_IND",
    0x06: "ADV_SCAN_IND",
    0x07: "ADV_EXT_IND",
}


# -- Flag bit masks (from BLE header flags byte) -----------------------------

FLAG_CRC_OK      = 0x01
FLAG_DIRECTION   = 0x02   # 0 = master->slave, 1 = slave->master
FLAG_ENCRYPTED   = 0x04
FLAG_MIC_OK      = 0x08
FLAG_PHY_CODED   = 0x10   # 1 = coded PHY, 0 = 1M PHY
FLAG_ADDRESS_OK  = 0x20


# -- AD structure type names --------------------------------------------------

AD_TYPE_NAMES = {
    0x01: "Flags",
    0x02: "Incomplete List of 16-bit Service UUIDs",
    0x03: "Complete List of 16-bit Service UUIDs",
    0x04: "Incomplete List of 32-bit Service UUIDs",
    0x05: "Complete List of 32-bit Service UUIDs",
    0x06: "Incomplete List of 128-bit Service UUIDs",
    0x07: "Complete List of 128-bit Service UUIDs",
    0x08: "Shortened Local Name",
    0x09: "Complete Local Name",
    0x0A: "TX Power Level",
    0x0D: "Class of Device",
    0x0E: "Simple Pairing Hash C-192",
    0x0F: "Simple Pairing Randomizer R-192",
    0x10: "Device ID / Security Manager TK Value",
    0x11: "Security Manager OOB Flags",
    0x12: "Slave Connection Interval Range",
    0x14: "List of 16-bit Solicitation UUIDs",
    0x15: "List of 128-bit Solicitation UUIDs",
    0x16: "Service Data - 16-bit UUID",
    0x17: "Public Target Address",
    0x18: "Random Target Address",
    0x19: "Appearance",
    0x1A: "Advertising Interval",
    0x1B: "LE Bluetooth Device Address",
    0x1C: "LE Role",
    0x1F: "List of 32-bit Solicitation UUIDs",
    0x20: "Service Data - 32-bit UUID",
    0x21: "Service Data - 128-bit UUID",
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


# -- LL Control PDU opcodes ---------------------------------------------------

LL_OPCODES = {
    0x00: "LL_CONNECTION_UPDATE_IND",
    0x01: "LL_CHANNEL_MAP_IND",
    0x02: "LL_TERMINATE_IND",
    0x03: "LL_ENC_REQ",
    0x04: "LL_ENC_RSP",
    0x05: "LL_START_ENC_REQ",
    0x06: "LL_START_ENC_RSP",
    0x07: "LL_UNKNOWN_RSP",
    0x08: "LL_FEATURE_REQ",
    0x09: "LL_FEATURE_RSP",
    0x0A: "LL_PAUSE_ENC_REQ",
    0x0B: "LL_PAUSE_ENC_RSP",
    0x0C: "LL_VERSION_IND",
    0x0D: "LL_REJECT_IND",
    0x0E: "LL_SLAVE_FEATURE_REQ",
    0x0F: "LL_CONNECTION_PARAM_REQ",
    0x10: "LL_CONNECTION_PARAM_RSP",
    0x11: "LL_REJECT_EXT_IND",
    0x12: "LL_PHY_REQ",
    0x13: "LL_PHY_RSP",
    0x14: "LL_LENGTH_REQ",
    0x15: "LL_LENGTH_RSP",
    0x16: "LL_PING_REQ",
    0x17: "LL_PING_RSP",
    0x18: "LL_CTE_REQ",
    0x19: "LL_CTE_RSP",
    0x1A: "LL_PERIODIC_SYNC_IND",
    0x1B: "LL_CLOCK_ACCURACY_REQ",
    0x1C: "LL_CLOCK_ACCURACY_RSP",
    0x1D: "LL_CIS_REQ",
    0x1E: "LL_CIS_RSP",
    0x1F: "LL_CIS_IND",
    0x20: "LL_CIS_TERMINATE_IND",
    0x21: "LL_POWER_CONTROL_REQ",
    0x22: "LL_POWER_CONTROL_RSP",
    0x23: "LL_POWER_CHANGE_IND",
    0x24: "LL_SUBRATE_REQ",
    0x25: "LL_SUBRATE_IND",
}


# -- LLID definitions ---------------------------------------------------------

LLID_NAMES = {
    0b00: "Reserved",
    0b01: "LL Data PDU (continuation/empty)",
    0b10: "LL Data PDU (start/complete L2CAP)",
    0b11: "LL Control PDU",
}


# -- HCI error codes for LL_TERMINATE_IND ------------------------------------

HCI_ERROR_CODES = {
    0x00: "Success",
    0x05: "Authentication Failure",
    0x06: "PIN/Key Missing",
    0x07: "Memory Capacity Exceeded",
    0x08: "Connection Timeout",
    0x0A: "Connection Already Exists",
    0x0C: "Command Disallowed",
    0x12: "Invalid LMP/LL Parameters",
    0x13: "Remote User Terminated Connection",
    0x14: "Remote Device Terminated (Low Resources)",
    0x15: "Remote Device Terminated (Power Off)",
    0x16: "Connection Terminated By Local Host",
    0x1A: "Unsupported Remote Feature",
    0x1F: "Unspecified Error",
    0x22: "LMP/LL Response Timeout",
    0x23: "LMP/LL Error Transaction Collision",
    0x28: "Instant Passed",
    0x2A: "Different Transaction Collision",
    0x3B: "Unacceptable Connection Parameters",
    0x3E: "Connection Failed to be Established",
}


# -- BLE version numbers for LL_VERSION_IND ----------------------------------

BLE_VERSIONS = {
    0x06: "4.0",
    0x07: "4.1",
    0x08: "4.2",
    0x09: "5.0",
    0x0A: "5.1",
    0x0B: "5.2",
    0x0C: "5.3",
    0x0D: "5.4",
}


# -- Sleep Clock Accuracy (SCA) mapping ---------------------------------------

SCA_VALUES = {
    0: "251-500 ppm",
    1: "151-250 ppm",
    2: "101-150 ppm",
    3: "76-100 ppm",
    4: "51-75 ppm",
    5: "31-50 ppm",
    6: "21-30 ppm",
    7: "0-20 ppm",
}


# -- Bluetooth SIG Company Identifiers (subset) ------------------------------

COMPANY_IDS: Dict[int, str] = {
    0x0000: "Ericsson Technology Licensing",
    0x0001: "Nokia Mobile Phones",
    0x0002: "Intel Corp.",
    0x0003: "IBM Corp.",
    0x0004: "Toshiba Corp.",
    0x0006: "Microsoft",
    0x000A: "Qualcomm Technologies International",
    0x000D: "Texas Instruments",
    0x000F: "Broadcom",
    0x0010: "Mitel Semiconductor",
    0x0013: "Atmel Corp.",
    0x001D: "Qualcomm",
    0x0029: "Harman International",
    0x002C: "Bose Corp.",
    0x0031: "Sennheiser Communications",
    0x0038: "Samsung Semiconductor",
    0x003F: "Plantronics",
    0x0046: "Sony Ericsson",
    0x004C: "Apple, Inc.",
    0x004E: "Belkin International",
    0x0056: "Sony Corporation",
    0x0059: "Nordic Semiconductor ASA",
    0x005B: "Seiko Epson Corp.",
    0x0075: "Samsung Electronics",
    0x0078: "Nike, Inc.",
    0x0080: "GN Netcom A/S",
    0x0087: "Garmin International",
    0x008A: "LG Electronics",
    0x0094: "Beats Electronics",
    0x009E: "Bose Corporation",
    0x00A2: "Realtek Semiconductor Corp.",
    0x00D2: "Dialog Semiconductor B.V.",
    0x00E0: "Google LLC",
    0x00E5: "Polar Electro Oy",
    0x00E7: "Suunto Oy",
    0x00F0: "Cypress Semiconductor",
    0x0100: "Fitbit, Inc.",
    0x010F: "Huawei Technologies Co.",
    0x0112: "Amazon.com Services",
    0x0116: "Xiaomi Inc.",
    0x011B: "OnePlus Electronics",
    0x0131: "Tile, Inc.",
    0x0157: "Roku, Inc.",
    0x015D: "Silicon Laboratories",
    0x0171: "Amazon Lab126",
    0x018B: "Sonos, Inc.",
    0x01C7: "Motorola Mobility LLC",
    0x01D5: "Logitech International SA",
    0x01DA: "JBL (Harman)",
    0x0235: "Espressif Systems (Shanghai) Co.",
    0x024F: "Meta Platforms, Inc.",
    0x0269: "Shenzhen Goodix Technology Co.",
    0x026A: "Qualcomm Technologies Inc.",
    0x0271: "Wyze Labs, Inc.",
    0x02A5: "OPPO Guangdong Mobile Telecom",
    0x0310: "Peloton Interactive",
    0x0376: "Ring LLC",
    0x038F: "Govee Moments",
    0x0499: "Ruuvi Innovations Oy",
    0x0660: "Tuya Global Inc.",
    0x0822: "Skullcandy",
    0x08FC: "Shenzhen Jieli Technology",
    0x09D0: "Jabra (GN Audio)",
    0x0A69: "Nothing Technology Limited",
}


# -- BLE Appearance Values (GAP Assigned Numbers) ----------------------------

APPEARANCE_VALUES: Dict[int, str] = {
    0x0000: "Unknown",
    0x0040: "Generic Phone",
    0x0041: "Phone - Smartphone",
    0x0042: "Phone - Feature Phone",
    0x0043: "Phone - Media Player",
    0x0080: "Generic Computer",
    0x0081: "Desktop Workstation",
    0x0082: "Server-class Computer",
    0x0083: "Laptop",
    0x0084: "Handheld PC/PDA",
    0x0085: "Palm-size PC/PDA",
    0x0086: "Wearable Computer (Watch-size)",
    0x0087: "Tablet",
    0x00C0: "Generic Watch",
    0x00C1: "Sports Watch",
    0x00C2: "Smartwatch",
    0x0100: "Generic Clock",
    0x0140: "Generic Display",
    0x0180: "Generic Remote Control",
    0x01C0: "Generic Eye-glasses",
    0x0200: "Generic Tag",
    0x0240: "Generic Keyring",
    0x0280: "Generic Media Player",
    0x02C0: "Generic Barcode Scanner",
    0x0300: "Generic Thermometer",
    0x0301: "Ear Thermometer",
    0x0340: "Generic Heart Rate Sensor",
    0x0341: "Heart Rate Belt",
    0x0380: "Generic Blood Pressure",
    0x0381: "Blood Pressure - Arm",
    0x0382: "Blood Pressure - Wrist",
    0x03C0: "Generic HID",
    0x03C1: "Keyboard",
    0x03C2: "Mouse",
    0x03C3: "Joystick",
    0x03C4: "Gamepad",
    0x03C5: "Digitizer Tablet",
    0x03C6: "Card Reader",
    0x03C7: "Digital Pen",
    0x03C8: "Barcode Scanner",
    0x03C9: "Touchpad",
    0x03CA: "Presentation Remote",
    0x0400: "Generic Glucose Meter",
    0x0440: "Generic Running Walking Sensor",
    0x0441: "In-Shoe Running Walking Sensor",
    0x0442: "On-Shoe Running Walking Sensor",
    0x0443: "On-Hip Running Walking Sensor",
    0x0480: "Generic Cycling",
    0x0481: "Cycling Computer",
    0x0482: "Cycling Speed Sensor",
    0x0483: "Cycling Cadence Sensor",
    0x0484: "Cycling Power Sensor",
    0x0485: "Cycling Speed and Cadence Sensor",
    0x04C0: "Generic Control Device",
    0x04C1: "Switch",
    0x04C2: "Multi-switch",
    0x04C3: "Button",
    0x04C4: "Slider",
    0x0500: "Generic Network Device",
    0x0501: "Access Point",
    0x0540: "Generic Sensor",
    0x0541: "Motion Sensor",
    0x0542: "Air Quality Sensor",
    0x0543: "Temperature Sensor",
    0x0544: "Humidity Sensor",
    0x0545: "Leak Sensor",
    0x0546: "Smoke Sensor",
    0x0547: "Occupancy Sensor",
    0x0548: "Contact Sensor",
    0x0549: "Carbon Monoxide Sensor",
    0x054A: "Carbon Dioxide Sensor",
    0x054B: "Ambient Light Sensor",
    0x054C: "Energy Sensor",
    0x054D: "Color Light Sensor",
    0x054E: "Rain Sensor",
    0x054F: "Fire Sensor",
    0x0550: "Wind Sensor",
    0x0551: "Proximity Sensor",
    0x0580: "Generic Light Fixture",
    0x0581: "Wall Light",
    0x0582: "Ceiling Light",
    0x0583: "Floor Light",
    0x05C0: "Generic Fan",
    0x05C1: "Ceiling Fan",
    0x05C2: "Axial Fan",
    0x0600: "Generic HVAC",
    0x0601: "Thermostat",
    0x0640: "Generic Air Conditioning",
    0x0680: "Generic Humidifier",
    0x06C0: "Generic Heating",
    0x06C1: "Radiator",
    0x06C2: "Boiler",
    0x0700: "Generic Access Control",
    0x0701: "Access Door",
    0x0702: "Garage Door",
    0x0740: "Generic Motorized Device",
    0x0741: "Motorized Gate",
    0x0780: "Generic Power Device",
    0x0781: "Power Outlet",
    0x0782: "Power Strip",
    0x07C0: "Generic Light Source",
    0x0840: "Generic Window Covering",
    0x0841: "Window Shades",
    0x0842: "Window Blinds",
    0x0880: "Generic Audio Sink",
    0x0881: "Standalone Speaker",
    0x0882: "Soundbar",
    0x0883: "Bookshelf Speaker",
    0x08C0: "Generic Audio Source",
    0x08C1: "Microphone",
    0x08C2: "Alarm",
    0x0900: "Generic Motorized Vehicle",
    0x0940: "Generic Domestic Appliance",
    0x0941: "Refrigerator",
    0x0942: "Freezer",
    0x0943: "Oven",
    0x0944: "Microwave",
    0x0945: "Toaster",
    0x0946: "Washing Machine",
    0x0947: "Dryer",
    0x0948: "Coffee Maker",
    0x0949: "Clothes Iron",
    0x094A: "Curling Iron",
    0x094B: "Hair Dryer",
    0x094C: "Vacuum Cleaner",
    0x094D: "Robotic Vacuum Cleaner",
    0x0980: "Generic Wearable Audio Device",
    0x0981: "Earbud",
    0x0982: "Headset",
    0x0983: "Headphones",
    0x0984: "Neck Band",
    0x0A41: "Personal e-Mobility Device",
    0x0A42: "Electric Scooter",
    0x0A43: "Self-balancing Device",
}


# =============================================================================
#  NrfSniffer -- real hardware driver
# =============================================================================

class NrfSniffer:
    """
    BLE sniffer driver for the nRF52840 dongle with Nordic sniffer firmware.

    Usage::

        sniffer = NrfSniffer(port="/dev/ttyACM0")
        sniffer.open()
        sniffer.start_scan()
        time.sleep(10)
        for pkt in sniffer.get_packets():
            print(pkt)
        sniffer.stop_scan()
        sniffer.close()
    """

    def __init__(self, port: str = "/dev/ttyACM0", baudrate: int = 1_000_000):
        self.port      = port
        self.baudrate  = baudrate
        self._serial   = None          # serial.Serial instance
        self._running  = False
        self._thread: Optional[threading.Thread] = None

        # Thread-safe packet buffer
        self._lock     = threading.Lock()
        self._packets: List[dict]  = []

        # Discovered devices: MAC -> {address, name, rssi, last_seen, adv_count, ...}
        self._devices: Dict[str, dict] = {}

        # Observed connections: access_address -> {central, peripheral, ...}
        self._connections: Dict[int, dict] = {}

        # Internal counters
        self._pkt_counter = 0
        self._rx_buf      = bytearray()

        # Statistics tracking
        self._stat_total    = 0
        self._stat_by_type: Dict[str, int] = {"adv": 0, "data": 0, "connect": 0, "disconnect": 0}
        self._stat_channel: Dict[int, int] = {37: 0, 38: 0, 39: 0}
        self._stat_timestamps: deque = deque(maxlen=500)  # for PPS calculation
        self._start_time: float = 0.0

    # -- serial port management -----------------------------------------------

    def open(self) -> None:
        """Open the serial port to the nRF52840 dongle."""
        import serial  # type: ignore

        if self._serial and self._serial.is_open:
            return

        self._serial = serial.Serial(
            port=self.port,
            baudrate=self.baudrate,
            rtscts=True,           # hardware flow control
            timeout=0.1,           # non-blocking reads with short timeout
        )
        self._rx_buf.clear()
        self._start_time = time.monotonic()
        logger.info("nRF Sniffer opened on %s @ %d baud", self.port, self.baudrate)

    def close(self) -> None:
        """Stop any active scan and close the serial port."""
        if self._running:
            self.stop_scan()
        if self._serial and self._serial.is_open:
            self._serial.close()
            logger.info("nRF Sniffer serial port closed")
        self._serial = None

    # -- scanning -------------------------------------------------------------

    def start_scan(self) -> None:
        """Send REQ_SCAN_CONT and start the background reader thread."""
        if self._running:
            return
        if not self._serial or not self._serial.is_open:
            raise RuntimeError("Serial port not open -- call open() first")

        self._running = True
        if self._start_time == 0.0:
            self._start_time = time.monotonic()

        # Issue scan command with flags byte (required by firmware v4.x)
        # flags: bit0=findScanRsp, bit1=findAux, bit2=scanCoded
        scan_flags = bytes([0x00])
        cmd = self._build_command(CMD_REQ_SCAN_CONT, scan_flags)
        self._serial.write(self._slip_encode(cmd))
        logger.info("Scan started (REQ_SCAN_CONT, flags=0x00)")

        self._thread = threading.Thread(
            target=self._reader_thread,
            daemon=True,
            name="NrfSnifferReader",
        )
        self._thread.start()

    def stop_scan(self) -> None:
        """Send GO_IDLE and stop the reader thread."""
        self._running = False
        if self._serial and self._serial.is_open:
            try:
                cmd = self._build_command(CMD_GO_IDLE)
                self._serial.write(self._slip_encode(cmd))
                logger.info("Scan stopped (GO_IDLE)")
            except Exception as exc:
                logger.warning("Could not send GO_IDLE: %s", exc)
        if self._thread:
            self._thread.join(timeout=2.0)
            self._thread = None

    def follow_device(self, address: str) -> None:
        """
        Send REQ_FOLLOW to track a specific BLE device by MAC address.

        Args:
            address: BLE MAC like "AA:BB:CC:DD:EE:FF".
        """
        if not self._serial or not self._serial.is_open:
            raise RuntimeError("Serial port not open -- call open() first")

        # Convert MAC string to 6 bytes (LE byte order for the firmware)
        try:
            octets = [int(b, 16) for b in address.split(":")]
            if len(octets) != 6:
                raise ValueError("MAC must have 6 octets")
            mac_bytes = bytes(reversed(octets))  # firmware expects LE order
        except Exception as exc:
            raise ValueError(f"Invalid BLE MAC address '{address}': {exc}") from exc

        # Payload: address(6, LE) + flags(1)
        # flags: bit0=followOnlyAdv, bit1=followOnlyLegacy, bit2=followCoded
        payload = mac_bytes + bytes([0x00])
        cmd = self._build_command(CMD_REQ_FOLLOW, payload)
        self._serial.write(self._slip_encode(cmd))
        logger.info("Following device %s", address)

    # -- data access (thread-safe) --------------------------------------------

    def get_packets(self, clear: bool = True) -> List[dict]:
        """
        Return all captured packets.

        Args:
            clear: If True (default), the internal buffer is cleared after
                   the snapshot is taken.
        """
        with self._lock:
            snapshot = list(self._packets)
            if clear:
                self._packets.clear()
        return snapshot

    def get_devices(self) -> List[dict]:
        """Return discovered devices sorted by RSSI (strongest first)."""
        with self._lock:
            devs = list(self._devices.values())
        devs.sort(key=lambda d: d["rssi"], reverse=True)
        return devs

    def get_connections(self) -> List[dict]:
        """Return observed BLE connections."""
        with self._lock:
            return list(self._connections.values())

    def get_statistics(self) -> dict:
        """Return sniffer statistics."""
        with self._lock:
            now = time.monotonic()
            # Packets per second: count timestamps in last 5 seconds
            cutoff = now - 5.0
            recent = sum(1 for ts in self._stat_timestamps if ts >= cutoff)
            pps = recent / 5.0 if self._start_time > 0 else 0.0

            active_conns = sum(
                1 for c in self._connections.values() if c.get("end_time") is None
            )

            uptime = now - self._start_time if self._start_time > 0 else 0.0

            return {
                "total_packets": self._stat_total,
                "packets_by_type": dict(self._stat_by_type),
                "packets_per_second": round(pps, 2),
                "unique_devices": len(self._devices),
                "active_connections": active_conns,
                "channel_distribution": dict(self._stat_channel),
                "uptime_seconds": round(uptime, 2),
            }

    def ping(self) -> bool:
        """
        Send PING_REQ to the firmware and wait for PING_RESP.

        Returns True if the dongle answers within 1 second.
        """
        if not self._serial or not self._serial.is_open:
            return False

        cmd = self._build_command(CMD_PING_REQ)
        try:
            self._serial.write(self._slip_encode(cmd))
        except Exception:
            return False

        # Wait for a PING_RESP (crude but sufficient for a health check)
        deadline = time.monotonic() + 1.0
        while time.monotonic() < deadline:
            try:
                chunk = self._serial.read(256)
                if not chunk:
                    continue
                self._rx_buf.extend(chunk)
                frames = self._extract_slip_frames()
                for frame in frames:
                    decoded = self._slip_decode(frame)
                    if len(decoded) >= PROTO_HDR_LEN:
                        pkt_type = decoded[5]   # offset 5 in 6-byte header
                        if pkt_type == EVT_PING_RESP:
                            return True
            except Exception:
                return False
        return False

    # -- background reader ----------------------------------------------------

    def _reader_thread(self) -> None:
        """Continuously read serial data, decode SLIP frames, parse packets."""
        while self._running:
            try:
                if not self._serial or not self._serial.is_open:
                    logger.error("Serial port lost -- stopping reader")
                    break

                chunk = self._serial.read(4096)
                if not chunk:
                    continue

                self._rx_buf.extend(chunk)
                frames = self._extract_slip_frames()
                for frame in frames:
                    decoded = self._slip_decode(frame)
                    pkt = self._parse_packet(decoded)
                    if pkt:
                        with self._lock:
                            self._packets.append(pkt)
                            # Cap buffer at 5000 packets
                            if len(self._packets) > 5000:
                                self._packets = self._packets[-5000:]
                            self._pkt_counter += 1
                            self._update_device_table(pkt)
                            self._update_connection_table(pkt)
                            # Update statistics
                            self._stat_total += 1
                            ptype = pkt.get("type", "")
                            if ptype in self._stat_by_type:
                                self._stat_by_type[ptype] += 1
                            ch = pkt.get("channel")
                            if ch in self._stat_channel:
                                self._stat_channel[ch] += 1
                            self._stat_timestamps.append(time.monotonic())

            except Exception as exc:
                logger.error("Reader thread error: %s", exc)
                # Brief pause to avoid spinning on persistent errors
                time.sleep(0.1)

        logger.debug("Reader thread exited")

    def _extract_slip_frames(self) -> List[bytearray]:
        """
        Pull complete SLIP frames out of the receive buffer.

        Each frame is delimited by SLIP_START ... SLIP_END.  Incomplete
        trailing data is left in self._rx_buf for the next read cycle.
        """
        frames: List[bytearray] = []
        while True:
            # Find start marker
            start_idx = self._rx_buf.find(bytes([SLIP_START]))
            if start_idx == -1:
                self._rx_buf.clear()
                break

            # Discard garbage before start
            if start_idx > 0:
                del self._rx_buf[:start_idx]

            # Find end marker after start
            end_idx = self._rx_buf.find(bytes([SLIP_END]), 1)
            if end_idx == -1:
                break   # incomplete frame, wait for more data

            # Extract frame content (between start and end markers, exclusive)
            frame = bytearray(self._rx_buf[1:end_idx])
            frames.append(frame)
            del self._rx_buf[:end_idx + 1]

        return frames

    # -- SLIP encoding / decoding ---------------------------------------------

    @staticmethod
    def _slip_encode(data: bytes) -> bytes:
        """
        Encode a raw command into a SLIP frame.

        Nordic variant: START=0xAB, END=0xBC, ESC=0xCD.
        """
        out = bytearray([SLIP_START])
        for b in data:
            if b == SLIP_START:
                out.extend([SLIP_ESC, SLIP_ESC_START])
            elif b == SLIP_END:
                out.extend([SLIP_ESC, SLIP_ESC_END])
            elif b == SLIP_ESC:
                out.extend([SLIP_ESC, SLIP_ESC_ESC])
            else:
                out.append(b)
        out.append(SLIP_END)
        return bytes(out)

    @staticmethod
    def _slip_decode(data: bytes) -> bytes:
        """
        Decode a SLIP frame payload (markers already stripped).

        Reverses the ESC sequences back to their original byte values.
        """
        out = bytearray()
        i = 0
        while i < len(data):
            b = data[i]
            if b == SLIP_ESC and i + 1 < len(data):
                nxt = data[i + 1]
                if nxt == SLIP_ESC_START:
                    out.append(SLIP_START)
                elif nxt == SLIP_ESC_END:
                    out.append(SLIP_END)
                elif nxt == SLIP_ESC_ESC:
                    out.append(SLIP_ESC)
                else:
                    # Unknown escape -- pass through as-is
                    out.append(b)
                    out.append(nxt)
                i += 2
            else:
                out.append(b)
                i += 1
        return bytes(out)

    # -- command building -----------------------------------------------------

    def _build_command(self, cmd_id: int, payload: bytes = b"") -> bytes:
        """
        Build a command packet for the nRF Sniffer firmware.

        The firmware expects commands in protocol v1 format even though
        it replies with v3 responses.

        v1 command header (6 bytes):
            header_length (1)  -- always 6
            payload_len   (1)  -- single byte, length of payload only
            proto_ver     (1)  -- 1 (PROTOVER_V1)
            pkt_counter   (2)  -- LE, rolling counter
            pkt_type      (1)  -- command ID

        Followed by optional payload bytes.
        """
        counter = self._pkt_counter & 0xFFFF
        hdr = bytes([
            PROTO_HDR_LEN,      # header_length = 6
            len(payload),       # payload length (1 byte)
            1,                  # PROTOVER_V1
            counter & 0xFF,
            (counter >> 8) & 0xFF,
            cmd_id,
        ])
        self._pkt_counter += 1
        return hdr + payload

    # -- packet parsing -------------------------------------------------------

    def _parse_packet(self, data: bytes) -> Optional[dict]:
        """
        Parse a protocol v3 event packet received from the dongle.

        Returns a dict with packet fields, or None if the data cannot be
        parsed (wrong version, too short, unknown event, etc.).
        """
        if len(data) < PROTO_HDR_LEN:
            return None

        # Unpack protocol v3 header (6 bytes, no board_id)
        payload_len = struct.unpack_from("<H", data, 0)[0]
        proto_ver   = data[2]
        pkt_counter = struct.unpack_from("<H", data, 3)[0]
        pkt_type    = data[5]

        if proto_ver != PROTO_VERSION:
            logger.debug("Ignoring packet with proto_ver=%d", proto_ver)
            return None

        body = data[PROTO_HDR_LEN:]

        # -- advertising PDU --------------------------------------------------
        if pkt_type == EVT_PACKET_ADV_PDU:
            return self._parse_adv_pdu(body, pkt_counter)

        # -- data PDU ---------------------------------------------------------
        if pkt_type == EVT_PACKET_DATA_PDU:
            return self._parse_data_pdu(body, pkt_counter)

        # -- connect event ----------------------------------------------------
        if pkt_type == EVT_CONNECT:
            return self._parse_connect_event(body, pkt_counter)

        # -- disconnect event -------------------------------------------------
        if pkt_type == EVT_DISCONNECT:
            return self._parse_disconnect_event(body, pkt_counter)

        # -- ping response (handled inline during ping()) ---------------------
        if pkt_type == EVT_PING_RESP:
            return None   # not a BLE packet

        logger.debug("Unknown event type 0x%02X", pkt_type)
        return None

    def _parse_ble_header(self, data: bytes) -> Optional[dict]:
        """Parse the 10-byte BLE payload header common to ADV and DATA events."""
        if len(data) < BLE_HDR_LEN:
            return None

        hdr_len       = data[0]
        flags         = data[1]
        channel       = data[2]
        raw_rssi      = data[3]
        evt_counter   = struct.unpack_from("<H", data, 4)[0]
        timestamp_us  = struct.unpack_from("<I", data, 6)[0]

        # RSSI is stored as unsigned; negate to get dBm
        rssi = -raw_rssi

        crc_ok  = bool(flags & FLAG_CRC_OK)
        phy     = "coded" if (flags & FLAG_PHY_CODED) else "1M"

        return {
            "hdr_len":      hdr_len,
            "flags":        flags,
            "channel":      channel,
            "rssi":         rssi,
            "evt_counter":  evt_counter,
            "timestamp_us": timestamp_us,
            "crc_ok":       crc_ok,
            "phy":          phy,
        }

    def _parse_adv_pdu(self, body: bytes, pkt_counter: int) -> Optional[dict]:
        """Parse an advertising PDU event with full AD structure decoding."""
        ble = self._parse_ble_header(body)
        if not ble:
            return None

        raw = body[BLE_HDR_LEN:]

        # nRF Sniffer firmware v4.x includes 4-byte access address before PDU.
        # Advertising channel access address is always 0x8E89BED6 (LE: D6 BE 89 8E).
        access_address = 0x8E89BED6
        if len(raw) >= 4:
            aa = struct.unpack_from("<I", raw, 0)[0]
            if aa == 0x8E89BED6:
                access_address = aa
                raw = raw[4:]       # skip access address
            else:
                # Data channel AA or no AA present — try parsing as-is
                access_address = aa
                raw = raw[4:]

        pdu = raw
        if len(pdu) < 3:
            return None

        # PDU header: byte 0 lower 4 = PDU type, byte 1 = payload length
        adv_type_raw = pdu[0] & 0x0F
        adv_type_name = ADV_PDU_TYPES.get(adv_type_raw, f"0x{adv_type_raw:02X}")
        pdu_length = pdu[1]   # declared payload length (addr + AD, no CRC)

        # The firmware inserts a padding byte at pdu[2] (not sent on air).
        # Remove it so the address starts at pdu[2] as expected.
        phy = ble.get("phy", "1M")
        if phy == "coded":
            pdu = pdu[:3] + pdu[4:]   # padding at index 3 for coded PHY
        else:
            pdu = pdu[:2] + pdu[3:]   # padding at index 2 for 1M/2M PHY

        # Trim to declared length to exclude trailing CRC bytes
        pdu = pdu[:2 + pdu_length]

        # Extract advertiser address from the PDU (bytes 2..7, LE)
        adv_address = None
        if len(pdu) >= 8:
            addr_bytes = pdu[2:8]
            adv_address = ":".join(f"{b:02X}" for b in reversed(addr_bytes))

        # Parse all AD structures from the trimmed PDU
        ad_result = self._parse_ad_structures(pdu)

        return {
            "type":                "adv",
            "channel":             ble["channel"],
            "rssi":                ble["rssi"],
            "timestamp_us":        ble["timestamp_us"],
            "crc_ok":              ble["crc_ok"],
            "phy":                 ble["phy"],
            "access_address":      f"0x{access_address:08X}",
            "pdu":                 pdu.hex(),
            "adv_address":         adv_address,
            "adv_type":            adv_type_raw,
            "adv_type_name":       adv_type_name,
            "adv_name":            ad_result["name"],
            "pkt_counter":         pkt_counter,
            # New enhanced fields
            "ad_structures":       ad_result["ad_structures"],
            "service_uuids":       ad_result["service_uuids"],
            "manufacturer_id":     ad_result["manufacturer_id"],
            "manufacturer_name":   ad_result["manufacturer_name"],
            "manufacturer_data_hex": ad_result["manufacturer_data_hex"],
            "tx_power":            ad_result["tx_power"],
            "appearance":          ad_result["appearance"],
            "flags_str":           ad_result["flags_str"],
        }

    def _parse_data_pdu(self, body: bytes, pkt_counter: int) -> Optional[dict]:
        """Parse a data channel PDU event with LLID and LL Control decoding."""
        ble = self._parse_ble_header(body)
        if not ble:
            return None

        raw = body[BLE_HDR_LEN:]
        # Skip 4-byte access address (included by firmware v4.x)
        pdu = raw[4:] if len(raw) > 4 else raw

        # Extract LLID from first byte of data PDU
        llid = 0
        llid_name = "Unknown"
        ll_opcode = None
        ll_opcode_name = None
        ll_decoded: Dict[str, Any] = {}

        if len(pdu) >= 1:
            llid = pdu[0] & 0x03
            llid_name = LLID_NAMES.get(llid, f"Reserved(0b{llid:02b})")

            # LL Control PDU decoding
            if llid == 0b11 and len(pdu) >= 3:
                # pdu[0]=header, pdu[1]=length, pdu[2]=opcode
                ll_opcode = pdu[2]
                ll_opcode_name = LL_OPCODES.get(ll_opcode, f"0x{ll_opcode:02X}")
                ll_decoded = self._decode_ll_control(ll_opcode, pdu[3:] if len(pdu) > 3 else b"")

        return {
            "type":           "data",
            "channel":        ble["channel"],
            "rssi":           ble["rssi"],
            "timestamp_us":   ble["timestamp_us"],
            "crc_ok":         ble["crc_ok"],
            "phy":            ble["phy"],
            "access_address": None,   # data PDU AA is context-dependent
            "pdu":            pdu.hex(),
            "adv_address":    None,
            "adv_type":       None,
            "adv_type_name":  None,
            "adv_name":       None,
            "pkt_counter":    pkt_counter,
            # New LL fields
            "llid":           llid,
            "llid_name":      llid_name,
            "ll_opcode":      ll_opcode,
            "ll_opcode_name": ll_opcode_name,
            "ll_decoded":     ll_decoded,
        }

    def _parse_connect_event(self, body: bytes, pkt_counter: int) -> Optional[dict]:
        """Parse a connection event (firmware notification of CONNECT_IND) with full LL data decode."""
        ble = self._parse_ble_header(body)
        if not ble:
            return None

        pdu = body[BLE_HDR_LEN:]
        if len(pdu) < 20:
            return None

        # CONNECT_IND layout after PDU header (2 bytes):
        #   InitA(6) + AdvA(6) + LLData(22)
        #   LLData: AA(4) + CRCInit(3) + WinSize(1) + WinOffset(2) +
        #           Interval(2) + Latency(2) + Timeout(2) + ChMap(5) + Hop/SCA(1)
        pdu_body = pdu[2:] if len(pdu) >= 22 else pdu

        central_mac    = None
        peripheral_mac = None
        conn_aa        = None

        # Full LL data decode fields
        conn_interval_ms = None
        conn_timeout_ms  = None
        conn_latency     = None
        channels_used    = None
        hop_increment    = None
        crc_init         = None
        win_size         = None
        win_offset       = None
        sca_str          = None

        if len(pdu_body) >= 16:
            init_a = pdu_body[0:6]
            adv_a  = pdu_body[6:12]
            central_mac    = ":".join(f"{b:02X}" for b in reversed(init_a))
            peripheral_mac = ":".join(f"{b:02X}" for b in reversed(adv_a))
            conn_aa        = struct.unpack_from("<I", pdu_body, 12)[0]

        # Decode the full LLData if we have enough bytes (22 bytes of LLData starting at offset 12)
        if len(pdu_body) >= 34:
            ll_data = pdu_body[12:]
            # AA already extracted above (4 bytes at offset 0)
            # CRC Init: 3 bytes at offset 4
            crc_init = (ll_data[4] | (ll_data[5] << 8) | (ll_data[6] << 16))
            # WinSize: 1 byte at offset 7 (unit: 1.25ms)
            win_size = ll_data[7]
            # WinOffset: 2 bytes at offset 8 (unit: 1.25ms)
            win_offset = struct.unpack_from("<H", ll_data, 8)[0]
            # Interval: 2 bytes at offset 10 (unit: 1.25ms)
            interval_raw = struct.unpack_from("<H", ll_data, 10)[0]
            conn_interval_ms = interval_raw * 1.25
            # Latency: 2 bytes at offset 12
            conn_latency = struct.unpack_from("<H", ll_data, 12)[0]
            # Timeout: 2 bytes at offset 14 (unit: 10ms)
            timeout_raw = struct.unpack_from("<H", ll_data, 14)[0]
            conn_timeout_ms = timeout_raw * 10.0
            # Channel Map: 5 bytes at offset 16 -- bitmap of data channels 0-36
            ch_map_bytes = ll_data[16:21]
            ch_map_int = int.from_bytes(ch_map_bytes, byteorder="little")
            channels_used = bin(ch_map_int).count("1")
            # Hop/SCA: 1 byte at offset 21
            #   lower 5 bits = hop increment (5..16)
            #   upper 3 bits = SCA
            hop_sca = ll_data[21]
            hop_increment = hop_sca & 0x1F
            sca_field = (hop_sca >> 5) & 0x07
            sca_str = SCA_VALUES.get(sca_field, f"Reserved({sca_field})")

        return {
            "type":              "connect",
            "channel":           ble["channel"],
            "rssi":              ble["rssi"],
            "timestamp_us":      ble["timestamp_us"],
            "crc_ok":            ble["crc_ok"],
            "phy":               ble["phy"],
            "access_address":    f"0x{conn_aa:08X}" if conn_aa else None,
            "pdu":               pdu.hex(),
            "adv_address":       peripheral_mac,
            "adv_type":          0x05,
            "adv_type_name":     "CONNECT_IND",
            "adv_name":          None,
            "central_mac":       central_mac,
            "peripheral_mac":    peripheral_mac,
            "pkt_counter":       pkt_counter,
            # New CONNECT_IND decode fields
            "conn_interval_ms":  conn_interval_ms,
            "conn_timeout_ms":   conn_timeout_ms,
            "conn_latency":      conn_latency,
            "channels_used":     channels_used,
            "hop_increment":     hop_increment,
            "crc_init":          f"0x{crc_init:06X}" if crc_init is not None else None,
            "win_size":          win_size,
            "win_offset":        win_offset,
            "sca":               sca_str,
        }

    def _parse_disconnect_event(self, body: bytes, pkt_counter: int) -> Optional[dict]:
        """Parse a disconnect notification from the firmware."""
        ble = self._parse_ble_header(body)
        if not ble:
            # Disconnect events may have a shorter body
            return {
                "type":           "disconnect",
                "channel":        0,
                "rssi":           0,
                "timestamp_us":   0,
                "crc_ok":         True,
                "phy":            "1M",
                "access_address": None,
                "pdu":            body.hex() if body else "",
                "adv_address":    None,
                "adv_type":       None,
                "adv_type_name":  None,
                "adv_name":       None,
                "pkt_counter":    pkt_counter,
            }

        return {
            "type":           "disconnect",
            "channel":        ble["channel"],
            "rssi":           ble["rssi"],
            "timestamp_us":   ble["timestamp_us"],
            "crc_ok":         ble["crc_ok"],
            "phy":            ble["phy"],
            "access_address": None,
            "pdu":            body[BLE_HDR_LEN:].hex(),
            "adv_address":    None,
            "adv_type":       None,
            "adv_type_name":  None,
            "adv_name":       None,
            "pkt_counter":    pkt_counter,
        }

    # -- AD structure parser --------------------------------------------------

    @staticmethod
    def _extract_adv_name(pdu: bytes) -> Optional[str]:
        """
        Walk the AD structures in an advertising PDU and extract the
        Complete Local Name (type 0x09) or Shortened Local Name (type 0x08).

        Returns the name string or None.
        """
        # AD structures start after the 2-byte PDU header + 6-byte address
        offset = 8
        while offset + 1 < len(pdu):
            ad_len = pdu[offset]
            if ad_len == 0:
                break
            if offset + 1 + ad_len > len(pdu):
                break
            ad_type = pdu[offset + 1]
            if ad_type in (0x08, 0x09):  # shortened or complete local name
                try:
                    return pdu[offset + 2 : offset + 1 + ad_len].decode("utf-8", errors="replace")
                except Exception:
                    pass
            offset += 1 + ad_len
        return None

    @staticmethod
    def _parse_ad_structures(pdu: bytes) -> dict:
        """
        Walk the full AD structure chain in an advertising PDU payload.

        Parses all standard AD types including flags, service UUIDs,
        local name, TX power, service data, appearance, and manufacturer data.

        Returns a dict with parsed fields.
        """
        result: Dict[str, Any] = {
            "name":                 None,
            "ad_structures":        [],
            "service_uuids":        [],
            "manufacturer_id":      None,
            "manufacturer_name":    "",
            "manufacturer_data_hex": "",
            "tx_power":             None,
            "appearance":           None,
            "flags_str":            "",
        }

        # AD structures start after the 2-byte PDU header + 6-byte address
        offset = 8
        flags_parts: List[str] = []
        service_uuids: List[str] = []

        while offset + 1 < len(pdu):
            ad_len = pdu[offset]
            if ad_len == 0:
                break
            if offset + 1 + ad_len > len(pdu):
                break

            ad_type = pdu[offset + 1]
            ad_data = pdu[offset + 2 : offset + 1 + ad_len]
            ad_type_name = AD_TYPE_NAMES.get(ad_type, f"Unknown(0x{ad_type:02X})")

            result["ad_structures"].append({
                "type":      ad_type,
                "type_name": ad_type_name,
                "data_hex":  ad_data.hex(),
            })

            # -- Type 0x01: Flags -----------------------------------------------
            if ad_type == 0x01 and len(ad_data) >= 1:
                flag_byte = ad_data[0]
                if flag_byte & 0x01:
                    flags_parts.append("LE Limited Discoverable")
                if flag_byte & 0x02:
                    flags_parts.append("LE General Discoverable")
                if flag_byte & 0x04:
                    flags_parts.append("BR/EDR Not Supported")
                if flag_byte & 0x08:
                    flags_parts.append("LE+BR/EDR Controller")
                if flag_byte & 0x10:
                    flags_parts.append("LE+BR/EDR Host")

            # -- Type 0x02/0x03: 16-bit Service UUIDs ---------------------------
            elif ad_type in (0x02, 0x03):
                i = 0
                while i + 1 < len(ad_data):
                    uuid16 = struct.unpack_from("<H", ad_data, i)[0]
                    service_uuids.append(f"0x{uuid16:04X}")
                    i += 2

            # -- Type 0x04/0x05: 32-bit Service UUIDs ---------------------------
            elif ad_type in (0x04, 0x05):
                i = 0
                while i + 3 < len(ad_data):
                    uuid32 = struct.unpack_from("<I", ad_data, i)[0]
                    service_uuids.append(f"0x{uuid32:08X}")
                    i += 4

            # -- Type 0x06/0x07: 128-bit Service UUIDs --------------------------
            elif ad_type in (0x06, 0x07):
                i = 0
                while i + 15 < len(ad_data):
                    uuid_bytes = ad_data[i:i + 16]
                    # Convert LE byte order to standard UUID string
                    b = bytes(reversed(uuid_bytes))
                    uuid128 = (
                        f"{b[0:4].hex()}-{b[4:6].hex()}-{b[6:8].hex()}-"
                        f"{b[8:10].hex()}-{b[10:16].hex()}"
                    )
                    service_uuids.append(uuid128)
                    i += 16

            # -- Type 0x08/0x09: Local Name -------------------------------------
            elif ad_type in (0x08, 0x09):
                try:
                    result["name"] = ad_data.decode("utf-8", errors="replace")
                except Exception:
                    pass

            # -- Type 0x0A: TX Power Level --------------------------------------
            elif ad_type == 0x0A and len(ad_data) >= 1:
                # TX power is a signed int8
                result["tx_power"] = struct.unpack_from("b", ad_data, 0)[0]

            # -- Type 0x16: Service Data (16-bit UUID + data) -------------------
            elif ad_type == 0x16 and len(ad_data) >= 2:
                svc_uuid = struct.unpack_from("<H", ad_data, 0)[0]
                if f"0x{svc_uuid:04X}" not in service_uuids:
                    service_uuids.append(f"0x{svc_uuid:04X}")

            # -- Type 0x19: Appearance ------------------------------------------
            elif ad_type == 0x19 and len(ad_data) >= 2:
                appearance_val = struct.unpack_from("<H", ad_data, 0)[0]
                result["appearance"] = APPEARANCE_VALUES.get(
                    appearance_val,
                    # Try category match (upper byte)
                    APPEARANCE_VALUES.get(
                        appearance_val & 0xFFC0,
                        f"0x{appearance_val:04X}"
                    ),
                )

            # -- Type 0xFF: Manufacturer Specific Data --------------------------
            elif ad_type == 0xFF and len(ad_data) >= 2:
                mfr_id = struct.unpack_from("<H", ad_data, 0)[0]
                result["manufacturer_id"] = mfr_id
                result["manufacturer_name"] = COMPANY_IDS.get(mfr_id, f"Unknown(0x{mfr_id:04X})")
                result["manufacturer_data_hex"] = ad_data[2:].hex() if len(ad_data) > 2 else ""

            offset += 1 + ad_len

        result["service_uuids"] = service_uuids
        result["flags_str"] = ", ".join(flags_parts)

        return result

    # -- LL Control PDU decoder -----------------------------------------------

    @staticmethod
    def _decode_ll_control(opcode: int, payload: bytes) -> Dict[str, Any]:
        """
        Decode known LL Control PDU payloads.

        Returns a dict with opcode-specific decoded fields.
        """
        decoded: Dict[str, Any] = {}

        # LL_TERMINATE_IND: 1 byte error code
        if opcode == 0x02 and len(payload) >= 1:
            error_code = payload[0]
            decoded["error_code"] = error_code
            decoded["error_name"] = HCI_ERROR_CODES.get(error_code, f"0x{error_code:02X}")

        # LL_ENC_REQ: Rand(8) + EDIV(2) + SKDm(8) + IVm(4)
        elif opcode == 0x03 and len(payload) >= 22:
            decoded["rand"] = payload[0:8].hex()
            decoded["ediv"] = struct.unpack_from("<H", payload, 8)[0]
            decoded["skd_master"] = payload[10:18].hex()
            decoded["iv_master"] = payload[18:22].hex()

        # LL_ENC_RSP: SKDs(8) + IVs(4)
        elif opcode == 0x04 and len(payload) >= 12:
            decoded["skd_slave"] = payload[0:8].hex()
            decoded["iv_slave"] = payload[8:12].hex()

        # LL_FEATURE_REQ / LL_FEATURE_RSP: FeatureSet(8)
        elif opcode in (0x08, 0x09) and len(payload) >= 8:
            features = int.from_bytes(payload[0:8], byteorder="little")
            decoded["features_raw"] = f"0x{features:016X}"
            feature_list = []
            feature_names = {
                0: "LE Encryption",
                1: "Connection Parameters Request",
                2: "Extended Reject Indication",
                3: "Slave-Initiated Features Exchange",
                4: "LE Ping",
                5: "LE Data Packet Length Extension",
                6: "LL Privacy",
                7: "Extended Scanner Filter Policies",
                8: "LE 2M PHY",
                9: "Stable Modulation Index (TX)",
                10: "Stable Modulation Index (RX)",
                11: "LE Coded PHY",
                12: "LE Extended Advertising",
                13: "LE Periodic Advertising",
                14: "Channel Selection Algorithm #2",
                15: "LE Power Class 1",
                16: "Minimum Number of Used Channels",
                17: "Connection CTE Request",
                18: "Connection CTE Response",
                19: "Connectionless CTE Transmitter",
                20: "Connectionless CTE Receiver",
                21: "Antenna Switching (CTE TX, AoD)",
                22: "Antenna Switching (CTE RX, AoA)",
                23: "Receiving CTE",
                24: "Periodic Advertising Sync Transfer - Sender",
                25: "Periodic Advertising Sync Transfer - Recipient",
                26: "Sleep Clock Accuracy Updates",
                27: "Remote Public Key Validation",
                28: "Connected Isochronous Stream - Central",
                29: "Connected Isochronous Stream - Peripheral",
                30: "Isochronous Broadcaster",
                31: "Synchronized Receiver",
                32: "Connected Isochronous Stream (Host Support)",
                33: "LE Power Control Request",
                34: "LE Power Control Request (Peer)",
                35: "LE Path Loss Monitoring",
                36: "Periodic Advertising ADI",
                37: "Connection Subrating",
                38: "Connection Subrating (Host Support)",
                39: "Channel Classification",
            }
            for bit, name in feature_names.items():
                if features & (1 << bit):
                    feature_list.append(name)
            decoded["features"] = feature_list

        # LL_VERSION_IND: VersNr(1) + CompId(2) + SubVersNr(2)
        elif opcode == 0x0C and len(payload) >= 5:
            vers_nr = payload[0]
            comp_id = struct.unpack_from("<H", payload, 1)[0]
            sub_vers = struct.unpack_from("<H", payload, 3)[0]
            decoded["ble_version"] = BLE_VERSIONS.get(vers_nr, f"0x{vers_nr:02X}")
            decoded["company_id"] = comp_id
            decoded["company_name"] = COMPANY_IDS.get(comp_id, f"Unknown(0x{comp_id:04X})")
            decoded["subversion"] = sub_vers

        # LL_CONNECTION_UPDATE_IND: WinSize(1) + WinOffset(2) + Interval(2) + Latency(2) + Timeout(2) + Instant(2)
        elif opcode == 0x00 and len(payload) >= 11:
            decoded["win_size"] = payload[0]
            decoded["win_offset"] = struct.unpack_from("<H", payload, 1)[0]
            interval = struct.unpack_from("<H", payload, 3)[0]
            decoded["interval_raw"] = interval
            decoded["interval_ms"] = interval * 1.25
            decoded["latency"] = struct.unpack_from("<H", payload, 5)[0]
            timeout = struct.unpack_from("<H", payload, 7)[0]
            decoded["timeout_raw"] = timeout
            decoded["timeout_ms"] = timeout * 10.0
            decoded["instant"] = struct.unpack_from("<H", payload, 9)[0]

        # LL_CHANNEL_MAP_IND: ChM(5) + Instant(2)
        elif opcode == 0x01 and len(payload) >= 7:
            ch_map = int.from_bytes(payload[0:5], byteorder="little")
            decoded["channel_map"] = f"0x{ch_map:010X}"
            decoded["channels_used"] = bin(ch_map).count("1")
            decoded["instant"] = struct.unpack_from("<H", payload, 5)[0]

        # LL_PHY_REQ / LL_PHY_RSP: TX_PHYS(1) + RX_PHYS(1)
        elif opcode in (0x12, 0x13) and len(payload) >= 2:
            phy_names = {0x01: "1M", 0x02: "2M", 0x04: "Coded"}
            tx_phys = payload[0]
            rx_phys = payload[1]
            decoded["tx_phys"] = [n for v, n in phy_names.items() if tx_phys & v]
            decoded["rx_phys"] = [n for v, n in phy_names.items() if rx_phys & v]

        # LL_LENGTH_REQ / LL_LENGTH_RSP: MaxRxOctets(2) + MaxRxTime(2) + MaxTxOctets(2) + MaxTxTime(2)
        elif opcode in (0x14, 0x15) and len(payload) >= 8:
            decoded["max_rx_octets"] = struct.unpack_from("<H", payload, 0)[0]
            decoded["max_rx_time_us"] = struct.unpack_from("<H", payload, 2)[0]
            decoded["max_tx_octets"] = struct.unpack_from("<H", payload, 4)[0]
            decoded["max_tx_time_us"] = struct.unpack_from("<H", payload, 6)[0]

        # LL_REJECT_IND: ErrorCode(1)
        elif opcode == 0x0D and len(payload) >= 1:
            decoded["error_code"] = payload[0]
            decoded["error_name"] = HCI_ERROR_CODES.get(payload[0], f"0x{payload[0]:02X}")

        # LL_REJECT_EXT_IND: RejectOpcode(1) + ErrorCode(1)
        elif opcode == 0x11 and len(payload) >= 2:
            decoded["reject_opcode"] = payload[0]
            decoded["reject_opcode_name"] = LL_OPCODES.get(payload[0], f"0x{payload[0]:02X}")
            decoded["error_code"] = payload[1]
            decoded["error_name"] = HCI_ERROR_CODES.get(payload[1], f"0x{payload[1]:02X}")

        return decoded

    # -- state table updates --------------------------------------------------

    def _update_device_table(self, pkt: dict) -> None:
        """Update the discovered-device table from an advertising packet."""
        if pkt["type"] != "adv":
            return
        addr = pkt.get("adv_address")
        if not addr:
            return

        now = time.time()
        channel = pkt.get("channel")
        adv_type = pkt.get("adv_type")

        if addr in self._devices:
            entry = self._devices[addr]
            entry["rssi"] = pkt["rssi"]
            entry["last_seen"] = now
            entry["adv_count"] += 1
            if pkt.get("adv_name"):
                entry["name"] = pkt["adv_name"]
            # Update extended fields
            if pkt.get("service_uuids"):
                for uuid in pkt["service_uuids"]:
                    if uuid not in entry["service_uuids"]:
                        entry["service_uuids"].append(uuid)
            if pkt.get("manufacturer_id") is not None:
                entry["manufacturer_id"] = pkt["manufacturer_id"]
                entry["manufacturer_name"] = pkt.get("manufacturer_name", "")
            if pkt.get("tx_power") is not None:
                entry["tx_power"] = pkt["tx_power"]
            if pkt.get("appearance"):
                entry["appearance"] = pkt["appearance"]
            if adv_type is not None:
                entry["adv_types_seen"].add(adv_type)
                # Update connectability based on PDU types
                if adv_type in (0x00, 0x01, 0x06):
                    entry["is_connectable"] = True
            if channel in (37, 38, 39):
                entry["channel_distribution"][channel] = entry["channel_distribution"].get(channel, 0) + 1
            entry["rssi_history"].append(pkt["rssi"])
        else:
            is_connectable = adv_type in (0x00, 0x01, 0x06) if adv_type is not None else False
            rssi_hist: deque = deque(maxlen=20)
            rssi_hist.append(pkt["rssi"])
            ch_dist: Dict[int, int] = {}
            if channel in (37, 38, 39):
                ch_dist[channel] = 1

            self._devices[addr] = {
                "address":              addr,
                "name":                 pkt.get("adv_name"),
                "rssi":                 pkt["rssi"],
                "last_seen":            now,
                "first_seen":           now,
                "adv_count":            1,
                "service_uuids":        list(pkt.get("service_uuids") or []),
                "manufacturer_id":      pkt.get("manufacturer_id"),
                "manufacturer_name":    pkt.get("manufacturer_name", ""),
                "tx_power":             pkt.get("tx_power"),
                "appearance":           pkt.get("appearance"),
                "is_connectable":       is_connectable,
                "adv_types_seen":       {adv_type} if adv_type is not None else set(),
                "channel_distribution": ch_dist,
                "rssi_history":         rssi_hist,
            }

    def _update_connection_table(self, pkt: dict) -> None:
        """Track connections and disconnections."""
        if pkt["type"] == "connect":
            aa_str = pkt.get("access_address")
            if aa_str:
                try:
                    aa_int = int(aa_str, 16)
                except (ValueError, TypeError):
                    aa_int = 0
                self._connections[aa_int] = {
                    "access_address":  aa_str,
                    "central_mac":     pkt.get("central_mac"),
                    "peripheral_mac":  pkt.get("peripheral_mac"),
                    "start_time":      time.time(),
                    "end_time":        None,
                    # Include CONNECT_IND decode data
                    "conn_interval_ms": pkt.get("conn_interval_ms"),
                    "conn_timeout_ms":  pkt.get("conn_timeout_ms"),
                    "conn_latency":     pkt.get("conn_latency"),
                    "channels_used":    pkt.get("channels_used"),
                    "hop_increment":    pkt.get("hop_increment"),
                }

        elif pkt["type"] == "disconnect":
            # Mark all active connections as ended (firmware doesn't always
            # give us the specific AA in the disconnect event)
            for conn in self._connections.values():
                if conn["end_time"] is None:
                    conn["end_time"] = time.time()


# =============================================================================
#  SimulatedNrfSniffer -- fake traffic for dashboard testing
# =============================================================================

_SIM_DEVICES = [
    ("E4:28:B2:11:A0:01", "iPhone 15",         -52, 0x004C, "Apple, Inc.",           ["0x1805", "0xFD6F"],         0x0041, 4),
    ("A0:B1:C2:D3:E4:F5", "Galaxy Buds2 Pro",  -61, 0x0075, "Samsung Electronics",   ["0x1108", "0xFD5A"],         0x0982, -2),
    ("11:22:33:44:55:66", "Tile Slim",          -74, 0x0131, "Tile, Inc.",            ["0xFEED"],                   0x0200, -8),
    ("AA:BB:CC:DD:EE:01", "Smart Thermostat",   -68, 0x0660, "Tuya Global Inc.",      ["0x1800", "0x1801"],         0x0601, 0),
    ("DE:AD:BE:EF:00:01", "Unknown Device",     -83, None,   "",                      [],                           None,   None),
    ("B8:27:EB:12:34:56", "Raspberry Pi",       -47, 0x000F, "Broadcom",              ["0x180A"],                   0x0080, 8),
    ("C0:FF:EE:BA:BE:01", "Fitbit Sense 2",     -59, 0x0100, "Fitbit, Inc.",          ["0x180D", "0x1816"],         0x00C2, -1),
    ("08:3A:88:AB:CD:EF", "MacBook Pro",        -44, 0x004C, "Apple, Inc.",           ["0x1805", "0x180A", "0x12"], 0x0083, 12),
]

_SIM_FLAGS = [
    "LE General Discoverable, BR/EDR Not Supported",
    "LE General Discoverable",
    "LE Limited Discoverable, BR/EDR Not Supported",
    "LE General Discoverable, LE+BR/EDR Controller",
]


class SimulatedNrfSniffer:
    """
    Drop-in replacement for NrfSniffer that generates synthetic BLE
    packets without any hardware.  Useful for dashboard development
    and integration testing.
    """

    def __init__(self, port: str = "/dev/null", baudrate: int = 1_000_000):
        self.port      = port
        self.baudrate  = baudrate
        self._running  = False
        self._thread: Optional[threading.Thread] = None

        self._lock     = threading.Lock()
        self._packets: List[dict]  = []
        self._devices: Dict[str, dict] = {}
        self._connections: Dict[int, dict] = {}
        self._pkt_counter = 0
        self._start_time  = 0.0

        # Statistics tracking
        self._stat_total    = 0
        self._stat_by_type: Dict[str, int] = {"adv": 0, "data": 0, "connect": 0, "disconnect": 0}
        self._stat_channel: Dict[int, int] = {37: 0, 38: 0, 39: 0}
        self._stat_timestamps: deque = deque(maxlen=500)

    # -- mimic NrfSniffer public API ------------------------------------------

    def open(self) -> None:
        logger.info("SimulatedNrfSniffer: open (no hardware)")

    def close(self) -> None:
        if self._running:
            self.stop_scan()
        logger.info("SimulatedNrfSniffer: closed")

    def start_scan(self) -> None:
        if self._running:
            return
        self._running    = True
        self._start_time = time.monotonic()
        self._thread = threading.Thread(
            target=self._sim_loop,
            daemon=True,
            name="SimNrfReader",
        )
        self._thread.start()
        logger.info("SimulatedNrfSniffer: scan started")

    def stop_scan(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join(timeout=2.0)
            self._thread = None
        logger.info("SimulatedNrfSniffer: scan stopped")

    def follow_device(self, address: str) -> None:
        logger.info("SimulatedNrfSniffer: follow %s (no-op)", address)

    def get_packets(self, clear: bool = True) -> List[dict]:
        with self._lock:
            snapshot = list(self._packets)
            if clear:
                self._packets.clear()
        return snapshot

    def get_devices(self) -> List[dict]:
        with self._lock:
            devs = list(self._devices.values())
        devs.sort(key=lambda d: d["rssi"], reverse=True)
        return devs

    def get_connections(self) -> List[dict]:
        with self._lock:
            return list(self._connections.values())

    def get_statistics(self) -> dict:
        """Return sniffer statistics."""
        with self._lock:
            now = time.monotonic()
            cutoff = now - 5.0
            recent = sum(1 for ts in self._stat_timestamps if ts >= cutoff)
            pps = recent / 5.0 if self._start_time > 0 else 0.0
            active_conns = sum(
                1 for c in self._connections.values() if c.get("end_time") is None
            )
            uptime = now - self._start_time if self._start_time > 0 else 0.0
            return {
                "total_packets": self._stat_total,
                "packets_by_type": dict(self._stat_by_type),
                "packets_per_second": round(pps, 2),
                "unique_devices": len(self._devices),
                "active_connections": active_conns,
                "channel_distribution": dict(self._stat_channel),
                "uptime_seconds": round(uptime, 2),
            }

    def ping(self) -> bool:
        return True   # always "alive"

    # -- simulation loop ------------------------------------------------------

    def _sim_loop(self) -> None:
        conn_emitted = False
        data_counter = 0

        while self._running:
            elapsed = time.monotonic() - self._start_time

            # Emit advertising packets from random devices
            n = random.randint(1, 4)
            for _ in range(n):
                dev = random.choice(_SIM_DEVICES)
                mac, name, base_rssi, mfr_id, mfr_name, svc_uuids, appearance_val, tx_pwr = dev
                rssi = base_rssi + random.randint(-6, 6)
                channel = random.choice([37, 38, 39])
                adv_type = random.choice([0x00, 0x02])
                ts_us = int((time.monotonic() - self._start_time) * 1_000_000) & 0xFFFFFFFF

                # Build simulated AD structures
                ad_structures = []
                flags_str = random.choice(_SIM_FLAGS)

                # Flags AD structure
                ad_structures.append({
                    "type": 0x01,
                    "type_name": "Flags",
                    "data_hex": "06",
                })

                # Name AD structure
                if name:
                    ad_structures.append({
                        "type": 0x09,
                        "type_name": "Complete Local Name",
                        "data_hex": name.encode("utf-8").hex(),
                    })

                # Service UUIDs
                if svc_uuids:
                    ad_structures.append({
                        "type": 0x03,
                        "type_name": "Complete List of 16-bit Service UUIDs",
                        "data_hex": "".join(
                            struct.pack("<H", int(u, 16)).hex()
                            for u in svc_uuids
                            if u.startswith("0x") and len(u) == 6
                        ),
                    })

                # Manufacturer data
                if mfr_id is not None:
                    mfr_payload = os.urandom(random.randint(2, 8)).hex()
                    ad_structures.append({
                        "type": 0xFF,
                        "type_name": "Manufacturer Specific Data",
                        "data_hex": struct.pack("<H", mfr_id).hex() + mfr_payload,
                    })

                # TX Power
                if tx_pwr is not None:
                    ad_structures.append({
                        "type": 0x0A,
                        "type_name": "TX Power Level",
                        "data_hex": struct.pack("b", tx_pwr).hex(),
                    })

                # Appearance
                appearance_str = None
                if appearance_val is not None:
                    appearance_str = APPEARANCE_VALUES.get(appearance_val, f"0x{appearance_val:04X}")
                    ad_structures.append({
                        "type": 0x19,
                        "type_name": "Appearance",
                        "data_hex": struct.pack("<H", appearance_val).hex(),
                    })

                pkt = {
                    "type":                  "adv",
                    "channel":               channel,
                    "rssi":                  rssi,
                    "timestamp_us":          ts_us,
                    "crc_ok":                True,
                    "phy":                   "1M",
                    "access_address":        "0x8E89BED6",
                    "pdu":                   os.urandom(random.randint(12, 30)).hex(),
                    "adv_address":           mac,
                    "adv_type":              adv_type,
                    "adv_type_name":         ADV_PDU_TYPES.get(adv_type, "UNKNOWN"),
                    "adv_name":              name,
                    "pkt_counter":           self._pkt_counter,
                    # Enhanced fields
                    "ad_structures":         ad_structures,
                    "service_uuids":         list(svc_uuids),
                    "manufacturer_id":       mfr_id,
                    "manufacturer_name":     mfr_name,
                    "manufacturer_data_hex": os.urandom(4).hex() if mfr_id else "",
                    "tx_power":              tx_pwr,
                    "appearance":            appearance_str,
                    "flags_str":             flags_str,
                }
                self._store_packet(pkt)

            # Emit simulated data PDUs after a connection
            if conn_emitted and random.random() < 0.3:
                data_counter += 1
                llid = random.choice([0b01, 0b10, 0b11])
                ll_opcode = None
                ll_opcode_name = None
                ll_decoded: Dict[str, Any] = {}

                if llid == 0b11:
                    ll_opcode = random.choice([0x00, 0x01, 0x08, 0x09, 0x0C, 0x12, 0x14])
                    ll_opcode_name = LL_OPCODES.get(ll_opcode, f"0x{ll_opcode:02X}")
                    if ll_opcode == 0x0C:
                        ll_decoded = {
                            "ble_version": "5.3",
                            "company_id": 0x004C,
                            "company_name": "Apple, Inc.",
                            "subversion": 0x0001,
                        }
                    elif ll_opcode == 0x08:
                        ll_decoded = {
                            "features_raw": "0x00000000000001FF",
                            "features": [
                                "LE Encryption",
                                "Connection Parameters Request",
                                "Extended Reject Indication",
                                "Slave-Initiated Features Exchange",
                                "LE Ping",
                                "LE Data Packet Length Extension",
                                "LL Privacy",
                                "Extended Scanner Filter Policies",
                                "LE 2M PHY",
                            ],
                        }

                data_pkt = {
                    "type":           "data",
                    "channel":        random.randint(0, 36),
                    "rssi":           -50 + random.randint(-10, 10),
                    "timestamp_us":   int(elapsed * 1_000_000) & 0xFFFFFFFF,
                    "crc_ok":         True,
                    "phy":            "1M",
                    "access_address": None,
                    "pdu":            os.urandom(random.randint(4, 27)).hex(),
                    "adv_address":    None,
                    "adv_type":       None,
                    "adv_type_name":  None,
                    "adv_name":       None,
                    "pkt_counter":    self._pkt_counter,
                    "llid":           llid,
                    "llid_name":      LLID_NAMES.get(llid, "Unknown"),
                    "ll_opcode":      ll_opcode,
                    "ll_opcode_name": ll_opcode_name,
                    "ll_decoded":     ll_decoded,
                }
                self._store_packet(data_pkt)

            # Emit a simulated connection after ~5 seconds
            if elapsed > 5.0 and not conn_emitted:
                conn_emitted = True
                conn_aa = random.randint(0x10000000, 0xEFFFFFFF)
                central, peripheral = "08:3A:88:AB:CD:EF", "C0:FF:EE:BA:BE:01"
                conn_interval = round(random.uniform(7.5, 100.0), 2)
                conn_timeout = round(random.uniform(100.0, 3200.0), 2)
                conn_lat = random.randint(0, 10)
                ch_used = random.randint(30, 37)
                hop_inc = random.randint(5, 16)

                conn_pkt = {
                    "type":              "connect",
                    "channel":           random.choice([37, 38, 39]),
                    "rssi":              -48,
                    "timestamp_us":      int(elapsed * 1_000_000) & 0xFFFFFFFF,
                    "crc_ok":            True,
                    "phy":               "1M",
                    "access_address":    f"0x{conn_aa:08X}",
                    "pdu":               os.urandom(34).hex(),
                    "adv_address":       peripheral,
                    "adv_type":          0x05,
                    "adv_type_name":     "CONNECT_IND",
                    "adv_name":          None,
                    "central_mac":       central,
                    "peripheral_mac":    peripheral,
                    "pkt_counter":       self._pkt_counter,
                    # CONNECT_IND decode fields
                    "conn_interval_ms":  conn_interval,
                    "conn_timeout_ms":   conn_timeout,
                    "conn_latency":      conn_lat,
                    "channels_used":     ch_used,
                    "hop_increment":     hop_inc,
                    "crc_init":          f"0x{random.randint(0, 0xFFFFFF):06X}",
                    "win_size":          random.randint(1, 8),
                    "win_offset":        random.randint(0, 6),
                    "sca":               random.choice(list(SCA_VALUES.values())),
                }
                self._store_packet(conn_pkt)
                with self._lock:
                    self._connections[conn_aa] = {
                        "access_address":   f"0x{conn_aa:08X}",
                        "central_mac":      central,
                        "peripheral_mac":   peripheral,
                        "start_time":       time.time(),
                        "end_time":         None,
                        "conn_interval_ms": conn_interval,
                        "conn_timeout_ms":  conn_timeout,
                        "conn_latency":     conn_lat,
                        "channels_used":    ch_used,
                        "hop_increment":    hop_inc,
                    }

            time.sleep(0.3 + random.uniform(-0.05, 0.1))

    def _store_packet(self, pkt: dict) -> None:
        with self._lock:
            self._packets.append(pkt)
            if len(self._packets) > 5000:
                self._packets = self._packets[-5000:]
            self._pkt_counter += 1

            # Update statistics
            self._stat_total += 1
            ptype = pkt.get("type", "")
            if ptype in self._stat_by_type:
                self._stat_by_type[ptype] += 1
            ch = pkt.get("channel")
            if ch in self._stat_channel:
                self._stat_channel[ch] += 1
            self._stat_timestamps.append(time.monotonic())

            # Update device table for adv packets
            if pkt["type"] == "adv" and pkt.get("adv_address"):
                addr = pkt["adv_address"]
                now = time.time()
                channel = pkt.get("channel")
                adv_type = pkt.get("adv_type")

                if addr in self._devices:
                    entry = self._devices[addr]
                    entry["rssi"]      = pkt["rssi"]
                    entry["last_seen"] = now
                    entry["adv_count"] += 1
                    if pkt.get("adv_name"):
                        entry["name"] = pkt["adv_name"]
                    if pkt.get("service_uuids"):
                        for uuid in pkt["service_uuids"]:
                            if uuid not in entry["service_uuids"]:
                                entry["service_uuids"].append(uuid)
                    if pkt.get("manufacturer_id") is not None:
                        entry["manufacturer_id"] = pkt["manufacturer_id"]
                        entry["manufacturer_name"] = pkt.get("manufacturer_name", "")
                    if pkt.get("tx_power") is not None:
                        entry["tx_power"] = pkt["tx_power"]
                    if pkt.get("appearance"):
                        entry["appearance"] = pkt["appearance"]
                    if adv_type is not None:
                        entry["adv_types_seen"].add(adv_type)
                        if adv_type in (0x00, 0x01, 0x06):
                            entry["is_connectable"] = True
                    if channel in (37, 38, 39):
                        entry["channel_distribution"][channel] = entry["channel_distribution"].get(channel, 0) + 1
                    entry["rssi_history"].append(pkt["rssi"])
                else:
                    is_connectable = adv_type in (0x00, 0x01, 0x06) if adv_type is not None else False
                    rssi_hist: deque = deque(maxlen=20)
                    rssi_hist.append(pkt["rssi"])
                    ch_dist: Dict[int, int] = {}
                    if channel in (37, 38, 39):
                        ch_dist[channel] = 1

                    self._devices[addr] = {
                        "address":              addr,
                        "name":                 pkt.get("adv_name"),
                        "rssi":                 pkt["rssi"],
                        "last_seen":            now,
                        "first_seen":           now,
                        "adv_count":            1,
                        "service_uuids":        list(pkt.get("service_uuids") or []),
                        "manufacturer_id":      pkt.get("manufacturer_id"),
                        "manufacturer_name":    pkt.get("manufacturer_name", ""),
                        "tx_power":             pkt.get("tx_power"),
                        "appearance":           pkt.get("appearance"),
                        "is_connectable":       is_connectable,
                        "adv_types_seen":       {adv_type} if adv_type is not None else set(),
                        "channel_distribution": ch_dist,
                        "rssi_history":         rssi_hist,
                    }


# =============================================================================
#  Factory helper
# =============================================================================

def make_nrf_sniffer(
    sim: bool = False,
    port: str = "/dev/ttyACM0",
    baudrate: int = 1_000_000,
) -> NrfSniffer | SimulatedNrfSniffer:
    """
    Return an nRF sniffer instance.

    Args:
        sim:      Force the simulated backend (no hardware needed).
        port:     Serial port for the nRF52840 dongle.
        baudrate: Baud rate (default 1 000 000).
    """
    if sim:
        return SimulatedNrfSniffer(port=port, baudrate=baudrate)

    # Try to open real hardware; fall back to simulated if unavailable
    try:
        import serial  # type: ignore  # noqa: F401
        sniffer = NrfSniffer(port=port, baudrate=baudrate)
        return sniffer
    except ImportError:
        logger.warning("pyserial not installed -- using simulated nRF sniffer")
        return SimulatedNrfSniffer(port=port, baudrate=baudrate)


# =============================================================================
#  CLI quick-test
# =============================================================================

if __name__ == "__main__":
    import argparse
    import sys

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    parser = argparse.ArgumentParser(description="nRF52840 BLE Sniffer quick test")
    parser.add_argument("--port",     default="/dev/ttyACM0", help="Serial port")
    parser.add_argument("--sim",      action="store_true",    help="Use simulated sniffer")
    parser.add_argument("--duration", type=int, default=10,   help="Scan duration (seconds)")
    args = parser.parse_args()

    sniffer = make_nrf_sniffer(sim=args.sim, port=args.port)

    print(f"Opening sniffer on {sniffer.port} ...")
    sniffer.open()

    if not args.sim:
        print("Pinging firmware ... ", end="", flush=True)
        if sniffer.ping():
            print("OK")
        else:
            print("FAILED (firmware may not be running)")
            sniffer.close()
            sys.exit(1)

    print(f"Scanning for {args.duration} seconds ...")
    sniffer.start_scan()

    try:
        time.sleep(args.duration)
    except KeyboardInterrupt:
        print("\nInterrupted")

    sniffer.stop_scan()

    # Report
    devices = sniffer.get_devices()
    connections = sniffer.get_connections()
    packets = sniffer.get_packets(clear=False)
    stats = sniffer.get_statistics()

    print(f"\n{'=' * 70}")
    print(f"  Packets captured : {len(packets)}")
    print(f"  Devices found    : {len(devices)}")
    print(f"  Connections seen : {len(connections)}")
    print(f"  Packets/sec      : {stats['packets_per_second']}")
    print(f"  Uptime           : {stats['uptime_seconds']:.1f}s")
    print(f"  Channel dist     : {stats['channel_distribution']}")
    print(f"{'=' * 70}")

    if devices:
        print("\nDiscovered devices:")
        print(f"  {'Address':<20} {'RSSI':>5}  {'MFR':<22} {'Name'}")
        print(f"  {'-' * 18:<20} {'-----':>5}  {'-' * 20:<22} {'----'}")
        for dev in devices:
            name = dev.get("name") or "(unknown)"
            mfr = dev.get("manufacturer_name") or ""
            if len(mfr) > 20:
                mfr = mfr[:18] + ".."
            svc = ", ".join(dev.get("service_uuids", [])[:3])
            appear = dev.get("appearance") or ""
            connectable = "Y" if dev.get("is_connectable") else "N"
            tx = dev.get("tx_power")
            tx_str = f"{tx}dBm" if tx is not None else ""

            print(f"  {dev['address']:<20} {dev['rssi']:>5}  {mfr:<22} {name}")
            if svc or appear or tx_str:
                extras = []
                if svc:
                    extras.append(f"SVC=[{svc}]")
                if appear:
                    extras.append(f"Appear={appear}")
                if tx_str:
                    extras.append(f"TX={tx_str}")
                extras.append(f"Conn={connectable}")
                print(f"  {'':20} {'':>5}  {' | '.join(extras)}")

    if connections:
        print("\nConnections:")
        for conn in connections:
            interval = conn.get("conn_interval_ms")
            timeout = conn.get("conn_timeout_ms")
            latency = conn.get("conn_latency")
            channels = conn.get("channels_used")
            hop = conn.get("hop_increment")
            print(f"  {conn.get('central_mac', '?')} -> {conn.get('peripheral_mac', '?')}"
                  f"  AA={conn.get('access_address', '?')}")
            if interval is not None:
                print(f"    Interval={interval}ms  Timeout={timeout}ms  "
                      f"Latency={latency}  Channels={channels}  Hop={hop}")

    sniffer.close()
    print("\nDone.")
