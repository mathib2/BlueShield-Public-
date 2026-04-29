"""
WHAD/ButteRFly BLE sniffer backend.

Plugs into the same _BaseSniffleEngine interface as SniffleEngine, but uses a
ButteRFly-flashed nRF52840 dongle over WHAD instead of the TI CC1352 +
Sniffle-firmware stack. This is the backend BlueShield actually ships with,
since the nRF dongles we own are flashed with ButteRFly v1.1.3.

Emits BLEPacket records compatible with the rest of the dashboard
(pcap writer, pairing detector, correlator, UI packet list).
"""
from __future__ import annotations

import time
from typing import Optional

from .sniffle_engine import _BaseSniffleEngine, BLEPacket


class WhadSniffleEngine(_BaseSniffleEngine):
    """Sniffer engine backed by a ButteRFly nRF52840 via WHAD."""

    def __init__(self, serial_port: str = "/dev/ttyACM0", **kwargs):
        super().__init__(**kwargs)
        self.serial_port = serial_port
        self.hardware_available = False
        self._dev = None
        self._conn = None
        try:
            from whad.device import WhadDevice  # noqa: F401
            from whad.ble.connector.sniffer import Sniffer as _S  # noqa: F401
            self.hardware_available = True
        except ImportError:
            pass

    def _run_loop(self, target_mac, rssi_min, coded_phy):
        if not self.hardware_available:
            self._emit_error("whad library not installed")
            self._running = False
            return

        try:
            from whad.device import WhadDevice
            from whad.ble.connector.sniffer import Sniffer as BLESniffer
            from scapy.layers.bluetooth4LE import (
                BTLE, BTLE_ADV, BTLE_ADV_IND, BTLE_ADV_NONCONN_IND,
                BTLE_SCAN_RSP, BTLE_CONNECT_REQ, BTLE_DATA,
            )
        except Exception as e:
            self._emit_error(f"whad import failed: {e}")
            self._running = False
            return

        try:
            self._dev = WhadDevice.create(f"uart:{self.serial_port}")
            self._dev.open()
            self._dev.discover()
            self._conn = BLESniffer(self._dev)
            self._conn.sniff_advertisements()
            self._conn.start()
        except Exception as e:
            self._emit_error(f"butterfly sniffer start: {e}")
            self._running = False
            self._cleanup()
            return

        target = (target_mac or "").upper().strip() or None

        try:
            while self._running:
                try:
                    for pkt in self._conn.sniff(timeout=0.5):
                        if not self._running:
                            break
                        bp = self._decode(pkt, BTLE, BTLE_ADV, BTLE_ADV_IND,
                                           BTLE_ADV_NONCONN_IND, BTLE_SCAN_RSP,
                                           BTLE_CONNECT_REQ, BTLE_DATA)
                        if bp is None:
                            continue
                        if target and bp.adv_address and bp.adv_address != target:
                            continue
                        if bp.rssi is not None and bp.rssi < rssi_min:
                            continue
                        self._emit_packet(bp)
                        if bp.pkt_type == "connect_ind":
                            self._handle_connect_ind(bp)
                        elif bp.pkt_type == "data":
                            self._handle_data_pdu(bp)
                except Exception as e:
                    self._emit_error(f"sniff loop: {type(e).__name__}: {e}")
                    time.sleep(0.2)
        finally:
            self._cleanup()
            self._running = False

    # ── packet decode ────────────────────────────────────────────────────────

    @staticmethod
    def _decode(pkt, BTLE, BTLE_ADV, BTLE_ADV_IND, BTLE_ADV_NONCONN_IND,
                BTLE_SCAN_RSP, BTLE_CONNECT_REQ, BTLE_DATA) -> Optional[BLEPacket]:
        try:
            raw = bytes(pkt)
            channel = int(getattr(pkt, "Channel", getattr(pkt, "channel", 37)) or 37)
            rssi = int(getattr(pkt, "rssi", getattr(pkt, "RSSI", -70)) or -70)
            aa = int(getattr(pkt, "access_addr",
                             getattr(pkt, "AA", 0x8E89BED6)) or 0x8E89BED6)
        except Exception:
            return None

        pkt_type = "adv"
        adv_type = None
        adv_type_name = None
        adv_addr = None
        conn_aa = None
        hop_increment = None
        crc_init = None
        llid = None

        try:
            if BTLE_CONNECT_REQ in pkt:
                cr = pkt[BTLE_CONNECT_REQ]
                pkt_type = "connect_ind"
                adv_type = 0x05
                adv_type_name = "CONNECT_IND"
                adv_addr = str(getattr(cr, "AdvA", "") or "").upper() or None
                conn_aa = int(getattr(cr, "AA", 0) or getattr(cr, "access_addr", 0) or 0) or None
                hop_increment = int(getattr(cr, "hop", 0) or 0) or None
                crc_init = int(getattr(cr, "crc_init", 0) or 0) or None
            elif BTLE_ADV_IND in pkt:
                ad = pkt[BTLE_ADV_IND]
                adv_type = 0x00; adv_type_name = "ADV_IND"
                adv_addr = str(getattr(ad, "AdvA", "") or "").upper() or None
            elif BTLE_ADV_NONCONN_IND in pkt:
                ad = pkt[BTLE_ADV_NONCONN_IND]
                adv_type = 0x02; adv_type_name = "ADV_NONCONN_IND"
                adv_addr = str(getattr(ad, "AdvA", "") or "").upper() or None
            elif BTLE_SCAN_RSP in pkt:
                sr = pkt[BTLE_SCAN_RSP]
                adv_type = 0x04; adv_type_name = "SCAN_RSP"
                adv_addr = str(getattr(sr, "AdvA", "") or "").upper() or None
            elif BTLE_DATA in pkt:
                d = pkt[BTLE_DATA]
                pkt_type = "data"
                llid = int(getattr(d, "LLID", 0) or 0)
            elif BTLE_ADV in pkt:
                ad = pkt[BTLE_ADV]
                adv_addr = str(getattr(ad, "AdvA", "") or "").upper() or None
        except Exception:
            pass

        return BLEPacket(
            ts=time.time(),
            pkt_type=pkt_type,
            channel=channel,
            rssi=rssi,
            access_address=aa,
            adv_address=adv_addr,
            adv_type=adv_type,
            adv_type_name=adv_type_name,
            payload=raw,
            conn_aa=conn_aa,
            hop_increment=hop_increment,
            crc_init=crc_init,
            llid=llid,
        )

    # ── cleanup ──────────────────────────────────────────────────────────────

    def _cleanup(self):
        if self._conn:
            try: self._conn.stop()
            except Exception: pass
            self._conn = None
        if self._dev:
            try: self._dev.close()
            except Exception: pass
            self._dev = None
