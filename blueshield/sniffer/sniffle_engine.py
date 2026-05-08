"""
Sniffle Engine — BLE packet capture backend (real hardware only).

Tries to import the real Sniffle library (nccgroup/Sniffle) for TI CC1352/CC2652
hardware. On systems without that hardware, the WhadSniffleEngine backend is
used instead (nRF52840 + WHAD ButteRFly firmware — what BlueShield ships).

Packet types emitted via callback:
  "adv"         — ADV_IND / ADV_NONCONN_IND / ADV_EXT_IND
  "scan_rsp"    — SCAN_RSP
  "connect_ind" — CONNECT_IND (connection setup)
  "data"        — LL data PDU (L2CAP, ATT, SMP)
  "state"       — sniffer state change (SCANNING -> CONNECTED, etc.)
  "error"       — hardware/decode error
"""

from __future__ import annotations

import math
import os
import struct
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from .pairing_detector import PairingDetector, PairingEvent
from .pcap_writer import PCAPWriter


# ── Packet data model ────────────────────────────────────────────────────────

@dataclass
class BLEPacket:
    """Normalised BLE packet (advertising or data)."""
    ts: float
    pkt_type: str                      # "adv" | "scan_rsp" | "connect_ind" | "data"
    channel: int
    rssi: int
    access_address: int                # 0x8E89BED6 for advertising
    adv_address: Optional[str]         # advertiser MAC (advertising pkts)
    adv_type: Optional[int]            # PDU type nibble
    adv_type_name: Optional[str]
    payload: bytes                     # raw PDU bytes (after AA, no CRC)
    # Connection-specific
    conn_aa: Optional[int] = None      # negotiated access address (CONNECT_IND)
    hop_increment: Optional[int] = None
    crc_init: Optional[int] = None
    # Data PDU
    llid: Optional[int] = None
    data_length: Optional[int] = None
    # Decoded name / manufacturer
    adv_name: Optional[str] = None
    manufacturer: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "ts":              self.ts,
            "pkt_type":        self.pkt_type,
            "channel":         self.channel,
            "rssi":            self.rssi,
            "access_address":  f"0x{self.access_address:08X}",
            "adv_address":     self.adv_address,
            "adv_type":        self.adv_type,
            "adv_type_name":   self.adv_type_name,
            "payload_hex":     self.payload.hex() if self.payload else "",
            "payload_len":     len(self.payload) if self.payload else 0,
            "conn_aa":         f"0x{self.conn_aa:08X}" if self.conn_aa else None,
            "hop_increment":   self.hop_increment,
            "crc_init":        f"0x{self.crc_init:06X}" if self.crc_init else None,
            "llid":            self.llid,
            "data_length":     self.data_length,
            "adv_name":        self.adv_name,
            "manufacturer":    self.manufacturer,
        }


@dataclass
class ConnectionRecord:
    """Tracks a captured BLE connection."""
    session_id: str
    access_address: int
    central_mac: str
    peripheral_mac: str
    start_ts: float
    end_ts: Optional[float] = None
    hop_increment: int = 5
    crc_init: int = 0
    channel_map: int = 0x1FFFFFFFFF    # all 37 data channels
    packet_count: int = 0
    data_bytes: int = 0

    def to_dict(self) -> dict:
        return {
            "session_id":      self.session_id,
            "access_address":  f"0x{self.access_address:08X}",
            "central_mac":     self.central_mac,
            "peripheral_mac":  self.peripheral_mac,
            "start_ts":        self.start_ts,
            "end_ts":          self.end_ts,
            "duration_s":      round(self.end_ts - self.start_ts, 2) if self.end_ts else None,
            "hop_increment":   self.hop_increment,
            "crc_init":        f"0x{self.crc_init:06X}",
            "packet_count":    self.packet_count,
            "data_bytes":      self.data_bytes,
        }


# ── ADV PDU type table ───────────────────────────────────────────────────────

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

MANUFACTURER_PREFIXES: Dict[str, str] = {
    "4C:00": "Apple",
    "00:00": "Ericsson",
    "75:00": "Samsung",
    "E0:00": "Google",
    "06:00": "Microsoft",
}


# ── Base engine interface ────────────────────────────────────────────────────

class _BaseSniffleEngine:
    """
    Abstract base for both real and simulated sniffer engines.

    Subclasses must implement _run_loop().

    Callbacks:
        on_packet(BLEPacket)               — every captured packet
        on_connection(ConnectionRecord)    — new CONNECT_IND detected
        on_pairing(PairingEvent)           — SMP pairing event detected
        on_state(str)                      — state change string
        on_error(str)                      — error message
    """

    def __init__(self, pcap_dir: str = "/tmp/blueshield_pcaps"):
        self.pcap_dir = pcap_dir
        os.makedirs(pcap_dir, exist_ok=True)

        self._running  = False
        self._thread: Optional[threading.Thread] = None

        self.on_packet:     Optional[Callable[[BLEPacket], None]]          = None
        self.on_connection: Optional[Callable[[ConnectionRecord], None]]   = None
        self.on_pairing:    Optional[Callable[[PairingEvent], None]]       = None
        self.on_state:      Optional[Callable[[str], None]]                = None
        self.on_error:      Optional[Callable[[str], None]]                = None

        # State
        self.packets:      List[BLEPacket]      = []
        self.connections:  List[ConnectionRecord] = []
        self._pkt_counter  = 0
        self._conn_counter = 0

        self.pairing_detector = PairingDetector()
        self._pcap: Optional[PCAPWriter] = None
        self._pcap_lock = threading.Lock()

    # ── public ───────────────────────────────────────────────────────────────

    def start(
        self,
        target_mac: Optional[str] = None,
        rssi_min: int = -100,
        coded_phy: bool = False,
    ) -> None:
        if self._running:
            return
        self._running = True
        self._start_pcap()
        self._thread = threading.Thread(
            target=self._run_loop,
            args=(target_mac, rssi_min, coded_phy),
            daemon=True,
            name="SniffleEngine",
        )
        self._thread.start()
        self._emit_state("SCANNING")

    def stop(self) -> None:
        self._running = False
        self._stop_pcap()
        self._emit_state("IDLE")

    def get_stats(self) -> dict:
        return {
            "running":       self._running,
            "packet_count":  self._pkt_counter,
            "connection_count": len(self.connections),
            "pcap_path":     str(self._current_pcap_path) if hasattr(self, "_current_pcap_path") else None,
            "pcap_size":     self._pcap.file_size if self._pcap else 0,
        }

    def get_recent_packets(self, count: int = 100) -> List[dict]:
        return [p.to_dict() for p in self.packets[-count:]]

    def get_connections(self) -> List[dict]:
        return [c.to_dict() for c in self.connections]

    # ── internal ─────────────────────────────────────────────────────────────

    def _run_loop(self, target_mac, rssi_min, coded_phy):
        raise NotImplementedError

    def _emit_packet(self, pkt: BLEPacket) -> None:
        self.packets.append(pkt)
        if len(self.packets) > 2000:
            self.packets = self.packets[-2000:]
        self._pkt_counter += 1

        # Write to PCAP
        if self._pcap:
            with self._pcap_lock:
                try:
                    self._pcap.write_packet(
                        payload=pkt.payload,
                        channel=pkt.channel,
                        rssi=pkt.rssi,
                        access_address=pkt.access_address,
                    )
                except Exception:
                    pass

        if self.on_packet:
            self.on_packet(pkt)

    def _handle_connect_ind(self, pkt: BLEPacket) -> None:
        """Parse CONNECT_IND payload and register a new connection."""
        if not pkt.payload or len(pkt.payload) < 22:
            return

        # CONNECT_IND PDU structure (after 2-byte PDU header):
        #   InitA[6] AdvA[6] AA[4] CRCInit[3] WinSize[1] WinOffset[2]
        #   Interval[2] Latency[2] Timeout[2] ChM[5] Hop+SCA[1]
        try:
            offset    = 2   # skip PDU header bytes in the payload
            # InitA = central
            init_a    = pkt.payload[offset: offset + 6]
            adv_a     = pkt.payload[offset + 6: offset + 12]
            conn_aa,  = struct.unpack_from("<I", pkt.payload, offset + 12)
            crc_init  = int.from_bytes(pkt.payload[offset + 16: offset + 19], "little")
            hop_sca   = pkt.payload[offset + 33] if len(pkt.payload) > offset + 33 else 0
            hop_inc   = hop_sca & 0x1F   # lower 5 bits

            def mac_from_bytes(b: bytes) -> str:
                return ":".join(f"{x:02X}" for x in reversed(b))

            central_mac    = mac_from_bytes(init_a)
            peripheral_mac = mac_from_bytes(adv_a)

            conn = ConnectionRecord(
                session_id=f"conn_{self._conn_counter:04d}",
                access_address=conn_aa,
                central_mac=central_mac,
                peripheral_mac=peripheral_mac,
                start_ts=pkt.ts,
                hop_increment=hop_inc,
                crc_init=crc_init,
            )
            self._conn_counter += 1
            self.connections.append(conn)
            if len(self.connections) > 200:
                self.connections = self.connections[-200:]

            # Register with pairing detector
            self.pairing_detector.register_connection(
                conn_aa, central_mac, peripheral_mac, pkt.ts
            )

            # Update packet with parsed fields
            pkt.conn_aa        = conn_aa
            pkt.hop_increment  = hop_inc
            pkt.crc_init       = crc_init

            if self.on_connection:
                self.on_connection(conn)

        except Exception as e:
            self._emit_error(f"CONNECT_IND parse error: {e}")

    def _handle_data_pdu(self, pkt: BLEPacket) -> None:
        """Feed data PDU to pairing detector."""
        if len(pkt.payload) < 6:
            return
        # LL Data PDU: 2 bytes header, then L2CAP
        ll_payload = pkt.payload[2:]
        smp_pkt = self.pairing_detector.ingest_data_pdu(
            pkt.access_address, ll_payload, pkt.ts
        )
        if smp_pkt and self.on_pairing:
            # Find the session
            sessions = self.pairing_detector._sessions
            session = sessions.get(pkt.access_address)
            if session:
                self.on_pairing(session)

    def _start_pcap(self) -> None:
        fname = f"blueshield_{int(time.time())}.pcap"
        self._current_pcap_path = os.path.join(self.pcap_dir, fname)
        try:
            self._pcap = PCAPWriter(self._current_pcap_path)
        except Exception as e:
            self._pcap = None
            self._emit_error(f"Could not open PCAP: {e}")

    def _stop_pcap(self) -> None:
        if self._pcap:
            with self._pcap_lock:
                self._pcap.close()
                self._pcap = None

    def _emit_state(self, state: str) -> None:
        if self.on_state:
            self.on_state(state)

    def _emit_error(self, msg: str) -> None:
        if self.on_error:
            self.on_error(msg)


# ── Real Sniffle hardware engine ─────────────────────────────────────────────

class SniffleEngine(_BaseSniffleEngine):
    """
    Hardware-backed engine using the nccgroup/Sniffle Python API.

    Requires: pip install sniffle (and flashed TI CC1352/CC26x2 hardware)

    Falls back gracefully if hardware is absent — check .hardware_available
    after construction.
    """

    def __init__(self, serial_port: str = "/dev/ttyACM0", **kwargs):
        super().__init__(**kwargs)
        self.serial_port = serial_port
        self.hardware_available = False
        self._hw = None

        try:
            from sniffle.sniffle_hw import make_sniffle_hw  # type: ignore
            self._make_hw = make_sniffle_hw
            self.hardware_available = True
        except ImportError:
            pass

    def _run_loop(self, target_mac, rssi_min, coded_phy):
        if not self.hardware_available:
            self._emit_error("Sniffle library not installed (pip install sniffle)")
            self._running = False
            return

        try:
            from sniffle.sniffle_hw import (  # type: ignore
                SnifferMode, PacketMessage, DebugMessage, StateMessage,
            )
            from sniffle.packet_decoder import (  # type: ignore
                AdvaMessage, ScanRspMessage, DataMessage,
            )

            hw = self._make_hw(serport=self.serial_port, baud=2000000)

            targ_bytes = None
            if target_mac:
                try:
                    targ_bytes = [int(b, 16) for b in target_mac.split(":")]
                except Exception:
                    pass

            hw.setup_sniffer(
                mode=SnifferMode.CONN_FOLLOW,
                chan=37,
                targ_mac=targ_bytes,
                targ_irk=None,
                hop3=True,
                ext_adv=False,
                coded_phy=coded_phy,
                rssi_min=rssi_min,
                validate_crc=True,
            )
            hw.mark_and_flush()
            self._hw = hw

            while self._running:
                msg = hw.recv_and_decode()

                if isinstance(msg, PacketMessage):
                    pkt = self._decode_sniffle_packet(msg)
                    if pkt:
                        self._emit_packet(pkt)
                        if pkt.adv_type == 0x05:   # CONNECT_IND
                            self._handle_connect_ind(pkt)
                        elif pkt.pkt_type == "data":
                            self._handle_data_pdu(pkt)

                elif isinstance(msg, StateMessage):
                    state_names = {0: "ADVERTISING", 1: "INITIATING",
                                   2: "CONNECTED",   3: "SCANNING"}
                    self._emit_state(state_names.get(msg.state, f"STATE_{msg.state}"))

        except Exception as e:
            self._emit_error(f"Sniffle hardware error: {e}")
        finally:
            self._running = False
            if self._hw:
                try:
                    self._hw.cancel_recv()
                except Exception:
                    pass

    def _decode_sniffle_packet(self, msg) -> Optional[BLEPacket]:
        """Convert a Sniffle PacketMessage into our BLEPacket."""
        try:
            from sniffle.packet_decoder import (  # type: ignore
                AdvaMessage, AdvDirectIndMessage, AdvExtIndMessage,
                ScanRspMessage, DataMessage,
            )

            ts       = msg.ts_epoch if hasattr(msg, "ts_epoch") else time.time()
            channel  = getattr(msg, "chan", 37)
            rssi     = getattr(msg, "rssi", 0)
            aa       = getattr(msg, "access_address", 0x8E89BED6)
            body     = bytes(getattr(msg, "body", b""))

            if isinstance(msg, (AdvaMessage, AdvDirectIndMessage)):
                adv_a = getattr(msg, "AdvA", None)
                adv_t = getattr(msg, "PDU_type", 0)
                return BLEPacket(
                    ts=ts, pkt_type="adv", channel=channel, rssi=rssi,
                    access_address=aa, adv_address=str(adv_a) if adv_a else None,
                    adv_type=adv_t, adv_type_name=ADV_PDU_TYPES.get(adv_t),
                    payload=body,
                )

            elif isinstance(msg, ScanRspMessage):
                adv_a = getattr(msg, "AdvA", None)
                return BLEPacket(
                    ts=ts, pkt_type="scan_rsp", channel=channel, rssi=rssi,
                    access_address=aa, adv_address=str(adv_a) if adv_a else None,
                    adv_type=0x04, adv_type_name="SCAN_RSP",
                    payload=body,
                )

            elif isinstance(msg, DataMessage):
                llid = getattr(msg, "llid", 0)
                dlen = getattr(msg, "data_length", len(body))
                return BLEPacket(
                    ts=ts, pkt_type="data", channel=channel, rssi=rssi,
                    access_address=aa, adv_address=None,
                    adv_type=None, adv_type_name=None,
                    payload=body, llid=llid, data_length=dlen,
                )

        except Exception:
            pass
        return None




# ── Factory function ─────────────────────────────────────────────────────────

def make_sniffer(
    serial_port: str = "/dev/ttyACM0",
    pcap_dir: str = "/tmp/blueshield_pcaps",
) -> _BaseSniffleEngine:
    """
    Return a real sniffer engine. No simulation paths — real hardware only.
    If hardware is unavailable, returns an engine with hardware_available=False
    so the dashboard surfaces "sniffer unavailable" rather than fake data.

    Backend selection:
      1. TI CC1352/CC2652 with Sniffle firmware (if `/dev/ttyACM*` matches)
      2. nRF52840 ButteRFly via WHAD (this is what BlueShield ships with)
    """
    sniffle_eng = SniffleEngine(serial_port=serial_port, pcap_dir=pcap_dir)
    if sniffle_eng.hardware_available:
        return sniffle_eng

    try:
        from .whad_sniffer_engine import WhadSniffleEngine
        whad_eng = WhadSniffleEngine(serial_port=serial_port, pcap_dir=pcap_dir)
        if whad_eng.hardware_available:
            return whad_eng
    except Exception:
        pass

    # Neither backend available — surface hardware_available=False to UI.
    return sniffle_eng
