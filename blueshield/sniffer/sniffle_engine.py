"""
Sniffle Engine — BLE packet capture backend.

Tries to import the real Sniffle library (nccgroup/Sniffle).
If unavailable, falls back to SimulatedSniffleEngine which produces
realistic synthetic BLE traffic for UI development and testing.

Real hardware: TI CC1352R / CC26x2 / LAUNCHXL-CC26X2R1 on /dev/ttyACM0

Packet types emitted via callback:
  "adv"         — ADV_IND / ADV_NONCONN_IND / ADV_EXT_IND
  "scan_rsp"    — SCAN_RSP
  "connect_ind" — CONNECT_IND (connection setup)
  "data"        — LL data PDU (L2CAP, ATT, SMP)
  "state"       — sniffer state change (SCANNING → CONNECTED, etc.)
  "error"       — hardware/decode error
"""

from __future__ import annotations

import math
import os
import random
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


# ── Simulated engine (no hardware required) ──────────────────────────────────

_SIMULATED_DEVICES = [
    ("E4:28:B2:11:A0:01", "iPhone 15",           0x004C, "ADV_IND"),
    ("A0:B1:C2:D3:E4:F5", "Galaxy Buds2 Pro",    0x0075, "ADV_IND"),
    ("11:22:33:44:55:66", "Tile Slim",            0x00E0, "ADV_NONCONN_IND"),
    ("AA:BB:CC:DD:EE:01", "Smart Thermostat",     0x0000, "ADV_IND"),
    ("DE:AD:BE:EF:00:01", "Unknown BLE Device",  None,   "ADV_NONCONN_IND"),
    ("B8:27:EB:12:34:56", "Raspberry Pi",         None,   "ADV_IND"),
    ("C0:FF:EE:BA:BE:01", "Fitbit Sense 2",       0x0000, "ADV_IND"),
    ("08:3A:88:AB:CD:EF", "MacBook Pro",          0x004C, "ADV_IND"),
]

_CONN_PAIRS = [
    ("E4:28:B2:11:A0:01", "AA:BB:CC:DD:EE:01"),
    ("08:3A:88:AB:CD:EF", "C0:FF:EE:BA:BE:01"),
]


class SimulatedSniffleEngine(_BaseSniffleEngine):
    """
    Simulated BLE sniffer that generates realistic synthetic traffic.

    Produces:
      - Advertisement floods from _SIMULATED_DEVICES at realistic intervals
      - Periodic CONNECT_IND pairs followed by L2CAP/ATT data PDUs
      - One complete SMP legacy Just Works pairing sequence (crackable)
      - One LESC pairing sequence
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.hardware_available = False   # mark as simulated
        self._adv_seq   = 0
        self._conn_aas: Dict[str, int] = {}   # peripheral → access address

    def _run_loop(self, target_mac, rssi_min, coded_phy):
        self._emit_state("SCANNING")
        adv_timer      = 0.0
        conn_timer     = 15.0
        legacy_pair_ts = 30.0
        lesc_pair_ts   = 60.0
        t0 = time.monotonic()

        while self._running:
            elapsed = time.monotonic() - t0

            # Advertisement flood every ~0.5s
            if elapsed >= adv_timer:
                self._emit_simulated_advs(target_mac, rssi_min)
                adv_timer = elapsed + 0.5 + random.uniform(-0.1, 0.1)

            # Simulate a connection setup
            if elapsed >= conn_timer and len(self.connections) < 4:
                self._emit_simulated_connection()
                conn_timer = elapsed + 20.0 + random.uniform(-3, 3)

            # Legacy Just Works pairing (crackable demo)
            if elapsed >= legacy_pair_ts and not hasattr(self, "_legacy_done"):
                self._emit_legacy_pairing()
                self._legacy_done = True

            # LESC pairing demo
            if elapsed >= lesc_pair_ts and not hasattr(self, "_lesc_done"):
                self._emit_lesc_pairing()
                self._lesc_done = True

            # Data PDUs on active connections
            if self._conn_aas and random.random() < 0.3:
                self._emit_data_pdu()

            time.sleep(0.05)

    # ── simulated emission helpers ────────────────────────────────────────────

    def _emit_simulated_advs(self, target_mac, rssi_min):
        now = time.time()
        n = random.randint(2, 5)
        for _ in range(n):
            mac, name, mfr_id, pdu_type_name = random.choice(_SIMULATED_DEVICES)
            if target_mac and mac.upper() != target_mac.upper():
                continue

            rssi = random.randint(-85, -40)
            if rssi < rssi_min:
                continue

            channel = random.choice([37, 38, 39])
            adv_type = {"ADV_IND": 0x00, "ADV_NONCONN_IND": 0x02}.get(pdu_type_name, 0x00)

            payload = self._build_adv_payload(name, mfr_id)

            pkt = BLEPacket(
                ts=now,
                pkt_type="adv",
                channel=channel,
                rssi=rssi,
                access_address=0x8E89BED6,
                adv_address=mac,
                adv_type=adv_type,
                adv_type_name=ADV_PDU_TYPES.get(adv_type),
                payload=payload,
                adv_name=name,
                manufacturer=self._mfr_name(mfr_id),
            )
            self._emit_packet(pkt)

    def _emit_simulated_connection(self):
        if not _CONN_PAIRS:
            return
        central, peripheral = random.choice(_CONN_PAIRS)
        conn_aa   = random.randint(0x10000000, 0xEFFFFFFF)
        hop_inc   = random.randint(5, 16)
        crc_init  = random.randint(0, 0xFFFFFF)

        # Build a minimal CONNECT_IND payload
        def mac_to_bytes(mac):
            return bytes(int(b, 16) for b in reversed(mac.split(":")))

        init_a = mac_to_bytes(central)
        adv_a  = mac_to_bytes(peripheral)
        aa_b   = struct.pack("<I", conn_aa)
        crc_b  = crc_init.to_bytes(3, "little")
        rest   = bytes([1, 0, 0, 6, 0, 0, 1, 0, 200, 0]) + b'\xff\xff\xff\xff\x1f' + bytes([hop_inc])

        # PDU header: type=CONNECT_IND(5), length=34
        pdu_hdr = bytes([0x05, 34])
        pdu_payload = pdu_hdr + init_a + adv_a + aa_b + crc_b + rest

        pkt = BLEPacket(
            ts=time.time(),
            pkt_type="connect_ind",
            channel=random.choice([37, 38, 39]),
            rssi=random.randint(-70, -45),
            access_address=0x8E89BED6,
            adv_address=peripheral,
            adv_type=0x05,
            adv_type_name="CONNECT_IND",
            payload=pdu_payload,
        )
        self._emit_packet(pkt)
        self._handle_connect_ind(pkt)
        self._conn_aas[peripheral] = conn_aa
        self._emit_state("CONNECTED")

    def _emit_data_pdu(self):
        if not self._conn_aas:
            return
        peripheral, conn_aa = random.choice(list(self._conn_aas.items()))
        # Simulate ATT Read Response
        att_op = random.choice([0x0b, 0x1b, 0x09])
        att_val = bytes(random.getrandbits(8) for _ in range(random.randint(2, 18)))
        l2cap = struct.pack("<HH", len(att_val) + 1, 0x0004) + bytes([att_op]) + att_val
        ll_hdr = struct.pack("<BB", 0x02, len(l2cap))  # LLID=2, length

        pkt = BLEPacket(
            ts=time.time(),
            pkt_type="data",
            channel=random.randint(0, 36),
            rssi=random.randint(-75, -40),
            access_address=conn_aa,
            adv_address=None,
            adv_type=None,
            adv_type_name=None,
            payload=ll_hdr + l2cap,
            llid=2,
            data_length=len(l2cap),
        )
        self._emit_packet(pkt)
        self._handle_data_pdu(pkt)

    def _emit_legacy_pairing(self):
        """Emit a complete Legacy Just Works pairing (Just Works, TK=0)."""
        # Use one of the active connections if available
        if not self._conn_aas:
            # create a synthetic connection first
            self._emit_simulated_connection()
            time.sleep(0.1)

        if not self._conn_aas:
            return

        peripheral, conn_aa = next(iter(self._conn_aas.items()))
        ts = time.time()

        # io_cap=NoInputNoOutput, oob=none, auth_req=bonding(01)|SC=0 → legacy
        pairing_req  = bytes([0x01, 0x03, 0x00, 0x01, 0x10, 0x05, 0x05])
        pairing_rsp  = bytes([0x02, 0x03, 0x00, 0x01, 0x10, 0x05, 0x05])
        mconfirm     = bytes([0x03]) + bytes(os.urandom(16))
        sconfirm     = bytes([0x03]) + bytes(os.urandom(16))
        mrand        = bytes([0x04]) + bytes(os.urandom(16))
        srand        = bytes([0x04]) + bytes(os.urandom(16))

        for smp_payload in [pairing_req, pairing_rsp, mconfirm, sconfirm, mrand, srand]:
            l2cap  = struct.pack("<HH", len(smp_payload), 0x0006) + smp_payload
            ll_hdr = struct.pack("<BB", 0x02, len(l2cap))
            pkt = BLEPacket(
                ts=ts, pkt_type="data", channel=random.randint(0, 36),
                rssi=-55, access_address=conn_aa, adv_address=None,
                adv_type=None, adv_type_name=None,
                payload=ll_hdr + l2cap, llid=2, data_length=len(l2cap),
            )
            self._emit_packet(pkt)
            self._handle_data_pdu(pkt)
            ts += 0.015

    def _emit_lesc_pairing(self):
        """Emit a LESC pairing sequence (LE Secure Connections)."""
        if not self._conn_aas:
            return

        peripheral, conn_aa = list(self._conn_aas.items())[-1]
        ts = time.time()

        # auth_req with SC bit set (0x08+0x01=0x09)
        pairing_req  = bytes([0x01, 0x01, 0x00, 0x09, 0x10, 0x09, 0x09])
        pairing_rsp  = bytes([0x02, 0x01, 0x00, 0x09, 0x10, 0x09, 0x09])
        pub_key_init = bytes([0x0C]) + bytes(os.urandom(64))
        pub_key_resp = bytes([0x0C]) + bytes(os.urandom(64))
        dhkey_check  = bytes([0x0D]) + bytes(os.urandom(16))

        for smp_payload in [pairing_req, pairing_rsp, pub_key_init, pub_key_resp, dhkey_check]:
            l2cap  = struct.pack("<HH", len(smp_payload), 0x0006) + smp_payload
            ll_hdr = struct.pack("<BB", 0x02, len(l2cap))
            pkt = BLEPacket(
                ts=ts, pkt_type="data", channel=random.randint(0, 36),
                rssi=-52, access_address=conn_aa, adv_address=None,
                adv_type=None, adv_type_name=None,
                payload=ll_hdr + l2cap, llid=2, data_length=len(l2cap),
            )
            self._emit_packet(pkt)
            self._handle_data_pdu(pkt)
            ts += 0.02

    # ── helpers ───────────────────────────────────────────────────────────────

    def _build_adv_payload(self, name: str, mfr_id: Optional[int]) -> bytes:
        b = bytearray()
        # Flags: LE General Discoverable, no BR/EDR
        b += bytes([2, 0x01, 0x06])
        # Complete local name
        name_b = name.encode("utf-8")[:29]
        b += bytes([len(name_b) + 1, 0x09]) + name_b
        # Manufacturer specific
        if mfr_id is not None:
            mfr_b = struct.pack("<H", mfr_id) + bytes(os.urandom(4))
            b += bytes([len(mfr_b) + 1, 0xFF]) + mfr_b
        return bytes(b)

    def _mfr_name(self, mfr_id: Optional[int]) -> Optional[str]:
        names = {0x004C: "Apple", 0x0075: "Samsung", 0x00E0: "Google",
                 0x0006: "Microsoft", 0x0059: "Nordic"}
        return names.get(mfr_id) if mfr_id is not None else None


# ── Factory function ─────────────────────────────────────────────────────────

def make_sniffer(
    sim: bool = False,
    serial_port: str = "/dev/ttyACM0",
    pcap_dir: str = "/tmp/blueshield_pcaps",
) -> _BaseSniffleEngine:
    """
    Return a sniffer engine — REAL hardware by default, sim only if explicit.

    IMPORTANT: This function will NEVER silently return simulated data.
    If the user did not pass sim=True and real hardware is not available,
    returns a disabled engine that surfaces `hardware_available=False` to
    the dashboard, which must show "sniffer unavailable" instead of fake data.

    Args:
        sim:         Only set True when --sim CLI flag is explicit.
        serial_port: Serial port for real Sniffle hardware.
        pcap_dir:    Directory for PCAP output files.
    """
    if sim:
        # Explicit simulation request (e.g., development without hardware)
        eng = SimulatedSniffleEngine(pcap_dir=pcap_dir)
        eng._is_simulated_explicit = True
        return eng

    # Prefer Sniffle-firmware if installed; otherwise fall back to ButteRFly
    # via WHAD (this is what we ship with — see whad_sniffer_engine.py).
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

    # Neither backend available — return the Sniffle engine so the UI can
    # surface hardware_available=False (never silently switch to sim).
    return sniffle_eng
