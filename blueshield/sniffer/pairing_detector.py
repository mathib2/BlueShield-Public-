"""
BLE SMP (Security Manager Protocol) Pairing Detector.

Parses L2CAP/SMP packets extracted from BLE data PDUs and classifies
pairing exchanges as Legacy or LE Secure Connections (LESC).

SMP sits on L2CAP CID 0x0006.  L2CAP basic-mode header (4 bytes):
  [0:2] length   uint16le  — payload length (not including this header)
  [2:4] CID      uint16le  — 0x0006 for SMP

SMP AuthReq flags byte (in Pairing Request / Pairing Response):
  bit 0-1: Bonding_Flags (00=no bond, 01=bond)
  bit 2:   MITM
  bit 3:   SC   ← 1 = LE Secure Connections requested
  bit 4:   Keypress
  bit 5:   CT2

Connection event context: once CONNECT_IND is seen, subsequent data PDUs
on that connection's access address are queued here.
"""

from __future__ import annotations

import struct
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


# ── Constants ────────────────────────────────────────────────────────────────

L2CAP_CID_SMP = 0x0006
L2CAP_CID_ATT = 0x0004

# SMP command codes
SMP_PAIRING_REQUEST        = 0x01
SMP_PAIRING_RESPONSE       = 0x02
SMP_PAIRING_CONFIRM        = 0x03
SMP_PAIRING_RANDOM         = 0x04
SMP_PAIRING_FAILED         = 0x05
SMP_ENCRYPTION_INFORMATION = 0x06   # LTK (legacy)
SMP_MASTER_IDENTIFICATION  = 0x07   # EDIV + Rand (legacy)
SMP_IDENTITY_INFORMATION   = 0x08   # IRK
SMP_IDENTITY_ADDR_INFO     = 0x09
SMP_SIGNING_INFORMATION    = 0x0A
SMP_SECURITY_REQUEST       = 0x0B
SMP_PAIRING_PUBLIC_KEY     = 0x0C   # LESC only
SMP_PAIRING_DHKEY_CHECK    = 0x0D   # LESC only
SMP_PAIRING_KEYPRESS       = 0x0E

SMP_COMMAND_NAMES = {
    SMP_PAIRING_REQUEST:        "Pairing Request",
    SMP_PAIRING_RESPONSE:       "Pairing Response",
    SMP_PAIRING_CONFIRM:        "Pairing Confirm",
    SMP_PAIRING_RANDOM:         "Pairing Random",
    SMP_PAIRING_FAILED:         "Pairing Failed",
    SMP_ENCRYPTION_INFORMATION: "Encryption Information (LTK)",
    SMP_MASTER_IDENTIFICATION:  "Master Identification",
    SMP_IDENTITY_INFORMATION:   "Identity Information (IRK)",
    SMP_IDENTITY_ADDR_INFO:     "Identity Address Info",
    SMP_SIGNING_INFORMATION:    "Signing Information (CSRK)",
    SMP_SECURITY_REQUEST:       "Security Request",
    SMP_PAIRING_PUBLIC_KEY:     "Pairing Public Key",
    SMP_PAIRING_DHKEY_CHECK:    "Pairing DHKey Check",
    SMP_PAIRING_KEYPRESS:       "Pairing Keypress Notification",
}

SMP_FAILURE_REASONS = {
    0x01: "Passkey Entry Failed",
    0x02: "OOB Not Available",
    0x03: "Authentication Requirements",
    0x04: "Confirm Value Failed",
    0x05: "Pairing Not Supported",
    0x06: "Encryption Key Size",
    0x07: "Command Not Supported",
    0x08: "Unspecified Reason",
    0x09: "Repeated Attempts",
    0x0A: "Invalid Parameters",
    0x0B: "DHKey Check Failed",
    0x0C: "Numeric Comparison Failed",
    0x0D: "BR/EDR Pairing in Progress",
    0x0E: "Cross-Transport Key Derivation Not Allowed",
}

IO_CAPABILITY_NAMES = {
    0x00: "DisplayOnly",
    0x01: "DisplayYesNo",
    0x02: "KeyboardOnly",
    0x03: "NoInputNoOutput",
    0x04: "KeyboardDisplay",
}

AUTH_METHOD_NAMES = {
    0x00: "Just Works",
    0x01: "Passkey Entry (Initiator displays)",
    0x02: "Passkey Entry (Responder displays)",
    0x03: "Passkey Entry (Both keyboard)",
    0x04: "Numeric Comparison",
    0x05: "OOB",
}


class PairingType(Enum):
    UNKNOWN  = "unknown"
    LEGACY   = "legacy"         # LE Legacy Pairing (vulnerable to crackle when Just Works)
    LESC     = "lesc"           # LE Secure Connections (ECDH-based, crackle-immune)


@dataclass
class SMPPacket:
    """A single decoded SMP command."""
    ts: float
    access_address: int
    command: int
    command_name: str
    raw_payload: bytes             # bytes after the command byte
    details: dict = field(default_factory=dict)


@dataclass
class PairingEvent:
    """
    A complete (or in-progress) BLE pairing exchange between two devices.
    Accumulates SMP packets as they arrive.
    """
    session_id: str
    access_address: int
    central_mac: str               # device initiating connection
    peripheral_mac: str            # device receiving connection
    start_ts: float
    end_ts: Optional[float] = None

    pairing_type: PairingType = PairingType.UNKNOWN
    auth_method: str = "Unknown"
    mitm_protected: bool = False
    bonding: bool = False
    sc_requested: bool = False     # both sides requested SC
    just_works: bool = False       # TK=0 — crackle-vulnerable!

    # Extracted crypto material (present only for legacy captures)
    mconfirm: Optional[bytes] = None
    sconfirm: Optional[bytes] = None
    mrand: Optional[bytes] = None
    srand: Optional[bytes] = None
    ltk: Optional[bytes] = None
    ediv: Optional[int] = None
    rand_val: Optional[bytes] = None

    packets: List[SMPPacket] = field(default_factory=list)
    failed: bool = False
    failure_reason: str = ""
    crackable: bool = False        # legacy + just_works → crackable with crackle
    pcap_path: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "session_id":       self.session_id,
            "access_address":   f"0x{self.access_address:08X}",
            "central_mac":      self.central_mac,
            "peripheral_mac":   self.peripheral_mac,
            "start_ts":         self.start_ts,
            "end_ts":           self.end_ts,
            "duration_ms":      int((self.end_ts - self.start_ts) * 1000) if self.end_ts else None,
            "pairing_type":     self.pairing_type.value,
            "auth_method":      self.auth_method,
            "mitm_protected":   self.mitm_protected,
            "bonding":          self.bonding,
            "sc_requested":     self.sc_requested,
            "just_works":       self.just_works,
            "crackable":        self.crackable,
            "failed":           self.failed,
            "failure_reason":   self.failure_reason,
            "packet_count":     len(self.packets),
            "pcap_path":        self.pcap_path,
            "packets": [
                {
                    "ts":           p.ts,
                    "command":      f"0x{p.command:02X}",
                    "name":         p.command_name,
                    "hex":          p.raw_payload.hex(),
                    "details":      p.details,
                }
                for p in self.packets
            ],
        }


class PairingDetector:
    """
    Stateful SMP pairing session tracker.

    Feed raw BLE data PDU payloads (after the 2-byte LL header) via
    ingest_data_pdu().  The detector tracks pairing sessions per
    access address and fires callbacks when events occur.

    Thread-safety: single-threaded; callers must synchronise externally.
    """

    def __init__(self):
        # active sessions keyed by access_address
        self._sessions: Dict[int, PairingEvent] = {}
        # completed sessions (capped at 100)
        self._history: List[PairingEvent] = []
        self._session_counter = 0

    # ── public API ───────────────────────────────────────────────────────────

    def register_connection(
        self,
        access_address: int,
        central_mac: str,
        peripheral_mac: str,
        ts: Optional[float] = None,
    ) -> None:
        """
        Call this when a CONNECT_IND is captured so the detector can associate
        MAC addresses with the resulting access address.
        """
        self._sessions[access_address] = PairingEvent(
            session_id=f"pair_{self._session_counter:04d}",
            access_address=access_address,
            central_mac=central_mac,
            peripheral_mac=peripheral_mac,
            start_ts=ts or time.time(),
        )
        self._session_counter += 1

    def ingest_data_pdu(
        self,
        access_address: int,
        ll_payload: bytes,
        ts: Optional[float] = None,
    ) -> Optional[SMPPacket]:
        """
        Process a BLE LL data PDU payload (bytes after the 2-byte LL header).

        Returns an SMPPacket if this was an SMP message, else None.
        """
        if len(ll_payload) < 4:
            return None

        l2cap_len, l2cap_cid = struct.unpack_from("<HH", ll_payload, 0)
        if l2cap_cid != L2CAP_CID_SMP:
            return None
        if len(ll_payload) < 4 + l2cap_len or l2cap_len < 1:
            return None

        smp_data    = ll_payload[4: 4 + l2cap_len]
        command     = smp_data[0]
        payload     = smp_data[1:]
        command_name = SMP_COMMAND_NAMES.get(command, f"Unknown(0x{command:02X})")

        details = self._decode_smp_command(command, payload)
        pkt = SMPPacket(
            ts=ts or time.time(),
            access_address=access_address,
            command=command,
            command_name=command_name,
            raw_payload=payload,
            details=details,
        )

        # Ensure a session exists (connection may have been missed)
        if access_address not in self._sessions:
            self._sessions[access_address] = PairingEvent(
                session_id=f"pair_{self._session_counter:04d}",
                access_address=access_address,
                central_mac="??:??:??:??:??:??",
                peripheral_mac="??:??:??:??:??:??",
                start_ts=pkt.ts,
            )
            self._session_counter += 1

        session = self._sessions[access_address]
        session.packets.append(pkt)
        self._update_session(session, pkt)

        return pkt

    def get_active_sessions(self) -> List[dict]:
        return [s.to_dict() for s in self._sessions.values()]

    def get_history(self) -> List[dict]:
        return [s.to_dict() for s in self._history]

    def close_connection(self, access_address: int) -> Optional[PairingEvent]:
        """Call when a connection is terminated to finalise the session."""
        session = self._sessions.pop(access_address, None)
        if session:
            session.end_ts = time.time()
            self._history.append(session)
            if len(self._history) > 100:
                self._history = self._history[-100:]
        return session

    # ── internal ─────────────────────────────────────────────────────────────

    def _update_session(self, session: PairingEvent, pkt: SMPPacket) -> None:
        """Update session state based on the incoming SMP packet."""
        cmd = pkt.command

        if cmd == SMP_PAIRING_REQUEST:
            self._apply_pairing_params(session, pkt.details, is_request=True)

        elif cmd == SMP_PAIRING_RESPONSE:
            self._apply_pairing_params(session, pkt.details, is_request=False)
            # Both sides have now declared their AuthReq — determine type
            self._finalise_pairing_type(session)

        elif cmd == SMP_PAIRING_PUBLIC_KEY:
            # LESC confirmed: public key exchange is LESC-exclusive
            session.pairing_type = PairingType.LESC
            session.sc_requested = True

        elif cmd == SMP_PAIRING_CONFIRM:
            if len(pkt.raw_payload) == 16:
                if session.mconfirm is None:
                    session.mconfirm = pkt.raw_payload
                else:
                    session.sconfirm = pkt.raw_payload

        elif cmd == SMP_PAIRING_RANDOM:
            if len(pkt.raw_payload) == 16:
                if session.mrand is None:
                    session.mrand = pkt.raw_payload
                else:
                    session.srand = pkt.raw_payload

        elif cmd == SMP_ENCRYPTION_INFORMATION:
            # LTK distributed — legacy pairing
            if len(pkt.raw_payload) >= 16:
                session.ltk = pkt.raw_payload[:16]

        elif cmd == SMP_MASTER_IDENTIFICATION:
            if len(pkt.raw_payload) >= 10:
                session.ediv     = struct.unpack_from("<H", pkt.raw_payload, 0)[0]
                session.rand_val = pkt.raw_payload[2:10]

        elif cmd == SMP_PAIRING_FAILED:
            session.failed = True
            reason_code    = pkt.raw_payload[0] if pkt.raw_payload else 0
            session.failure_reason = SMP_FAILURE_REASONS.get(reason_code, f"0x{reason_code:02X}")
            self._finalise_session(session)

        # Determine crackability after enough material is collected
        self._check_crackable(session)

    def _apply_pairing_params(self, session: PairingEvent, details: dict, is_request: bool) -> None:
        auth = details.get("auth_req_raw", 0)
        sc_bit = bool(auth & 0x08)
        mitm   = bool(auth & 0x04)
        bond   = bool(auth & 0x03)

        if is_request:
            session.sc_requested = sc_bit
        else:
            # Response: SC only if BOTH sides set SC bit
            session.sc_requested = session.sc_requested and sc_bit

        session.mitm_protected = session.mitm_protected or mitm
        session.bonding         = session.bonding or bool(bond)

    def _finalise_pairing_type(self, session: PairingEvent) -> None:
        """Called after Pairing Response is received."""
        if session.sc_requested:
            session.pairing_type = PairingType.LESC
        else:
            session.pairing_type = PairingType.LEGACY

        # Determine auth method from IO capabilities and MITM flag
        if session.pairing_type == PairingType.LEGACY:
            session.just_works = not session.mitm_protected

    def _check_crackable(self, session: PairingEvent) -> None:
        """
        A legacy Just Works session with Mconfirm + Sconfirm + Mrand + Srand
        is crackable by crackle in < 1 second (TK = 0).
        """
        if (
            session.pairing_type == PairingType.LEGACY
            and session.just_works
            and session.mconfirm is not None
            and session.sconfirm is not None
            and session.mrand is not None
            and session.srand is not None
        ):
            session.crackable = True

    def _finalise_session(self, session: PairingEvent) -> None:
        session.end_ts = time.time()

    def _decode_smp_command(self, command: int, payload: bytes) -> dict:
        """Decode SMP command payload into a human-readable dict."""
        d: dict = {}
        try:
            if command in (SMP_PAIRING_REQUEST, SMP_PAIRING_RESPONSE):
                if len(payload) >= 6:
                    d["io_capability"]     = IO_CAPABILITY_NAMES.get(payload[0], f"0x{payload[0]:02X}")
                    d["oob_data_flag"]     = "OOB Present" if payload[1] else "None"
                    auth_req               = payload[2]
                    d["auth_req_raw"]      = auth_req
                    d["bonding"]           = bool(auth_req & 0x03)
                    d["mitm"]              = bool(auth_req & 0x04)
                    d["sc"]                = bool(auth_req & 0x08)
                    d["keypress"]          = bool(auth_req & 0x10)
                    d["max_enc_key_size"]  = payload[3]
                    d["initiator_key_dist"]= f"0x{payload[4]:02X}"
                    d["responder_key_dist"]= f"0x{payload[5]:02X}"

            elif command in (SMP_PAIRING_CONFIRM, SMP_PAIRING_RANDOM):
                if len(payload) >= 16:
                    d["value_hex"] = payload[:16].hex()

            elif command == SMP_PAIRING_FAILED:
                code = payload[0] if payload else 0
                d["reason_code"] = f"0x{code:02X}"
                d["reason"]      = SMP_FAILURE_REASONS.get(code, "Unknown")

            elif command == SMP_ENCRYPTION_INFORMATION:
                if len(payload) >= 16:
                    d["ltk_hex"] = payload[:16].hex()
                    d["warning"] = "LTK exposed in plaintext — legacy pairing"

            elif command == SMP_PAIRING_PUBLIC_KEY:
                if len(payload) >= 64:
                    d["public_key_x"] = payload[:32].hex()
                    d["public_key_y"] = payload[32:64].hex()
                    d["note"] = "LE Secure Connections — ECDH P-256"

            elif command == SMP_PAIRING_DHKEY_CHECK:
                if len(payload) >= 16:
                    d["ea_or_eb"] = payload[:16].hex()

            elif command == SMP_SECURITY_REQUEST:
                if payload:
                    auth = payload[0]
                    d["bonding"] = bool(auth & 0x03)
                    d["mitm"]    = bool(auth & 0x04)
                    d["sc"]      = bool(auth & 0x08)

        except Exception:
            pass
        return d
