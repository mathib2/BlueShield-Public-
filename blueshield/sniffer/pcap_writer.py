"""
PCAP Writer for BLE captures.

Writes standard .pcap files using DLT_BLUETOOTH_LE_LL_WITH_PHDR (256),
the same link-layer type used by nRF Sniffer and Wireshark's BLE dissector.

No external dependencies — uses only struct and pathlib.

DLT_BLUETOOTH_LE_LL_WITH_PHDR pseudo-header (10 bytes):
  [0]   rf_channel     uint8  — BLE channel number (0–39)
  [1]   signal_power   int8   — RSSI in dBm (or 0x80 = invalid)
  [2]   noise_power    int8   — noise RSSI or 0x80
  [3]   access_address_offenses uint8
  [4:8] ref_access_address uint32le
  [8:10] flags          uint16le — bit 0: CRC ok, bit 10: MIC fail, bit 11: PHY 2M,
                                    bit 12: PHY coded
"""

import struct
import time
from pathlib import Path
from typing import Optional

# PCAP global header constants
PCAP_MAGIC_NUMBER  = 0xA1B2C3D4   # little-endian, microsecond timestamps
PCAP_VERSION_MAJOR = 2
PCAP_VERSION_MINOR = 4
PCAP_SNAPLEN       = 65535
DLT_BLUETOOTH_LE_LL_WITH_PHDR = 256


class PCAPWriter:
    """
    Thread-safe PCAP writer for BLE link-layer captures.

    Usage:
        writer = PCAPWriter("/tmp/capture.pcap")
        writer.write_packet(channel=37, rssi=-65, aa=0x8E89BED6, payload=bytes(...))
        writer.close()

    Or as a context manager:
        with PCAPWriter("/tmp/capture.pcap") as w:
            w.write_packet(...)
    """

    def __init__(self, path: str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = open(self.path, "wb")
        self._write_global_header()
        self._packet_count = 0

    # ── public interface ─────────────────────────────────────────────────────

    def write_packet(
        self,
        payload: bytes,
        channel: int = 37,
        rssi: int = 0,
        access_address: int = 0x8E89BED6,
        crc_ok: bool = True,
        phy_coded: bool = False,
        phy_2m: bool = False,
        ts: Optional[float] = None,
    ) -> None:
        """
        Write one BLE packet to the PCAP file.

        Args:
            payload:        Raw BLE link-layer PDU bytes (without preamble or CRC).
            channel:        BLE channel number 0–39.
            rssi:           Received signal strength in dBm (signed int8 range).
            access_address: 32-bit BLE access address.
            crc_ok:         Whether the CRC passed.
            phy_coded:      True if captured on Coded PHY (long range).
            phy_2m:         True if captured on 2 Mbit/s PHY.
            ts:             Unix timestamp (float). Defaults to now.
        """
        if self._fh.closed:
            raise IOError("PCAPWriter is closed")

        ts = ts or time.time()
        ts_sec  = int(ts)
        ts_usec = int((ts - ts_sec) * 1_000_000)

        flags = 0
        if crc_ok:
            flags |= 0x0001
        if phy_2m:
            flags |= 0x0800
        if phy_coded:
            flags |= 0x1000

        # Clamp RSSI to int8 range; 0x80 means "invalid"
        rssi_byte = max(-128, min(127, rssi)) & 0xFF

        phdr = struct.pack(
            "<BBBBIHxx",         # note: pad 2 bytes to align to 10 bytes total
            channel & 0xFF,      # rf_channel
            rssi_byte,           # signal_power (int8 stored as uint8)
            0x80,                # noise_power — unknown
            0,                   # access_address_offenses
            access_address,      # ref_access_address (uint32le)
            flags,               # flags (uint16le)
        )
        # struct "<BBBBIHxx" = 1+1+1+1+4+2+2 = 12 bytes. The actual phdr is 10.
        # Correct: "<BBBBIh" = 1+1+1+1+4+2 = 10 bytes exactly.
        phdr = struct.pack(
            "<BBBBIh",
            channel & 0xFF,
            rssi_byte,
            0x80,
            0,
            access_address,
            flags,
        )

        frame = phdr + payload
        incl_len = len(frame)
        orig_len = incl_len

        rec_hdr = struct.pack("<IIII", ts_sec, ts_usec, incl_len, orig_len)
        self._fh.write(rec_hdr + frame)
        self._fh.flush()
        self._packet_count += 1

    def write_adv_packet(self, mac: str, adv_type: int, payload: bytes,
                         channel: int = 37, rssi: int = 0,
                         ts: Optional[float] = None) -> None:
        """
        Convenience method: build a minimal BLE ADV PDU and write it.

        Args:
            mac:      Advertiser address string "AA:BB:CC:DD:EE:FF".
            adv_type: PDU type byte (0=ADV_IND, 2=ADV_NONCONN_IND, 4=SCAN_RSP, 5=CONNECT_IND).
            payload:  Raw advertisement data payload (after AdvA).
        """
        try:
            addr_bytes = bytes(int(b, 16) for b in mac.split(":"))[::-1]  # little-endian
        except Exception:
            addr_bytes = b'\x00' * 6

        # PDU Header: PDU_type[3:0] | RFU | TxAdd | RxAdd | RFU[7:6]
        # Length = 6 (AdvA) + len(payload)
        pdu_len = 6 + len(payload)
        pdu_hdr = struct.pack("<BB", adv_type & 0x0F, pdu_len & 0xFF)
        pdu     = pdu_hdr + addr_bytes + payload

        # Fake CRC (3 bytes, not checked by Wireshark when CRC flag is set)
        crc = b'\x00\x00\x00'

        # Full LL frame: AA (4 bytes) + PDU + CRC (3 bytes)
        aa = struct.pack("<I", 0x8E89BED6)
        frame = aa + pdu + crc

        self.write_packet(frame, channel=channel, rssi=rssi,
                          access_address=0x8E89BED6, ts=ts)

    @property
    def packet_count(self) -> int:
        return self._packet_count

    @property
    def file_size(self) -> int:
        if self._fh.closed:
            return self.path.stat().st_size if self.path.exists() else 0
        return self._fh.tell()

    def close(self) -> None:
        if not self._fh.closed:
            self._fh.flush()
            self._fh.close()

    # ── context manager ──────────────────────────────────────────────────────

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    # ── internal ─────────────────────────────────────────────────────────────

    def _write_global_header(self) -> None:
        hdr = struct.pack(
            "<IHHiIII",
            PCAP_MAGIC_NUMBER,
            PCAP_VERSION_MAJOR,
            PCAP_VERSION_MINOR,
            0,                      # thiszone (GMT offset)
            0,                      # sigfigs
            PCAP_SNAPLEN,
            DLT_BLUETOOTH_LE_LL_WITH_PHDR,
        )
        self._fh.write(hdr)
