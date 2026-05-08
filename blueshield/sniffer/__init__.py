"""
BlueShield Sniffer Module v1.0

Provides:
  - SniffleEngine    — Sniffle hardware abstraction (TI CC1352)
  - WhadSniffleEngine — WHAD/ButteRFly nRF52840 backend (default)
  - GATTInspector    — Bleak-based GATT service/characteristic enumeration
  - PairingDetector  — SMP packet parser; legacy vs. LE Secure Connections detection
  - PCAPWriter       — Self-contained PCAP writer (no external dependency)
  - CrackleRunner    — crackle subprocess wrapper + Python fallback
"""

from .sniffle_engine import SniffleEngine, make_sniffer
from .gatt_inspector import GATTInspector
from .pairing_detector import PairingDetector, PairingEvent, PairingType
from .pcap_writer import PCAPWriter
from .crackle_runner import CrackleRunner

__all__ = [
    "SniffleEngine",
    "make_sniffer",
    "GATTInspector",
    "PairingDetector",
    "PairingEvent",
    "PairingType",
    "PCAPWriter",
    "CrackleRunner",
]
