"""
IEEE OUI MAC vendor lookup + Bluetooth LE address-type detection.

The first 24 bits of a *public* Bluetooth address are an IEEE-assigned OUI
that identifies the hardware vendor. The Wireshark `manuf` database (bundled
as `oui_db.tsv`) ships ~57k vendor mappings — including narrower 28/36-bit
allocations IEEE assigns to smaller OEMs.

This module:
  - Loads the OUI table once at import time (~3 MB → ~3 dicts in RAM)
  - Returns vendor short + full names for any public-address MAC
  - Detects whether an address is *public* (OUI-resolvable) or one of the
    Bluetooth LE *random* address types (RPA / static-random / NRPA), which
    do NOT correspond to a vendor — they're privacy-rotating addresses.

Sources:
  - https://www.wireshark.org/download/automated/data/manuf
    (TShark-generated, canonical, refreshed daily; 24/28/36-bit prefixes)
  - Bluetooth Core 5.4 Vol 6 Part B §1.3 — random address sub-types

Notes on accuracy:
  - 24-bit OUI matches an entire vendor block (16M MACs).
  - 28-bit and 36-bit narrower allocations identify smaller OEMs that share
    a 24-bit parent block. We try the longest match first so a 36-bit OEM
    (e.g., a small IoT brand inside an Espressif wholesale block) wins
    over the parent vendor.
"""
from __future__ import annotations
import os
from typing import Optional

DB_PATH = os.path.join(os.path.dirname(__file__), "oui_db.tsv")

# (OUI hex, mask_bits) -> (short_name, full_name)
# We split into 3 length-buckets so lookup is O(1) per length.
_OUI_24: dict[int, tuple[str, str]] = {}
_OUI_28: dict[int, tuple[str, str]] = {}
_OUI_36: dict[int, tuple[str, str]] = {}
_LOADED = False


def _hex_to_int(s: str) -> int:
    return int(s.replace(":", "").replace("-", ""), 16)


def _load() -> None:
    """Load the bundled Wireshark manuf table on first use."""
    global _LOADED
    if _LOADED:
        return
    _LOADED = True
    if not os.path.exists(DB_PATH):
        return
    with open(DB_PATH, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if not line or line.startswith("#"):
                continue
            parts = line.rstrip("\n").split("\t")
            # Skip blank rows
            parts = [p.strip() for p in parts if p.strip()]
            if len(parts) < 2:
                continue
            prefix_field = parts[0]
            short = parts[1]
            full  = parts[2] if len(parts) >= 3 else short
            # Format: "AA:BB:CC" (24-bit), "AA:BB:CC:D0/28" (28-bit),
            # or "AA:BB:CC:DD:E0/36" (36-bit).
            if "/" in prefix_field:
                hex_part, _, bits = prefix_field.partition("/")
                try:
                    bits = int(bits)
                except ValueError:
                    continue
            else:
                hex_part = prefix_field
                bits = 24
            try:
                val = _hex_to_int(hex_part)
            except ValueError:
                continue
            # Normalize so val occupies (bits) MSBs of a 48-bit MAC.
            shift = 48 - bits
            key = val << shift
            entry = (short, full)
            if bits == 24:
                _OUI_24[key] = entry
            elif bits == 28:
                _OUI_28[key & ((0xF << 20) | (0xFFFFF << 0)) << 0] = entry  # store as-is, mask on lookup
                _OUI_28[key] = entry
            elif bits == 36:
                _OUI_36[key] = entry
            else:
                # Treat anything else as a 24-bit lookup at the closest power
                _OUI_24[(val >> max(0, bits - 24)) << 24] = entry


def _mac_to_int48(mac: str) -> Optional[int]:
    if not mac:
        return None
    s = mac.replace(":", "").replace("-", "").lower()
    if len(s) != 12:
        return None
    try:
        return int(s, 16)
    except ValueError:
        return None


def lookup(mac: str) -> Optional[dict]:
    """Return {vendor_short, vendor_full, oui_bits} or None if MAC is random/unknown."""
    _load()
    n = _mac_to_int48(mac)
    if n is None:
        return None
    # Try longest match first
    k36 = n & 0xFFFFFFFFF000000000000  # not meaningful — use proper mask below
    # Actually: 36-bit prefix lives in the top 36 bits of the 48-bit MAC.
    k36_top = (n >> 12) << 12   # zero-out lowest 12 bits
    k28_top = (n >> 20) << 20
    k24_top = (n >> 24) << 24
    # Lookups
    for k, table, bits in (
        (k36_top, _OUI_36, 36),
        (k28_top, _OUI_28, 28),
        (k24_top, _OUI_24, 24),
    ):
        hit = table.get(k)
        if hit:
            return {
                "vendor_short": hit[0],
                "vendor_full":  hit[1],
                "oui_bits":     bits,
            }
    return None


# ── BLE address-type detection ────────────────────────────────────────────────
def address_type(mac: str) -> str:
    """Classify a Bluetooth address into:
       'public'         — IEEE OUI-allocated (vendor-resolvable)
       'rpa'            — Resolvable Private Address (rotates ~every 15 min)
       'static_random'  — Random Static (set at boot, fixed for device lifetime)
       'nrpa'           — Non-Resolvable Private Address (rotates, no IRK)
       'unknown'        — malformed
    """
    n = _mac_to_int48(mac)
    if n is None:
        return "unknown"
    # If we got an OUI hit, it's a public address (or a static-random that
    # happens to collide — extremely unlikely with the random distribution).
    if lookup(mac) is not None:
        return "public"
    # Top 2 bits of the most-significant byte classify the random address.
    top_byte = (n >> 40) & 0xFF
    top2 = (top_byte >> 6) & 0b11
    if top2 == 0b11:
        return "rpa"
    if top2 == 0b10:
        return "static_random"
    if top2 == 0b00:
        return "nrpa"
    # 0b01 — should not occur for random addresses; treat as public-shaped.
    return "public"


def enrich(mac: str) -> dict:
    """Combined helper: returns vendor info + address-type classification."""
    out: dict = {"address_type": address_type(mac)}
    hit = lookup(mac)
    if hit:
        out.update(hit)
    return out
