"""
Samsung BLE manufacturer-data decoder.

Samsung uses company ID 0x0075 ("Samsung Electronics") with several
sub-formats analogous to Apple's Continuity:

  - Galaxy Buds proximity pairing: prefix 01 00 02 ...
    The 4th byte after the prefix encodes the Buds model (e.g., 0x40 = Buds2 Pro).
    Subsequent bytes carry the 6-byte BD_ADDR fragment.

  - SmartTag / SmartTag+ Find-My-Device beacon: prefix 42 04 01 80 (Search-By-Owner)
    or 42 04 01 00 (Generic broadcast).

  - SmartThings Find ("Wearable network"): prefix 01 02 ...

  - Samsung Galaxy Watch / Galaxy phone Active proximity: subtype 00 01 ...

References:
  - https://github.com/Freeyourgadget/Gadgetbridge (Galaxy Buds protocol RE)
  - https://github.com/atc1441/SmartTagAdvertiser (SmartTag format RE)
  - Bluetooth-Devices/airpods-data-types (cross-checked Buds models)
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Optional

SAMSUNG_COMPANY_ID = 0x0075


# Galaxy Buds model registry — keyed off byte 7 of the manufacturer data
# (after company id 75 00 + prefix 01 00 02 + 3 reserved bytes).
GALAXY_BUDS_MODELS: dict[int, str] = {
    0x10: "Galaxy Buds (R170)",
    0x11: "Galaxy Buds+",
    0x12: "Galaxy Buds Live",
    0x13: "Galaxy Buds Pro",
    0x14: "Galaxy Buds 2",
    0x15: "Galaxy Buds 2 Pro",
    0x16: "Galaxy Buds FE",
    0x17: "Galaxy Buds 3",
    0x18: "Galaxy Buds 3 Pro",
}


@dataclass
class SamsungDevice:
    device_class: str = "samsung_unknown"
    label: str = "Samsung device"
    model: Optional[str] = None
    confidence: float = 0.0
    is_smarttag: bool = False
    is_buds: bool = False
    is_watch: bool = False


def decode(payload_after_company_id: bytes) -> Optional[SamsungDevice]:
    """Decode a Samsung mfr-data payload (after the 0x75 0x00 company ID)."""
    if len(payload_after_company_id) < 2:
        return None
    p = payload_after_company_id
    dev = SamsungDevice()

    # ── Galaxy Buds (prefix 01 00 02) ──────────────────────────────────────────
    if len(p) >= 8 and p[0] == 0x01 and p[1] == 0x00 and p[2] == 0x02:
        dev.is_buds = True
        dev.device_class = "buds"
        model_byte = p[6] if len(p) > 6 else None
        if model_byte is not None:
            dev.model = GALAXY_BUDS_MODELS.get(model_byte, f"Galaxy Buds (0x{model_byte:02X})")
            dev.label = dev.model
            dev.confidence = 0.92 if model_byte in GALAXY_BUDS_MODELS else 0.65
        else:
            dev.label = "Galaxy Buds (model unknown)"
            dev.confidence = 0.60
        return dev

    # ── SmartTag / SmartTag+ (Find My Device beacon) ───────────────────────────
    # Documented frame starts with 42 04 01 [00|80] or 0x10 0x02 0x01 0x80
    if (len(p) >= 4 and p[0] == 0x42 and p[1] == 0x04 and p[2] == 0x01) or \
       (len(p) >= 4 and p[0] == 0x10 and p[1] == 0x02 and p[2] == 0x01):
        dev.is_smarttag = True
        dev.device_class = "smarttag"
        # 0x80 = Search-by-owner broadcast (lost mode), 0x00 = generic
        searchmode = p[3] if len(p) > 3 else 0
        dev.label = "Galaxy SmartTag (lost mode)" if searchmode == 0x80 else "Galaxy SmartTag"
        dev.confidence = 0.90
        return dev

    # ── Galaxy Watch / Wear (subtype 01 02 / 02 02) ────────────────────────────
    if len(p) >= 3 and p[0] in (0x01, 0x02) and p[1] == 0x02:
        dev.is_watch = True
        dev.device_class = "watch"
        dev.label = "Galaxy Watch"
        dev.confidence = 0.55
        return dev

    # ── Generic Samsung phone / tab ────────────────────────────────────────────
    if len(p) >= 4 and p[0] in (0x42, 0x10, 0x01):
        dev.device_class = "phone"
        dev.label = "Samsung phone or tablet"
        dev.confidence = 0.40
        return dev

    return None


def decode_from_dict(mfg_data_dict: dict) -> Optional[SamsungDevice]:
    if not mfg_data_dict:
        return None
    raw = mfg_data_dict.get(SAMSUNG_COMPANY_ID)
    if raw is None:
        return None
    if isinstance(raw, (bytes, bytearray)):
        return decode(bytes(raw))
    return None
