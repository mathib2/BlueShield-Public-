"""
Microsoft Swift Pair / Cross-Device beacon decoder.

Microsoft uses company ID 0x0006 for several BLE features:

  - Swift Pair: pairing prompt for accessories. Subtype 0x03 0x05 ... is the
    well-known "audio peripheral, advertise me to nearby Windows".

  - Cross-Device Platform (CDP): "Continue from your phone" handoff. Subtype
    starts with 0x01 (CDP advertising) or 0x05 (proximity).

  - Surface Hub / Microsoft 365 device proximity beacons: 0x01 ... 0x80.

References:
  - https://docs.microsoft.com/windows-hardware/design/component-guidelines/bluetooth-swift-pair
  - https://github.com/grimhilt/SwiftPair (Linux-side reverse-engineering)
  - Wireshark capture analysis from publicly archived Surface Pen pairings
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Optional


MICROSOFT_COMPANY_ID = 0x0006


# Subtype byte 0 in Microsoft mfr data identifies the feature class.
MS_SUBTYPES: dict[int, str] = {
    0x01: "Cross-Device Platform",          # phone-to-PC continuity
    0x03: "Swift Pair",                     # accessory pairing
    0x05: "Surface proximity beacon",
}


@dataclass
class MicrosoftDevice:
    device_class: str = "ms_unknown"
    label: str = "Microsoft device"
    feature: Optional[str] = None           # Swift Pair / CDP / Beacon
    is_swiftpair: bool = False
    is_cdp: bool = False
    confidence: float = 0.0


def decode(payload_after_company_id: bytes) -> Optional[MicrosoftDevice]:
    """Decode a Microsoft mfr-data payload (after the 0x06 0x00 company ID)."""
    if len(payload_after_company_id) < 1:
        return None
    p = payload_after_company_id
    sub = p[0]
    feature = MS_SUBTYPES.get(sub)
    dev = MicrosoftDevice(feature=feature)

    if sub == 0x03:
        # Swift Pair frame: 03 [model-byte] [scenario-byte] [BD_ADDR(6)] ...
        dev.is_swiftpair = True
        dev.device_class = "windows_accessory"
        # Byte 1 hints at device type:
        #   0x00 = generic, 0x01 = mouse, 0x02 = keyboard,
        #   0x05 = audio (headphones / speaker), 0x06 = remote
        type_byte = p[1] if len(p) > 1 else 0x00
        type_map = {
            0x00: "Windows accessory (Swift Pair)",
            0x01: "Mouse (Swift Pair)",
            0x02: "Keyboard (Swift Pair)",
            0x05: "Audio device (Swift Pair)",
            0x06: "Remote (Swift Pair)",
        }
        dev.label = type_map.get(type_byte, "Windows accessory (Swift Pair)")
        if type_byte == 0x01:
            dev.device_class = "hid_mouse"
        elif type_byte == 0x02:
            dev.device_class = "hid_keyboard"
        elif type_byte == 0x05:
            dev.device_class = "audio"
        dev.confidence = 0.85
        return dev

    if sub == 0x01:
        # Cross-Device Platform — usually a Windows PC announcing itself for
        # Phone Link / Continue On PC. Format: 01 [salt][hash...]
        dev.is_cdp = True
        dev.device_class = "computer"
        dev.label = "Windows PC (Cross-Device)"
        dev.confidence = 0.75
        return dev

    if sub == 0x05:
        dev.device_class = "computer"
        dev.label = "Surface device (proximity)"
        dev.confidence = 0.65
        return dev

    # Unrecognised but Microsoft-tagged
    dev.device_class = "ms_unknown"
    dev.label = "Microsoft device"
    dev.confidence = 0.30
    return dev


def decode_from_dict(mfg_data_dict: dict) -> Optional[MicrosoftDevice]:
    if not mfg_data_dict:
        return None
    raw = mfg_data_dict.get(MICROSOFT_COMPANY_ID)
    if raw is None:
        return None
    if isinstance(raw, (bytes, bytearray)):
        return decode(bytes(raw))
    return None
