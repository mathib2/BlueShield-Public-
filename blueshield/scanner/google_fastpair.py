"""
Google Fast Pair decoder.

Fast Pair advertises on service UUID 0xFE2C. The service-data payload format
distinguishes between two states:

  - 3 bytes: device is in pairing mode, payload is a 3-byte model ID (UINT24).
    The model ID can be looked up in Google's Fast Pair model registry to
    learn the exact device (e.g., Pixel Buds Pro, JBL Tour Pro 2, Bose QC45).

  - 1 byte (0x00 - 0x09 typical):  the device is "subsequent pair" — already
    bonded. The first byte's high nibble is the version (0x4 currently),
    the rest of the payload is the encrypted account key filter.

References:
  - https://developers.google.com/nearby/fast-pair/specifications/service/provider
  - https://developers.google.com/nearby/fast-pair/specifications/extensions/devicemodelmap
  - openbluetoothmesh/fast-pair-python parsing patterns
  - Google's public Fast Pair partner showcase (model names visible)
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Optional


FASTPAIR_SERVICE_UUID = 0xFE2C
FASTPAIR_SERVICE_HEX = "fe2c"


# Public sample of Google Fast Pair model IDs.  Google's full registry is
# proprietary (3 byte ID -> partner-supplied model name). The public subset
# below comes from devices observed in the wild + leaked partner submissions.
# Keys are the 3-byte ID as UINT24 big-endian.
FASTPAIR_MODELS: dict[int, str] = {
    # Google
    0x718FA4: "Pixel Buds A-Series",
    0x9ADB11: "Pixel Buds Pro",
    0x35B3D6: "Pixel Buds Pro 2",
    0x000F00: "Pixel Buds 2",
    0x294E64: "Pixel Buds (1st gen)",
    0x4CCE00: "Pixel Buds Pro (Bay)",
    # JBL
    0x82DA7C: "JBL Live Pro+ TWS",
    0x092E5B: "JBL Tune 230NC TWS",
    0x18BBC9: "JBL Tour Pro 2",
    0x10A19D: "JBL Live 770NC",
    0x0E1F28: "JBL Reflect Mini NC",
    0x0BA73E: "JBL Endurance Peak II",
    0x0E5FB0: "JBL Live 460NC",
    0x10B2A1: "JBL Tour One M2",
    # Sony
    0x29DC22: "Sony WF-1000XM4",
    0xCC4A12: "Sony WF-1000XM5",
    0x77B2C6: "Sony WH-1000XM4",
    0x7C9CE2: "Sony WH-1000XM5",
    0x4D1F24: "Sony LinkBuds S",
    0xCD1D04: "Sony LinkBuds",
    # Bose
    0x9E1E48: "Bose QuietComfort Earbuds",
    0xC15A2A: "Bose QC Ultra Earbuds",
    0x6F7E8A: "Bose QC45",
    0x8F2E10: "Bose QC Ultra Headphones",
    # Sennheiser
    0x4E16AC: "Sennheiser Momentum True Wireless 3",
    0xB0E9D2: "Sennheiser Momentum 4 Wireless",
    # Anker / Soundcore
    0xF52494: "Anker Soundcore Liberty 4 NC",
    0xF52495: "Anker Soundcore Space One",
    0xC0F058: "Anker Soundcore Liberty 3 Pro",
    # Microsoft
    0xD3041F: "Surface Headphones 2",
    # Beats (also via Apple Continuity, but Beats supports Fast Pair on Android)
    0x9C9D63: "Beats Studio Buds",
    0xA34B7B: "Beats Fit Pro",
    # OnePlus
    0xB6E2BE: "OnePlus Buds Pro 2",
    0xE9E364: "OnePlus Buds 3",
    # Nothing
    0x9D7AD7: "Nothing Ear (1)",
    0x6B538F: "Nothing Ear (2)",
    0xC4B2A1: "Nothing Ear",
    # Samsung Galaxy Buds (also via Samsung continuity)
    0x86E5BC: "Galaxy Buds 2 Pro",
    0xCAEF4D: "Galaxy Buds Pro",
    0x4F2D6F: "Galaxy Buds Live",
}


@dataclass
class FastPairDevice:
    in_pairing_mode: bool = False
    model_id: Optional[int] = None
    model_name: Optional[str] = None
    label: str = "Fast Pair audio device"
    confidence: float = 0.0


def decode_service_data(data: bytes) -> Optional[FastPairDevice]:
    """Decode a Fast Pair service-data payload (associated with UUID 0xFE2C).

    Returns FastPairDevice when the payload is a recognisable Fast Pair frame.
    """
    if not data:
        return None

    fp = FastPairDevice()
    if len(data) == 3:
        # Pairing mode — full model ID
        fp.in_pairing_mode = True
        mid = (data[0] << 16) | (data[1] << 8) | data[2]
        fp.model_id = mid
        named = FASTPAIR_MODELS.get(mid)
        if named:
            fp.model_name = named
            fp.label = f"{named} (pairing)"
            fp.confidence = 0.95
        else:
            fp.label = f"Fast Pair audio (model 0x{mid:06X}, pairing)"
            fp.confidence = 0.65
        return fp

    if len(data) >= 4:
        # Subsequent pair — high nibble of byte 0 is version (typically 0x4).
        # Payload is encrypted account-key filter; we can only confirm "this
        # is a known Fast Pair audio device that's already bonded".
        version = data[0] >> 4
        fp.in_pairing_mode = False
        fp.label = "Fast Pair audio (paired)"
        fp.confidence = 0.55 if version in (0x4, 0x0) else 0.40
        return fp

    return None


def decode_service_data_dict(svc_data: dict) -> Optional[FastPairDevice]:
    """Decode from advertisement_data.service_data (dict of UUID -> bytes)."""
    if not svc_data:
        return None
    for uuid, raw in svc_data.items():
        s = str(uuid).lower().replace("-", "")
        if FASTPAIR_SERVICE_HEX in s[:8] or FASTPAIR_SERVICE_HEX == s[4:8]:
            if isinstance(raw, (bytes, bytearray)):
                return decode_service_data(bytes(raw))
    return None
