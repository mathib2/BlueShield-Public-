"""
Apple Continuity protocol decoder.

Identifies specific Apple devices (AirPods Pro 2, Apple Watch, iPhone, AirTag,
HomePod, etc.) from BLE manufacturer-specific advertisements (company id 0x004C).

The Continuity payload is a chain of TLVs after the 2-byte company ID.
Each TLV: [type:1][length:1][data:length].

Sources:
  - furiousMAC/continuity (Wireshark dissector + 14 message specs)
  - hexway/apple_bleee (proximity_dev_models, airpods_states)
  - Celosia & Cunche, "Discontinued Privacy: Personal Data Leaks in Apple
    Bluetooth-Low-Energy Continuity Protocols" (PETS 2020)
  - Heinrich et al., "Who Can Find My Devices?" (PoPETs 2021)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


APPLE_COMPANY_ID = 0x004C


# ── Continuity TLV types (canonical, from furiousMAC dissector) ────────────────
CONTINUITY_TYPES: dict[int, str] = {
    0x02: "iBeacon",
    0x03: "AirPrint",
    0x05: "AirDrop",
    0x06: "HomeKit",
    0x07: "Proximity Pairing",      # AirPods, Beats
    0x08: "Hey Siri",
    0x09: "AirPlay Target",
    0x0A: "AirPlay Source",
    0x0B: "Magic Switch",           # Apple Watch unlock
    0x0C: "Handoff",
    0x0D: "Tethering Target",
    0x0E: "Tethering Source",
    0x0F: "Nearby Action",
    0x10: "Nearby Info",            # iPhone/iPad/Mac state broadcast (very common)
    0x11: "Power & Charging",
    0x12: "Find My",                # AirTag, "Marked As Lost" devices
    0x14: "AirPods Pairing Setup",
    0x16: "Watch Setup",
    0x19: "Find My (Separated)",
}


# ── AirPods / Beats model registry — UINT16 big-endian keys ────────────────────
# Key reads as `data[1] << 8 | data[2]` after the 0x01 prefix in the type-0x07 TLV.
# Cross-referenced with hexway/apple_bleee, furiousMAC proximity_pairing.md,
# and post-2023 Apple firmware reports.
AIRPODS_MODELS: dict[int, str] = {
    0x0220: "AirPods (1st gen)",
    0x0F20: "AirPods (2nd gen)",
    0x1320: "AirPods (3rd gen)",
    0x1920: "AirPods 4",
    0x1B20: "AirPods 4 (ANC)",
    0x0E20: "AirPods Pro",
    0x1420: "AirPods Pro 2",
    0x2420: "AirPods Pro 2 (USB-C)",
    0x0A20: "AirPods Max",
    0x1F20: "AirPods Max (USB-C)",
    0x0520: "Beats Solo3",
    0x0620: "Powerbeats3",
    0x0920: "BeatsX",
    0x0B20: "Beats Studio3",
    0x0C20: "Powerbeats Pro",
    0x1020: "Beats Solo Pro",
    0x1120: "Powerbeats4",
    0x1220: "Beats Flex",
    0x1720: "Beats Studio Buds",
    0x1E20: "Beats Studio Buds +",
    0x2020: "Beats Fit Pro",
    0x2920: "Beats Studio Pro",
    0x3520: "Beats Solo 4",
}


# ── AirPods position state (UTP byte from proximity-pairing TLV) ───────────────
# From hexway/apple_bleee airpods_states. Tells you whether the case is open,
# whether one or both buds are out of the case / in the ear, etc.
AIRPODS_STATES: dict[int, str] = {
    0x00: "Case closed",
    0x01: "Both buds out of case",
    0x02: "Left bud out",
    0x03: "Left bud out",
    0x05: "Right bud out",
    0x09: "Right bud out",
    0x0B: "Both buds in ear",
    0x11: "Right bud out",
    0x13: "Right bud in case",
    0x15: "Right bud in case",
    0x20: "Left bud out",
    0x21: "Both buds out of case",
    0x22: "Case open, left bud out",
    0x23: "Right bud out",
    0x29: "Left bud out",
    0x2B: "Both buds in ear",
    0x31: "Case open, left bud out",
    0x33: "Case open, left bud out",
    0x50: "Case open",
    0x51: "Left bud out",
    0x53: "Left bud in case",
    0x55: "Both buds in case (lid open)",
    0x70: "Case open",
    0x71: "Right bud out",
    0x73: "Right bud out",
    0x75: "Both buds in case (lid open)",
}


# ── Nearby Info (type 0x10) — iPhone / iPad / Mac state flags ──────────────────
# The most common Apple BLE broadcast: every iPhone/iPad/Mac emits this.
# Action code (low nibble of byte 1) tells you what the device is doing.
NEARBY_ACTION_CODES: dict[int, str] = {
    0x00: "Activity unknown",
    0x01: "Activity reporting disabled",
    0x03: "Idle (locked)",
    0x05: "Audio playing, screen off",
    0x07: "Active user (screen on)",
    0x09: "Screen on with video",
    0x0A: "Watch on wrist, unlocked",
    0x0B: "Recent user interaction",
    0x0D: "Driving a vehicle",
    0x0E: "Phone or FaceTime call",
}

# Status flags (high nibble of byte 1) for Nearby Info
# 0x01 primary device, 0x04 AirDrop receiving enabled
NEARBY_STATUS_PRIMARY = 0x10
NEARBY_STATUS_AIRDROP = 0x40

# Data flags (byte 2) bitmask for Nearby Info
NEARBY_DATA_AIRPODS_CONNECTED  = 0x01
NEARBY_DATA_AUTHTAG_FOURBYTE   = 0x02
NEARBY_DATA_WIFI_ON            = 0x04
NEARBY_DATA_AUTHTAG_PRESENT    = 0x10
NEARBY_DATA_WATCH_LOCKED       = 0x20
NEARBY_DATA_AUTOUNLOCK_WATCH   = 0x40
NEARBY_DATA_AUTOUNLOCK_DEVICE  = 0x80


# ── Nearby Action (type 0x0F) — pairing prompts ────────────────────────────────
NEARBY_ACTION_TYPES: dict[int, str] = {
    0x01: "Apple TV Setup",
    0x04: "Mobile Backup",
    0x05: "Watch Setup",
    0x06: "Apple TV Pair",
    0x07: "Internet Tethering",
    0x08: "Wi-Fi Password",
    0x09: "iOS Setup",
    0x0A: "Repair",
    0x0B: "Speaker Setup",
    0x0C: "Apple Pay",
    0x0D: "Whole Home Audio Setup",
    0x0E: "Developer Tools",
    0x13: "HomePod Setup",
}


# ── Result container ───────────────────────────────────────────────────────────
@dataclass
class AppleDevice:
    """Distilled Apple device identity from one Continuity advertisement.

    Fields are populated only when the corresponding TLV is present.
    `device_class` is the high-level rollup the dashboard uses
    (`airpods` / `iphone` / `ipad` / `mac` / `watch` / `airtag` / ...).
    """
    device_class: str = "apple_unknown"      # airpods | iphone | ipad | mac | watch | airtag | homepod | apple_tv | beats | apple_unknown
    label: str = "Apple device"              # human-readable best guess
    model: Optional[str] = None              # e.g. "AirPods Pro 2 (USB-C)"
    confidence: float = 0.0                  # 0.0..1.0 — how sure we are

    # AirPods-specific (type 0x07)
    airpods_state: Optional[str] = None
    battery_left:  Optional[int] = None      # percent
    battery_right: Optional[int] = None
    battery_case:  Optional[int] = None
    charging_left:  Optional[bool] = None
    charging_right: Optional[bool] = None
    charging_case:  Optional[bool] = None
    color: Optional[int] = None

    # Nearby Info-specific (type 0x10)
    user_activity: Optional[str] = None      # e.g. "Active user (screen on)"
    is_primary_device: Optional[bool] = None
    airdrop_receiving: Optional[bool] = None
    wifi_on: Optional[bool] = None
    watch_unlocked: Optional[bool] = None    # autounlock flag set
    airpods_connected: Optional[bool] = None # this iPhone has AirPods active

    # Find My-specific (type 0x12 / 0x19)
    findmy_separated: Optional[bool] = None  # AirTag in lost mode / separated key
    findmy_battery_status: Optional[int] = None  # 0..3 (full/medium/low/critical)

    # Diagnostics
    tlv_types: list[int] = field(default_factory=list)
    raw_summary: str = ""

    def to_dict(self) -> dict:
        return {
            k: v for k, v in self.__dict__.items()
            if v is not None and v != [] and v != ""
        }


# ── Decoder ────────────────────────────────────────────────────────────────────
def _walk_tlvs(payload: bytes) -> list[tuple[int, bytes]]:
    """Walk the TLV chain, return list of (type, data) pairs."""
    out: list[tuple[int, bytes]] = []
    off = 0
    n = len(payload)
    while off + 2 <= n:
        ttype = payload[off]
        tlen = payload[off + 1]
        if off + 2 + tlen > n:
            break
        out.append((ttype, payload[off + 2 : off + 2 + tlen]))
        off += 2 + tlen
    return out


def _decode_proximity_pairing(data: bytes, dev: AppleDevice) -> None:
    """Type 0x07 — AirPods / Beats proximity pairing."""
    # Per furiousMAC proximity_pairing.md:
    # [0]=prefix(0x01) [1..2]=model UINT16-BE [3]=status [4]=L/R battery
    # [5]=case-charging-flags+case-battery [6]=lid-open count [7]=color
    # [8]=suffix(0x00) [9..24]=encrypted
    if len(data) < 6 or data[0] != 0x01:
        # Not a real proximity-pairing frame — skip rather than emit a bogus
        # "Unknown audio" for misaligned bytes.
        return
    model_id = (data[1] << 8) | data[2]
    if model_id in AIRPODS_MODELS:
        dev.model = AIRPODS_MODELS[model_id]
        dev.device_class = "beats" if any(k in dev.model for k in ("Beats", "Powerbeats")) else "airpods"
        dev.label = dev.model
        dev.confidence = max(dev.confidence, 0.95)
    else:
        # Unknown but otherwise well-formed — signal as Apple audio with
        # moderate confidence; record the model code for later cataloguing.
        dev.model = f"Apple audio (model 0x{model_id:04X})"
        dev.device_class = "airpods" if dev.device_class == "apple_unknown" else dev.device_class
        dev.label = dev.model
        dev.confidence = max(dev.confidence, 0.55)

    if len(data) > 3:
        dev.airpods_state = AIRPODS_STATES.get(data[3], f"State 0x{data[3]:02X}")

    if len(data) > 4:
        # Battery byte: high nibble = right, low nibble = left, 0xF = unknown
        right = (data[4] >> 4) & 0x0F
        left = data[4] & 0x0F
        dev.battery_right = right * 10 if right != 0x0F else None
        dev.battery_left  = left * 10 if left != 0x0F else None

    if len(data) > 5:
        # Case-byte: bits 0-3 = case battery (×10%), bits 4-6 = charging flags
        case = data[5] & 0x0F
        dev.battery_case = case * 10 if case != 0x0F else None
        flags = (data[5] >> 4) & 0x07
        dev.charging_right = bool(flags & 0x01)
        dev.charging_left  = bool(flags & 0x02)
        dev.charging_case  = bool(flags & 0x04)

    if len(data) > 7:
        dev.color = data[7]


def _decode_nearby_info(data: bytes, dev: AppleDevice) -> None:
    """Type 0x10 — iPhone/iPad/Mac state broadcast (most common Apple BLE)."""
    if len(data) < 1:
        return
    # data[0] = status flags (high nibble) | action code (low nibble)
    status_flags = data[0] & 0xF0
    action_code = data[0] & 0x0F
    dev.is_primary_device = bool(status_flags & NEARBY_STATUS_PRIMARY)
    dev.airdrop_receiving = bool(status_flags & NEARBY_STATUS_AIRDROP)
    dev.user_activity = NEARBY_ACTION_CODES.get(action_code)

    if len(data) >= 2:
        df = data[1]
        dev.airpods_connected = bool(df & NEARBY_DATA_AIRPODS_CONNECTED)
        dev.wifi_on           = bool(df & NEARBY_DATA_WIFI_ON)
        dev.watch_unlocked    = bool(df & NEARBY_DATA_AUTOUNLOCK_WATCH)

    # The Nearby Info action code itself tells us a lot about the device class:
    if action_code == 0x0A:
        # "Watch on wrist, unlocked" — only Apple Watch ever sends this code.
        dev.device_class = "watch"
        dev.label = "Apple Watch"
        dev.confidence = max(dev.confidence, 0.85)
    elif action_code in (0x07, 0x09, 0x0B, 0x0E):
        # Active user / screen on / video / call — phone or pad
        if dev.device_class == "apple_unknown":
            dev.device_class = "iphone"
            dev.label = "iPhone (active)"
            dev.confidence = max(dev.confidence, 0.55)
    elif action_code in (0x03, 0x05):
        # Locked / audio while locked — phone or pad
        if dev.device_class == "apple_unknown":
            dev.device_class = "iphone"
            dev.label = "iPhone (locked)"
            dev.confidence = max(dev.confidence, 0.45)


def _decode_findmy(data: bytes, dev: AppleDevice, separated: bool) -> None:
    """Type 0x12 (Find My) / 0x19 (Find My Separated)."""
    if len(data) < 1:
        return
    status = data[0]
    # Bits 6-7 of status = battery (full/medium/low/critical) when bit 2 is set
    if status & 0x04:
        dev.findmy_battery_status = (status >> 6) & 0x03

    dev.findmy_separated = separated
    if dev.device_class == "apple_unknown":
        # AirTag-shaped FindMy beacons are 25 bytes long (full PK fragment).
        # Other "marked as lost" iPhones / Macs send variable-length 0x12.
        dev.device_class = "airtag" if len(data) >= 25 else "findmy"
        dev.label = "AirTag (Find My)" if dev.device_class == "airtag" else "Find My beacon"
        dev.confidence = max(dev.confidence, 0.80 if dev.device_class == "airtag" else 0.5)


def _decode_handoff(_data: bytes, dev: AppleDevice) -> None:
    """Type 0x0C — Handoff. Indicates an iPhone/iPad/Mac with active Continuity."""
    if dev.device_class == "apple_unknown":
        # Handoff broadcasters are always full-fat Apple devices (phone / pad / mac).
        dev.device_class = "iphone"
        dev.label = "iPhone / iPad / Mac"
        dev.confidence = max(dev.confidence, 0.45)


def _decode_magic_switch(_data: bytes, dev: AppleDevice) -> None:
    """Type 0x0B — Magic Switch (Apple Watch auto-unlock)."""
    dev.device_class = "watch"
    dev.label = "Apple Watch"
    dev.confidence = max(dev.confidence, 0.75)


def _decode_airplay_target(_data: bytes, dev: AppleDevice) -> None:
    """Type 0x09 — AirPlay Target (HomePod, Apple TV, AirPlay speakers)."""
    if dev.device_class == "apple_unknown":
        dev.device_class = "homepod"
        dev.label = "HomePod / Apple TV"
        dev.confidence = max(dev.confidence, 0.60)


def _decode_airdrop(_data: bytes, dev: AppleDevice) -> None:
    """Type 0x05 — AirDrop. Active Mac / iPhone advertising AirDrop receivability."""
    if dev.device_class == "apple_unknown":
        dev.device_class = "iphone"
        dev.label = "Mac or iPhone (AirDrop)"
        dev.confidence = max(dev.confidence, 0.50)


def _decode_watch_setup(_data: bytes, dev: AppleDevice) -> None:
    """Type 0x16 — Watch Setup. Only Apple Watch sends this.

    Reference: furiousMAC continuity dissector.
    """
    dev.device_class = "watch"
    dev.label = "Apple Watch (setup)"
    dev.confidence = max(dev.confidence, 0.80)


def _decode_pairing_setup(_data: bytes, dev: AppleDevice) -> None:
    """Type 0x14 — AirPods Pairing Setup beacon (case lid open without target)."""
    if dev.device_class == "apple_unknown":
        dev.device_class = "airpods"
        dev.label = "AirPods (pairing)"
        dev.confidence = max(dev.confidence, 0.65)


def decode(payload_after_company_id: bytes) -> Optional[AppleDevice]:
    """Decode an Apple Continuity payload.

    Args:
        payload_after_company_id: manufacturer data with the 2-byte 0x4C 0x00
            company ID already stripped.

    Returns:
        AppleDevice with populated fields, or None if no parseable TLVs.
    """
    tlvs = _walk_tlvs(payload_after_company_id)
    if not tlvs:
        return None

    dev = AppleDevice()
    dev.tlv_types = [t for t, _ in tlvs]

    # Decode in order of fingerprint strength: AirPods (0x07) is the most
    # specific, so let it set device_class first; weaker signals only override
    # when device_class is still apple_unknown.
    priority = {0x07: 0, 0x0B: 1, 0x16: 1, 0x12: 2, 0x19: 2,
                0x14: 3, 0x10: 4, 0x0C: 5, 0x09: 6, 0x05: 7, 0x0F: 8}
    tlvs_sorted = sorted(tlvs, key=lambda t: priority.get(t[0], 99))

    for ttype, data in tlvs_sorted:
        if ttype == 0x07:
            _decode_proximity_pairing(data, dev)
        elif ttype == 0x10:
            _decode_nearby_info(data, dev)
        elif ttype == 0x12:
            _decode_findmy(data, dev, separated=False)
        elif ttype == 0x19:
            _decode_findmy(data, dev, separated=True)
        elif ttype == 0x0B:
            _decode_magic_switch(data, dev)
        elif ttype == 0x0C:
            _decode_handoff(data, dev)
        elif ttype == 0x09:
            _decode_airplay_target(data, dev)
        elif ttype == 0x05:
            _decode_airdrop(data, dev)
        elif ttype == 0x16:
            _decode_watch_setup(data, dev)
        elif ttype == 0x14:
            _decode_pairing_setup(data, dev)

    # Build a one-line summary for logs / dashboard tooltip
    parts = [dev.label]
    if dev.airpods_state:
        parts.append(dev.airpods_state)
    if dev.user_activity:
        parts.append(dev.user_activity)
    if dev.battery_left is not None or dev.battery_right is not None:
        L = f"{dev.battery_left}%" if dev.battery_left is not None else "?"
        R = f"{dev.battery_right}%" if dev.battery_right is not None else "?"
        parts.append(f"L:{L} R:{R}")
    dev.raw_summary = " · ".join(parts)
    return dev


def decode_from_manufacturer_data(mfg_data: bytes) -> Optional[AppleDevice]:
    """Decode from full manufacturer data — verifies the Apple company ID first."""
    if len(mfg_data) < 2:
        return None
    cid = mfg_data[0] | (mfg_data[1] << 8)
    if cid != APPLE_COMPANY_ID:
        return None
    return decode(mfg_data[2:])


def decode_from_dict(mfg_data_dict: dict) -> Optional[AppleDevice]:
    """Decode from Bleak-style manufacturer-data dict {company_id: bytes(...)}."""
    if not mfg_data_dict:
        return None
    raw = mfg_data_dict.get(APPLE_COMPANY_ID)
    if raw is None:
        return None
    if isinstance(raw, (bytes, bytearray)):
        return decode(bytes(raw))
    return None
