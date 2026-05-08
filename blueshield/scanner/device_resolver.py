"""
Unified BLE device resolver.

Runs every fingerprinting layer we have over a single advertisement and
returns the best-confidence answer, plus the supporting evidence from each
layer. The dashboard surfaces the result to the user; downstream classifiers
use it as the authoritative answer when confidence is high.

Layer priority (highest accuracy first):
  1. Apple Continuity TLV (apple_continuity.py)            — exact model id
  2. Samsung manufacturer-data prefix (samsung_continuity)  — Galaxy Buds / SmartTag
  3. Google Fast Pair model id (google_fastpair.py)         — exact model id
  4. Microsoft Swift Pair / CDP (microsoft_swiftpair.py)    — Win accessory class
  5. GATT service UUIDs (gatt_services.py)                  — heart rate, glucose, HID, etc.
  6. Vendor mfg-id pattern + name match (vendor_signatures) — Sony / Bose / Logitech / Garmin / etc.
  7. Name-only pattern (vendor_signatures.match_by_name)    — fallback for IoT / no mfg-id devices
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional

from . import apple_continuity
from . import samsung_continuity
from . import microsoft_swiftpair
from . import google_fastpair
from . import gatt_services
from . import vendor_signatures
from . import mac_oui


@dataclass
class ResolvedDevice:
    """Best-effort identification across all fingerprint layers."""
    label: str = "Unknown"
    device_class: str = "ble_device"
    category: str = "unknown"
    vendor: str = ""
    model: Optional[str] = None
    confidence: float = 0.0
    sources: list[str] = field(default_factory=list)  # which layers contributed
    apple_info: Optional[dict] = None
    fastpair_info: Optional[dict] = None
    samsung_info: Optional[dict] = None
    microsoft_info: Optional[dict] = None
    service_match: Optional[dict] = None
    oui_info: Optional[dict] = None      # IEEE MAC vendor + address-type
    address_type: str = ""               # public / rpa / static_random / nrpa
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = {k: v for k, v in self.__dict__.items() if v not in (None, "", [], {})}
        # Always include the headline fields so the UI can rely on them
        d.setdefault("label", self.label)
        d.setdefault("device_class", self.device_class)
        d.setdefault("category", self.category)
        d.setdefault("confidence", self.confidence)
        return d


# Map device_class (decoder output) → dashboard category bucket
CLASS_TO_CATEGORY: dict[str, str] = {
    # audio
    "airpods": "audio", "beats": "audio", "buds": "audio", "audio": "audio",
    "le_audio": "audio", "le_audio_broadcast": "audio",
    "fastpair_audio": "audio", "jabra_audio": "audio", "sonos_speaker": "audio",
    # phones / computers
    "iphone": "phone", "phone": "phone", "samsung_device": "phone",
    "google_device": "phone", "ipad": "tablet",
    "mac": "computer", "computer": "computer", "windows_accessory": "input",
    # watches / wearables
    "watch": "watch", "fitness_tracker": "fitness", "apple_watch": "watch",
    # input
    "hid_device": "input", "hid_keyboard": "input", "hid_mouse": "input",
    "hid_input": "input", "hid_logitech": "input", "hid_apple": "input",
    "controller": "gaming",
    # medical
    "cgm": "medical", "glucose_meter": "medical", "insulin_pump": "medical",
    "pacemaker": "medical", "hearing_aid": "medical", "blood_pressure": "medical",
    "pulse_oximeter": "medical", "thermometer": "medical", "weight_scale": "medical",
    "body_composition": "medical", "medical": "medical",
    # tracker / proximity
    "airtag": "tracker", "findmy": "tracker", "tracker_tag": "tracker",
    "tile_tag": "tracker", "smarttag": "tracker", "fmd_tag": "tracker",
    "beacon": "proximity",
    # IoT
    "smart_light": "iot", "smart_lock": "iot", "smart_speaker": "iot",
    "iot": "iot", "iot_device": "iot", "env_sensor": "iot", "govee_sensor": "iot",
    "bthome_sensor": "iot", "industrial": "iot", "amazon_device": "iot",
    "nest_device": "iot",
    # cars
    "car": "vehicle",
    # tv / streaming
    "smart_tv": "tv", "tv": "tv", "streaming_device": "tv",
    # cardiology / fitness
    "heart_rate_strap": "fitness", "cycling_sensor": "fitness",
    "cycling_power": "fitness", "running_pod": "fitness",
    "fitness_machine": "fitness", "fitness": "fitness",
    # styluses, cameras
    "stylus": "input",
    "camera": "camera",
    "industrial": "iot", "controller": "gaming",
    # generic / unknown
    "ble_device": "generic", "ble_chip": "generic",
}


def resolve(*,
            local_name: str = "",
            manufacturer_data: Optional[dict] = None,
            service_uuids: Optional[list] = None,
            service_data: Optional[dict] = None,
            mac_address: str = "",
            ) -> ResolvedDevice:
    """Run every layer; return the highest-confidence ResolvedDevice.

    The `mac_address` argument unlocks the OUI / address-type layer. Pass the
    BD_ADDR (e.g. ``"A4:5E:60:00:00:01"``); random-shaped addresses (RPA /
    static / NRPA) are flagged accordingly so the dashboard can warn that the
    address is privacy-rotating and not a stable identity.
    """
    out = ResolvedDevice(label=local_name or "Unknown")

    # ── Layer 0: IEEE OUI + address-type — fast and always-applicable ─────────
    # Even random addresses produce a useful classification (RPA = phone with
    # privacy on, static = peripheral). Public addresses give a hard vendor
    # fact that anchors the rest of the resolution chain.
    if mac_address:
        oui = mac_oui.enrich(mac_address)
        if oui:
            out.address_type = oui.get("address_type", "")
            if oui.get("vendor_full"):
                out.oui_info = oui
                out.sources.append("oui")
                # Vendor fact at 0.40 — beats the no-mfg-id fallback but yields
                # to TLV decoders that also identify the model.
                if 0.40 > out.confidence:
                    out.vendor = oui["vendor_full"]
                    out.confidence = 0.40
                    if not out.label or out.label == "Unknown":
                        out.label = oui["vendor_short"] + " device"

    # ── Layer 1: Apple Continuity ──────────────────────────────────────────────
    ad = apple_continuity.decode_from_dict(manufacturer_data or {})
    if ad is not None:
        out.apple_info = ad.to_dict()
        out.sources.append("apple_continuity")
        if ad.confidence > out.confidence:
            out.label = ad.label or out.label
            out.device_class = ad.device_class
            out.confidence = ad.confidence
            out.vendor = "Apple"
            out.model = ad.model

    # ── Layer 2: Samsung ───────────────────────────────────────────────────────
    sd = samsung_continuity.decode_from_dict(manufacturer_data or {})
    if sd is not None:
        out.samsung_info = sd.__dict__
        out.sources.append("samsung")
        if sd.confidence > out.confidence:
            out.label = sd.label or out.label
            out.device_class = sd.device_class
            out.confidence = sd.confidence
            out.vendor = "Samsung"
            out.model = sd.model

    # ── Layer 3: Microsoft Swift Pair / CDP ────────────────────────────────────
    md = microsoft_swiftpair.decode_from_dict(manufacturer_data or {})
    if md is not None:
        out.microsoft_info = md.__dict__
        out.sources.append("microsoft")
        if md.confidence > out.confidence:
            out.label = md.label or out.label
            out.device_class = md.device_class
            out.confidence = md.confidence
            out.vendor = "Microsoft"

    # ── Layer 4: Google Fast Pair (service-data) ──────────────────────────────
    fp = google_fastpair.decode_service_data_dict(service_data or {})
    if fp is not None:
        out.fastpair_info = fp.__dict__
        out.sources.append("fastpair")
        if fp.confidence > out.confidence:
            out.label = fp.label or out.label
            out.device_class = "audio"
            out.confidence = fp.confidence
            out.vendor = "Fast Pair"
            out.model = fp.model_name

    # ── Layer 5: GATT services UUID classification ────────────────────────────
    svc_match = gatt_services.classify_by_services(service_uuids or [])
    if svc_match is not None:
        out.service_match = svc_match
        out.sources.append("gatt_service")
        if svc_match["confidence"] > out.confidence:
            out.device_class = svc_match["device_class"]
            out.confidence = svc_match["confidence"]
            # Don't overwrite a real product label with the service category;
            # service is more about *what it does*, mfg/name is *what it is*.
            if not out.label or out.label == "Unknown":
                out.label = svc_match["service_label"]

    # ── Layer 6: Vendor manufacturer-ID + name pattern ─────────────────────────
    if manufacturer_data:
        for mfg_id in manufacturer_data.keys():
            vm = vendor_signatures.match_by_mfg_id(mfg_id, local_name)
            if vm is None:
                continue
            out.sources.append(f"vendor:{vm.vendor}")
            if vm.confidence > out.confidence:
                out.label = vm.label or out.label
                out.device_class = vm.device_class
                out.confidence = vm.confidence
                out.vendor = vm.vendor

    # ── Layer 7: Name-only fallback ────────────────────────────────────────────
    nm = vendor_signatures.match_by_name(local_name)
    if nm is not None:
        out.sources.append("name_pattern")
        if nm.confidence > out.confidence:
            out.label = nm.label
            out.device_class = nm.device_class
            out.confidence = nm.confidence

    # ── Cross-source confidence bump ──────────────────────────────────────────
    # When the OUI vendor agrees with what a TLV/Fast-Pair/Samsung decoder
    # already concluded, that's two independent sources confirming the same
    # vendor. Push confidence above the floor of any single source.
    if out.oui_info and out.vendor and out.confidence < 0.99:
        oui_vendor = (out.oui_info.get("vendor_short") or "").lower()
        primary    = out.vendor.lower()
        # "Apple", "Apple, Inc.", "Apple Inc" all reduce to "apple"
        oui_norm   = oui_vendor.split(",")[0].split(" ")[0]
        prim_norm  = primary.split(",")[0].split(" ")[0]
        if oui_norm and prim_norm and (oui_norm == prim_norm or oui_norm in prim_norm or prim_norm in oui_norm):
            out.confidence = min(0.99, out.confidence + 0.10)
            out.sources.append("oui+vendor-agree")

    # When 3+ independent sources contributed, trim a bit more uncertainty
    # off (separate-source corroboration is the strongest signal we have).
    distinct_sources = {s.split(":")[0] for s in out.sources}
    if len(distinct_sources) >= 3 and out.confidence < 0.97:
        out.confidence = min(0.97, out.confidence + 0.05)

    out.category = CLASS_TO_CATEGORY.get(out.device_class, "unknown")
    return out
