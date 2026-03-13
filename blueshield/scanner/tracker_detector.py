"""
BlueShield Tracker Detection Engine
Detects Apple AirTag, Samsung SmartTag, Tile, Chipolo and unknown trackers
using signature matching and behavioural pattern analysis.
"""

from dataclasses import dataclass, field
from collections import deque
import time
import math

# ── Known tracker signatures ────────────────────────────────────────────────

TRACKER_SIGNATURES = {
    # Apple AirTag & Find My network
    "apple_airtag": {
        "manufacturer_id": 76,          # Apple Inc.
        "service_uuids": ["fd6f"],      # Find My Network
        "device_type_byte": 0x14,       # AirTag in Apple continuity
        "adv_payload_range": (25, 31),  # Typical payload length
        "name_patterns": ["airtag", "found"],
    },
    "apple_findmy": {
        "manufacturer_id": 76,
        "service_uuids": ["fd6f"],
        "device_type_byte": None,
        "adv_payload_range": (20, 40),
        "name_patterns": [],
    },
    # Samsung SmartTag / SmartTag+
    "samsung_smarttag": {
        "manufacturer_id": 117,         # Samsung
        "service_uuids": ["fd5a", "fd69"],
        "device_type_byte": None,
        "adv_payload_range": (15, 35),
        "name_patterns": ["smart-tag", "smarttag", "galaxy smart"],
    },
    # Tile trackers
    "tile": {
        "manufacturer_id": 272,         # Tile Inc. (0x0110)
        "service_uuids": ["feed", "feed0001-c497-4573-4569-6c65546f7949"],
        "device_type_byte": None,
        "adv_payload_range": (10, 30),
        "name_patterns": ["tile"],
    },
    # Chipolo
    "chipolo": {
        "manufacturer_id": 784,         # Chipolo (0x0310)
        "service_uuids": [],
        "device_type_byte": None,
        "adv_payload_range": (10, 30),
        "name_patterns": ["chipolo"],
    },
    # Eufy SmartTrack
    "eufy": {
        "manufacturer_id": None,
        "service_uuids": [],
        "device_type_byte": None,
        "adv_payload_range": (10, 30),
        "name_patterns": ["eufy", "smarttrack"],
    },
}

# Manufacturer IDs known to make tracking devices
TRACKER_MANUFACTURER_IDS = {76, 117, 272, 784}


@dataclass
class TrackerSuspect:
    """A device suspected of being a Bluetooth tracker."""
    device_id: str = ""               # fingerprint_id or MAC
    device_name: str = ""
    tracker_type: str = "unknown"     # airtag, smarttag, tile, chipolo, unknown
    confidence: float = 0.0           # 0.0 - 1.0
    detection_reasons: list = field(default_factory=list)
    first_detected: float = 0.0       # unix timestamp
    last_seen: float = 0.0
    rssi_stability: float = 0.0       # low stdev = stable = following
    duration_minutes: float = 0.0
    avg_rssi: float = -100.0
    is_following: bool = False         # True if "follow mode" triggers

    def to_dict(self):
        return {
            "device_id": self.device_id,
            "device_name": self.device_name,
            "tracker_type": self.tracker_type,
            "confidence": round(self.confidence, 2),
            "detection_reasons": self.detection_reasons,
            "first_detected": self.first_detected,
            "last_seen": self.last_seen,
            "rssi_stability": round(self.rssi_stability, 2),
            "duration_minutes": round(self.duration_minutes, 1),
            "avg_rssi": round(self.avg_rssi, 1),
            "is_following": self.is_following,
        }


class TrackerDetector:
    """
    Detects known and unknown Bluetooth trackers.
    Uses both signature matching (known devices) and behavioral analysis
    (following patterns, persistence, RSSI stability).
    """

    # Thresholds
    FOLLOW_MIN_DURATION_S = 600       # 10 minutes to consider following
    FOLLOW_RSSI_STDEV_MAX = 8.0       # Low RSSI variance = stable distance
    FOLLOW_CONFIDENCE_BOOST = 0.35
    SIGNATURE_CONFIDENCE = 0.70
    PERSISTENT_UNKNOWN_MIN_S = 1800   # 30 min for persistent unknown alert
    PERSISTENT_CONFIDENCE = 0.40

    def __init__(self):
        self.suspects: dict[str, TrackerSuspect] = {}   # device_id -> suspect
        self._rssi_windows: dict[str, deque] = {}       # device_id -> recent RSSI

    # ── Public API ───────────────────────────────────────────────────────

    def evaluate_device(self, device_id: str, name: str,
                        manufacturer_id: int, service_uuids: list,
                        payload_len: int, rssi_history: list,
                        first_seen: float, last_seen: float,
                        mfr_data_bytes: bytes = b"",
                        category: str = "") -> TrackerSuspect | None:
        """
        Evaluate a single device/fingerprint for tracker characteristics.
        Returns TrackerSuspect if suspicious, None if clean.
        """
        confidence = 0.0
        reasons = []
        tracker_type = "unknown"

        # 1 ─ Signature matching against known trackers
        sig_result = self._check_signatures(
            manufacturer_id, service_uuids, payload_len,
            name, mfr_data_bytes
        )
        if sig_result:
            tracker_type = sig_result[0]
            confidence += sig_result[1]
            reasons.append(f"Known {sig_result[0]} signature match")

        # 2 ─ Category hint (already classified as tracker by scanner)
        if category and "tracker" in category.lower():
            confidence += 0.20
            reasons.append("Categorized as tracker device")

        # 3 ─ Following pattern analysis
        duration_s = last_seen - first_seen if last_seen > first_seen else 0
        duration_min = duration_s / 60.0
        is_following = False

        rssi_stdev = self._calc_rssi_stdev(rssi_history)
        avg_rssi = self._calc_rssi_avg(rssi_history)

        if duration_s >= self.FOLLOW_MIN_DURATION_S and rssi_stdev <= self.FOLLOW_RSSI_STDEV_MAX:
            confidence += self.FOLLOW_CONFIDENCE_BOOST
            reasons.append(f"Following pattern: {duration_min:.0f}min, σ={rssi_stdev:.1f}")
            is_following = True

        # 4 ─ Persistent unknown device
        if duration_s >= self.PERSISTENT_UNKNOWN_MIN_S and not name:
            confidence += self.PERSISTENT_CONFIDENCE * 0.5
            reasons.append(f"Persistent unnamed device ({duration_min:.0f}min)")

        # 5 ─ Close proximity bonus
        if avg_rssi > -55:
            confidence += 0.10
            reasons.append(f"Close proximity (RSSI {avg_rssi:.0f} dBm)")

        # 6 ─ No name + tracker-range manufacturer
        if not name and manufacturer_id in TRACKER_MANUFACTURER_IDS:
            confidence += 0.15
            reasons.append("Unnamed device from tracker manufacturer")

        # Clamp
        confidence = min(confidence, 1.0)

        # Only flag if confidence above threshold
        if confidence < 0.25:
            # Remove from suspects if it was there
            self.suspects.pop(device_id, None)
            return None

        suspect = TrackerSuspect(
            device_id=device_id,
            device_name=name or "Unknown",
            tracker_type=tracker_type,
            confidence=confidence,
            detection_reasons=reasons,
            first_detected=first_seen,
            last_seen=last_seen,
            rssi_stability=rssi_stdev,
            duration_minutes=duration_min,
            avg_rssi=avg_rssi,
            is_following=is_following,
        )
        self.suspects[device_id] = suspect
        return suspect

    def get_all_suspects(self) -> list[dict]:
        """Return all current tracker suspects as dicts."""
        now = time.time()
        # Prune stale suspects (not seen in 10 minutes)
        stale = [k for k, v in self.suspects.items() if now - v.last_seen > 600]
        for k in stale:
            del self.suspects[k]
        return [s.to_dict() for s in sorted(
            self.suspects.values(), key=lambda s: -s.confidence
        )]

    def clear(self):
        self.suspects.clear()
        self._rssi_windows.clear()

    # ── Private helpers ──────────────────────────────────────────────────

    def _check_signatures(self, mfr_id, uuids, payload_len, name, mfr_data):
        """Check against known tracker signatures. Returns (type, confidence) or None."""
        name_lower = (name or "").lower()
        uuid_set = set(str(u).lower() for u in (uuids or []))

        for sig_name, sig in TRACKER_SIGNATURES.items():
            score = 0.0

            # Manufacturer ID match
            if sig["manufacturer_id"] is not None and mfr_id == sig["manufacturer_id"]:
                score += 0.30

            # Service UUID match
            sig_uuids = set(str(u).lower() for u in sig["service_uuids"])
            if sig_uuids and sig_uuids & uuid_set:
                score += 0.30

            # Payload length in expected range
            pmin, pmax = sig["adv_payload_range"]
            if pmin <= payload_len <= pmax and (mfr_id == sig.get("manufacturer_id")):
                score += 0.10

            # Name pattern match
            for pattern in sig["name_patterns"]:
                if pattern in name_lower:
                    score += 0.25
                    break

            # Device type byte for Apple
            if sig.get("device_type_byte") and mfr_data and len(mfr_data) >= 1:
                if mfr_data[0] == sig["device_type_byte"]:
                    score += 0.25

            if score >= 0.30:
                return (sig_name.replace("apple_", ""), min(score, 1.0))

        return None

    @staticmethod
    def _calc_rssi_stdev(rssi_history: list) -> float:
        """Calculate RSSI standard deviation from history [(timestamp, rssi), ...]."""
        values = []
        for item in (rssi_history or []):
            if isinstance(item, (list, tuple)) and len(item) >= 2:
                values.append(item[1])
            elif isinstance(item, (int, float)):
                values.append(item)
        if len(values) < 2:
            return 99.0  # Not enough data = assume unstable
        mean = sum(values) / len(values)
        variance = sum((v - mean) ** 2 for v in values) / len(values)
        return math.sqrt(variance)

    @staticmethod
    def _calc_rssi_avg(rssi_history: list) -> float:
        """Calculate average RSSI from history."""
        values = []
        for item in (rssi_history or []):
            if isinstance(item, (list, tuple)) and len(item) >= 2:
                values.append(item[1])
            elif isinstance(item, (int, float)):
                values.append(item)
        if not values:
            return -100.0
        return sum(values) / len(values)
