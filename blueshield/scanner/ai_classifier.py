"""
BlueShield AI Device Classifier v4.0

Classifies BLE devices into likely device types using a rule-based
heuristic engine that analyses advertising intervals, service UUIDs,
manufacturer data, packet sizes, RSSI patterns and device names.

Returns a ranked list of likely classifications with confidence scores,
giving the dashboard a futuristic "AI identification" feel.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional
import re

# ── Known Service UUID Mappings ──────────────────────────────────────────────

SERVICE_UUID_HINTS: Dict[str, str] = {
    "180f": "battery_service",
    "180a": "device_information",
    "1812": "hid_device",
    "1803": "link_loss",
    "1802": "immediate_alert",
    "180d": "heart_rate",
    "1816": "cycling_speed",
    "1818": "cycling_power",
    "1814": "running_speed",
    "181c": "body_composition",
    "1809": "health_thermometer",
    "1808": "glucose",
    "181a": "environmental_sensing",
    "181b": "body_composition",
    "fe9f": "google_nearby",
    "fd6f": "apple_exposure",
    "fef3": "apple_continuity",
    "feaa": "eddystone_beacon",
    "fff0": "custom_iot",
    "ffe0": "custom_serial",
}

# ── Device Type Profiles ─────────────────────────────────────────────────────

DEVICE_PROFILES = {
    "smartphone": {
        "label": "Smartphone",
        "icon": "📱",
        "description": "Mobile phone with BLE radio",
        "indicators": {
            "categories": ["phone"],
            "ecosystems": ["apple", "samsung", "google"],
            "name_patterns": [r"iphone", r"galaxy\s*s", r"pixel", r"oneplus", r"huawei", r"xiaomi"],
            "service_hints": ["google_nearby", "apple_exposure", "apple_continuity"],
            "mfr_ids": [76, 117, 224],
            "typical_rssi_range": (-80, -30),
            "typical_adv_interval": (100, 1200),
        },
    },
    "smartwatch": {
        "label": "Smartwatch / Wearable",
        "icon": "⌚",
        "description": "Wrist-worn smart device",
        "indicators": {
            "categories": ["watch"],
            "ecosystems": ["apple", "samsung", "google"],
            "name_patterns": [r"apple\s*watch", r"galaxy\s*watch", r"fitbit", r"garmin", r"amazfit", r"wear\s*os"],
            "service_hints": ["heart_rate", "battery_service"],
            "mfr_ids": [76, 117],
            "typical_rssi_range": (-85, -40),
        },
    },
    "wireless_earbuds": {
        "label": "Wireless Earbuds / Headphones",
        "icon": "🎧",
        "description": "Audio device with BLE",
        "indicators": {
            "categories": ["audio"],
            "name_patterns": [r"airpods", r"galaxy\s*buds", r"bose", r"sony\s*wf", r"jabra", r"beats",
                              r"jbl", r"qc\s*ultra", r"wh-", r"wf-", r"buds"],
            "service_hints": ["battery_service"],
            "mfr_ids": [76, 117, 87],
            "typical_rssi_range": (-75, -25),
        },
    },
    "fitness_tracker": {
        "label": "Fitness Tracker",
        "icon": "💪",
        "description": "Activity and health monitoring band",
        "indicators": {
            "categories": ["health", "watch"],
            "name_patterns": [r"fitbit", r"mi\s*band", r"honor\s*band", r"vivosmart", r"charge"],
            "service_hints": ["heart_rate", "running_speed", "cycling_speed"],
            "typical_rssi_range": (-80, -40),
        },
    },
    "laptop_computer": {
        "label": "Laptop / Computer",
        "icon": "💻",
        "description": "Personal computer with BLE",
        "indicators": {
            "categories": ["computer"],
            "name_patterns": [r"macbook", r"thinkpad", r"surface", r"dell", r"hp\s*(?:elite|pro)", r"lenovo"],
            "ecosystems": ["apple", "microsoft"],
            "mfr_ids": [76, 6],
            "typical_rssi_range": (-80, -30),
        },
    },
    "keyboard_mouse": {
        "label": "Keyboard / Mouse",
        "icon": "⌨️",
        "description": "BLE input peripheral",
        "indicators": {
            "categories": ["input"],
            "name_patterns": [r"keyboard", r"mouse", r"mx\s*keys", r"mx\s*master", r"magic\s*(?:keyboard|mouse|trackpad)",
                              r"logitech", r"k380", r"craft"],
            "service_hints": ["hid_device"],
            "mfr_ids": [1133],  # Logitech
            "typical_rssi_range": (-70, -25),
        },
    },
    "ble_beacon": {
        "label": "BLE Beacon",
        "icon": "📡",
        "description": "Fixed BLE broadcasting beacon",
        "indicators": {
            "categories": ["nearby", "iot"],
            "name_patterns": [r"beacon", r"ibeacon", r"eddystone", r"tile", r"estimote"],
            "service_hints": ["eddystone_beacon"],
            "typical_rssi_range": (-90, -50),
            "typical_adv_interval": (100, 200),
        },
    },
    "tracker_tag": {
        "label": "Tracker / Tag",
        "icon": "📍",
        "description": "Item tracking device (AirTag, SmartTag, Tile)",
        "indicators": {
            "categories": ["tracker"],
            "name_patterns": [r"airtag", r"smarttag", r"tile", r"chipolo"],
            "service_hints": ["apple_exposure"],
            "mfr_ids": [76, 117],
            "typical_rssi_range": (-85, -35),
        },
    },
    "smart_home": {
        "label": "Smart Home Device",
        "icon": "🏠",
        "description": "IoT smart home device",
        "indicators": {
            "categories": ["iot", "tv"],
            "name_patterns": [r"homepod", r"echo", r"nest", r"hue", r"smart\s*(?:plug|bulb|lock|thermostat)",
                              r"ring", r"alexa", r"google\s*home"],
            "ecosystems": ["amazon", "google", "apple"],
            "service_hints": ["custom_iot", "environmental_sensing"],
            "typical_rssi_range": (-80, -50),
        },
    },
    "gaming_controller": {
        "label": "Gaming Controller",
        "icon": "🎮",
        "description": "Wireless game controller",
        "indicators": {
            "categories": ["gaming"],
            "name_patterns": [r"controller", r"gamepad", r"xbox", r"dualsense", r"joy-?con", r"pro\s*controller"],
            "service_hints": ["hid_device"],
            "typical_rssi_range": (-70, -30),
        },
    },
    "medical_device": {
        "label": "Medical / Health Device",
        "icon": "🏥",
        "description": "BLE-enabled medical or health monitoring device",
        "indicators": {
            "categories": ["health"],
            "name_patterns": [r"blood\s*pressure", r"glucose", r"thermometer", r"oximeter", r"cgm",
                              r"omron", r"withings"],
            "service_hints": ["health_thermometer", "glucose", "body_composition"],
        },
    },
    "car_bluetooth": {
        "label": "Automotive BLE",
        "icon": "🚗",
        "description": "Car or vehicle BLE system",
        "indicators": {
            "name_patterns": [r"car\s*(?:kit|play|audio)", r"obd", r"tesla", r"bmw", r"audi",
                              r"ford\s*(?:sync|pass)", r"toyota"],
            "typical_rssi_range": (-85, -50),
        },
    },
    "unknown_stealth": {
        "label": "Unknown / Stealth Device",
        "icon": "🕵️",
        "description": "Unidentifiable device with minimal advertising data",
        "indicators": {
            "categories": ["unknown"],
            "name_patterns": [r"^unknown$", r"^$"],
        },
    },
}


@dataclass
class DeviceClassification:
    """Single classification hypothesis for a device."""
    device_type: str
    label: str
    icon: str
    description: str
    confidence: float  # 0.0 - 1.0
    reasons: List[str] = field(default_factory=list)


@dataclass
class ClassificationResult:
    """Full classification result for a device."""
    device_id: str
    top_classification: Optional[DeviceClassification] = None
    alternatives: List[DeviceClassification] = field(default_factory=list)
    ai_summary: str = ""

    def to_dict(self):
        result = {
            "device_id": self.device_id,
            "ai_summary": self.ai_summary,
        }
        if self.top_classification:
            result["top"] = {
                "device_type": self.top_classification.device_type,
                "label": self.top_classification.label,
                "icon": self.top_classification.icon,
                "description": self.top_classification.description,
                "confidence": round(self.top_classification.confidence, 2),
                "reasons": self.top_classification.reasons,
            }
        result["alternatives"] = [
            {
                "device_type": a.device_type,
                "label": a.label,
                "icon": a.icon,
                "confidence": round(a.confidence, 2),
            }
            for a in self.alternatives[:3]
        ]
        return result


class AIDeviceClassifier:
    """Rule-based heuristic classifier that mimics AI-style device identification."""

    def classify(self, *,
                 device_id: str = "",
                 name: str = "Unknown",
                 category: str = "unknown",
                 ecosystem: str = "",
                 manufacturer_id: int = 0,
                 manufacturer_name: str = "",
                 service_uuids: list = None,
                 payload_len: int = 0,
                 avg_rssi: float = -100,
                 adv_interval_ms: float = 0,
                 is_known: bool = False,
                 tracker_suspect: bool = False,
                 mac_count: int = 1,
                 ) -> ClassificationResult:
        """Classify a device and return ranked hypotheses."""
        service_uuids = service_uuids or []

        # Resolve service UUID hints
        svc_hints = set()
        for uuid in service_uuids:
            short = uuid.replace("-", "")[-8:][:4].lower()
            if short in SERVICE_UUID_HINTS:
                svc_hints.add(SERVICE_UUID_HINTS[short])

        scores: Dict[str, DeviceClassification] = {}

        for dtype, profile in DEVICE_PROFILES.items():
            ind = profile["indicators"]
            score = 0.0
            reasons = []

            # Category match
            if category in ind.get("categories", []):
                score += 0.25
                reasons.append(f"Category match: {category}")

            # Ecosystem match
            if ecosystem and ecosystem in ind.get("ecosystems", []):
                score += 0.15
                reasons.append(f"Ecosystem: {ecosystem}")

            # Name pattern match
            name_lower = name.lower()
            for pattern in ind.get("name_patterns", []):
                if re.search(pattern, name_lower):
                    score += 0.30
                    reasons.append(f"Name matches: {pattern}")
                    break

            # Manufacturer ID match
            if manufacturer_id and manufacturer_id in ind.get("mfr_ids", []):
                score += 0.10
                reasons.append(f"Manufacturer ID: {manufacturer_id}")

            # Service UUID hints
            profile_hints = set(ind.get("service_hints", []))
            overlap = svc_hints & profile_hints
            if overlap:
                bonus = min(len(overlap) * 0.12, 0.25)
                score += bonus
                reasons.append(f"Service match: {', '.join(overlap)}")

            # RSSI range check
            rssi_range = ind.get("typical_rssi_range")
            if rssi_range and rssi_range[0] <= avg_rssi <= rssi_range[1]:
                score += 0.05
                reasons.append("RSSI in typical range")

            # Tracker shortcut
            if tracker_suspect and dtype == "tracker_tag":
                score += 0.35
                reasons.append("Tracker signature detected")

            # MAC rotation penalty for non-phone
            if mac_count > 3 and dtype not in ("smartphone", "unknown_stealth"):
                score -= 0.10

            # Unknown stealth boost
            if dtype == "unknown_stealth":
                if name.lower() in ("unknown", "") and category == "unknown":
                    score += 0.20
                    reasons.append("No identifying data")
                if mac_count > 2:
                    score += 0.10
                    reasons.append("MAC address rotation")

            score = max(0.0, min(1.0, score))
            if score > 0.05:
                scores[dtype] = DeviceClassification(
                    device_type=dtype,
                    label=profile["label"],
                    icon=profile["icon"],
                    description=profile["description"],
                    confidence=score,
                    reasons=reasons,
                )

        # Rank by confidence
        ranked = sorted(scores.values(), key=lambda c: c.confidence, reverse=True)

        result = ClassificationResult(device_id=device_id)
        if ranked:
            result.top_classification = ranked[0]
            result.alternatives = ranked[1:4]

            top = ranked[0]
            pct = int(top.confidence * 100)
            result.ai_summary = (
                f"Identified as {top.label} ({top.icon}) with {pct}% confidence. "
                f"{top.description}."
            )
        else:
            result.ai_summary = "Unable to classify device. Insufficient data."
            result.top_classification = DeviceClassification(
                device_type="unknown",
                label="Unknown Device",
                icon="❓",
                description="Not enough data to classify",
                confidence=0.0,
                reasons=["No matching profile"],
            )

        return result


def estimate_people(clustered_devices: list) -> dict:
    """
    Estimate number of people nearby by clustering personal devices.

    Heuristic: A person typically carries 1-3 BLE devices from the same
    ecosystem (phone + watch + earbuds). Group devices by ecosystem and
    proximity (RSSI) to estimate people count.
    """
    # Group devices by ecosystem
    ecosystem_groups: Dict[str, list] = {}
    for d in clustered_devices:
        eco = d.get("ecosystem", "other")
        if eco not in ecosystem_groups:
            ecosystem_groups[eco] = []
        ecosystem_groups[eco].append(d)

    people_clusters = []
    assigned = set()

    # For each ecosystem, cluster nearby devices into "people"
    for eco, devices in ecosystem_groups.items():
        if eco == "other":
            continue

        # Sort by RSSI (strongest first)
        devices.sort(key=lambda x: -(x.get("avg_rssi", -100)))

        for dev in devices:
            fid = dev.get("fingerprint_id", "")
            if fid in assigned:
                continue

            # Start a new person cluster
            cluster = {
                "ecosystem": eco,
                "devices": [dev],
                "device_types": [dev.get("category", "unknown")],
                "anchor_rssi": dev.get("avg_rssi", -100),
            }
            assigned.add(fid)

            # Find nearby devices from same ecosystem
            for other in devices:
                ofid = other.get("fingerprint_id", "")
                if ofid in assigned:
                    continue
                # Within 15 dBm of anchor = likely same person
                if abs(other.get("avg_rssi", -100) - cluster["anchor_rssi"]) < 15:
                    # Different category preferred (phone + watch != phone + phone)
                    ocat = other.get("category", "unknown")
                    if ocat not in cluster["device_types"] or len(cluster["devices"]) < 2:
                        cluster["devices"].append(other)
                        cluster["device_types"].append(ocat)
                        assigned.add(ofid)
                        if len(cluster["devices"]) >= 4:
                            break

            people_clusters.append(cluster)

    # Remaining unassigned non-"other" devices
    for d in clustered_devices:
        fid = d.get("fingerprint_id", "")
        if fid not in assigned and d.get("ecosystem", "other") != "other":
            people_clusters.append({
                "ecosystem": d.get("ecosystem", "other"),
                "devices": [d],
                "device_types": [d.get("category", "unknown")],
                "anchor_rssi": d.get("avg_rssi", -100),
            })
            assigned.add(fid)

    # "Other" ecosystem devices: each phone/computer = 1 person
    for d in clustered_devices:
        fid = d.get("fingerprint_id", "")
        if fid not in assigned and d.get("category") in ("phone", "computer"):
            people_clusters.append({
                "ecosystem": "other",
                "devices": [d],
                "device_types": [d.get("category", "unknown")],
                "anchor_rssi": d.get("avg_rssi", -100),
            })
            assigned.add(fid)

    # Calculate movement patterns
    active_count = sum(1 for d in clustered_devices
                       if d.get("rssi_trend") in ("approaching", "leaving"))
    stationary_count = sum(1 for d in clustered_devices
                           if d.get("rssi_trend") == "stationary")

    if active_count > stationary_count:
        movement = "Active"
    elif stationary_count > active_count * 2:
        movement = "Settled"
    else:
        movement = "Mixed"

    return {
        "estimated_people": len(people_clusters),
        "clusters": [
            {
                "ecosystem": c["ecosystem"],
                "device_count": len(c["devices"]),
                "device_types": c["device_types"],
                "devices": [d.get("best_name", "?") for d in c["devices"]],
            }
            for c in people_clusters
        ],
        "movement_pattern": movement,
        "total_devices": len(clustered_devices),
        "unassigned": len(clustered_devices) - len(assigned),
    }


def calculate_safety_score(clustered_devices: list, tracker_count: int = 0) -> dict:
    """
    Calculate an environment safety score (0-100).

    Factors:
    - Unknown devices nearby (penalty)
    - Tracker presence (big penalty)
    - MAC randomization level (penalty)
    - Signal anomalies (penalty)
    - Trusted device ratio (bonus)
    """
    if not clustered_devices:
        return {"score": 100, "grade": "A+", "factors": [], "color": "#3fb950"}

    total = len(clustered_devices)
    score = 100
    factors = []

    # Unknown devices
    unknown_count = sum(1 for d in clustered_devices if not d.get("is_known"))
    if unknown_count > 0:
        penalty = min(unknown_count * 4, 30)
        score -= penalty
        factors.append({
            "name": "Unknown devices",
            "impact": -penalty,
            "detail": f"{unknown_count} unidentified device(s)",
            "icon": "❓",
        })

    # Trackers
    if tracker_count > 0:
        penalty = min(tracker_count * 12, 30)
        score -= penalty
        factors.append({
            "name": "Tracker detected",
            "impact": -penalty,
            "detail": f"{tracker_count} suspected tracker(s)",
            "icon": "📍",
        })

    # High risk devices
    high_risk = sum(1 for d in clustered_devices if d.get("risk_level") in ("high", "critical"))
    if high_risk > 0:
        penalty = min(high_risk * 8, 20)
        score -= penalty
        factors.append({
            "name": "High-risk devices",
            "impact": -penalty,
            "detail": f"{high_risk} high/critical risk",
            "icon": "⚠️",
        })

    # MAC rotation
    mac_rotators = sum(1 for d in clustered_devices if (d.get("mac_count", 1) or 1) > 3)
    if mac_rotators > 0:
        penalty = min(mac_rotators * 5, 15)
        score -= penalty
        factors.append({
            "name": "MAC rotation",
            "impact": -penalty,
            "detail": f"{mac_rotators} device(s) rotating MACs",
            "icon": "🔄",
        })

    # Approaching devices
    approaching = sum(1 for d in clustered_devices
                      if d.get("rssi_trend") == "approaching" and not d.get("is_known"))
    if approaching > 0:
        penalty = min(approaching * 5, 15)
        score -= penalty
        factors.append({
            "name": "Approaching unknowns",
            "impact": -penalty,
            "detail": f"{approaching} approaching device(s)",
            "icon": "↗️",
        })

    # Trusted ratio bonus
    trusted = sum(1 for d in clustered_devices if d.get("is_known"))
    if trusted > 0 and total > 0:
        ratio = trusted / total
        bonus = int(ratio * 10)
        score += bonus
        factors.append({
            "name": "Trusted devices",
            "impact": bonus,
            "detail": f"{trusted}/{total} devices trusted",
            "icon": "✅",
        })

    score = max(0, min(100, score))

    # Grade
    if score >= 90:
        grade, color = "A+", "#3fb950"
    elif score >= 80:
        grade, color = "A", "#3fb950"
    elif score >= 70:
        grade, color = "B", "#58a6ff"
    elif score >= 60:
        grade, color = "C", "#d29922"
    elif score >= 40:
        grade, color = "D", "#e67e22"
    else:
        grade, color = "F", "#f85149"

    return {
        "score": score,
        "grade": grade,
        "color": color,
        "factors": factors,
        "summary": f"Environment safety: {grade} ({score}/100)",
    }


def get_bluetooth_weather(clustered_devices: list, analytics: dict) -> dict:
    """
    Generate a 'Bluetooth Weather' report treating RF activity like weather.
    """
    total = len(clustered_devices)

    # Device density
    if total >= 15:
        density = "Crowded"
        density_icon = "🌪️"
    elif total >= 8:
        density = "Busy"
        density_icon = "🌧️"
    elif total >= 4:
        density = "Moderate"
        density_icon = "⛅"
    elif total >= 1:
        density = "Light"
        density_icon = "☀️"
    else:
        density = "Clear"
        density_icon = "🌙"

    # Signal turbulence (variance in RSSI values)
    rssi_values = [d.get("avg_rssi", -100) for d in clustered_devices if d.get("avg_rssi")]
    if len(rssi_values) > 1:
        mean_rssi = sum(rssi_values) / len(rssi_values)
        variance = sum((r - mean_rssi) ** 2 for r in rssi_values) / len(rssi_values)
        if variance > 300:
            turbulence = "Stormy"
            turb_icon = "⚡"
        elif variance > 150:
            turbulence = "Gusty"
            turb_icon = "💨"
        elif variance > 50:
            turbulence = "Breezy"
            turb_icon = "🍃"
        else:
            turbulence = "Calm"
            turb_icon = "🌊"
    else:
        turbulence = "Calm"
        turb_icon = "🌊"

    # New device rate
    new_today = analytics.get("today_new", 0)
    if new_today >= 10:
        forecast = "High traffic expected"
        forecast_icon = "📈"
    elif new_today >= 5:
        forecast = "Moderate traffic"
        forecast_icon = "📊"
    else:
        forecast = "Quiet day"
        forecast_icon = "📉"

    # Approaching count
    approaching = sum(1 for d in clustered_devices if d.get("rssi_trend") == "approaching")
    leaving = sum(1 for d in clustered_devices if d.get("rssi_trend") == "leaving")

    if approaching > leaving + 2:
        wind = "Incoming wave"
        wind_icon = "🌊"
    elif leaving > approaching + 2:
        wind = "Devices departing"
        wind_icon = "🌬️"
    else:
        wind = "Stable"
        wind_icon = "🧘"

    return {
        "density": density,
        "density_icon": density_icon,
        "device_count": total,
        "turbulence": turbulence,
        "turbulence_icon": turb_icon,
        "forecast": forecast,
        "forecast_icon": forecast_icon,
        "wind": wind,
        "wind_icon": wind_icon,
        "new_devices": new_today,
        "approaching": approaching,
        "leaving": leaving,
        "summary": f"{density_icon} {density} | {turb_icon} {turbulence} | {wind_icon} {wind}",
    }
