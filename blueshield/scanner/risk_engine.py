"""
BlueShield Risk Scoring Engine
Calculates per-device risk scores (0-100) and RSSI movement trends.
"""

from dataclasses import dataclass, field
from enum import Enum
import math


class RiskLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


RISK_THRESHOLDS = {
    RiskLevel.LOW:      (0,  25),
    RiskLevel.MEDIUM:   (26, 50),
    RiskLevel.HIGH:     (51, 75),
    RiskLevel.CRITICAL: (76, 100),
}

# Manufacturer IDs considered well-known / reputable
KNOWN_MANUFACTURERS = {
    76,    # Apple
    6,     # Microsoft
    117,   # Samsung
    224,   # Google
    87,    # Garmin
    89,    # Nordic Semiconductor
    301,   # Bose
    269,   # Fitbit
    343,   # Sony
    637,   # JBL / Harman
    171,   # Amazon
    283,   # Xiaomi
    741,   # Tile
}


@dataclass
class RiskAssessment:
    """Per-device risk assessment result."""
    score: int = 0                    # 0-100
    level: str = "low"                # low / medium / high / critical
    factors: list = field(default_factory=list)
    rssi_trend: str = "stationary"    # approaching / leaving / stationary
    rssi_slope: float = 0.0           # dBm per minute
    mac_rotation_rate: float = 0.0    # rotations per hour
    is_tracker_suspect: bool = False

    def to_dict(self):
        return {
            "score": self.score,
            "level": self.level,
            "factors": self.factors,
            "rssi_trend": self.rssi_trend,
            "rssi_slope": round(self.rssi_slope, 2),
            "mac_rotation_rate": round(self.mac_rotation_rate, 2),
            "is_tracker_suspect": self.is_tracker_suspect,
        }


def score_to_level(score: int) -> str:
    """Map numeric score to risk level string."""
    if score <= 25:
        return "low"
    elif score <= 50:
        return "medium"
    elif score <= 75:
        return "high"
    return "critical"


def calculate_rssi_trend(rssi_history: list) -> tuple[str, float]:
    """
    Determine if device is approaching, leaving, or stationary.
    Uses linear regression on recent RSSI readings.

    Args:
        rssi_history: list of (timestamp, rssi) tuples, ordered by time

    Returns:
        (trend_string, slope_per_minute)
        slope > 0 means signal getting stronger = approaching
        slope < 0 means signal getting weaker = leaving
    """
    points = []
    for item in (rssi_history or []):
        if isinstance(item, (list, tuple)) and len(item) >= 2:
            points.append((float(item[0]), float(item[1])))
        elif isinstance(item, dict):
            points.append((float(item.get("t", 0)), float(item.get("rssi", -100))))

    if len(points) < 3:
        return ("stationary", 0.0)

    # Use last 20 points max
    points = points[-20:]

    # Normalize timestamps to minutes from first point
    t0 = points[0][0]
    xs = [(p[0] - t0) / 60.0 for p in points]
    ys = [p[1] for p in points]

    # Simple linear regression
    n = len(xs)
    sum_x = sum(xs)
    sum_y = sum(ys)
    sum_xy = sum(x * y for x, y in zip(xs, ys))
    sum_x2 = sum(x * x for x in xs)

    denom = n * sum_x2 - sum_x * sum_x
    if abs(denom) < 1e-10:
        return ("stationary", 0.0)

    slope = (n * sum_xy - sum_x * sum_y) / denom  # dBm per minute

    # Determine trend based on slope magnitude
    if slope > 1.0:        # Gaining > 1 dBm/min
        return ("approaching", slope)
    elif slope < -1.0:     # Losing > 1 dBm/min
        return ("leaving", slope)
    else:
        return ("stationary", slope)


def calculate_risk(
    fingerprint_id: str = "",
    name: str = "",
    manufacturer_id: int = 0,
    manufacturer_name: str = "",
    is_known: bool = False,
    mac_count: int = 1,
    rssi_history: list = None,
    first_seen: float = 0.0,
    last_seen: float = 0.0,
    observation_count: int = 0,
    avg_rssi: float = -100.0,
    service_uuids: list = None,
    tracker_suspect: bool = False,
    category: str = "",
) -> RiskAssessment:
    """
    Calculate comprehensive risk score for a device.

    Scoring factors (max 100):
      +10  Unknown manufacturer
      +10  MAC randomization (2+ MACs)
      +20  Heavy MAC randomization (5+ MACs)
      +20  RSSI approaching trend
      +10  Duration > 30 min unnamed
      +15  Duration > 60 min unnamed
      +30  Known tracker signature
      +10  Not trusted
      +10  High RSSI + low observation count (brief close contact)
      +10  No name + no services (stealth device)
       -20 Trusted device
       -10 Known manufacturer with name
    """
    score = 0
    factors = []

    # ── Positive risk factors ─────────────────────────────────────────

    # 1. Trusted = major reduction
    if is_known:
        score -= 20
        factors.append("✓ Trusted device (-20)")
    else:
        score += 10
        factors.append("Not in trusted list (+10)")

    # 2. Unknown manufacturer
    if manufacturer_id and manufacturer_id not in KNOWN_MANUFACTURERS:
        score += 10
        factors.append(f"Unknown manufacturer ID {manufacturer_id} (+10)")
    elif manufacturer_id and manufacturer_id in KNOWN_MANUFACTURERS and name:
        score -= 10
        factors.append(f"Known manufacturer: {manufacturer_name or manufacturer_id} (-10)")

    # 3. MAC randomization
    if mac_count >= 5:
        score += 20
        factors.append(f"Heavy MAC rotation: {mac_count} addresses (+20)")
    elif mac_count >= 2:
        score += 10
        factors.append(f"MAC randomization: {mac_count} addresses (+10)")

    # 4. RSSI trend
    trend, slope = calculate_rssi_trend(rssi_history or [])
    if trend == "approaching":
        score += 20
        factors.append(f"Approaching ({slope:+.1f} dBm/min) (+20)")

    # 5. Duration-based risk
    duration_s = last_seen - first_seen if last_seen > first_seen else 0
    duration_min = duration_s / 60.0
    if duration_min > 60 and not name and not is_known:
        score += 15
        factors.append(f"Persistent unnamed device: {duration_min:.0f}min (+15)")
    elif duration_min > 30 and not name and not is_known:
        score += 10
        factors.append(f"Unnamed device present {duration_min:.0f}min (+10)")

    # 6. Tracker suspect
    if tracker_suspect:
        score += 30
        factors.append("Matches tracker signature (+30)")

    # 7. Brief close contact (high RSSI but low observations = just appeared close)
    if avg_rssi > -50 and observation_count < 5 and not is_known:
        score += 10
        factors.append(f"Sudden close proximity: {avg_rssi:.0f} dBm (+10)")

    # 8. Stealth device (no name, no services, no category)
    if not name and not (service_uuids or []) and category in ("", "unknown"):
        score += 10
        factors.append("Stealth device: no name/services/category (+10)")

    # Clamp 0-100
    score = max(0, min(100, score))
    level = score_to_level(score)

    # MAC rotation rate (rotations per hour)
    mac_rate = 0.0
    if mac_count > 1 and duration_s > 0:
        mac_rate = (mac_count - 1) / (duration_s / 3600.0)

    return RiskAssessment(
        score=score,
        level=level,
        factors=factors,
        rssi_trend=trend,
        rssi_slope=slope,
        mac_rotation_rate=mac_rate,
        is_tracker_suspect=tracker_suspect,
    )
