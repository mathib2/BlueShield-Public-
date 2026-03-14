"""
BlueShield Advanced Analysis Engine v5.0

Advanced behavioral analysis modules:
- FollowingDetector: Detects if a device is following you (≥70% confidence)
- ShadowDeviceDetector: Detects devices trying to hide/be stealthy
- EnvironmentFingerprint: Learns normal environment and flags anomalies
- DeviceLifeStory: Generates narrative timeline for each device
- ConversationGraph: Maps device relationships and ecosystems
"""

import time
import math
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from collections import defaultdict


# ── Following Detector ───────────────────────────────────────────────────────

@dataclass
class FollowingAlert:
    """Alert for a device that may be following the user."""
    device_id: str
    device_name: str
    confidence: float          # 0.0 - 1.0
    duration_minutes: float
    evidence: List[str]
    threat_level: str          # "monitoring" | "suspicious" | "following"
    rssi_pattern: str          # "consistent" | "fluctuating" | "strengthening"

    def to_dict(self):
        return {
            "device_id": self.device_id,
            "device_name": self.device_name,
            "confidence": round(self.confidence, 2),
            "duration_minutes": round(self.duration_minutes, 1),
            "evidence": self.evidence,
            "threat_level": self.threat_level,
            "rssi_pattern": self.rssi_pattern,
        }


class FollowingDetector:
    """
    Detects if a BLE device is following the user by analyzing:
    - Persistent presence over time (unknown device stays nearby)
    - RSSI consistency (maintains similar distance)
    - Movement correlation (appears/disappears when you move)
    - MAC rotation while maintaining presence
    - Tracker signature match

    Confidence threshold: 70% for "following" alert.
    """

    def __init__(self):
        # device_id -> list of (timestamp, rssi) observations
        self.observation_log: Dict[str, List[Tuple[float, float]]] = defaultdict(list)
        # device_id -> first seen timestamp
        self.first_seen: Dict[str, float] = {}
        # Scan timestamps to track our own activity
        self.scan_times: List[float] = []
        self.MAX_OBSERVATIONS = 500

    def record_observation(self, device_id: str, rssi: float, timestamp: float = None):
        """Record a device observation for following analysis."""
        ts = timestamp or time.time()
        if device_id not in self.first_seen:
            self.first_seen[device_id] = ts
        obs = self.observation_log[device_id]
        obs.append((ts, rssi))
        if len(obs) > self.MAX_OBSERVATIONS:
            obs.pop(0)

    def record_scan(self, timestamp: float = None):
        """Record when a scan occurred."""
        ts = timestamp or time.time()
        self.scan_times.append(ts)
        if len(self.scan_times) > 200:
            self.scan_times.pop(0)

    def analyze_device(self, device_id: str, device_name: str = "Unknown",
                       is_known: bool = False, tracker_suspect: bool = False,
                       mac_count: int = 1, category: str = "unknown") -> Optional[FollowingAlert]:
        """
        Analyze if a device is following. Returns FollowingAlert if confidence ≥ 0.3.
        """
        if is_known:
            return None

        observations = self.observation_log.get(device_id, [])
        if len(observations) < 3:
            return None

        now = time.time()
        first = self.first_seen.get(device_id, now)
        duration_sec = now - first
        duration_min = duration_sec / 60

        confidence = 0.0
        evidence = []

        # ── Factor 1: Duration of presence (max +0.25) ──
        if duration_min >= 30:
            confidence += 0.25
            evidence.append(f"Present for {duration_min:.0f} minutes")
        elif duration_min >= 15:
            confidence += 0.18
            evidence.append(f"Present for {duration_min:.0f} minutes")
        elif duration_min >= 5:
            confidence += 0.10
            evidence.append(f"Present for {duration_min:.0f} minutes")

        # ── Factor 2: Scan consistency — appears in most scans (max +0.20) ──
        if len(self.scan_times) >= 5:
            recent_scans = [t for t in self.scan_times if now - t < 600]  # last 10 min
            obs_times = set()
            for ts, _ in observations:
                # Find nearest scan time
                for st in recent_scans:
                    if abs(ts - st) < 10:  # within 10s of scan
                        obs_times.add(st)
                        break
            if recent_scans:
                presence_ratio = len(obs_times) / len(recent_scans)
                if presence_ratio >= 0.8:
                    confidence += 0.20
                    evidence.append(f"Detected in {presence_ratio*100:.0f}% of recent scans")
                elif presence_ratio >= 0.5:
                    confidence += 0.12
                    evidence.append(f"Detected in {presence_ratio*100:.0f}% of recent scans")

        # ── Factor 3: RSSI consistency — maintains distance (max +0.15) ──
        recent_rssi = [r for _, r in observations[-20:]]
        if len(recent_rssi) >= 3:
            mean_rssi = sum(recent_rssi) / len(recent_rssi)
            variance = sum((r - mean_rssi) ** 2 for r in recent_rssi) / len(recent_rssi)
            std_dev = math.sqrt(variance)

            if std_dev < 5:
                confidence += 0.15
                evidence.append(f"Maintains consistent distance (±{std_dev:.1f} dBm)")
                rssi_pattern = "consistent"
            elif std_dev < 10:
                confidence += 0.08
                rssi_pattern = "fluctuating"
            else:
                rssi_pattern = "fluctuating"

            # Check if signal is getting stronger (approaching)
            if len(recent_rssi) >= 5:
                first_half = sum(recent_rssi[:len(recent_rssi)//2]) / (len(recent_rssi)//2)
                second_half = sum(recent_rssi[len(recent_rssi)//2:]) / (len(recent_rssi) - len(recent_rssi)//2)
                if second_half > first_half + 3:
                    confidence += 0.05
                    evidence.append("Signal strengthening (getting closer)")
                    rssi_pattern = "strengthening"
        else:
            rssi_pattern = "fluctuating"

        # ── Factor 4: MAC rotation while present (max +0.15) ──
        if mac_count > 2:
            confidence += 0.10
            evidence.append(f"Rotated through {mac_count} MAC addresses")
        if mac_count > 4:
            confidence += 0.05
            evidence.append("Aggressive MAC rotation (evasion behavior)")

        # ── Factor 5: Tracker signature (max +0.20) ──
        if tracker_suspect:
            confidence += 0.20
            evidence.append("Matches known tracker signature")

        # ── Factor 6: Unknown/stealth device category (max +0.10) ──
        if category == "unknown" and device_name.lower() in ("unknown", ""):
            confidence += 0.10
            evidence.append("No identifying information broadcast")
        elif category == "tracker":
            confidence += 0.08
            evidence.append("Classified as tracker device")

        # ── Factor 7: Close proximity (max +0.05) ──
        if recent_rssi and max(recent_rssi) > -50:
            confidence += 0.05
            evidence.append("Within close proximity (<3m)")

        confidence = min(1.0, confidence)

        if confidence < 0.30:
            return None

        # Determine threat level
        if confidence >= 0.70:
            threat_level = "following"
        elif confidence >= 0.50:
            threat_level = "suspicious"
        else:
            threat_level = "monitoring"

        return FollowingAlert(
            device_id=device_id,
            device_name=device_name,
            confidence=confidence,
            duration_minutes=duration_min,
            evidence=evidence,
            threat_level=threat_level,
            rssi_pattern=rssi_pattern,
        )

    def get_all_alerts(self, clustered_devices: list) -> List[dict]:
        """Analyze all current devices and return following alerts."""
        alerts = []
        for d in clustered_devices:
            fid = d.get("fingerprint_id", "")
            alert = self.analyze_device(
                device_id=fid,
                device_name=d.get("best_name", "Unknown"),
                is_known=d.get("is_known", False),
                tracker_suspect=d.get("tracker_suspect", False),
                mac_count=d.get("mac_count", 1),
                category=d.get("category", "unknown"),
            )
            if alert:
                alerts.append(alert.to_dict())
        return sorted(alerts, key=lambda a: -a["confidence"])

    def clear(self):
        self.observation_log.clear()
        self.first_seen.clear()
        self.scan_times.clear()


# ── Shadow Device Detector ───────────────────────────────────────────────────

@dataclass
class ShadowDevice:
    """A device exhibiting stealth/evasion behavior."""
    device_id: str
    device_name: str
    shadow_score: float        # 0-100
    behaviors: List[str]
    shadow_type: str           # "phantom" | "chameleon" | "ghost" | "lurker"
    risk_assessment: str

    def to_dict(self):
        return {
            "device_id": self.device_id,
            "device_name": self.device_name,
            "shadow_score": round(self.shadow_score, 1),
            "behaviors": self.behaviors,
            "shadow_type": self.shadow_type,
            "risk_assessment": self.risk_assessment,
        }


class ShadowDeviceDetector:
    """
    Detects devices exhibiting stealth behavior:
    - Phantom: Appears/disappears rapidly (intermittent visibility)
    - Chameleon: Changes identity (MAC rotation + name changes)
    - Ghost: Minimal advertising data, hard to fingerprint
    - Lurker: Stays at edge of detection range for extended time
    """

    def __init__(self):
        # device_id -> list of (timestamp, was_visible) tuples
        self.visibility_log: Dict[str, List[Tuple[float, bool]]] = defaultdict(list)
        # device_id -> set of names seen
        self.name_history: Dict[str, set] = defaultdict(set)
        self.MAX_LOG = 200

    def record_visibility(self, device_id: str, visible: bool, name: str = "",
                          timestamp: float = None):
        """Record whether a device was visible in a scan."""
        ts = timestamp or time.time()
        log = self.visibility_log[device_id]
        log.append((ts, visible))
        if len(log) > self.MAX_LOG:
            log.pop(0)
        if name and name.lower() != "unknown":
            self.name_history[device_id].add(name)

    def analyze_device(self, device_id: str, device_name: str = "Unknown",
                       mac_count: int = 1, avg_rssi: float = -100,
                       payload_len: int = 0, service_uuid_count: int = 0,
                       is_known: bool = False, category: str = "unknown",
                       observation_count: int = 0, duration_seconds: float = 0
                       ) -> Optional[ShadowDevice]:
        """Analyze a device for shadow/stealth behavior."""
        if is_known:
            return None

        score = 0.0
        behaviors = []

        # ── Intermittent visibility (Phantom) ──
        vis_log = self.visibility_log.get(device_id, [])
        if len(vis_log) >= 5:
            visible_count = sum(1 for _, v in vis_log[-20:] if v)
            total = len(vis_log[-20:])
            vis_ratio = visible_count / total
            if 0.2 <= vis_ratio <= 0.6:
                score += 25
                behaviors.append(f"Intermittent visibility ({vis_ratio*100:.0f}% of scans)")

        # ── MAC rotation (Chameleon) ──
        if mac_count > 3:
            score += 15
            behaviors.append(f"MAC rotation: {mac_count} addresses used")
        if mac_count > 6:
            score += 10
            behaviors.append("Aggressive identity changes")

        # ── Name changes (Chameleon) ──
        names = self.name_history.get(device_id, set())
        if len(names) > 1:
            score += 15
            behaviors.append(f"Name changed {len(names)} times: {', '.join(list(names)[:3])}")

        # ── Minimal advertising data (Ghost) ──
        if payload_len < 10 and category == "unknown":
            score += 20
            behaviors.append("Minimal advertising payload (stealth broadcast)")
        if service_uuid_count == 0 and category == "unknown":
            score += 10
            behaviors.append("No service UUIDs advertised")
        if device_name.lower() in ("unknown", "") and category == "unknown":
            score += 10
            behaviors.append("No device name broadcast")

        # ── Edge lurking (Lurker) ──
        if avg_rssi < -80 and duration_seconds > 300:
            score += 20
            behaviors.append(f"Lurking at detection edge ({avg_rssi:.0f} dBm for {duration_seconds/60:.0f} min)")
        elif avg_rssi < -85:
            score += 10
            behaviors.append(f"At extreme detection range ({avg_rssi:.0f} dBm)")

        # ── Low observation count relative to duration ──
        if duration_seconds > 120 and observation_count > 0:
            expected_obs = duration_seconds / 10  # ~1 obs per 10s
            if observation_count < expected_obs * 0.3:
                score += 15
                behaviors.append("Appears sporadically despite long presence")

        score = min(100, score)
        if score < 20:
            return None

        # Determine shadow type
        if len(names) > 1 or mac_count > 3:
            shadow_type = "chameleon"
        elif payload_len < 10 and service_uuid_count == 0:
            shadow_type = "ghost"
        elif avg_rssi < -80 and duration_seconds > 300:
            shadow_type = "lurker"
        else:
            shadow_type = "phantom"

        # Risk assessment
        if score >= 70:
            risk = "High — Device actively evading detection"
        elif score >= 50:
            risk = "Medium — Unusual stealth characteristics"
        else:
            risk = "Low — Minor stealth indicators"

        return ShadowDevice(
            device_id=device_id,
            device_name=device_name,
            shadow_score=score,
            behaviors=behaviors,
            shadow_type=shadow_type,
            risk_assessment=risk,
        )

    def get_all_shadows(self, clustered_devices: list) -> List[dict]:
        """Analyze all devices for shadow behavior."""
        shadows = []
        for d in clustered_devices:
            fid = d.get("fingerprint_id", "")
            shadow = self.analyze_device(
                device_id=fid,
                device_name=d.get("best_name", "Unknown"),
                mac_count=d.get("mac_count", 1),
                avg_rssi=d.get("avg_rssi", -100),
                payload_len=d.get("avg_payload_len", 0),
                service_uuid_count=len(d.get("service_uuids", [])),
                is_known=d.get("is_known", False),
                category=d.get("category", "unknown"),
                observation_count=d.get("observation_count", 0),
                duration_seconds=d.get("duration_seconds", 0),
            )
            if shadow:
                shadows.append(shadow.to_dict())
        return sorted(shadows, key=lambda s: -s["shadow_score"])

    def clear(self):
        self.visibility_log.clear()
        self.name_history.clear()


# ── Environment Fingerprint ──────────────────────────────────────────────────

class EnvironmentFingerprint:
    """
    Learns the 'normal' Bluetooth environment and detects anomalies.

    Tracks:
    - Baseline device count and types
    - Expected devices (regulars)
    - Normal RSSI ranges
    - Typical ecosystem distribution

    Flags:
    - Unusual spikes in device count
    - New device types never seen before
    - RSSI anomalies (devices suddenly much closer)
    - Environment composition shifts
    """

    def __init__(self):
        # Historical baselines
        self.device_count_history: List[int] = []
        self.category_history: Dict[str, int] = defaultdict(int)  # total observations per category
        self.ecosystem_history: Dict[str, int] = defaultdict(int)
        self.regular_devices: Dict[str, int] = defaultdict(int)   # device_id -> times seen
        self.scan_count = 0
        self.baseline_device_count = 0
        self.baseline_std = 5
        self.MAX_HISTORY = 500

    def record_scan(self, clustered_devices: list):
        """Record a scan observation for environment learning."""
        self.scan_count += 1
        count = len(clustered_devices)
        self.device_count_history.append(count)
        if len(self.device_count_history) > self.MAX_HISTORY:
            self.device_count_history.pop(0)

        for d in clustered_devices:
            cat = d.get("category", "unknown")
            eco = d.get("ecosystem", "other")
            fid = d.get("fingerprint_id", "")
            self.category_history[cat] += 1
            self.ecosystem_history[eco] += 1
            self.regular_devices[fid] += 1

        # Update baseline (rolling average)
        if len(self.device_count_history) >= 10:
            recent = self.device_count_history[-50:]
            self.baseline_device_count = sum(recent) / len(recent)
            if len(recent) > 1:
                variance = sum((x - self.baseline_device_count) ** 2 for x in recent) / len(recent)
                self.baseline_std = max(2, math.sqrt(variance))

    def get_anomalies(self, clustered_devices: list) -> dict:
        """Check current environment against learned baseline."""
        anomalies = []
        current_count = len(clustered_devices)

        # ── Device count anomaly ──
        if self.scan_count >= 10 and self.baseline_device_count > 0:
            z_score = (current_count - self.baseline_device_count) / max(self.baseline_std, 1)
            if z_score > 2:
                anomalies.append({
                    "type": "device_surge",
                    "severity": "high" if z_score > 3 else "medium",
                    "message": f"Unusual device surge: {current_count} devices (baseline: {self.baseline_device_count:.0f} ±{self.baseline_std:.0f})",
                    "icon": "📈",
                })
            elif z_score < -2:
                anomalies.append({
                    "type": "device_drop",
                    "severity": "medium",
                    "message": f"Unusual device drop: {current_count} devices (baseline: {self.baseline_device_count:.0f})",
                    "icon": "📉",
                })

        # ── New device categories ──
        if self.scan_count >= 5:
            current_cats = set(d.get("category", "unknown") for d in clustered_devices)
            known_cats = set(k for k, v in self.category_history.items() if v >= 3)
            new_cats = current_cats - known_cats - {"unknown"}
            if new_cats:
                anomalies.append({
                    "type": "new_category",
                    "severity": "low",
                    "message": f"New device type(s) detected: {', '.join(new_cats)}",
                    "icon": "🆕",
                })

        # ── First-time devices ──
        new_devices = []
        for d in clustered_devices:
            fid = d.get("fingerprint_id", "")
            if fid and self.regular_devices.get(fid, 0) <= 1 and not d.get("is_known"):
                new_devices.append(d.get("best_name", "Unknown"))
        if new_devices and self.scan_count >= 5:
            anomalies.append({
                "type": "new_devices",
                "severity": "low",
                "message": f"{len(new_devices)} first-time device(s): {', '.join(new_devices[:3])}",
                "icon": "👤",
            })

        # ── Proximity anomaly (device suddenly very close) ──
        close_unknowns = [d for d in clustered_devices
                          if not d.get("is_known") and (d.get("avg_rssi", -100) > -40)]
        if close_unknowns:
            anomalies.append({
                "type": "proximity_alert",
                "severity": "high",
                "message": f"{len(close_unknowns)} unknown device(s) within 1m range",
                "icon": "⚠️",
            })

        # Build environment profile
        total_cats = sum(self.category_history.values()) or 1
        top_categories = sorted(self.category_history.items(), key=lambda x: -x[1])[:5]
        top_ecosystems = sorted(self.ecosystem_history.items(), key=lambda x: -x[1])[:5]

        # Regulars — devices seen in >30% of scans
        regular_threshold = max(3, self.scan_count * 0.3)
        regulars = [fid for fid, count in self.regular_devices.items()
                     if count >= regular_threshold]

        return {
            "anomalies": anomalies,
            "anomaly_count": len(anomalies),
            "has_anomalies": len(anomalies) > 0,
            "baseline": {
                "avg_devices": round(self.baseline_device_count, 1),
                "std_dev": round(self.baseline_std, 1),
                "scans_learned": self.scan_count,
                "regular_count": len(regulars),
            },
            "profile": {
                "top_categories": [{"name": c, "count": n} for c, n in top_categories],
                "top_ecosystems": [{"name": e, "count": n} for e, n in top_ecosystems],
                "total_unique_seen": len(self.regular_devices),
            },
        }

    def clear(self):
        self.device_count_history.clear()
        self.category_history.clear()
        self.ecosystem_history.clear()
        self.regular_devices.clear()
        self.scan_count = 0
        self.baseline_device_count = 0
        self.baseline_std = 5


# ── Device Life Story ────────────────────────────────────────────────────────

class DeviceLifeStory:
    """
    Generates a narrative timeline for each device, tracking:
    - Discovery moment
    - RSSI changes (approaching, leaving)
    - Identity changes
    - Risk level changes
    - Tracker suspicion events
    - Trust/untrust events
    """

    def __init__(self):
        # device_id -> list of event dicts
        self.events: Dict[str, List[dict]] = defaultdict(list)
        # device_id -> last known state
        self.last_state: Dict[str, dict] = {}
        self.MAX_EVENTS = 100

    def record_state(self, device_id: str, state: dict, timestamp: float = None):
        """Record current device state and generate events on changes."""
        ts = timestamp or time.time()
        prev = self.last_state.get(device_id)

        events = self.events[device_id]

        if prev is None:
            # First sighting
            events.append({
                "time": ts,
                "type": "discovered",
                "icon": "🔍",
                "message": f"First detected at {state.get('avg_rssi', -100):.0f} dBm",
                "detail": f"Category: {state.get('category', 'unknown')}, "
                          f"Ecosystem: {state.get('ecosystem', 'other')}",
            })
        else:
            # Check for RSSI movement
            prev_rssi = prev.get("avg_rssi", -100)
            curr_rssi = state.get("avg_rssi", -100)
            delta = curr_rssi - prev_rssi

            if delta > 8:
                events.append({
                    "time": ts,
                    "type": "approaching",
                    "icon": "↗️",
                    "message": f"Moving closer ({prev_rssi:.0f} → {curr_rssi:.0f} dBm)",
                })
            elif delta < -8:
                events.append({
                    "time": ts,
                    "type": "leaving",
                    "icon": "↘️",
                    "message": f"Moving away ({prev_rssi:.0f} → {curr_rssi:.0f} dBm)",
                })

            # Risk level change
            prev_risk = prev.get("risk_level", "low")
            curr_risk = state.get("risk_level", "low")
            if prev_risk != curr_risk:
                events.append({
                    "time": ts,
                    "type": "risk_change",
                    "icon": "⚡",
                    "message": f"Risk level changed: {prev_risk} → {curr_risk}",
                })

            # Tracker suspicion
            if not prev.get("tracker_suspect") and state.get("tracker_suspect"):
                events.append({
                    "time": ts,
                    "type": "tracker_alert",
                    "icon": "🚨",
                    "message": "Flagged as possible tracker!",
                })

            # Trust change
            if not prev.get("is_known") and state.get("is_known"):
                events.append({
                    "time": ts,
                    "type": "trusted",
                    "icon": "✅",
                    "message": "Device marked as trusted",
                })
            elif prev.get("is_known") and not state.get("is_known"):
                events.append({
                    "time": ts,
                    "type": "untrusted",
                    "icon": "❌",
                    "message": "Trust revoked",
                })

            # MAC address change
            prev_macs = prev.get("mac_count", 1)
            curr_macs = state.get("mac_count", 1)
            if curr_macs > prev_macs:
                events.append({
                    "time": ts,
                    "type": "mac_change",
                    "icon": "🔄",
                    "message": f"New MAC address detected (total: {curr_macs})",
                })

        # Trim old events
        if len(events) > self.MAX_EVENTS:
            self.events[device_id] = events[-self.MAX_EVENTS:]

        self.last_state[device_id] = dict(state)

    def get_story(self, device_id: str) -> dict:
        """Get the life story for a device."""
        events = self.events.get(device_id, [])
        if not events:
            return {"device_id": device_id, "events": [], "summary": "No history yet."}

        # Build summary
        first_event = events[0]
        last_event = events[-1]
        duration = last_event["time"] - first_event["time"]
        duration_str = f"{duration/60:.0f} min" if duration > 60 else f"{duration:.0f} sec"

        event_types = [e["type"] for e in events]
        if "tracker_alert" in event_types:
            summary = f"Potential tracker device — observed for {duration_str} with suspicious behavior."
        elif event_types.count("approaching") > event_types.count("leaving"):
            summary = f"Device has been getting closer over {duration_str}."
        elif "risk_change" in event_types:
            summary = f"Device risk level changed during {duration_str} of observation."
        else:
            summary = f"Observed for {duration_str} with {len(events)} events recorded."

        return {
            "device_id": device_id,
            "events": [
                {
                    "time": e["time"],
                    "time_str": time.strftime("%H:%M:%S", time.localtime(e["time"])),
                    "type": e["type"],
                    "icon": e["icon"],
                    "message": e["message"],
                    "detail": e.get("detail", ""),
                }
                for e in events[-30:]  # Last 30 events
            ],
            "summary": summary,
            "total_events": len(events),
        }

    def clear(self):
        self.events.clear()
        self.last_state.clear()


# ── Conversation Graph ───────────────────────────────────────────────────────

class ConversationGraph:
    """
    Maps relationships between BLE devices based on:
    - Ecosystem affiliation (Apple, Samsung, Google, etc.)
    - RSSI proximity clustering (devices near each other)
    - Co-occurrence patterns (devices that appear/disappear together)
    - Service UUID overlap
    """

    def __init__(self):
        # Track co-occurrence: (device_a, device_b) -> count
        self.co_occurrence: Dict[Tuple[str, str], int] = defaultdict(int)
        self.scan_count = 0

    def record_scan(self, device_ids: List[str]):
        """Record which devices appeared together in a scan."""
        self.scan_count += 1
        sorted_ids = sorted(device_ids)
        for i in range(len(sorted_ids)):
            for j in range(i + 1, len(sorted_ids)):
                pair = (sorted_ids[i], sorted_ids[j])
                self.co_occurrence[pair] += 1

    def build_graph(self, clustered_devices: list) -> dict:
        """Build a conversation graph from current devices."""
        nodes = []
        edges = []
        device_map = {d.get("fingerprint_id", ""): d for d in clustered_devices}

        # Build nodes
        for d in clustered_devices:
            fid = d.get("fingerprint_id", "")
            eco = d.get("ecosystem", "other")
            nodes.append({
                "id": fid,
                "name": d.get("best_name", "Unknown"),
                "category": d.get("category", "unknown"),
                "category_icon": d.get("category_icon", "❓"),
                "ecosystem": eco,
                "rssi": d.get("avg_rssi", -100),
                "risk_level": d.get("risk_level", "low"),
                "is_known": d.get("is_known", False),
                "tracker_suspect": d.get("tracker_suspect", False),
            })

        # Build edges from ecosystem relationships
        eco_groups: Dict[str, List[str]] = defaultdict(list)
        for d in clustered_devices:
            eco = d.get("ecosystem", "other")
            if eco != "other":
                eco_groups[eco].append(d.get("fingerprint_id", ""))

        for eco, members in eco_groups.items():
            for i in range(len(members)):
                for j in range(i + 1, len(members)):
                    edges.append({
                        "source": members[i],
                        "target": members[j],
                        "type": "ecosystem",
                        "label": eco,
                        "strength": 0.8,
                    })

        # Build edges from RSSI proximity
        for i in range(len(clustered_devices)):
            for j in range(i + 1, len(clustered_devices)):
                d1 = clustered_devices[i]
                d2 = clustered_devices[j]
                r1 = d1.get("avg_rssi", -100)
                r2 = d2.get("avg_rssi", -100)
                # Devices at similar RSSI are likely near each other
                if abs(r1 - r2) < 10 and r1 > -80 and r2 > -80:
                    fid1 = d1.get("fingerprint_id", "")
                    fid2 = d2.get("fingerprint_id", "")
                    # Check if already has ecosystem edge
                    existing = any(e for e in edges
                                   if {e["source"], e["target"]} == {fid1, fid2})
                    if not existing:
                        edges.append({
                            "source": fid1,
                            "target": fid2,
                            "type": "proximity",
                            "label": "nearby",
                            "strength": 0.4,
                        })

        # Build edges from co-occurrence
        if self.scan_count >= 5:
            threshold = max(3, self.scan_count * 0.5)
            for (a, b), count in self.co_occurrence.items():
                if count >= threshold and a in device_map and b in device_map:
                    existing = any(e for e in edges
                                   if {e["source"], e["target"]} == {a, b})
                    if not existing:
                        strength = min(1.0, count / self.scan_count)
                        edges.append({
                            "source": a,
                            "target": b,
                            "type": "co_occurrence",
                            "label": f"seen together {count}x",
                            "strength": strength,
                        })

        return {
            "nodes": nodes,
            "edges": edges,
            "ecosystems": {eco: len(members) for eco, members in eco_groups.items()},
            "total_connections": len(edges),
        }

    def clear(self):
        self.co_occurrence.clear()
        self.scan_count = 0


# ── Movement Trail Tracker ───────────────────────────────────────────────────

class MovementTrailTracker:
    """
    Tracks RSSI-based position history for each device to render
    movement trails on the radar display.
    """

    def __init__(self):
        # device_id -> list of (timestamp, rssi, angle)
        self.trails: Dict[str, List[dict]] = defaultdict(list)
        self.MAX_TRAIL_POINTS = 30

    def record_position(self, device_id: str, rssi: float, angle: float,
                        timestamp: float = None):
        """Record a device's position for trail rendering."""
        ts = timestamp or time.time()
        trail = self.trails[device_id]
        trail.append({
            "time": ts,
            "rssi": rssi,
            "angle": angle,
        })
        if len(trail) > self.MAX_TRAIL_POINTS:
            trail.pop(0)

    def get_all_trails(self) -> dict:
        """Get all device movement trails."""
        return {
            device_id: [
                {"rssi": p["rssi"], "angle": p["angle"], "age": time.time() - p["time"]}
                for p in trail
            ]
            for device_id, trail in self.trails.items()
            if len(trail) >= 2
        }

    def clear(self):
        self.trails.clear()
