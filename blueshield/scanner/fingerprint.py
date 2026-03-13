"""
BlueShield BLE Fingerprinting Engine v4.0

Clusters BLE devices by behavioral fingerprint to defeat MAC address randomization.
Features:
  - Enhanced similarity scoring with advertisement intervals, name similarity,
    payload patterns, and improved temporal correlation
  - Cluster confidence scoring (0.0 - 1.0)
  - Rolling RSSI history per fingerprint (for charts and trend analysis)
  - Ecosystem classification (Apple, Samsung, Google, etc.)
  - Risk and tracker integration points
"""

import time
import hashlib
import math
from collections import defaultdict, deque
from dataclasses import dataclass, field, asdict
from statistics import mean, stdev
from typing import Optional


# ── Ecosystem mapping ────────────────────────────────────────────────────────

MANUFACTURER_ECOSYSTEM = {
    76: "apple",       # Apple Inc.
    6: "microsoft",    # Microsoft
    117: "samsung",    # Samsung
    224: "google",     # Google
    87: "garmin",      # Garmin
    89: "nordic",      # Nordic Semiconductor
    301: "bose",       # Bose
    269: "fitbit",     # Fitbit (Google)
    343: "sony",       # Sony (via TI)
    637: "jbl",        # JBL / Harman
    171: "amazon",     # Amazon
    283: "xiaomi",     # Xiaomi
    741: "tile",       # Tile
    1452: "logitech",  # Logitech
    1177: "fitbit",    # Fitbit
    1370: "jbl",       # JBL
    2558: "meta",      # Meta Platforms
}


@dataclass
class AdvertisementRecord:
    """Single BLE advertisement observation."""
    timestamp: float
    mac: str
    rssi: int
    payload_len: int
    manufacturer_id: int  # 0 if unknown
    service_uuids: list
    name: str = ""
    tx_power: int = 0
    category: str = "unknown"
    category_icon: str = ""
    manufacturer_name: str = "Unknown"
    mfr_data_bytes: bytes = b""       # raw manufacturer data
    raw_adv_data: dict = field(default_factory=dict)  # full raw advertisement


@dataclass
class DeviceFingerprint:
    """Behavioral fingerprint derived from advertisement observations."""
    fingerprint_id: str = ""
    manufacturer_id: int = 0
    manufacturer_name: str = "Unknown"
    avg_payload_len: float = 0.0
    service_uuids: list = field(default_factory=list)
    avg_rssi: float = -100.0
    rssi_stdev: float = 0.0
    adv_interval: float = 0.0          # seconds between advertisements
    best_name: str = "Unknown"
    category: str = "unknown"
    category_icon: str = ""
    mac_addresses: list = field(default_factory=list)
    first_seen: float = 0.0
    last_seen: float = 0.0
    observation_count: int = 0
    is_known: bool = False
    alert_level: str = "warning"
    # ── v4 new fields ──
    confidence_score: float = 0.0       # cluster confidence 0.0 - 1.0
    risk_score: int = 0                 # 0-100 from risk engine
    risk_level: str = "low"             # low/medium/high/critical
    risk_factors: list = field(default_factory=list)
    rssi_trend: str = "stationary"      # approaching / leaving / stationary
    tracker_suspect: bool = False
    tracker_type: str = ""
    tracker_confidence: float = 0.0
    ecosystem: str = ""                 # apple, samsung, google, etc.
    movement_indicator: str = "stationary"
    rssi_history: list = field(default_factory=list)  # [(timestamp, rssi), ...]
    raw_adv_data: dict = field(default_factory=dict)  # latest raw advertisement

    def to_dict(self):
        d = asdict(self)
        d["duration_seconds"] = round(self.last_seen - self.first_seen, 1) if self.first_seen else 0
        d["mac_count"] = len(self.mac_addresses)
        # Human-readable duration
        dur = d["duration_seconds"]
        if dur < 60:
            d["duration_display"] = f"{int(dur)}s"
        elif dur < 3600:
            d["duration_display"] = f"{int(dur // 60)}m {int(dur % 60)}s"
        else:
            d["duration_display"] = f"{int(dur // 3600)}h {int((dur % 3600) // 60)}m"
        # Trim rssi_history for frontend (last 30 points)
        d["rssi_history"] = [(round(t, 1), r) for t, r in self.rssi_history[-30:]]
        # Remove raw bytes (not JSON serializable)
        d.pop("raw_adv_data", None)
        # Add readable raw_adv for packet inspector
        d["packet_data"] = self.raw_adv_data if self.raw_adv_data else {}
        return d


class BLEFingerprintEngine:
    """Clusters BLE devices by behavioral fingerprint.

    Maintains a rolling window of advertisement observations and
    periodically re-clusters them to identify unique physical devices
    despite MAC address rotation.
    """

    # Similarity thresholds
    MANUFACTURER_WEIGHT = 3
    PAYLOAD_LEN_WEIGHT = 2
    SERVICE_UUID_WEIGHT = 2
    RSSI_WEIGHT = 1
    INTERVAL_WEIGHT = 2
    NAME_WEIGHT = 2
    TEMPORAL_WEIGHT = 2
    CATEGORY_WEIGHT = 1
    MIN_SIMILARITY_SCORE = 6  # raised from 5 for fewer false positives

    def __init__(self, max_observations: int = 5000, cluster_window: float = 300.0):
        self.observations: deque[AdvertisementRecord] = deque(maxlen=max_observations)
        self.cluster_window = cluster_window

        # MAC -> list of observations
        self._mac_observations: dict[str, list[AdvertisementRecord]] = defaultdict(list)

        # Fingerprint clusters: fingerprint_id -> DeviceFingerprint
        self.clusters: dict[str, DeviceFingerprint] = {}

        # MAC -> fingerprint_id mapping
        self._mac_to_cluster: dict[str, str] = {}

        # Known (trusted) fingerprint IDs
        self.known_fingerprints: set[str] = set()

        # Rolling RSSI history per fingerprint_id
        self._rssi_history: dict[str, deque] = defaultdict(lambda: deque(maxlen=60))

        # Track MAC disappearance times for rotation detection
        self._mac_last_seen: dict[str, float] = {}

    def record_advertisement(self, mac: str, rssi: int, payload_len: int,
                              manufacturer_id: int, service_uuids: list,
                              name: str = "", tx_power: int = 0,
                              category: str = "unknown", category_icon: str = "",
                              manufacturer_name: str = "Unknown",
                              mfr_data_bytes: bytes = b"",
                              raw_adv_data: dict = None):
        """Record a single BLE advertisement observation."""
        record = AdvertisementRecord(
            timestamp=time.time(),
            mac=mac.upper(),
            rssi=rssi,
            payload_len=payload_len,
            manufacturer_id=manufacturer_id,
            service_uuids=sorted(service_uuids),
            name=name,
            tx_power=tx_power,
            category=category,
            category_icon=category_icon,
            manufacturer_name=manufacturer_name,
            mfr_data_bytes=mfr_data_bytes if isinstance(mfr_data_bytes, bytes) else b"",
            raw_adv_data=raw_adv_data or {},
        )
        self.observations.append(record)
        self._mac_observations[mac.upper()].append(record)
        self._mac_last_seen[mac.upper()] = time.time()

        # Trim old observations per MAC
        cutoff = time.time() - self.cluster_window
        for m in list(self._mac_observations.keys()):
            self._mac_observations[m] = [
                r for r in self._mac_observations[m] if r.timestamp > cutoff
            ]
            if not self._mac_observations[m]:
                del self._mac_observations[m]

    def _build_mac_fingerprint(self, mac: str) -> Optional[dict]:
        """Build a feature vector for a single MAC address."""
        records = self._mac_observations.get(mac, [])
        if not records:
            return None

        rssi_values = [r.rssi for r in records if r.rssi != 0]
        payload_lens = [r.payload_len for r in records]
        timestamps = [r.timestamp for r in records]

        # Calculate advertisement interval
        adv_interval = 0.0
        if len(timestamps) > 1:
            diffs = [timestamps[i] - timestamps[i - 1] for i in range(1, len(timestamps))]
            short_diffs = [d for d in diffs if d < 5.0]
            if short_diffs:
                adv_interval = mean(short_diffs)

        # Best name (prefer non-Unknown)
        names = [r.name for r in records if r.name and r.name != "Unknown"]
        best_name = names[-1] if names else "Unknown"

        # All names for similarity comparison
        all_names = list(set(n.lower() for n in names)) if names else []

        # Most common manufacturer
        mfr_ids = [r.manufacturer_id for r in records if r.manufacturer_id != 0]
        mfr_id = max(set(mfr_ids), key=mfr_ids.count) if mfr_ids else 0

        # Manufacturer name
        mfr_names = [r.manufacturer_name for r in records if r.manufacturer_name != "Unknown"]
        mfr_name = mfr_names[-1] if mfr_names else "Unknown"

        # All service UUIDs seen
        all_uuids = set()
        for r in records:
            all_uuids.update(r.service_uuids)

        # Category (prefer non-unknown)
        cats = [r.category for r in records if r.category != "unknown"]
        category = cats[-1] if cats else "unknown"

        icons = [r.category_icon for r in records if r.category_icon]
        icon = icons[-1] if icons else ""

        # Payload length distribution (pattern, not just average)
        payload_mode = max(set(payload_lens), key=payload_lens.count) if payload_lens else 0

        # Latest raw advertisement data
        latest_raw = {}
        latest_mfr_bytes = b""
        for r in reversed(records):
            if r.raw_adv_data:
                latest_raw = r.raw_adv_data
                break
        for r in reversed(records):
            if r.mfr_data_bytes:
                latest_mfr_bytes = r.mfr_data_bytes
                break

        return {
            "mac": mac,
            "manufacturer_id": mfr_id,
            "manufacturer_name": mfr_name,
            "avg_payload_len": mean(payload_lens) if payload_lens else 0,
            "payload_mode": payload_mode,
            "service_uuids": sorted(all_uuids),
            "avg_rssi": mean(rssi_values) if rssi_values else -100,
            "rssi_stdev": stdev(rssi_values) if len(rssi_values) > 1 else 0,
            "adv_interval": adv_interval,
            "best_name": best_name,
            "all_names": all_names,
            "category": category,
            "category_icon": icon,
            "first_seen": timestamps[0] if timestamps else 0,
            "last_seen": timestamps[-1] if timestamps else 0,
            "observation_count": len(records),
            "rssi_history": [(r.timestamp, r.rssi) for r in records if r.rssi != 0],
            "raw_adv_data": latest_raw,
            "mfr_data_bytes": latest_mfr_bytes,
        }

    def _similarity_score(self, fp1: dict, fp2: dict) -> int:
        """Calculate similarity between two MAC fingerprints.

        Enhanced scoring with interval matching, name similarity,
        payload pattern matching, and improved temporal correlation.
        """
        score = 0

        # 1. Same manufacturer ID (strong signal)
        if fp1["manufacturer_id"] and fp2["manufacturer_id"]:
            if fp1["manufacturer_id"] == fp2["manufacturer_id"]:
                score += self.MANUFACTURER_WEIGHT
            else:
                score -= 3  # Different manufacturers = definitely different devices

        # 2. Similar payload length (mode-based for better pattern matching)
        payload_diff = abs(fp1["avg_payload_len"] - fp2["avg_payload_len"])
        if payload_diff < 2:
            score += self.PAYLOAD_LEN_WEIGHT
        elif payload_diff < 4:
            score += 1  # Partial credit

        # 3. Overlapping service UUIDs
        uuids1 = set(fp1["service_uuids"])
        uuids2 = set(fp2["service_uuids"])
        if uuids1 and uuids2:
            overlap = len(uuids1 & uuids2) / max(len(uuids1 | uuids2), 1)
            if overlap > 0.5:
                score += self.SERVICE_UUID_WEIGHT
            elif overlap > 0.25:
                score += 1

        # 4. Similar RSSI (proximity)
        rssi_diff = abs(fp1["avg_rssi"] - fp2["avg_rssi"])
        if rssi_diff < 8:
            score += self.RSSI_WEIGHT

        # 5. Advertisement interval matching (NEW)
        if fp1["adv_interval"] > 0 and fp2["adv_interval"] > 0:
            interval_diff = abs(fp1["adv_interval"] - fp2["adv_interval"])
            if interval_diff < 0.05:
                score += self.INTERVAL_WEIGHT
            elif interval_diff < 0.15:
                score += 1

        # 6. Name similarity (NEW)
        names1 = fp1.get("all_names", [])
        names2 = fp2.get("all_names", [])
        if names1 and names2:
            # Check for shared prefix or substring
            for n1 in names1:
                for n2 in names2:
                    if n1 and n2:
                        # Common prefix of at least 4 characters
                        common_prefix = 0
                        for a, b in zip(n1, n2):
                            if a == b:
                                common_prefix += 1
                            else:
                                break
                        if common_prefix >= 4:
                            score += self.NAME_WEIGHT
                            break
                        # One contains the other
                        if len(n1) > 3 and len(n2) > 3 and (n1 in n2 or n2 in n1):
                            score += self.NAME_WEIGHT
                            break
                else:
                    continue
                break

        # 7. Temporal: MAC rotation detection (ENHANCED)
        # Check if one disappears as other appears
        gap1 = abs(fp2["first_seen"] - fp1["last_seen"]) if fp1["last_seen"] and fp2["first_seen"] else 999
        gap2 = abs(fp1["first_seen"] - fp2["last_seen"]) if fp2["last_seen"] and fp1["first_seen"] else 999
        min_gap = min(gap1, gap2)
        if min_gap < 2.0:
            score += self.TEMPORAL_WEIGHT + 1  # Strong rotation signal
        elif min_gap < 5.0:
            score += self.TEMPORAL_WEIGHT

        # 8. Same category boost
        if fp1["category"] == fp2["category"] and fp1["category"] != "unknown":
            score += self.CATEGORY_WEIGHT

        return score

    def _calculate_cluster_confidence(self, cluster_fps: list) -> float:
        """Calculate confidence score for a cluster (0.0 - 1.0).

        Based on consistency of features across cluster members.
        """
        if len(cluster_fps) <= 1:
            return 0.8  # Single MAC = moderate confidence

        score = 0.0
        checks = 0

        # Manufacturer consistency
        mfr_ids = [fp["manufacturer_id"] for fp in cluster_fps if fp["manufacturer_id"]]
        if mfr_ids:
            checks += 1
            if len(set(mfr_ids)) == 1:
                score += 1.0
            else:
                score += 0.3

        # Payload length consistency
        payloads = [fp["avg_payload_len"] for fp in cluster_fps]
        if payloads and max(payloads) - min(payloads) < 3:
            checks += 1
            score += 1.0
        elif payloads:
            checks += 1
            score += 0.4

        # Service UUID overlap quality
        all_uuid_sets = [set(fp["service_uuids"]) for fp in cluster_fps if fp["service_uuids"]]
        if len(all_uuid_sets) >= 2:
            checks += 1
            intersection = all_uuid_sets[0]
            for s in all_uuid_sets[1:]:
                intersection &= s
            union = set()
            for s in all_uuid_sets:
                union |= s
            if union:
                score += len(intersection) / len(union)
            else:
                score += 0.5

        # Category consistency
        cats = [fp["category"] for fp in cluster_fps if fp["category"] != "unknown"]
        if cats:
            checks += 1
            if len(set(cats)) == 1:
                score += 1.0
            else:
                score += 0.2

        if checks == 0:
            return 0.5
        return min(score / checks, 1.0)

    @staticmethod
    def _assign_ecosystem(manufacturer_id: int) -> str:
        """Map manufacturer ID to ecosystem string."""
        return MANUFACTURER_ECOSYSTEM.get(manufacturer_id, "")

    def _generate_fingerprint_id(self, fp: dict) -> str:
        """Generate a stable ID for a fingerprint cluster."""
        key = f"{fp['manufacturer_id']}:{fp['avg_payload_len']:.0f}:{','.join(fp['service_uuids'][:3])}"
        return "FP-" + hashlib.md5(key.encode()).hexdigest()[:8].upper()

    def run_clustering(self) -> dict[str, DeviceFingerprint]:
        """Re-cluster all observed MACs into physical device groups.

        Uses greedy similarity-based clustering with enhanced scoring.
        """
        active_macs = list(self._mac_observations.keys())
        if not active_macs:
            return self.clusters

        # Build per-MAC fingerprints
        mac_fps = {}
        for mac in active_macs:
            fp = self._build_mac_fingerprint(mac)
            if fp:
                mac_fps[mac] = fp

        if not mac_fps:
            return self.clusters

        # Greedy clustering
        clustered = set()
        new_clusters: dict[str, DeviceFingerprint] = {}

        mac_list = list(mac_fps.keys())
        for i, mac_a in enumerate(mac_list):
            if mac_a in clustered:
                continue

            fp_a = mac_fps[mac_a]
            cluster_macs = [mac_a]
            cluster_fps = [fp_a]
            clustered.add(mac_a)

            for mac_b in mac_list[i + 1:]:
                if mac_b in clustered:
                    continue
                fp_b = mac_fps[mac_b]
                score = self._similarity_score(fp_a, fp_b)
                if score >= self.MIN_SIMILARITY_SCORE:
                    cluster_macs.append(mac_b)
                    cluster_fps.append(fp_b)
                    clustered.add(mac_b)

            # Build cluster fingerprint
            all_rssi = [fp["avg_rssi"] for fp in cluster_fps]
            all_names = [fp["best_name"] for fp in cluster_fps if fp["best_name"] != "Unknown"]
            all_cats = [fp["category"] for fp in cluster_fps if fp["category"] != "unknown"]
            all_icons = [fp["category_icon"] for fp in cluster_fps if fp["category_icon"]]
            all_uuids = set()
            for fp in cluster_fps:
                all_uuids.update(fp["service_uuids"])

            best_name = all_names[-1] if all_names else "Unknown"
            category = all_cats[-1] if all_cats else "unknown"
            icon = all_icons[-1] if all_icons else ""

            fp_id = self._generate_fingerprint_id(cluster_fps[0])

            # Check if this cluster was previously known
            is_known = fp_id in self.known_fingerprints
            for m in cluster_macs:
                if m in self._mac_to_cluster and self._mac_to_cluster[m] in self.known_fingerprints:
                    is_known = True
                    self.known_fingerprints.add(fp_id)
                    break

            # Calculate confidence
            confidence = self._calculate_cluster_confidence(cluster_fps)

            # Determine ecosystem
            ecosystem = self._assign_ecosystem(cluster_fps[0]["manufacturer_id"])

            # Merge RSSI histories from all MACs in cluster
            merged_rssi = []
            for fp in cluster_fps:
                merged_rssi.extend(fp.get("rssi_history", []))
            merged_rssi.sort(key=lambda x: x[0])  # sort by timestamp

            # Update persistent RSSI history for this fingerprint
            for t, r in merged_rssi:
                self._rssi_history[fp_id].append((t, r))

            # Get latest raw advertisement data
            latest_raw = {}
            for fp in reversed(cluster_fps):
                if fp.get("raw_adv_data"):
                    latest_raw = fp["raw_adv_data"]
                    break

            device_fp = DeviceFingerprint(
                fingerprint_id=fp_id,
                manufacturer_id=cluster_fps[0]["manufacturer_id"],
                manufacturer_name=cluster_fps[0]["manufacturer_name"],
                avg_payload_len=mean([fp["avg_payload_len"] for fp in cluster_fps]),
                service_uuids=sorted(all_uuids),
                avg_rssi=mean(all_rssi) if all_rssi else -100,
                rssi_stdev=stdev(all_rssi) if len(all_rssi) > 1 else 0,
                adv_interval=cluster_fps[0]["adv_interval"],
                best_name=best_name,
                category=category,
                category_icon=icon,
                mac_addresses=cluster_macs,
                first_seen=min(fp["first_seen"] for fp in cluster_fps),
                last_seen=max(fp["last_seen"] for fp in cluster_fps),
                observation_count=sum(fp["observation_count"] for fp in cluster_fps),
                is_known=is_known,
                alert_level="none" if is_known else "warning",
                confidence_score=confidence,
                ecosystem=ecosystem,
                rssi_history=list(self._rssi_history[fp_id]),
                raw_adv_data=latest_raw,
            )

            new_clusters[fp_id] = device_fp
            for m in cluster_macs:
                self._mac_to_cluster[m] = fp_id

        self.clusters = new_clusters
        return self.clusters

    def trust_fingerprint(self, fingerprint_id: str):
        """Mark a fingerprint (physical device) as trusted."""
        self.known_fingerprints.add(fingerprint_id)
        if fingerprint_id in self.clusters:
            self.clusters[fingerprint_id].is_known = True
            self.clusters[fingerprint_id].alert_level = "none"

    def untrust_fingerprint(self, fingerprint_id: str):
        """Remove trust from a fingerprint."""
        self.known_fingerprints.discard(fingerprint_id)
        if fingerprint_id in self.clusters:
            self.clusters[fingerprint_id].is_known = False
            self.clusters[fingerprint_id].alert_level = "warning"

    def get_clustered_devices(self) -> list[dict]:
        """Get all clustered devices sorted by last_seen."""
        devices = sorted(
            self.clusters.values(),
            key=lambda d: d.last_seen,
            reverse=True
        )
        return [d.to_dict() for d in devices]

    def get_cluster_summary(self) -> dict:
        """Get summary statistics."""
        total = len(self.clusters)
        known = sum(1 for d in self.clusters.values() if d.is_known)
        unknown = total - known
        total_macs = sum(len(d.mac_addresses) for d in self.clusters.values())

        categories = {}
        for d in self.clusters.values():
            cat = d.category or "unknown"
            categories[cat] = categories.get(cat, 0) + 1

        ecosystems = {}
        for d in self.clusters.values():
            eco = d.ecosystem or "other"
            ecosystems[eco] = ecosystems.get(eco, 0) + 1

        return {
            "total_physical_devices": total,
            "known_devices": known,
            "unknown_devices": unknown,
            "total_mac_addresses": total_macs,
            "mac_reduction": total_macs - total if total_macs > total else 0,
            "categories": categories,
            "ecosystems": ecosystems,
        }

    def get_rssi_history(self, fingerprint_id: str) -> list:
        """Get RSSI history for a specific fingerprint."""
        return list(self._rssi_history.get(fingerprint_id, []))

    def get_fingerprint_for_mac(self, mac: str) -> Optional[str]:
        """Get the fingerprint ID for a given MAC address."""
        return self._mac_to_cluster.get(mac.upper())

    def filter_by_rssi(self, min_rssi: int = -100, max_rssi: int = 0) -> list[dict]:
        """Filter clustered devices by RSSI range."""
        devices = []
        for d in self.clusters.values():
            if min_rssi <= d.avg_rssi <= max_rssi:
                devices.append(d.to_dict())
        return sorted(devices, key=lambda x: x["last_seen"], reverse=True)
