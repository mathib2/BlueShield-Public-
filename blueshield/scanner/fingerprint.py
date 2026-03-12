"""
BlueShield BLE Fingerprinting Engine

Clusters BLE devices by behavioral fingerprint to defeat MAC address randomization.
Instead of tracking by MAC, we build a feature vector from:
  - Manufacturer ID
  - Payload length
  - Service UUIDs
  - RSSI trajectory
  - Advertisement interval timing

Then use similarity scoring to cluster rotating MACs into single "physical devices".
"""

import time
import hashlib
from collections import defaultdict, deque
from dataclasses import dataclass, field, asdict
from statistics import mean, stdev
from typing import Optional


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
    adv_interval: float = 0.0  # seconds between advertisements
    best_name: str = "Unknown"
    category: str = "unknown"
    category_icon: str = ""
    mac_addresses: list = field(default_factory=list)
    first_seen: float = 0.0
    last_seen: float = 0.0
    observation_count: int = 0
    is_known: bool = False
    alert_level: str = "warning"

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
    MIN_SIMILARITY_SCORE = 5  # minimum to consider same device

    def __init__(self, max_observations: int = 5000, cluster_window: float = 300.0):
        """
        Args:
            max_observations: Max advertisement records to keep in memory
            cluster_window: Time window (seconds) for clustering analysis
        """
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

    def record_advertisement(self, mac: str, rssi: int, payload_len: int,
                              manufacturer_id: int, service_uuids: list,
                              name: str = "", tx_power: int = 0,
                              category: str = "unknown", category_icon: str = "",
                              manufacturer_name: str = "Unknown"):
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
        )
        self.observations.append(record)
        self._mac_observations[mac.upper()].append(record)

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
            # Filter out gaps > 5 seconds (likely missed packets)
            short_diffs = [d for d in diffs if d < 5.0]
            if short_diffs:
                adv_interval = mean(short_diffs)

        # Best name (prefer non-Unknown)
        names = [r.name for r in records if r.name and r.name != "Unknown"]
        best_name = names[-1] if names else "Unknown"

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

        return {
            "mac": mac,
            "manufacturer_id": mfr_id,
            "manufacturer_name": mfr_name,
            "avg_payload_len": mean(payload_lens) if payload_lens else 0,
            "service_uuids": sorted(all_uuids),
            "avg_rssi": mean(rssi_values) if rssi_values else -100,
            "rssi_stdev": stdev(rssi_values) if len(rssi_values) > 1 else 0,
            "adv_interval": adv_interval,
            "best_name": best_name,
            "category": category,
            "category_icon": icon,
            "first_seen": timestamps[0] if timestamps else 0,
            "last_seen": timestamps[-1] if timestamps else 0,
            "observation_count": len(records),
        }

    def _similarity_score(self, fp1: dict, fp2: dict) -> int:
        """Calculate similarity between two MAC fingerprints.

        Higher score = more likely same physical device.
        """
        score = 0

        # Same manufacturer ID (strong signal)
        if fp1["manufacturer_id"] and fp2["manufacturer_id"]:
            if fp1["manufacturer_id"] == fp2["manufacturer_id"]:
                score += self.MANUFACTURER_WEIGHT
            else:
                score -= 3  # Different manufacturers = definitely different devices

        # Similar payload length
        if abs(fp1["avg_payload_len"] - fp2["avg_payload_len"]) < 2:
            score += self.PAYLOAD_LEN_WEIGHT

        # Overlapping service UUIDs
        uuids1 = set(fp1["service_uuids"])
        uuids2 = set(fp2["service_uuids"])
        if uuids1 and uuids2:
            overlap = len(uuids1 & uuids2) / max(len(uuids1 | uuids2), 1)
            if overlap > 0.5:
                score += self.SERVICE_UUID_WEIGHT

        # Similar RSSI (proximity)
        if abs(fp1["avg_rssi"] - fp2["avg_rssi"]) < 8:
            score += self.RSSI_WEIGHT

        # Temporal: one disappears as other appears (MAC rotation)
        if fp1["last_seen"] and fp2["first_seen"]:
            gap = abs(fp2["first_seen"] - fp1["last_seen"])
            if gap < 3.0:  # Within 3 seconds
                score += 2

        # Same category boost
        if fp1["category"] == fp2["category"] and fp1["category"] != "unknown":
            score += 1

        return score

    def _generate_fingerprint_id(self, fp: dict) -> str:
        """Generate a stable ID for a fingerprint cluster."""
        # Hash based on key behavioral features
        key = f"{fp['manufacturer_id']}:{fp['avg_payload_len']:.0f}:{','.join(fp['service_uuids'][:3])}"
        return "FP-" + hashlib.md5(key.encode()).hexdigest()[:8].upper()

    def run_clustering(self) -> dict[str, DeviceFingerprint]:
        """Re-cluster all observed MACs into physical device groups.

        Uses greedy similarity-based clustering:
        1. Build fingerprint for each active MAC
        2. Compare all pairs
        3. Merge similar fingerprints into clusters
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
            # Also check if any MAC in the cluster was trusted
            for m in cluster_macs:
                if m in self._mac_to_cluster and self._mac_to_cluster[m] in self.known_fingerprints:
                    is_known = True
                    self.known_fingerprints.add(fp_id)
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

        return {
            "total_physical_devices": total,
            "known_devices": known,
            "unknown_devices": unknown,
            "total_mac_addresses": total_macs,
            "mac_reduction": total_macs - total if total_macs > total else 0,
            "categories": categories,
        }

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
