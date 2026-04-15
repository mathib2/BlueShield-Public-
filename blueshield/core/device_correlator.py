"""
BlueShield Device Correlation AI Engine

Tracks Bluetooth devices across scans, correlates randomized MAC addresses
to physical devices, and maintains a unified deduplicated device database.

Architecture:
  1. Feature Extraction  -- pull fingerprint features from each advertisement
  2. MAC Analysis        -- detect random vs public OUI-based MACs
  3. Similarity Scoring  -- weighted multi-feature cosine similarity
  4. Bayesian Matching   -- update P(same_device | features) over time
  5. Cluster Management  -- group observations into physical device clusters
  6. Device Following    -- track a device across MAC address changes

The model is self-training: confirmed re-appearances of the same MAC
are used to update feature weights in real time, improving correlation
accuracy as the system gathers more data.
"""

import hashlib
import math
import os
import time
import threading
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# Feature extraction helpers
# ---------------------------------------------------------------------------

def _is_random_mac(mac: str) -> bool:
    """Check if MAC has the locally-administered bit set (random address).

    BLE devices using MAC randomization set bit 1 of the first octet.
    E.g., xx:xx:xx:xx:xx:xx where first octet's bit 1 = 1.
    """
    try:
        first_octet = int(mac.split(":")[0], 16)
        return bool(first_octet & 0x02)
    except (ValueError, IndexError):
        return False


def _mac_oui(mac: str) -> str:
    """Extract OUI (first 3 bytes) from MAC address."""
    parts = mac.upper().split(":")
    if len(parts) >= 3:
        return ":".join(parts[:3])
    return ""


def _hash_feature(data: str) -> int:
    """Stable 32-bit hash of a string feature for fast comparison."""
    return int(hashlib.md5(data.encode()).hexdigest()[:8], 16)


# ---------------------------------------------------------------------------
# Device Fingerprint
# ---------------------------------------------------------------------------

@dataclass
class DeviceFingerprint:
    """Extracted feature vector from a BLE device observation."""
    mac: str = ""
    name: str = ""
    manufacturer: str = ""
    manufacturer_id: int = 0
    service_uuids: frozenset = field(default_factory=frozenset)
    tx_power: Optional[int] = None
    rssi: int = -100
    is_random_mac: bool = False
    oui: str = ""
    name_hash: int = 0
    mfr_hash: int = 0
    uuid_hash: int = 0
    appearance: int = 0
    adv_interval_ms: float = 0.0
    timestamp: float = 0.0

    def feature_vector(self) -> Tuple[int, int, int, int, int]:
        """Return a compact feature vector for similarity comparison."""
        return (
            self.name_hash,
            self.mfr_hash,
            self.uuid_hash,
            self.appearance,
            self.manufacturer_id,
        )


# ---------------------------------------------------------------------------
# Physical Device Cluster
# ---------------------------------------------------------------------------

@dataclass
class DeviceCluster:
    """Represents a single physical device that may use multiple MACs."""
    cluster_id: str = ""
    primary_mac: str = ""
    all_macs: Set[str] = field(default_factory=set)
    best_name: str = ""
    manufacturer: str = ""
    manufacturer_id: int = 0
    service_uuids: Set[str] = field(default_factory=set)
    best_rssi: int = -100
    last_rssi: int = -100
    first_seen: float = 0.0
    last_seen: float = 0.0
    observation_count: int = 0
    rssi_history: List[Tuple[float, int]] = field(default_factory=list)
    fingerprints: List[DeviceFingerprint] = field(default_factory=list)
    is_following: bool = False
    confidence: float = 0.5
    risk_score: int = 0

    def to_dict(self) -> dict:
        """Serialize cluster to a dict for API/dashboard consumption."""
        return {
            "cluster_id": self.cluster_id,
            "primary_mac": self.primary_mac,
            "all_macs": sorted(self.all_macs),
            "mac_count": len(self.all_macs),
            "name": self.best_name,
            "manufacturer": self.manufacturer,
            "manufacturer_id": self.manufacturer_id,
            "service_uuids": sorted(self.service_uuids),
            "best_rssi": self.best_rssi,
            "last_rssi": self.last_rssi,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "observation_count": self.observation_count,
            "is_random_mac": _is_random_mac(self.primary_mac),
            "is_following": self.is_following,
            "confidence": round(self.confidence, 3),
            "risk_score": self.risk_score,
            "rssi_trend": self._rssi_trend(),
        }

    def _rssi_trend(self) -> str:
        """Calculate RSSI trend: approaching, receding, or stable."""
        if len(self.rssi_history) < 3:
            return "stable"
        recent = [r for _, r in self.rssi_history[-5:]]
        older = [r for _, r in self.rssi_history[-10:-5]] if len(self.rssi_history) >= 10 else [r for _, r in self.rssi_history[:len(self.rssi_history)//2]]
        if not older:
            return "stable"
        avg_recent = sum(recent) / len(recent)
        avg_older = sum(older) / len(older)
        diff = avg_recent - avg_older
        if diff > 5:
            return "approaching"
        elif diff < -5:
            return "receding"
        return "stable"


# ---------------------------------------------------------------------------
# Lightweight Neural Similarity Model
# ---------------------------------------------------------------------------

class SimilarityModel:
    """Lightweight neural similarity scorer.

    A single-layer perceptron that takes pairwise feature differences
    and outputs a match probability. Self-trains from confirmed matches
    (same MAC seen again) and confirmed non-matches (different OUI).

    Features per pair:
      0: name_hash match (0 or 1)
      1: manufacturer_id match (0 or 1)
      2: uuid_hash match (0 or 1)
      3: appearance match (0 or 1)
      4: OUI match (0 or 1)
      5: RSSI distance (normalized 0-1)
      6: time distance (normalized 0-1)
      7: both random MAC (0 or 1)
    """

    NUM_FEATURES = 8

    def __init__(self):
        # Initialize weights with domain knowledge priors
        self.weights = [
            3.0,   # name match is strong signal
            2.5,   # manufacturer match
            2.0,   # service UUID match
            1.5,   # appearance match
            1.0,   # OUI match
            -1.5,  # RSSI distance (penalty)
            -0.5,  # time distance (penalty)
            0.8,   # both random (slight boost — random MACs change)
        ]
        self.bias = -2.0
        self.learning_rate = 0.05
        self._train_count = 0
        self._lock = threading.Lock()

    @staticmethod
    def _sigmoid(x: float) -> float:
        """Numerically stable sigmoid."""
        if x >= 0:
            return 1.0 / (1.0 + math.exp(-x))
        ex = math.exp(x)
        return ex / (1.0 + ex)

    def predict(self, features: List[float]) -> float:
        """Forward pass: compute match probability from feature vector."""
        z = self.bias
        for w, f in zip(self.weights, features):
            z += w * f
        return self._sigmoid(z)

    def train(self, features: List[float], label: float):
        """Single SGD update step on one training example.

        label: 1.0 = same device, 0.0 = different device
        """
        with self._lock:
            pred = self.predict(features)
            error = label - pred
            grad = error * pred * (1 - pred)
            for i in range(min(len(self.weights), len(features))):
                self.weights[i] += self.learning_rate * grad * features[i]
            self.bias += self.learning_rate * grad
            self._train_count += 1

    def get_stats(self) -> dict:
        return {
            "weights": [round(w, 3) for w in self.weights],
            "bias": round(self.bias, 3),
            "train_samples": self._train_count,
        }


# ---------------------------------------------------------------------------
# Device Correlator — main engine
# ---------------------------------------------------------------------------

class DeviceCorrelator:
    """AI-powered device correlation and tracking engine.

    Maintains a database of device clusters, each representing a single
    physical device. New observations are matched against existing clusters
    using the neural similarity model. Random MAC addresses are tracked
    across changes using fingerprint correlation.

    Thread-safe: all public methods acquire _lock.
    """

    # Match threshold: above this similarity, devices are considered the same
    MATCH_THRESHOLD = 0.65
    # High confidence threshold for auto-merge
    HIGH_CONFIDENCE_THRESHOLD = 0.85
    # Maximum RSSI history per cluster
    MAX_RSSI_HISTORY = 100
    # Maximum age for stale clusters (seconds)
    STALE_TIMEOUT = 300
    # Maximum clusters to track
    MAX_CLUSTERS = 500

    def __init__(self):
        self._clusters: Dict[str, DeviceCluster] = {}
        self._mac_to_cluster: Dict[str, str] = {}
        self._model = SimilarityModel()
        self._lock = threading.RLock()
        self._observation_count = 0
        self._merge_count = 0
        self._stats = {"matches": 0, "new_devices": 0, "merges": 0}

    # ------------------------------------------------------------------
    # Feature extraction
    # ------------------------------------------------------------------

    def _extract_fingerprint(self, device: dict) -> DeviceFingerprint:
        """Extract fingerprint from a scanner device dict."""
        mac = device.get("address", device.get("mac", ""))
        name = device.get("name", "") or ""
        manufacturer = device.get("manufacturer", "") or ""
        mfr_id = device.get("manufacturer_id", 0) or 0
        uuids = device.get("service_uuids", []) or []
        rssi = device.get("rssi", -100) or -100
        tx_power = device.get("tx_power")
        appearance = device.get("appearance", 0) or 0

        fp = DeviceFingerprint(
            mac=mac.upper(),
            name=name,
            manufacturer=manufacturer,
            manufacturer_id=mfr_id,
            service_uuids=frozenset(uuids),
            tx_power=tx_power,
            rssi=rssi,
            is_random_mac=_is_random_mac(mac),
            oui=_mac_oui(mac),
            name_hash=_hash_feature(name.lower()) if name and name != "Unknown" else 0,
            mfr_hash=_hash_feature(manufacturer.lower()) if manufacturer else 0,
            uuid_hash=_hash_feature("|".join(sorted(uuids))) if uuids else 0,
            appearance=appearance,
            timestamp=time.time(),
        )
        return fp

    def _compute_pair_features(self, fp1: DeviceFingerprint,
                                fp2: DeviceFingerprint) -> List[float]:
        """Compute pairwise feature vector for the similarity model."""
        # Feature 0: name match
        name_match = 1.0 if (fp1.name_hash and fp1.name_hash == fp2.name_hash) else 0.0

        # Feature 1: manufacturer ID match
        mfr_match = 1.0 if (fp1.manufacturer_id and fp1.manufacturer_id == fp2.manufacturer_id) else 0.0

        # Feature 2: service UUID match
        uuid_match = 1.0 if (fp1.uuid_hash and fp1.uuid_hash == fp2.uuid_hash) else 0.0

        # Feature 3: appearance match
        app_match = 1.0 if (fp1.appearance and fp1.appearance == fp2.appearance) else 0.0

        # Feature 4: OUI match (only meaningful for non-random MACs)
        oui_match = 0.0
        if fp1.oui and fp2.oui and not fp1.is_random_mac and not fp2.is_random_mac:
            oui_match = 1.0 if fp1.oui == fp2.oui else 0.0

        # Feature 5: RSSI distance (normalized, 0=close, 1=far)
        rssi_dist = min(abs(fp1.rssi - fp2.rssi) / 40.0, 1.0)

        # Feature 6: time distance (normalized, 0=recent, 1=old)
        time_dist = min(abs(fp1.timestamp - fp2.timestamp) / 120.0, 1.0)

        # Feature 7: both random MAC
        both_random = 1.0 if (fp1.is_random_mac and fp2.is_random_mac) else 0.0

        return [name_match, mfr_match, uuid_match, app_match,
                oui_match, rssi_dist, time_dist, both_random]

    # ------------------------------------------------------------------
    # Core correlation logic
    # ------------------------------------------------------------------

    def ingest_device(self, device: dict) -> str:
        """Process a new device observation and return its cluster_id.

        Steps:
        1. Extract fingerprint
        2. Check if MAC already belongs to a known cluster
        3. If not, search for matching cluster using the AI model
        4. Merge into existing cluster or create new one
        5. Self-train model from confirmed matches

        Returns the cluster_id this observation was assigned to.
        """
        with self._lock:
            fp = self._extract_fingerprint(device)
            if not fp.mac:
                return ""

            self._observation_count += 1

            # Fast path: MAC already tracked
            if fp.mac in self._mac_to_cluster:
                cid = self._mac_to_cluster[fp.mac]
                if cid in self._clusters:
                    cluster = self._clusters[cid]
                    self._update_cluster(cluster, fp, device)

                    # Self-train: confirmed same device (same MAC reappeared)
                    if len(cluster.fingerprints) >= 2:
                        prev_fp = cluster.fingerprints[-2]
                        pair_features = self._compute_pair_features(prev_fp, fp)
                        self._model.train(pair_features, 1.0)

                    return cid

            # Search for matching cluster
            best_match_id = None
            best_score = 0.0

            for cid, cluster in self._clusters.items():
                if not cluster.fingerprints:
                    continue

                # Compare against the most recent fingerprint in the cluster
                latest_fp = cluster.fingerprints[-1]
                pair_features = self._compute_pair_features(latest_fp, fp)
                score = self._model.predict(pair_features)

                if score > best_score:
                    best_score = score
                    best_match_id = cid

            # Decision: merge or create new
            if best_match_id and best_score >= self.MATCH_THRESHOLD:
                cluster = self._clusters[best_match_id]
                self._update_cluster(cluster, fp, device)
                self._mac_to_cluster[fp.mac] = best_match_id
                cluster.confidence = max(cluster.confidence, best_score)

                if best_score >= self.HIGH_CONFIDENCE_THRESHOLD:
                    self._merge_count += 1
                    self._stats["merges"] += 1

                self._stats["matches"] += 1

                # Train: matched pair is a positive example
                latest_fp = cluster.fingerprints[-2] if len(cluster.fingerprints) >= 2 else None
                if latest_fp:
                    pair_features = self._compute_pair_features(latest_fp, fp)
                    self._model.train(pair_features, 0.8)

                return best_match_id
            else:
                # Create new cluster
                cid = self._new_cluster_id(fp)
                cluster = DeviceCluster(
                    cluster_id=cid,
                    primary_mac=fp.mac,
                    all_macs={fp.mac},
                    best_name=fp.name if fp.name and fp.name != "Unknown" else "",
                    manufacturer=fp.manufacturer,
                    manufacturer_id=fp.manufacturer_id,
                    service_uuids=set(fp.service_uuids),
                    best_rssi=fp.rssi,
                    last_rssi=fp.rssi,
                    first_seen=fp.timestamp,
                    last_seen=fp.timestamp,
                    observation_count=1,
                    rssi_history=[(fp.timestamp, fp.rssi)],
                    fingerprints=[fp],
                    confidence=0.5,
                )
                self._clusters[cid] = cluster
                self._mac_to_cluster[fp.mac] = cid
                self._stats["new_devices"] += 1

                # Train: negative example against other clusters
                for other_cid, other_cluster in list(self._clusters.items()):
                    if other_cid == cid or not other_cluster.fingerprints:
                        continue
                    other_fp = other_cluster.fingerprints[-1]
                    pair_features = self._compute_pair_features(other_fp, fp)
                    score = self._model.predict(pair_features)
                    if score < 0.3:  # clearly different
                        self._model.train(pair_features, 0.0)
                    # Only train a few negatives per new device
                    if self._observation_count % 10 != 0:
                        break

                self._gc_clusters()
                return cid

    def _update_cluster(self, cluster: DeviceCluster, fp: DeviceFingerprint,
                        device: dict):
        """Update an existing cluster with a new observation."""
        cluster.all_macs.add(fp.mac)
        cluster.last_seen = fp.timestamp
        cluster.last_rssi = fp.rssi
        cluster.observation_count += 1

        if fp.rssi > cluster.best_rssi:
            cluster.best_rssi = fp.rssi

        if fp.name and fp.name != "Unknown" and not cluster.best_name:
            cluster.best_name = fp.name

        if fp.manufacturer and not cluster.manufacturer:
            cluster.manufacturer = fp.manufacturer
            cluster.manufacturer_id = fp.manufacturer_id

        cluster.service_uuids.update(fp.service_uuids)

        cluster.rssi_history.append((fp.timestamp, fp.rssi))
        if len(cluster.rssi_history) > self.MAX_RSSI_HISTORY:
            cluster.rssi_history = cluster.rssi_history[-self.MAX_RSSI_HISTORY:]

        # Keep last 10 fingerprints
        cluster.fingerprints.append(fp)
        if len(cluster.fingerprints) > 10:
            cluster.fingerprints = cluster.fingerprints[-10:]

        # Update risk from device data
        risk = device.get("risk_score", device.get("risk", 0))
        if risk:
            cluster.risk_score = max(cluster.risk_score, risk)

    def _new_cluster_id(self, fp: DeviceFingerprint) -> str:
        """Generate a stable cluster ID from fingerprint."""
        raw = f"{fp.mac}:{fp.timestamp}:{os.urandom(4).hex()}"
        return hashlib.sha256(raw.encode()).hexdigest()[:12]

    def _gc_clusters(self):
        """Garbage-collect stale clusters to prevent memory growth."""
        if len(self._clusters) <= self.MAX_CLUSTERS:
            return
        now = time.time()
        stale = []
        for cid, cluster in self._clusters.items():
            if now - cluster.last_seen > self.STALE_TIMEOUT:
                stale.append(cid)
        # Remove oldest stale clusters
        for cid in stale[:len(stale) // 2]:
            cluster = self._clusters.pop(cid, None)
            if cluster:
                for mac in cluster.all_macs:
                    self._mac_to_cluster.pop(mac, None)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def ingest_scan_results(self, devices: List[dict]) -> List[str]:
        """Process a full scan result, return list of cluster_ids."""
        return [self.ingest_device(d) for d in devices]

    def get_unified_devices(self) -> List[dict]:
        """Get deduplicated device list for the dashboard.

        Returns one entry per physical device (cluster), sorted by
        last_seen descending. Includes all correlated MACs.
        """
        with self._lock:
            clusters = sorted(
                self._clusters.values(),
                key=lambda c: c.last_seen,
                reverse=True,
            )
            return [c.to_dict() for c in clusters]

    def get_device_count(self) -> int:
        """Get number of unique physical devices."""
        with self._lock:
            return len(self._clusters)

    def get_cluster_for_mac(self, mac: str) -> Optional[dict]:
        """Look up which cluster a MAC belongs to."""
        with self._lock:
            mac = mac.upper()
            cid = self._mac_to_cluster.get(mac)
            if cid and cid in self._clusters:
                return self._clusters[cid].to_dict()
            return None

    def get_following_devices(self, min_observations: int = 5,
                               min_duration_s: float = 120.0) -> List[dict]:
        """Detect devices that appear to be following (persistent presence).

        A device is flagged as 'following' if it has been observed
        many times over a sustained period with consistent RSSI.
        """
        with self._lock:
            following = []
            now = time.time()
            for cluster in self._clusters.values():
                duration = cluster.last_seen - cluster.first_seen
                if (cluster.observation_count >= min_observations and
                        duration >= min_duration_s and
                        now - cluster.last_seen < 60):
                    cluster.is_following = True
                    following.append(cluster.to_dict())
            return following

    def get_stats(self) -> dict:
        """Get correlator statistics for the dashboard."""
        with self._lock:
            total_macs = sum(len(c.all_macs) for c in self._clusters.values())
            random_macs = sum(
                1 for c in self._clusters.values()
                if _is_random_mac(c.primary_mac)
            )
            return {
                "total_clusters": len(self._clusters),
                "total_macs_tracked": total_macs,
                "random_mac_devices": random_macs,
                "public_mac_devices": len(self._clusters) - random_macs,
                "observations": self._observation_count,
                "merges": self._merge_count,
                "model": self._model.get_stats(),
                **self._stats,
            }

    def reset(self):
        """Clear all correlation data."""
        with self._lock:
            self._clusters.clear()
            self._mac_to_cluster.clear()
            self._observation_count = 0
            self._merge_count = 0
            self._stats = {"matches": 0, "new_devices": 0, "merges": 0}
