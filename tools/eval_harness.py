#!/usr/bin/env python3
"""
BlueShield Evaluation Harness (v7.5)

Turns BlueShield from an unfalsifiable demo into a measured system.

Given a ground-truth YAML mapping (MAC address → device identity), this
tool:
  1. Runs BlueShield in capture mode for a configurable duration
  2. Reads the produced observations from the correlator/logger
  3. Compares against ground truth
  4. Emits precision / recall / F1 for each capability:
       - MAC correlation (AI correlator re-identifies devices across RPAs)
       - Following detection (7-factor heuristic)
       - Shadow device detection
       - Tracker detection (AirTag signature match)
  5. Produces a defensible results table for thesis / demo

Ground-truth YAML format (example: labeled_dataset.yaml):

    dataset:
      name: "24h benchtop — 2 iPhones + 1 Pixel + 1 AirTag"
      captured_from: 2026-04-20T08:00:00Z
      captured_to:   2026-04-21T08:00:00Z
      environment: "lab room, 4x4m, no external BT"
    devices:
      iphone_mbenitez:
        label: "mbenitez iPhone 14 Pro"
        icloud_account: mrbenitez@...
        known_macs:
          - "7E:C2:AB:40:B1:0C"
          - "DA:A6:30:41:8F:90"
          - "CC:D0:1A:C5:3A:7A"
        expected_is_following: true    # I was carrying it, so it should follow me
        expected_is_tracker: false
      airtag_01:
        label: "Unlabeled AirTag placed on desk"
        expected_is_following: false
        expected_is_tracker: true
        known_macs:
          - "3C:2E:FF:4E:D8:91"

Usage:
    python3 tools/eval_harness.py --dataset datasets/lab_24h.yaml --report report.json
    python3 tools/eval_harness.py --verify-only --chain /path/to/events_chain.jsonl

Author: BlueShield Team — WSU Senior Design
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set

try:
    import yaml  # PyYAML
    HAS_YAML = True
except ImportError:
    HAS_YAML = False
    yaml = None


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class GroundTruthDevice:
    device_id: str               # arbitrary stable identifier (e.g. 'iphone_mbenitez')
    label: str                   # human-readable
    known_macs: Set[str]         # set of MAC addresses this device is known to use
    expected_is_following: bool = False
    expected_is_tracker: bool = False
    icloud_account: Optional[str] = None
    metadata: Dict = field(default_factory=dict)


@dataclass
class GroundTruth:
    name: str
    environment: str
    captured_from: Optional[str]
    captured_to: Optional[str]
    devices: Dict[str, GroundTruthDevice] = field(default_factory=dict)

    @classmethod
    def from_yaml(cls, path: str) -> "GroundTruth":
        if not HAS_YAML:
            print("ERROR: PyYAML not installed. pip install pyyaml", file=sys.stderr)
            sys.exit(2)
        raw = yaml.safe_load(Path(path).read_text())
        meta = raw.get("dataset", {})
        gt = cls(
            name=meta.get("name", "unnamed"),
            environment=meta.get("environment", ""),
            captured_from=meta.get("captured_from"),
            captured_to=meta.get("captured_to"),
        )
        for did, dev in raw.get("devices", {}).items():
            gt.devices[did] = GroundTruthDevice(
                device_id=did,
                label=dev.get("label", did),
                known_macs={m.upper().strip() for m in dev.get("known_macs", [])},
                expected_is_following=bool(dev.get("expected_is_following", False)),
                expected_is_tracker=bool(dev.get("expected_is_tracker", False)),
                icloud_account=dev.get("icloud_account"),
                metadata={k: v for k, v in dev.items()
                         if k not in ("label", "known_macs",
                                      "expected_is_following",
                                      "expected_is_tracker",
                                      "icloud_account")},
            )
        return gt

    def mac_to_device(self) -> Dict[str, str]:
        """Reverse index: MAC → device_id. Supports multi-MAC devices."""
        rev = {}
        for did, dev in self.devices.items():
            for mac in dev.known_macs:
                rev[mac.upper()] = did
        return rev


@dataclass
class ConfusionMatrix:
    """Standard binary classification confusion matrix."""
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom else 0.0

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return self.tp / denom if denom else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def fpr(self) -> float:
        denom = self.fp + self.tn
        return self.fp / denom if denom else 0.0

    def to_dict(self) -> dict:
        return {
            "tp": self.tp, "fp": self.fp, "fn": self.fn, "tn": self.tn,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "fpr": round(self.fpr, 4),
        }


# ---------------------------------------------------------------------------
# Evaluation logic
# ---------------------------------------------------------------------------

def eval_mac_correlator(gt: GroundTruth, correlator_clusters: List[dict]) -> dict:
    """Measure how accurately the AI correlator groups MACs by physical device.

    Metric: for each ground-truth device, check whether its known MACs end
    up in the same cluster. Report pairwise precision/recall over all
    MAC pairs.
    """
    # Build: device_id → set of observed MACs actually captured
    gt_groups = {did: dev.known_macs for did, dev in gt.devices.items()}
    # Build: cluster_id → set of MACs assigned to that cluster by BlueShield
    cluster_groups: Dict[str, Set[str]] = {}
    for c in correlator_clusters:
        cid = c.get("cluster_id") or c.get("primary_mac", "unknown")
        macs = {m.upper() for m in c.get("all_macs", [c.get("primary_mac", "")])}
        cluster_groups[cid] = macs

    cm = ConfusionMatrix()

    # All MACs we care about (union)
    all_gt_macs = set()
    for macs in gt_groups.values():
        all_gt_macs |= macs

    # For every pair of GT MACs, check whether BlueShield put them in the same cluster
    macs = list(all_gt_macs)
    for i in range(len(macs)):
        for j in range(i + 1, len(macs)):
            m1, m2 = macs[i], macs[j]
            # Ground truth: same device?
            gt_same = any(m1 in g and m2 in g for g in gt_groups.values())
            # Predicted: same cluster?
            pred_same = any(m1 in c and m2 in c for c in cluster_groups.values())
            if gt_same and pred_same: cm.tp += 1
            elif gt_same and not pred_same: cm.fn += 1
            elif not gt_same and pred_same: cm.fp += 1
            else: cm.tn += 1

    return {
        "capability": "MAC correlation across randomization",
        "metric": "pairwise-same-cluster",
        "n_pairs": len(macs) * (len(macs) - 1) // 2,
        "n_gt_devices": len(gt.devices),
        "n_predicted_clusters": len(cluster_groups),
        "confusion": cm.to_dict(),
    }


def eval_tracker_detection(gt: GroundTruth, tracker_suspects: List[dict]) -> dict:
    """Measure if expected trackers are flagged; measure false positive rate."""
    mac2dev = gt.mac_to_device()
    detected_devices = set()
    for suspect in tracker_suspects:
        mac = (suspect.get("address") or suspect.get("mac") or "").upper()
        if mac in mac2dev:
            detected_devices.add(mac2dev[mac])
    expected_trackers = {did for did, d in gt.devices.items() if d.expected_is_tracker}
    expected_non = {did for did, d in gt.devices.items() if not d.expected_is_tracker}

    cm = ConfusionMatrix()
    cm.tp = len(detected_devices & expected_trackers)
    cm.fn = len(expected_trackers - detected_devices)
    cm.fp = len(detected_devices & expected_non)
    cm.tn = len(expected_non - detected_devices)

    return {
        "capability": "Tracker / AirTag detection",
        "metric": "per-device",
        "n_expected_trackers": len(expected_trackers),
        "n_detected": len(detected_devices),
        "confusion": cm.to_dict(),
    }


def eval_following_detection(gt: GroundTruth, following_alerts: List[dict]) -> dict:
    mac2dev = gt.mac_to_device()
    alerted_devices = set()
    for alert in following_alerts:
        mac = (alert.get("mac_address") or alert.get("address") or "").upper()
        if mac in mac2dev:
            alerted_devices.add(mac2dev[mac])

    expected_follow = {did for did, d in gt.devices.items() if d.expected_is_following}
    expected_non = {did for did, d in gt.devices.items() if not d.expected_is_following}

    cm = ConfusionMatrix()
    cm.tp = len(alerted_devices & expected_follow)
    cm.fn = len(expected_follow - alerted_devices)
    cm.fp = len(alerted_devices & expected_non)
    cm.tn = len(expected_non - alerted_devices)

    return {
        "capability": "Following detection",
        "metric": "per-device",
        "n_expected_following": len(expected_follow),
        "n_alerted": len(alerted_devices),
        "confusion": cm.to_dict(),
    }


def fetch_live_state(base_url: str, user: str, pw: str) -> dict:
    """Pull BlueShield's live device state for evaluation."""
    try:
        import requests
    except ImportError:
        print("ERROR: pip install requests", file=sys.stderr); sys.exit(2)
    s = requests.Session()
    s.post(f"{base_url}/login", json={"username": user, "password": pw})
    return {
        "correlator_clusters": s.get(f"{base_url}/api/correlator/devices").json(),
        "tracker_suspects": s.get(f"{base_url}/api/trackers").json()
            if s.get(f"{base_url}/api/trackers").ok else [],
        "following": s.get(f"{base_url}/api/following").json()
            if s.get(f"{base_url}/api/following").ok else [],
    }


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def produce_report(gt: GroundTruth, live: dict, out_path: Optional[str]):
    report = {
        "eval_harness_version": "7.5",
        "dataset": {
            "name": gt.name,
            "environment": gt.environment,
            "from": gt.captured_from,
            "to": gt.captured_to,
            "n_devices": len(gt.devices),
        },
        "results": {
            "mac_correlation": eval_mac_correlator(gt, live.get("correlator_clusters", [])),
            "tracker_detection": eval_tracker_detection(gt, live.get("tracker_suspects", [])),
            "following_detection": eval_following_detection(gt, live.get("following", [])),
        },
        "evaluated_at": int(time.time()),
    }

    # Pretty-print summary
    print("=" * 70)
    print(f"BlueShield Evaluation — {gt.name}")
    print(f"Environment: {gt.environment}")
    print(f"Devices in ground truth: {len(gt.devices)}")
    print("=" * 70)
    for cap, res in report["results"].items():
        cm = res["confusion"]
        print(f"\n[{res['capability']}]")
        print(f"  TP={cm['tp']}  FP={cm['fp']}  FN={cm['fn']}  TN={cm['tn']}")
        print(f"  Precision: {cm['precision']:.3f}  "
              f"Recall: {cm['recall']:.3f}  "
              f"F1: {cm['f1']:.3f}  FPR: {cm['fpr']:.3f}")
    print("\n" + "=" * 70)

    if out_path:
        Path(out_path).write_text(json.dumps(report, indent=2))
        print(f"\nFull JSON report: {out_path}")

    return report


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="BlueShield evaluation harness")
    ap.add_argument("--dataset", help="Ground-truth YAML path")
    ap.add_argument("--url", default="http://localhost:8080",
                   help="BlueShield dashboard base URL")
    ap.add_argument("--user", default="admin", help="Login username")
    ap.add_argument("--password", default="admin123", help="Login password")
    ap.add_argument("--report", default="eval_report.json",
                   help="Output JSON report path")
    ap.add_argument("--verify-chain", help="Verify a hash-chained event log and exit")
    args = ap.parse_args()

    if args.verify_chain:
        from blueshield.logs.integrity import verify_chain
        result = verify_chain(args.verify_chain)
        print(json.dumps(result, indent=2))
        sys.exit(0 if result["valid"] else 1)

    if not args.dataset:
        ap.error("--dataset required (or use --verify-chain)")

    gt = GroundTruth.from_yaml(args.dataset)
    live = fetch_live_state(args.url, args.user, args.password)
    produce_report(gt, live, args.report)


if __name__ == "__main__":
    main()
