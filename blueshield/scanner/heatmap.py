"""
BLE-Map: 2D room heatmap of BLE device RSSI.

Inspired by RemiFoucault/WiFiMap (2019) — operator walks a grid, recording
RSSI per cell. Picks a device, sees its signal strength colored across the
floor plan. Adapted from WiFi to BLE so we can use the rich device-identity
pipeline already built (AirPods, Apple Watch, AirTags, neighbor's iPhone,
etc. are pickable by friendly name, not just by BSSID).

Design:
  - Grid:        configurable rows x cols, default 6 x 8
  - Sample:      operator clicks a cell, snapshot of all currently-visible
                 devices' (fingerprint_id, rssi) is written to that cell
                 with a timestamp. A cell can hold multiple samples over
                 time (so we can time-travel like WiFiMap's per-timestamp view).
  - Devices:     identified by fingerprint_id (cluster id), with cached
                 best_name + category for the picker UI.
  - Persistence: JSON file under <pcap_dir>/heatmap.json so a survey
                 survives dashboard restarts.

Single source of truth: the *fingerprint engine's* clusters. We snapshot
their .avg_rssi at sample time — that already incorporates the rolling
RSSI smoothing the engine does, so the heatmap is more stable than
raw single-advertisement RSSIs.
"""
from __future__ import annotations

import json
import time
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class Sample:
    """A single per-cell observation of one device."""
    fingerprint_id: str
    rssi: float
    timestamp: float
    best_name: str = ""
    category: str = ""

    def to_dict(self) -> dict:
        return {
            "fingerprint_id": self.fingerprint_id,
            "rssi": round(self.rssi, 1),
            "timestamp": round(self.timestamp, 1),
            "best_name": self.best_name,
            "category": self.category,
        }


@dataclass
class HeatmapGrid:
    """Operator-configurable room grid + samples + room/wall geometry."""
    rows: int = 6
    cols: int = 8
    label: str = "Room"
    cell_size_m: float = 1.0   # metres per cell, used for distance estimates only
    samples: dict = field(default_factory=dict)   # "row,col" -> list[Sample]
    # Walls: list of {id, x1, y1, x2, y2}  in cell-fraction coords (0..cols, 0..rows)
    walls: list = field(default_factory=list)
    # Rooms: list of {id, x, y, w, h, label}  in cell-fraction coords
    rooms: list = field(default_factory=list)
    last_modified: float = field(default_factory=time.time)

    def cell_key(self, row: int, col: int) -> str:
        return f"{row},{col}"

    def add_sample(self, row: int, col: int, sample: Sample) -> None:
        if not (0 <= row < self.rows and 0 <= col < self.cols):
            raise ValueError(f"cell ({row},{col}) outside grid {self.rows}x{self.cols}")
        key = self.cell_key(row, col)
        self.samples.setdefault(key, []).append(sample)
        # Keep the last 50 samples per cell — enough for time-travel,
        # bounds memory if the operator hammers the sample button.
        if len(self.samples[key]) > 50:
            self.samples[key] = self.samples[key][-50:]
        self.last_modified = time.time()

    def clear_cell(self, row: int, col: int) -> int:
        key = self.cell_key(row, col)
        n = len(self.samples.get(key, []))
        self.samples.pop(key, None)
        self.last_modified = time.time()
        return n

    def clear_all(self) -> None:
        self.samples.clear()
        self.last_modified = time.time()

    def device_index(self) -> dict[str, dict]:
        """Build a fingerprint_id -> {best_name, category, sample_count} index
        from all cells. The dashboard's device picker reads this."""
        out: dict[str, dict] = {}
        for cell_samples in self.samples.values():
            for s in cell_samples:
                d = out.setdefault(s.fingerprint_id, {
                    "best_name": s.best_name or "Unknown",
                    "category": s.category or "unknown",
                    "sample_count": 0,
                })
                d["sample_count"] += 1
                # Prefer the most recent best_name we saw
                if s.best_name and s.best_name != "Unknown":
                    d["best_name"] = s.best_name
        return out

    def cells_for_device(self, fingerprint_id: str,
                         max_age_sec: Optional[float] = None) -> dict[str, float]:
        """For one device, return {"row,col": latest_rssi} across the grid.

        If max_age_sec is set, only consider samples newer than that.
        Returns the most recent RSSI per cell — picks the freshest sample
        within the window so the heatmap shows current state, not a stale
        average.
        """
        cutoff = (time.time() - max_age_sec) if max_age_sec else 0
        out: dict[str, float] = {}
        for key, cell_samples in self.samples.items():
            best: Optional[Sample] = None
            for s in cell_samples:
                if s.fingerprint_id != fingerprint_id:
                    continue
                if s.timestamp < cutoff:
                    continue
                if best is None or s.timestamp > best.timestamp:
                    best = s
            if best is not None:
                out[key] = best.rssi
        return out

    def to_dict(self) -> dict:
        return {
            "rows": self.rows,
            "cols": self.cols,
            "label": self.label,
            "cell_size_m": self.cell_size_m,
            "last_modified": round(self.last_modified, 1),
            "cell_count": sum(len(v) for v in self.samples.values()),
            "samples": {k: [s.to_dict() for s in v] for k, v in self.samples.items()},
            "device_index": self.device_index(),
            "walls": list(self.walls),
            "rooms": list(self.rooms),
        }


class HeatmapStore:
    """Thread-safe persistence layer for the heatmap grid."""

    def __init__(self, json_path: str):
        self.path = Path(json_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self.grid = HeatmapGrid()
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.grid = HeatmapGrid(
                rows=data.get("rows", 6),
                cols=data.get("cols", 8),
                label=data.get("label", "Room"),
                cell_size_m=data.get("cell_size_m", 1.0),
            )
            for key, samples in (data.get("samples") or {}).items():
                self.grid.samples[key] = [
                    Sample(
                        fingerprint_id=s["fingerprint_id"],
                        rssi=s["rssi"],
                        timestamp=s["timestamp"],
                        best_name=s.get("best_name", ""),
                        category=s.get("category", ""),
                    ) for s in samples
                ]
            self.grid.walls = list(data.get("walls") or [])
            self.grid.rooms = list(data.get("rooms") or [])
            self.grid.last_modified = data.get("last_modified", time.time())
        except Exception as e:
            # Corrupt file — start fresh rather than crash the dashboard.
            print(f"[heatmap] failed to load {self.path}: {e}")

    def save(self) -> None:
        with self._lock:
            tmp = self.path.with_suffix(".json.tmp")
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self.grid.to_dict(), f, indent=2)
            tmp.replace(self.path)

    def reshape(self, rows: int, cols: int, label: str = "", cell_size_m: float = 1.0) -> None:
        """Resize the grid. Drops samples that fall outside the new dimensions."""
        with self._lock:
            self.grid.rows = max(1, min(50, int(rows)))
            self.grid.cols = max(1, min(50, int(cols)))
            if label:
                self.grid.label = label[:60]
            self.grid.cell_size_m = max(0.1, float(cell_size_m))
            # Drop now-out-of-bounds cells
            for key in list(self.grid.samples.keys()):
                r, c = (int(x) for x in key.split(","))
                if r >= self.grid.rows or c >= self.grid.cols:
                    self.grid.samples.pop(key)
            self.grid.last_modified = time.time()
        self.save()

    def add_samples(self, row: int, col: int, samples: list[Sample]) -> int:
        """Add a batch of samples (one per visible device) to a single cell."""
        with self._lock:
            for s in samples:
                self.grid.add_sample(row, col, s)
        self.save()
        return len(samples)

    def clear_cell(self, row: int, col: int) -> int:
        with self._lock:
            n = self.grid.clear_cell(row, col)
        self.save()
        return n

    def clear_all(self) -> None:
        with self._lock:
            self.grid.clear_all()
        self.save()

    # ── Walls + rooms (geometry editor backing store) ───────────────────────
    def set_walls(self, walls: list) -> None:
        """Replace all walls. Each wall is {x1,y1,x2,y2[,id]} in cell-coords."""
        with self._lock:
            cleaned: list = []
            for w in walls or []:
                try:
                    cleaned.append({
                        "id":  str(w.get("id") or f"w{int(time.time()*1000)}{len(cleaned)}"),
                        "x1": float(w["x1"]), "y1": float(w["y1"]),
                        "x2": float(w["x2"]), "y2": float(w["y2"]),
                    })
                except (KeyError, TypeError, ValueError):
                    continue
            self.grid.walls = cleaned
            self.grid.last_modified = time.time()
        self.save()

    def set_rooms(self, rooms: list) -> None:
        """Replace all rooms. Each room is {x,y,w,h,label[,id]} in cell-coords."""
        with self._lock:
            cleaned: list = []
            for r in rooms or []:
                try:
                    cleaned.append({
                        "id": str(r.get("id") or f"r{int(time.time()*1000)}{len(cleaned)}"),
                        "x": float(r["x"]), "y": float(r["y"]),
                        "w": float(r["w"]), "h": float(r["h"]),
                        "label": str(r.get("label") or "")[:40],
                    })
                except (KeyError, TypeError, ValueError):
                    continue
            self.grid.rooms = cleaned
            self.grid.last_modified = time.time()
        self.save()

    def snapshot(self) -> dict:
        with self._lock:
            return self.grid.to_dict()
