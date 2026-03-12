"""
BlueShield JSON Logger

Logs all scan results, alerts, and jammer activity to structured JSON files.
Designed for audit trails and incident response.
"""

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from collections import deque


class BlueShieldLogger:
    """JSON-based event logger for BlueShield."""

    def __init__(self, config: dict):
        self.config = config
        self.log_file = Path(config.get("log_file", "blueshield.json"))
        self.max_entries = config.get("max_log_entries", 10000)
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        self.events: deque = deque(maxlen=self.max_entries)
        self._load_existing()

    def _load_existing(self):
        """Load existing log entries."""
        if self.log_file.exists():
            try:
                with open(self.log_file, "r") as f:
                    data = json.load(f)
                    for entry in data.get("events", []):
                        self.events.append(entry)
            except (json.JSONDecodeError, KeyError):
                pass

    def _save(self):
        """Write events to disk."""
        data = {
            "version": "1.0",
            "generated": datetime.now(timezone.utc).isoformat(),
            "total_events": len(self.events),
            "events": list(self.events),
        }
        with open(self.log_file, "w") as f:
            json.dump(data, f, indent=2)

    def log_event(self, event_type: str, data: dict):
        """Log a generic event."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "data": data,
        }
        self.events.append(entry)
        self._save()

    def log_scan(self, scan_result: dict):
        """Log a scan result."""
        self.log_event("scan", scan_result)

    def log_alert(self, alert_level: str, message: str, devices: list = None):
        """Log a security alert."""
        self.log_event("alert", {
            "level": alert_level,
            "message": message,
            "devices": devices or [],
        })

    def log_jam_session(self, session_data: dict):
        """Log a jammer session."""
        self.log_event("jam_session", session_data)

    def log_device_discovered(self, device: dict):
        """Log a new device discovery."""
        self.log_event("device_discovered", device)

    def get_recent_events(self, count: int = 50, event_type: str = None) -> list:
        """Get recent events, optionally filtered by type."""
        events = list(self.events)
        if event_type:
            events = [e for e in events if e.get("event_type") == event_type]
        return events[-count:]

    def get_alerts(self, count: int = 20) -> list:
        """Get recent alerts."""
        return self.get_recent_events(count=count, event_type="alert")

    def export_report(self, filepath: str = None) -> str:
        """Export a full JSON report."""
        if not filepath:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            filepath = str(self.log_file.parent / f"report_{ts}.json")

        report = {
            "report_generated": datetime.now(timezone.utc).isoformat(),
            "total_events": len(self.events),
            "alerts": self.get_alerts(count=100),
            "recent_scans": self.get_recent_events(count=50, event_type="scan"),
            "jam_sessions": self.get_recent_events(count=50, event_type="jam_session"),
            "all_events": list(self.events),
        }
        with open(filepath, "w") as f:
            json.dump(report, f, indent=2)
        return filepath

    def clear_logs(self):
        """Clear all logs."""
        self.events.clear()
        self._save()
