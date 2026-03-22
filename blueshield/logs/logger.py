"""
BlueShield JSON Logger + Analytics Tracker

Logs all scan results, alerts, and jammer activity to structured JSON files.
Tracks historical analytics for dashboard charts.
Designed for audit trails and incident response.
"""

import json
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from collections import deque


class AnalyticsTracker:
    """Tracks historical device analytics for dashboard charts and stats."""

    def __init__(self, data_dir: Path = None):
        self.data_dir = data_dir or Path(".")
        self.analytics_file = self.data_dir / "analytics.json"
        self.data_dir.mkdir(parents=True, exist_ok=True)

        # Daily stats: "YYYY-MM-DD" -> {count, new, returning, peak}
        self.daily_stats: dict[str, dict] = {}

        # All-time tracking
        self.all_seen_ids: set = set()       # all fingerprint IDs ever seen
        self.today_seen_ids: set = set()     # today's fingerprint IDs
        self.peak_device_count: int = 0
        self.peak_device_time: str = ""
        self._current_day: str = ""

        self._load()

    def _load(self):
        """Load persisted analytics."""
        if self.analytics_file.exists():
            try:
                with open(self.analytics_file, "r") as f:
                    data = json.load(f)
                self.daily_stats = data.get("daily_stats", {})
                self.all_seen_ids = set(data.get("all_seen_ids", []))
                self.peak_device_count = data.get("peak_device_count", 0)
                self.peak_device_time = data.get("peak_device_time", "")
            except (json.JSONDecodeError, KeyError):
                pass

    def _save(self):
        """Persist analytics to disk."""
        data = {
            "daily_stats": self.daily_stats,
            "all_seen_ids": list(self.all_seen_ids)[-500:],  # Keep last 500
            "peak_device_count": self.peak_device_count,
            "peak_device_time": self.peak_device_time,
        }
        try:
            # Only keep last 500 IDs
            data["all_seen_ids"] = list(self.all_seen_ids)[-500:]
            with open(self.analytics_file, "w") as f:
                json.dump(data, f, indent=2)
        except Exception:
            pass

    def record_scan(self, fingerprint_ids: list, device_count: int = 0):
        """Record analytics from a scan cycle."""
        today = datetime.now().strftime("%Y-%m-%d")
        now_iso = datetime.now(timezone.utc).isoformat()

        # Reset daily tracking on day change
        if today != self._current_day:
            self.today_seen_ids = set()
            self._current_day = today

        if today not in self.daily_stats:
            self.daily_stats[today] = {
                "total_seen": 0,
                "new_devices": 0,
                "returning_devices": 0,
                "peak": 0,
                "scans": 0,
            }

        day = self.daily_stats[today]
        day["scans"] += 1

        new_today = 0
        returning = 0
        for fp_id in fingerprint_ids:
            if fp_id not in self.today_seen_ids:
                self.today_seen_ids.add(fp_id)
                if fp_id in self.all_seen_ids:
                    returning += 1
                else:
                    new_today += 1
                    self.all_seen_ids.add(fp_id)

        day["total_seen"] = len(self.today_seen_ids)
        day["new_devices"] += new_today
        day["returning_devices"] += returning

        if device_count > day["peak"]:
            day["peak"] = device_count

        if device_count > self.peak_device_count:
            self.peak_device_count = device_count
            self.peak_device_time = now_iso

        # Prune old daily stats (keep last 30 days)
        cutoff = (datetime.now() - timedelta(days=30)).strftime("%Y-%m-%d")
        old_keys = [k for k in self.daily_stats if k < cutoff]
        for k in old_keys:
            del self.daily_stats[k]

        # Save periodically (every 10 scans)
        if day["scans"] % 10 == 0:
            self._save()

    def get_summary(self) -> dict:
        """Get analytics summary for the dashboard."""
        today = datetime.now().strftime("%Y-%m-%d")
        today_stats = self.daily_stats.get(today, {
            "total_seen": 0, "new_devices": 0, "returning_devices": 0, "peak": 0, "scans": 0
        })

        # Weekly totals
        week_start = (datetime.now() - timedelta(days=7)).strftime("%Y-%m-%d")
        week_total = 0
        week_new = 0
        for date_str, stats in self.daily_stats.items():
            if date_str >= week_start:
                week_total += stats.get("total_seen", 0)
                week_new += stats.get("new_devices", 0)

        # Daily chart data (last 7 days)
        daily_chart = []
        for i in range(6, -1, -1):
            day = (datetime.now() - timedelta(days=i)).strftime("%Y-%m-%d")
            stats = self.daily_stats.get(day, {"total_seen": 0, "peak": 0})
            daily_chart.append({
                "date": day,
                "count": stats.get("total_seen", 0),
                "peak": stats.get("peak", 0),
            })

        return {
            "today_devices": today_stats.get("total_seen", 0),
            "today_new": today_stats.get("new_devices", 0),
            "today_returning": today_stats.get("returning_devices", 0),
            "today_peak": today_stats.get("peak", 0),
            "week_total": week_total,
            "week_new": week_new,
            "all_time_total": len(self.all_seen_ids),
            "all_time_peak": self.peak_device_count,
            "all_time_peak_time": self.peak_device_time,
            "daily_chart": daily_chart,
        }


class BlueShieldLogger:
    """JSON-based event logger for BlueShield."""

    def __init__(self, config: dict):
        self.config = config
        self.log_file = Path(config.get("log_file", "blueshield.json"))
        self.max_entries = config.get("max_log_entries", 10000)
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        self.events: deque = deque(maxlen=self.max_entries)
        self._load_existing()

        # Initialize analytics tracker
        self.analytics = AnalyticsTracker(data_dir=self.log_file.parent)

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
            "analytics": self.analytics.get_summary(),
            "all_events": list(self.events),
        }
        with open(filepath, "w") as f:
            json.dump(report, f, indent=2)
        return filepath

    def clear_logs(self):
        """Clear all logs."""
        self.events.clear()
        self._save()
