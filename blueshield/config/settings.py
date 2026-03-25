"""BlueShield configuration settings."""

import os
import json
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
LOG_DIR = BASE_DIR / "logs"
CONFIG_DIR = BASE_DIR / "config"

# Ensure directories exist
LOG_DIR.mkdir(exist_ok=True)
CONFIG_DIR.mkdir(exist_ok=True)

DEFAULT_CONFIG = {
    "scan_interval": 15,          # seconds between scans (must be > scan_duration)
    "scan_duration": 5,           # seconds per BLE scan window
    "alert_threshold": 3,         # unknown devices before alert
    "known_devices_file": str(CONFIG_DIR / "known_devices.json"),
    "log_file": str(LOG_DIR / "blueshield.json"),
    "interface": "hci0",              # scanner adapter (Feasycom BP119)
    "jammer_interface": "hci1",       # dedicated jammer adapter (Hakimonoe BT548)
    "long_range_interface": "hci2",   # nRF52840 Zephyr HCI — Coded PHY long range
    "sniffle_port": "/dev/ttyACM0",   # nRF52840 #1 Sniffle serial port
    "sniffle_enabled": False,         # enable Sniffle packet capture
    "dashboard_refresh": 2,           # dashboard refresh rate (seconds)
    "jam_enabled": False,             # jamming disabled by default (research only)
    "jam_channel": 39,                # BLE advertising channel (37, 38, 39)
    "jam_power": -20,                 # transmit power dBm (low for research)
    "max_log_entries": 10000,         # max entries before rotation
}


def load_config():
    """Load config from file or return defaults."""
    config_file = CONFIG_DIR / "blueshield_config.json"
    if config_file.exists():
        with open(config_file, "r") as f:
            user_config = json.load(f)
        merged = {**DEFAULT_CONFIG, **user_config}
        return merged
    return DEFAULT_CONFIG.copy()


def save_config(config: dict):
    """Save config to file."""
    config_file = CONFIG_DIR / "blueshield_config.json"
    with open(config_file, "w") as f:
        json.dump(config, f, indent=2)
