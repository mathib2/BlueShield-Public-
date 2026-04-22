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
    "interface": "hci2",              # scanner adapter (Pi onboard Broadcom BT4.1)
    "jammer_interface": "hci0",       # primary jammer (Realtek BT5.1 USB)
    "jammer_secondary_interface": "hci1",  # secondary jammer (Realtek BT5.3 USB, may enumerate as hci1 or hci3)
    "nrf_sniffer_port": "/dev/ttyACM0",  # nRF52840 #1 BLE sniffer serial port
    "nrf_sniffer_port_2": "/dev/ttyACM1",  # nRF52840 #2 BLE sniffer serial port
    "sniffle_enabled": False,         # enable Sniffle packet capture
    "nrf_sniffer_enabled": True,      # enable nRF52 BLE sniffer
    "dashboard_refresh": 2,           # dashboard refresh rate (seconds)
    "jam_enabled": True,              # jamming enabled (WSU authorized research; disable elsewhere)
    "jam_channel": 39,                # BLE advertising channel (37, 38, 39)
    "jam_power": -20,                 # transmit power dBm (low for research)
    "max_log_entries": 10000,         # max entries before rotation

    # ── nRF52840 radio_test backend (real RF jamming, bypasses BlueZ) ──
    # Disabled by default; enable and point to a dongle flashed with radio_test
    # only if you have that specific firmware (not ButteRFly, not sniffer).
    "nrf_jammer_enabled": False,      # not flashed yet — leave false until radio_test is deployed
    "nrf_jammer_port": "/dev/nrf_radio_test",  # different path than ButteRFly to avoid collision
    "nrf_jammer_tx_power": 8,
    "nrf_jammer_phy": "nrf_1Mbit",

    # ── ButteRFly/WHAD backend (BLE injection + InjectaBLE DSN 2021) ──
    # Romain Cayre firmware v1.1.3 — we now have TWO of these dongles
    "butterfly_enabled": True,
    "butterfly_port": "/dev/ttyACM1",

    # ── AutoTerminator (v7.6): dual-ButteRFly sniff→inject pipeline ──
    # Observer sniffs CONNECT_IND, Injector fires LL_TERMINATE_IND
    "auto_terminator_observer_port": "/dev/ttyACM0",
    "auto_terminator_injector_port": "/dev/ttyACM1",
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
