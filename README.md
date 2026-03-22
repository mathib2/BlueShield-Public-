# BlueShield

**Bluetooth Security Monitoring Platform v5.0**

Raspberry Pi-based Bluetooth sniffing and jamming system with a real-time web dashboard featuring AI device classification, tracker detection, following detection, and environment safety scoring.

![BlueShield Logo](assets/logo.png)

## Team

- **Mathias Vera**
- **Daniel Halbleib Jr**
- **Andrew Sauls**

## Features

- Real-time BLE and Classic Bluetooth device scanning
- BLE fingerprinting engine with MAC rotation clustering
- AI-powered device classification (phone, laptop, tracker, audio, etc.)
- People estimation and environment safety scoring
- Tracker detection (AirTag, SmartTag, Tile)
- Following detection and shadow device analysis
- Research-grade BLE jammer with sweep/reactive/targeted/continuous modes
- Web dashboard with live device tracking, radar, signals, timeline
- Mobile-responsive UI with bottom navigation
- Login authentication (default: admin / admin123)
- JSON audit logging for compliance and incident response

## Quick Start (Raspberry Pi)

### 1. Clone and Install

```bash
git clone https://github.com/mathib2/BlueShield-Public-.git
cd BlueShield-Public-

# Install system packages
sudo apt update && sudo apt install -y python3-pip python3-venv bluetooth bluez libbluetooth-dev

# Create virtual environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Grant Bluetooth Permissions

```bash
sudo setcap 'cap_net_raw,cap_net_admin=eip' $(readlink -f $(which python3))
```

### 3. Run BlueShield

```bash
source venv/bin/activate
sudo venv/bin/python -m blueshield --port 8080
```

Open your browser to `http://<pi-ip>:8080`

**Default login:** `admin` / `admin123`

### 4. Using an External Bluetooth Antenna

If your Raspberry Pi has an external USB Bluetooth adapter (e.g., TP-Link UB500, ASUS USB-BT500), BlueShield will use it automatically if it's the active HCI interface.

To check which adapter is active:
```bash
hciconfig -a
```

If your external adapter is `hci1` instead of `hci0`, update the config:
```bash
# Edit blueshield/config/blueshield_config.json
{
  "interface": "hci1"
}
```

To verify your adapter is being used and check its capabilities:
```bash
# Check adapter info (look for Bus: USB = external adapter)
hciconfig hci0 -a

# Check if it supports LE (required for BLE scanning)
sudo hcitool -i hci0 lescan --duplicates
```

## Auto-Start on Boot (Never Turns Off)

Set up BlueShield to start automatically when the Raspberry Pi powers on and restart automatically if it crashes:

### Step 1: Create the systemd service

```bash
sudo tee /etc/systemd/system/blueshield.service > /dev/null <<'EOF'
[Unit]
Description=BlueShield Bluetooth Security Monitor
After=bluetooth.target network.target
Wants=bluetooth.target

[Service]
Type=simple
User=root
WorkingDirectory=/home/anon/BlueShield-Public-
ExecStartPre=/bin/sleep 5
ExecStart=/home/anon/BlueShield-Public-/venv/bin/python -m blueshield --port 8080
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
```

> **Note:** Change `/home/anon/BlueShield-Public-` to your actual path if different.

### Step 2: Enable and start

```bash
sudo systemctl daemon-reload
sudo systemctl enable blueshield
sudo systemctl start blueshield
```

### Step 3: Verify it's running

```bash
sudo systemctl status blueshield
```

### Useful commands

```bash
# View live logs
sudo journalctl -u blueshield -f

# Restart after code changes
sudo systemctl restart blueshield

# Stop temporarily
sudo systemctl stop blueshield

# Disable auto-start
sudo systemctl disable blueshield
```

## Platform Support

| Platform | BLE Scanning | Classic BT | Jammer | Dashboard |
|----------|-------------|------------|--------|-----------|
| Windows  | Bleak       | -          | Simulated | Full |
| Linux/RPi | Bleak + hcitool | hcitool/hcidump | Real HCI (raw socket) | Full |

## Project Structure

```
blueshield/
  scanner/
    bt_scanner.py           # BLE + Classic BT scanning with GATT resolution
    fingerprint.py          # BLE fingerprint engine (MAC clustering)
    risk_engine.py          # Risk scoring per device
    tracker_detector.py     # AirTag/SmartTag/Tile detection
    ai_classifier.py        # AI device classification + people estimation
    advanced_analysis.py    # Following, shadows, environment, life story
  jammer/
    bt_jammer.py            # BLE jammer (raw HCI + hcitool fallback)
  dashboard/
    app.py                  # Flask + Socket.IO web server
    static/                 # Web dashboard frontend (HTML/CSS/JS)
  logs/
    logger.py               # JSON event logging + analytics tracker
  config/
    settings.py             # Configuration management
```

## Documentation

- **BlueShield_NABC.pptx** -- NABC Presentation
- **BlueShield_Guide.pdf** -- Product & Technical Guide

## License

Research use only. Contact the team for commercial licensing.
