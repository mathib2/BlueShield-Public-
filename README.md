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

## Quick Start

**Tested on Raspberry Pi 3B+ / 4 / 5 with Debian 12 (Bookworm).**

### One-line install

```bash
curl -fsSL https://raw.githubusercontent.com/pineconegoat/BlueShield/master/scripts/install.sh | sudo bash
```

That's it. The installer:
1. Sanity-checks your Pi model + Debian version + Python (≥ 3.10).
2. `apt`-installs system deps (BlueZ, build tools, libcap, cloudflared).
3. Clones the repo into `/opt/blueshield`.
4. Creates a venv + pip-installs `requirements.txt` (Bleak, scapy, WHAD, Flask, etc.).
5. Drops the udev rules so nRF52 dongles work without sudo.
6. Adds your user to `dialout` + grants raw-HCI capabilities to the venv Python.
7. Installs the systemd unit + starts the service.
8. Prints the LAN URL and login.

After ~2 minutes (mostly pip), open the LAN URL it printed.

### From a clone

```bash
git clone https://github.com/pineconegoat/BlueShield.git
cd BlueShield
sudo bash scripts/install.sh
```

### Default credentials

`admin` / `admin123` — **change this** in Config → Operators before exposing the
dashboard to anyone you don't trust. The login page also surfaces a Cloudflare
quick-tunnel URL (third QR code) you can share for off-LAN access.

### Service control

```bash
sudo systemctl status blueshield     # is it running?
sudo journalctl -u blueshield -f     # tail logs
sudo systemctl restart blueshield    # after code changes
sudo bash /opt/blueshield/scripts/uninstall.sh    # clean removal
```

### External BLE adapters (recommended for sniffer / jammer)

The Pi's onboard Bluetooth radio works for the dashboard's basic BLE scanner,
but for the **sniffer** and **jammer** BlueShield expects:

| Hardware | Role | Notes |
|---|---|---|
| Realtek BT 5.x USB dongle | Scanner / jammer | Cheap (~$5–10), 4–5 dBm tx |
| nRF52840 dongle (ButteRFly firmware) | Sniffer + injection | [Flash guide](https://github.com/whad-team/butterfly) |
| nRF52840 dongle (Sniffle firmware) | Sniffer | [Flash guide](https://github.com/nccgroup/Sniffle) |

The installer's udev rules cover both `c0ff:eeee` (ButteRFly) and `1915:520f`
(Sniffle) USB IDs out of the box.

To check which HCI adapter is which:
```bash
hciconfig -a
```

If your scanner is `hci1` instead of the default `hci2`, set it from the
running dashboard:
```bash
curl -X POST -d '{"interface":"hci1"}' -H 'Content-Type: application/json' \
    http://localhost:8080/api/config
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
