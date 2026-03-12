# BlueShield

**Bluetooth Security Monitoring Platform**

Raspberry Pi-based Bluetooth sniffing and jamming system with a real-time web dashboard.

![BlueShield Logo](assets/logo.png)

## Team

- **Mathias Vera**
- **Daniel Halbleib Jr**
- **Andrew Sauls**

## Features

- Real-time BLE and Classic Bluetooth device scanning
- Web dashboard with live device tracking and RSSI visualization
- Automatic unknown device detection with configurable alert thresholds
- Research-grade BLE jamming (authorized use only)
- JSON audit logging for compliance and incident response
- Device whitelisting and trust management

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run with real BLE hardware
python -m blueshield --port 8080

# Run with simulated data (no hardware needed)
python -m blueshield --sim --port 8080

# Open dashboard at http://localhost:8080
```

## Platform Support

| Platform | BLE Scanning | Classic BT | Jammer | Dashboard |
|----------|-------------|------------|--------|-----------|
| Windows  | Bleak       | -          | Simulated | Full |
| Linux/RPi | Bleak + hcitool | hcitool/hcidump | Real HCI | Full |

## Project Structure

```
blueshield/
  scanner/bt_scanner.py    # BLE + Classic BT scanning
  jammer/bt_jammer.py      # BLE jamming (research only)
  dashboard/app.py          # Flask + Socket.IO web server
  dashboard/static/         # Web dashboard frontend
  logs/logger.py            # JSON event logging
  config/settings.py        # Configuration management
```

## Documentation

- **BlueShield_NABC.pptx** — NABC Presentation
- **BlueShield_Guide.pdf** — Product & Technical Guide

## License

Research use only. Contact the team for commercial licensing.
