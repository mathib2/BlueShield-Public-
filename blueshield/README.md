# blueshield package

Core application package for BlueShield. Run as a module:

```bash
python -m blueshield --port 8080
```

| Subpackage  | Responsibility |
|-------------|----------------|
| `scanner/`  | BLE + Classic scanning, fingerprinting, classification, following/tracker analysis |
| `jammer/`   | BLE jammer (raw HCI with hcitool fallback) |
| `sniffer/`  | nRF52840 capture (ButteRFly / Sniffle) |
| `dashboard/`| Flask + Socket.IO server and web frontend |
| `logs/`     | JSON event logging and analytics |
| `config/`   | Configuration management |

See the [repository README](../README.md) for installation and hardware setup.
