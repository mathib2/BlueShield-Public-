#!/usr/bin/env bash
# BlueShield uninstaller. Removes the service, code dir, udev rules, and
# (optionally) cloudflared.  Run as root: `sudo bash scripts/uninstall.sh`.
set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-/opt/blueshield}"

if [[ "$(id -u)" -ne 0 ]]; then
    echo "Please run as root (or via sudo)."; exit 1
fi

echo "[blueshield] stopping + disabling service"
systemctl stop    blueshield.service 2>/dev/null || true
systemctl disable blueshield.service 2>/dev/null || true
rm -f /etc/systemd/system/blueshield.service
systemctl daemon-reload

echo "[blueshield] removing udev rules"
rm -f /etc/udev/rules.d/99-blueshield.rules
udevadm control --reload-rules

echo "[blueshield] removing ${INSTALL_DIR}"
rm -rf "${INSTALL_DIR}"

if [[ "${1:-}" == "--purge-cloudflared" ]]; then
    echo "[blueshield] removing cloudflared (per --purge-cloudflared)"
    apt-get -y remove --purge cloudflared >/dev/null 2>&1 || true
fi

echo "[blueshield] uninstalled. Bluetooth packages (bluez, etc.) were left in place."
