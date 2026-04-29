#!/bin/bash
# BlueShield AP-fallback networking setup
#
# Goal: when the Pi powers on, the dashboard is accessible immediately from
# any laptop/phone with minimal interaction.
#
# Strategy (hybrid, NetworkManager-based):
#   1. On boot, NetworkManager tries known WiFi networks (autoconnect=yes,
#      priority-ranked). Current profiles:
#         - BlueShield-Hotspot  (priority 10, user's phone hotspot)
#         - Vera Torres Wifi    (priority  5, home WiFi)
#   2. A systemd service (blueshield-autonet.service) waits 45 seconds.
#      If NetworkManager is still not associated to any known WiFi network,
#      it activates the "BlueShield-AP" profile — creating a self-hosted
#      open AP named "BlueShield" on 10.42.0.1/24.
#   3. A laptop can connect to that AP and reach the dashboard at:
#         http://blueshield.local:8080  (mDNS, works on macOS + Linux +
#                                        Windows with Bonjour)
#         http://10.42.0.1:8080         (static fallback IP — always works)
#
# This script is idempotent. Safe to re-run.

set -euo pipefail

echo "=== BlueShield AP-fallback setup ==="

# 1. Create the AP profile (idempotent)
if ! nmcli -t con show | grep -q '^BlueShield-AP:'; then
    echo "[1/4] Creating BlueShield-AP NetworkManager profile..."
    sudo nmcli connection add \
        type wifi ifname wlan0 con-name BlueShield-AP \
        autoconnect no \
        wifi.mode ap \
        wifi.ssid "BlueShield" \
        wifi.band bg \
        ipv4.method shared \
        ipv4.addresses 10.42.0.1/24 \
        wifi-sec.key-mgmt none
    echo "  → profile created"
else
    echo "[1/4] BlueShield-AP profile already exists"
fi

# 2. Set priorities so known WiFi wins over AP by default
echo "[2/4] Setting connection priorities..."
sudo nmcli connection modify "BlueShield-Hotspot" connection.autoconnect-priority 20 2>/dev/null || true
sudo nmcli connection modify "Vera Torres Wifi"  connection.autoconnect-priority 10 2>/dev/null || true

# 3. Install the fallback watchdog service
echo "[3/4] Installing blueshield-autonet.service..."
sudo tee /etc/systemd/system/blueshield-autonet.service >/dev/null <<'UNIT'
[Unit]
Description=BlueShield WiFi-or-AP autonet fallback
After=NetworkManager.service
Wants=NetworkManager.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/blueshield-autonet.sh
RemainAfterExit=no

[Install]
WantedBy=multi-user.target
UNIT

sudo tee /usr/local/bin/blueshield-autonet.sh >/dev/null <<'SCRIPT'
#!/bin/bash
# Wait up to 45s for WiFi association. If none by then, start BlueShield-AP.
set -u
MAX_WAIT=45
TARGET_SSIDS=("BlueShield-Hotspot" "Vera Torres Wifi")

log() { echo "[autonet] $(date -Is) $*" >&2; }

waited=0
while [ $waited -lt $MAX_WAIT ]; do
    # Are we associated with a STA WiFi that's one of our target profiles?
    active=$(nmcli -t -f NAME,TYPE,STATE connection show --active | grep ':802-11-wireless:activated$' | cut -d: -f1)
    if [ -n "$active" ]; then
        for tgt in "${TARGET_SSIDS[@]}"; do
            if [ "$active" = "$tgt" ]; then
                log "Associated with '$active' — no AP needed."
                exit 0
            fi
        done
    fi
    sleep 3
    waited=$((waited + 3))
done

log "No known WiFi found after ${MAX_WAIT}s. Activating BlueShield-AP..."
nmcli connection up BlueShield-AP
log "BlueShield-AP active. Dashboard: http://10.42.0.1:8080 or http://blueshield.local:8080"
SCRIPT
sudo chmod +x /usr/local/bin/blueshield-autonet.sh
sudo systemctl daemon-reload
sudo systemctl enable blueshield-autonet.service
echo "  → service installed and enabled"

# 4. Summary
echo "[4/4] Setup complete. Current connection state:"
nmcli -t -f NAME,TYPE,AUTOCONNECT-PRIORITY connection show | grep -v '^lo:\|^Wired' || true
echo ""
echo "═══════════════════════════════════════════════════════════════════════════"
echo " BOOT FLOW"
echo "═══════════════════════════════════════════════════════════════════════════"
echo ""
echo " 1. Pi powers on"
echo " 2. NetworkManager tries:"
echo "      → BlueShield-Hotspot   (your phone, if reachable)"
echo "      → Vera Torres Wifi     (home WiFi, if reachable)"
echo " 3. If neither works in 45s → creates its own open AP named 'BlueShield'"
echo ""
echo " USER ACCESS (any of these):"
echo "   • Connect to WiFi 'BlueShield'                 → http://10.42.0.1:8080"
echo "   • On home/hotspot WiFi                         → http://blueshield.local:8080"
echo "   • Known IP (from router admin)                 → http://<ip>:8080"
echo ""
echo " Login: admin / admin123  (change via /api/auth/change-password)"
echo "═══════════════════════════════════════════════════════════════════════════"
